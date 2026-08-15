package com.example.lockdowndpc.policy;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.net.Uri;
import android.os.Build;
import android.os.SystemClock;
import android.util.Log;
import android.webkit.WebView;

import com.example.lockdowndpc.R;
import com.example.lockdowndpc.admin.LockdownAdminReceiver;
import com.example.lockdowndpc.kiosk.KioskConfigStore;
import com.example.lockdowndpc.kiosk.KioskAppCatalog;
import com.example.lockdowndpc.kiosk.KioskController;
import com.example.lockdowndpc.kiosk.KioskMode;
import com.example.lockdowndpc.maintenance.MaintenanceAppPolicy;
import com.example.lockdowndpc.maintenance.MaintenanceGuard;
import com.example.lockdowndpc.maintenance.MaintenancePlan;
import com.example.lockdowndpc.maintenance.MaintenanceStateMachine;
import com.example.lockdowndpc.maintenance.MaintenanceStore;
import com.example.lockdowndpc.maintenance.MaintenanceWindow;
import com.example.lockdowndpc.ui.BlockedBrowserActivity;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

public final class LockdownPolicyController {
    private static final String TAG = "LockdownPolicy";

    private LockdownPolicyController() {}

    public static synchronized PolicyResult apply(Context context) {
        AllowedAppsStore.markApplyStarted(context);
        DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
        ComponentName admin = LockdownAdminReceiver.componentName(context);
        if (dpm == null || !dpm.isDeviceOwnerApp(context.getPackageName())) {
            String error = "device-owner-required";
            AllowedAppsStore.markApplyFailed(context, error);
            return new PolicyResult(false, false, 0, 0, List.of(error));
        }

        ArrayList<String> errors = new ArrayList<>();
        applySystemPolicy(context, dpm, admin, errors);
        Set<String> trustedManagement = resolveTrustedManagementPackages(context, errors);
        // Kiosk reconciles before the link handlers: turning kiosk off clears
        // every persistent preferred activity of this package, and
        // configureBlockedBrowser below re-registers the managed-filtering ones.
        KioskController.reconcile(context, dpm, admin, errors);
        setBlockedBrowserComponentEnabled(context, true, errors);
        configureBlockedBrowser(context, dpm, admin, errors);
        protectManagementApps(context, dpm, admin, trustedManagement, errors);
        int[] packageCounts = applyPackagePolicy(context, dpm, admin, trustedManagement, errors);
        suspendBrowserBackedWebViewIfNeeded(context, dpm, admin, errors);
        boolean verified = errors.isEmpty();
        if (verified) {
            AllowedAppsStore.markApplySucceeded(context);
            Log.i(TAG, "Policy apply verified; blocked=" + packageCounts[0]
                    + ", allowed=" + packageCounts[1]);
        } else {
            String summary = summarizeErrors(errors);
            AllowedAppsStore.markApplyFailed(context, summary);
            AuditLog.append(context, "Policy apply failed: " + summary);
            Log.e(TAG, "Policy apply failed verification: " + summary);
        }
        return new PolicyResult(true, verified, packageCounts[0], packageCounts[1], errors);
    }

    public static synchronized PolicyResult pause(Context context) {
        AllowedAppsStore.markPauseStarted(context);
        DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
        ComponentName admin = LockdownAdminReceiver.componentName(context);
        if (dpm == null || !dpm.isDeviceOwnerApp(context.getPackageName())) {
            String error = "device-owner-required";
            AllowedAppsStore.markPauseFailed(context, error);
            return new PolicyResult(false, false, 0, 0, List.of(error));
        }

        ArrayList<String> errors = new ArrayList<>();
        // Maintenance is an exception to an enforced policy, so pausing ends it.
        // The record is dropped before the restrictions are released rather than
        // after: if this pass dies midway, the next maintenance refresh must not
        // find a window and "restore" the base policy onto a device an
        // administrator has just paused.
        closeMaintenanceForPause(context);
        releaseSystemPolicy(context, dpm, admin, errors);
        try {
            dpm.clearPackagePersistentPreferredActivities(admin, context.getPackageName());
        } catch (RuntimeException exception) {
            errors.add("link-block-clear:" + exception.getClass().getSimpleName());
        }
        setBlockedBrowserComponentEnabled(context, false, errors);

        Set<String> packagesToShow = new LinkedHashSet<>();
        for (ApplicationInfo info : getInstalledApplications(context.getPackageManager())) {
            packagesToShow.add(info.packageName);
        }
        // PackageManager may omit applications that the DPC itself hid. Add every
        // package we may have managed explicitly so pause always restores it.
        packagesToShow.addAll(LockdownPackages.ALWAYS_BLOCKED);
        packagesToShow.addAll(LockdownPackages.KNOWN_BROWSER_AND_SOCIAL);
        packagesToShow.addAll(AllowedAppsStore.getManagedPackages(context));
        // A device that never enabled kiosk skips this entirely; one that did must
        // get its escape surfaces back even though they are hidden from bulk
        // queries. An active kiosk keeps them hidden: pausing managed filtering is
        // not a way to widen kiosk.
        boolean kioskActive = KioskConfigStore.requiresContainment(context);
        if (!kioskActive && KioskConfigStore.wasEscapeSurfaceHidingApplied(context)) {
            packagesToShow.addAll(LockdownPackages.KIOSK_ESCAPE_SURFACES);
        }

        int visibleCount = 0;
        for (String packageName : packagesToShow) {
            if (packageName.equals(context.getPackageName())) {
                continue;
            }
            // The static browser/store catalog contains packages from many OEMs.
            // DevicePolicyManager may return false (instead of throwing) when
            // asked to update a package that is not present, which would turn a
            // successful pause into a false failure. Hidden apps still report
            // FLAG_INSTALLED, so this does not skip packages managed by this DPC.
            if (!isInstalled(context.getPackageManager(), packageName)) {
                continue;
            }
            try {
                boolean wasHidden = dpm.isApplicationHidden(admin, packageName);
                boolean updated = dpm.setApplicationHidden(admin, packageName, false);
                boolean hidden = dpm.isApplicationHidden(admin, packageName);
                if (hidden || (!updated && wasHidden)) {
                    errors.add("package-release-unverified:" + packageName);
                } else {
                    visibleCount++;
                }
            } catch (IllegalArgumentException ignored) {
                // Known package is not installed on this device.
            } catch (RuntimeException exception) {
                errors.add("package-release:" + packageName + ":" + exception.getClass().getSimpleName());
            }
        }
        unsuspendBrowserProviders(dpm, admin, errors);
        protectManagementApps(context, dpm, admin, resolveTrustedManagementPackages(context, errors), errors);
        // Pausing managed filtering is not a way out of kiosk: an active kiosk
        // keeps its lock task allowlist and re-registers the HOME preference that
        // clearPackagePersistentPreferredActivities() above removed.
        KioskController.reconcile(context, dpm, admin, errors);
        boolean verified = errors.isEmpty();
        if (verified) {
            AllowedAppsStore.markPauseSucceeded(context);
            Log.i(TAG, "Policy pause verified; visible=" + visibleCount);
        } else {
            String summary = summarizeErrors(errors);
            AllowedAppsStore.markPauseFailed(context, summary);
            AuditLog.append(context, "Policy pause failed: " + summary);
            Log.e(TAG, "Policy pause failed verification: " + summary);
        }
        return new PolicyResult(true, verified, 0, visibleCount, errors);
    }

    /**
     * Applies the administrator's system policy controls and verifies each one.
     *
     * <p>This replaces the fixed restriction list 0.5.1 sent unconditionally.
     * The set is not narrower: {@link SystemPolicyControl} defaults reproduce that
     * list exactly for a device with no stored choices, so an upgraded pilot
     * enforces what it enforced before — including keeping developer options and
     * ADB available, which the pilot still uses as its recovery path.
     *
     * <p>Only a <em>critical</em> control the administrator actually asked for can
     * add an error here, and an error is what makes {@code apply} report the
     * policy as unverified and drives the console's fault state. An advisory
     * refusal and a restriction this Android release does not implement are
     * recorded and shown, but neither is allowed to brick a working device.
     */
    private static void applySystemPolicy(
            Context context,
            DevicePolicyManager dpm,
            ComponentName admin,
            List<String> errors
    ) {
        SystemPolicyProfile profile = SystemPolicyStore.effectiveProfile(context);
        Map<SystemPolicyControl, Boolean> choices = effectiveChoicesFor(context, profile);
        SystemPolicyReport report = SystemPolicyEnforcer.enforce(
                Build.VERSION.SDK_INT,
                profile,
                choices,
                new SystemPolicyDeviceGateway(dpm, admin)
        );
        recordSystemPolicy(context, report);
        for (SystemPolicyControlStatus fault : report.faults()) {
            errors.add("system-policy:" + fault.summary());
        }
    }

    /**
     * The choices this pass should actually apply, maintenance included.
     *
     * <p>An apply is not the only thing that reaches this code: a reboot, a
     * package install and a periodic sweep all reconcile the policy. Without this,
     * any of them landing during an open maintenance window would silently
     * re-assert the restrictions the window had cleared — the technician would be
     * looking at a console that says a capability is open while the device had
     * already taken it away again. So the window, when one is live, is part of
     * what the base policy means.
     *
     * <p>A window that has lapsed is deliberately ignored here rather than
     * closed: closing is {@code MaintenanceGuard}'s job, it has to be read back,
     * and this pass re-applies the base policy anyway, which is the same device
     * state a restore would produce.
     */
    private static Map<SystemPolicyControl, Boolean> effectiveChoicesFor(
            Context context,
            SystemPolicyProfile profile
    ) {
        Map<SystemPolicyControl, Boolean> stored = SystemPolicyStore.explicitChoices(context);
        MaintenanceWindow window = liveMaintenanceWindow(context);
        if (window == null) {
            return stored;
        }
        // The full liveness evaluation, not a bare expiry check. An expiry-only
        // test reads a pre-reboot window as live — after a restart the monotonic
        // clock is near zero, comfortably below the old deadline — so a boot-time
        // reconcile would re-apply the window's relaxations and record the pass
        // as verified. The state machine's reboot and clock checks are the same
        // ones MaintenanceGuard closes the window with; this pass merely ignores
        // a window the guard would not honour, and leaves the closing (which
        // must be read back and audited) to the guard.
        return MaintenancePlan.forWindow(profile, stored, window).effectiveChoices();
    }

    /** The stored window only when the state machine would still honour it. */
    private static MaintenanceWindow liveMaintenanceWindow(Context context) {
        MaintenanceWindow window = MaintenanceStore.readWindow(context);
        if (window == null) {
            return null;
        }
        MaintenanceStateMachine.Evaluation evaluation =
                MaintenanceStateMachine.evaluate(window, MaintenanceStore.deviceClock());
        return evaluation.open() ? evaluation.window() : null;
    }

    /**
     * Ends any maintenance window because protection is being paused.
     *
     * <p>No restore is performed and none is owed: {@code releaseSystemPolicy}
     * withdraws every control a moment later, which is a superset of whatever the
     * window had relaxed. Leaving the record in place is what would be unsafe —
     * the maintenance timers would later fire on a paused device and re-assert
     * restrictions the console says are off.
     */
    private static void closeMaintenanceForPause(Context context) {
        try {
            boolean hadWindow = MaintenanceStore.readWindow(context) != null
                    || MaintenanceStore.restorePending(context);
            MaintenanceStore.clearWindow(context);
            MaintenanceStore.clearRestorePending(context);
            MaintenanceGuard.arm(context, null);
            if (hadWindow) {
                AuditLog.append(context, "maintenance:closed-by-pause");
            }
        } catch (RuntimeException exception) {
            // Pausing must not fail because the maintenance record misbehaved;
            // the release below is what actually frees the device.
            Log.e(TAG, "Could not clear the maintenance record while pausing", exception);
        }
    }

    /**
     * Withdraws every system policy control for {@code pause}.
     *
     * <p>Pause keeps the stricter rule 0.5.1 used: any restriction that will not
     * come off is a pause failure, advisory or not. A paused device that is still
     * enforcing something is exactly the state an administrator is trying to
     * leave, so it may not be reported as a clean pause.
     */
    private static void releaseSystemPolicy(
            Context context,
            DevicePolicyManager dpm,
            ComponentName admin,
            List<String> errors
    ) {
        SystemPolicyReport report = SystemPolicyEnforcer.release(
                Build.VERSION.SDK_INT,
                new SystemPolicyDeviceGateway(dpm, admin)
        );
        recordSystemPolicy(context, report);
        for (SystemPolicyControlStatus failure : report.failures()) {
            errors.add("system-policy-release:" + failure.summary());
        }
    }

    /**
     * Audits what changed, then stores the pass as the console's evidence.
     *
     * <p>Only problems are audited, and only when the outcome differs from the
     * one already on file. Reconciliation runs on every boot and every package
     * change; appending a line per control per pass would evict the
     * administrator actions the 50-entry log exists to keep.
     */
    private static void recordSystemPolicy(Context context, SystemPolicyReport report) {
        for (SystemPolicyControlStatus status : report.statuses()) {
            boolean problem = status.failed()
                    || (status.requested()
                        && status.outcome() == SystemPolicyOutcome.UNSUPPORTED);
            if (!problem
                    || SystemPolicyStore.lastOutcome(context, status.control())
                        == status.outcome()) {
                continue;
            }
            AuditLog.append(
                    context,
                    context.getString(R.string.audit_system_policy_unverified, status.summary())
            );
        }
        SystemPolicyStore.saveReport(context, report);
    }

    private static void configureBlockedBrowser(
            Context context,
            DevicePolicyManager dpm,
            ComponentName admin,
            List<String> errors
    ) {
        ComponentName blockedActivity = new ComponentName(admin.getPackageName(), BlockedBrowserActivity.class.getName());
        // Android 14+ applies this policy asynchronously. Register both filters
        // first, then verify their effective resolution with a short bounded
        // retry. PolicyUpdateAuditReceiver remains the authoritative backstop
        // for a later conflicting-admin result.
        for (String scheme : new String[]{"http", "https"}) {
            try {
                IntentFilter filter = new IntentFilter(Intent.ACTION_VIEW);
                filter.addCategory(Intent.CATEGORY_DEFAULT);
                filter.addCategory(Intent.CATEGORY_BROWSABLE);
                filter.addDataScheme(scheme);
                dpm.addPersistentPreferredActivity(admin, filter, blockedActivity);
            } catch (RuntimeException exception) {
                errors.add("link-filter:" + scheme + ":" + exception.getClass().getSimpleName());
            }
        }
        for (String scheme : new String[]{"http", "https"}) {
            try {
                Intent probe = new Intent(Intent.ACTION_VIEW, Uri.parse(scheme + "://policy-check.invalid"));
                probe.addCategory(Intent.CATEGORY_BROWSABLE);
                if (!eventuallyResolvesTo(context.getPackageManager(), probe, blockedActivity)) {
                    errors.add("link-filter-target-unverified:" + scheme);
                }
            } catch (RuntimeException exception) {
                errors.add("link-filter:" + scheme + ":" + exception.getClass().getSimpleName());
            }
        }
    }

    private static boolean eventuallyResolvesTo(
            PackageManager pm,
            Intent intent,
            ComponentName expected
    ) {
        int attempts = Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE ? 20 : 1;
        for (int attempt = 0; attempt < attempts; attempt++) {
            if (expected.equals(resolveActivity(pm, intent))) {
                return true;
            }
            if (attempt + 1 < attempts) {
                SystemClock.sleep(100);
            }
        }
        return false;
    }

    private static void setBlockedBrowserComponentEnabled(
            Context context,
            boolean enabled,
            List<String> errors
    ) {
        ComponentName component = new ComponentName(context, BlockedBrowserActivity.class);
        int state = enabled
                ? PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                : PackageManager.COMPONENT_ENABLED_STATE_DISABLED;
        try {
            context.getPackageManager().setComponentEnabledSetting(
                    component,
                    state,
                    PackageManager.DONT_KILL_APP
            );
            if (context.getPackageManager().getComponentEnabledSetting(component) != state) {
                errors.add("link-filter-update-unverified");
            }
        } catch (RuntimeException exception) {
            errors.add("link-filter-update:" + exception.getClass().getSimpleName());
        }
    }

    /**
     * Resolves which configured management packages may actually be treated as
     * management on this device.
     *
     * <p>Management identity is a configuration record ({@link
     * LockdownPackages.ManagementPackage}), not a package-name literal. When a
     * record carries an approved certificate digest, verification fails closed:
     * an unmatched or unreadable signer means the package gets no management
     * privilege and the apply is reported as unverified. When no digest is
     * configured — the default for the Tailscale pilot record — trust rests on
     * the package name alone, which is an explicit and documented proof gap.
     */
    private static Set<String> resolveTrustedManagementPackages(
            Context context,
            List<String> errors
    ) {
        LinkedHashSet<String> trusted = new LinkedHashSet<>();
        for (LockdownPackages.ManagementPackage record : LockdownPackages.managementPackages(
                AllowedAppsStore.getManagementCertificatePins(context))) {
            if (!isInstalled(context.getPackageManager(), record.packageName())) {
                continue;
            }
            LockdownPackages.SignerVerdict verdict = LockdownPackages.verifySigner(
                    record,
                    signingCertificateDigests(context, record.packageName())
            );
            if (LockdownPackages.grantsManagementTrust(verdict)) {
                trusted.add(record.packageName());
            } else {
                errors.add("management-signer-unverified:" + record.packageName()
                        + ":" + verdict.name());
                Log.e(TAG, "Management signer rejected for " + record.packageName() + ": " + verdict);
            }
        }
        return trusted;
    }

    private static Set<String> signingCertificateDigests(Context context, String packageName) {
        LinkedHashSet<String> digests = new LinkedHashSet<>();
        PackageManager pm = context.getPackageManager();
        try {
            Signature[] signatures;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageInfo info = getPackageInfo(pm, packageName,
                        PackageManager.GET_SIGNING_CERTIFICATES);
                SigningInfo signingInfo = info.signingInfo;
                if (signingInfo == null) {
                    return digests;
                }
                signatures = signingInfo.hasMultipleSigners()
                        ? signingInfo.getApkContentsSigners()
                        : signingInfo.getSigningCertificateHistory();
            } else {
                //noinspection deprecation
                PackageInfo info = getPackageInfo(pm, packageName, PackageManager.GET_SIGNATURES);
                //noinspection deprecation
                signatures = info.signatures;
            }
            if (signatures == null) {
                return digests;
            }
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            for (Signature signature : signatures) {
                digests.add(toHex(sha256.digest(signature.toByteArray())));
            }
        } catch (PackageManager.NameNotFoundException | NoSuchAlgorithmException ignored) {
            // An unreadable signer is reported as "no digest observed", which a
            // pinned record treats as UNKNOWN_SIGNER rather than as a pass.
        }
        return digests;
    }

    private static PackageInfo getPackageInfo(PackageManager pm, String packageName, int flags)
            throws PackageManager.NameNotFoundException {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(flags));
        }
        //noinspection deprecation
        return pm.getPackageInfo(packageName, flags);
    }

    private static String toHex(byte[] value) {
        StringBuilder hex = new StringBuilder(value.length * 2);
        for (byte b : value) {
            hex.append(String.format(Locale.ROOT, "%02x", b));
        }
        return hex.toString();
    }

    private static void protectManagementApps(
            Context context,
            DevicePolicyManager dpm,
            ComponentName admin,
            Set<String> trustedManagement,
            List<String> errors
    ) {
        LinkedHashSet<String> protectedPackages = new LinkedHashSet<>();
        protectedPackages.add(context.getPackageName());
        protectedPackages.addAll(trustedManagement);
        for (String packageName : protectedPackages) {
            if (!isInstalled(context.getPackageManager(), packageName)) {
                continue;
            }
            try {
                dpm.setUninstallBlocked(admin, packageName, true);
                if (!dpm.isUninstallBlocked(admin, packageName)) {
                    errors.add("uninstall-protection-unverified:" + packageName);
                }
            } catch (RuntimeException exception) {
                errors.add("uninstall-protection:" + packageName + ":"
                        + exception.getClass().getSimpleName());
            }
        }
    }

    /**
     * The opted-in system packages whose recorded risk acceptance still describes
     * the binary that is installed.
     *
     * <p>A package whose signer or version has drifted is dropped from management
     * rather than faulted: an OEM update is a normal event, and faulting
     * protection on every firmware update would strand a fleet for something an
     * administrator resolves in the console. The drop is audited so it is visible.
     */
    private static Set<String> revalidatedSystemSelection(Context context, PackageManager pm) {
        Set<String> selected = AllowedAppsStore.getAdminSelectedSystemPackages(context);
        if (selected.isEmpty()) {
            return selected;
        }
        java.util.LinkedHashMap<String, SystemAppRiskAcceptance> acceptances =
                new java.util.LinkedHashMap<>();
        java.util.LinkedHashMap<String, SystemAppSelection.InstalledIdentity> installed =
                new java.util.LinkedHashMap<>();
        for (String packageName : selected) {
            SystemAppRiskAcceptance acceptance =
                    AllowedAppsStore.getSystemRiskAcceptance(context, packageName);
            if (acceptance != null) {
                acceptances.put(packageName, acceptance);
            }
            installed.put(packageName, observedIdentity(context, pm, packageName));
        }
        SystemAppSelection.Revalidation revalidation =
                SystemAppSelection.revalidate(selected, acceptances, installed);
        if (revalidation.anyRevoked()) {
            Log.e(TAG, "System selections no longer match their acceptance: "
                    + revalidation.revokedSummary());
            AuditLog.append(
                    context,
                    "system-selection-revoked:" + revalidation.revokedSummary());
        }
        return revalidation.managed();
    }

    /** The signer digest and version of an installed package, as observed now. */
    private static SystemAppSelection.InstalledIdentity observedIdentity(
            Context context,
            PackageManager pm,
            String packageName
    ) {
        try {
            if (!isInstalled(pm, packageName)) {
                return SystemAppSelection.InstalledIdentity.unreadable();
            }
            // Both readings come from PackageIdentity, the same definition the
            // console records the acceptance with. Computing either here in a
            // second format is how every acceptance once became unsatisfiable
            // and every opted-in package was silently revoked on each pass.
            return new SystemAppSelection.InstalledIdentity(
                    PackageIdentity.currentSignerSha256(pm, packageName),
                    PackageIdentity.versionText(getPackageInfo(pm, packageName, 0)));
        } catch (RuntimeException | PackageManager.NameNotFoundException exception) {
            return SystemAppSelection.InstalledIdentity.unreadable();
        }
    }

    private static int[] applyPackagePolicy(
            Context context,
            DevicePolicyManager dpm,
            ComponentName admin,
            Set<String> trustedManagement,
            List<String> errors
    ) {
        PackageManager pm = context.getPackageManager();
        Set<String> allowed = AllowedAppsStore.getAllowedPackages(context);
        Set<String> managed = AllowedAppsStore.getManagedPackages(context);
        // Re-checked against what is installed right now, never taken on trust
        // from storage: an OEM update can replace the binary behind an accepted
        // package name, and acting on the old acceptance would hide a component
        // nobody reviewed during an automatic reconciliation pass.
        Set<String> adminSelectedSystem = revalidatedSystemSelection(context, pm);
        boolean appStoreMaintenanceOpen = MaintenanceAppPolicy.opensApplicationStores(
                liveMaintenanceWindow(context));
        boolean allowlistConfigured = AllowedAppsStore.isAllowlistConfigured(context);
        AllowedAppsStore.ProtectionMode mode = AllowedAppsStore.getProtectionMode(context);
        String webViewProvider = resolveWebViewProvider(pm);
        KioskConfigStore.Settings kiosk = KioskConfigStore.read(context);
        boolean kioskActive = KioskConfigStore.isContainmentState(kiosk.state());
        String requestedKioskTarget = kioskActive && kiosk.config().mode() == KioskMode.SINGLE_APP
                ? kiosk.config().targetPackage()
                : "";
        String kioskTarget = KioskAppCatalog.isProtectedFromKiosk(requestedKioskTarget)
                ? ""
                : requestedKioskTarget;
        int blockedCount = 0;
        int allowedCount = 0;

        Set<String> packageNames = new LinkedHashSet<>();
        for (ApplicationInfo info : getInstalledApplications(pm)) {
            packageNames.add(info.packageName);
            boolean system = (info.flags
                    & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0;
            if (!system
                    && !info.packageName.equals(context.getPackageName())
                    && !LockdownPackages.isManagementPackage(info.packageName)) {
                managed.add(info.packageName);
                AllowedAppsStore.rememberManagedPackage(
                        context,
                        info.packageName,
                        info.loadLabel(pm).toString()
                );
            }
        }
        // PackageManager omits packages hidden by this DPC from bulk queries.
        // Reconcile every package that may already be hidden explicitly.
        packageNames.addAll(LockdownPackages.ALWAYS_BLOCKED);
        if (appStoreMaintenanceOpen) {
            // Hidden applications are omitted from bulk PackageManager queries.
            // Name every reversible store explicitly so a live maintenance
            // window can restore it even when no earlier inventory saw it.
            packageNames.addAll(MaintenanceAppPolicy.managedStorePackages());
        }
        packageNames.addAll(LockdownPackages.KNOWN_BROWSER_AND_SOCIAL);
        packageNames.addAll(managed);
        packageNames.addAll(allowed);
        packageNames.addAll(LockdownPackages.managementPackageNames());
        // Escape surfaces are touched only once kiosk has actually been used, so a
        // device that never enables kiosk behaves exactly as it did in 0.4. The
        // stored flag keeps them in the reconcile set for the one pass that has to
        // restore them after kiosk is switched off.
        boolean reconcileEscapeSurfaces =
                kioskActive || KioskConfigStore.wasEscapeSurfaceHidingApplied(context);
        if (reconcileEscapeSurfaces) {
            packageNames.addAll(LockdownPackages.KIOSK_ESCAPE_SURFACES);
        }
        if (!kioskTarget.isEmpty()) {
            packageNames.add(kioskTarget);
        }
        if (webViewProvider != null) {
            packageNames.add(webViewProvider);
        }

        for (String packageName : packageNames) {
            if (packageName.equals(context.getPackageName())) {
                continue;
            }

            LockdownPackages.PackageClass packageClass =
                    LockdownPackages.classify(packageName, adminSelectedSystem);

            boolean shouldBlock = LockdownPackages.ALWAYS_BLOCKED.contains(packageName)
                    || LockdownPackages.KNOWN_BROWSER_AND_SOCIAL.contains(packageName);

            if (!shouldBlock && allowlistConfigured
                    && (managed.contains(packageName)
                        || packageClass == LockdownPackages.PackageClass.ADMIN_SELECTED_SYSTEM)) {
                shouldBlock = mode == AllowedAppsStore.ProtectionMode.ALLOW_SELECTED
                        ? !allowed.contains(packageName)
                        : allowed.contains(packageName);
            }

            // Store access is an explicit, timed exception to the built-in store
            // catalogue. It does not open browsers or social applications, and
            // the kiosk escape-surface rule below still wins while containment
            // is active.
            if (MaintenanceAppPolicy.keepsVisible(packageName, appStoreMaintenanceOpen)) {
                shouldBlock = false;
            }

            // Kiosk hides the known escape surfaces even though Lock Task already
            // blocks navigation to most of them; a share sheet or OEM shortcut is
            // a real exit. Outside kiosk they are deliberately left alone.
            if (reconcileEscapeSurfaces
                    && packageClass == LockdownPackages.PackageClass.KIOSK_ESCAPE_SURFACE) {
                shouldBlock = kioskActive;
            }

            // Management connectivity must survive policy changes. This is also
            // useful while an administrator is still configuring the device. A
            // configured record whose signer did not verify is absent from
            // trustedManagement and therefore gets no exemption here.
            if (trustedManagement.contains(packageName)) {
                shouldBlock = false;
            } else if (LockdownPackages.isManagementPackage(packageName)) {
                // A configured record whose signer did not verify is not the
                // management application. Fail closed: hide it rather than let an
                // impostor keep the exemption its package name would have bought.
                shouldBlock = true;
            }
            // On some Android releases Chrome is also the system WebView engine.
            // Hiding that package breaks otherwise allowed apps that render HTML.
            if (packageName.equals(webViewProvider)) {
                shouldBlock = false;
            }
            // Hiding these bricks OEM devices in ways the console cannot repair.
            if (packageClass == LockdownPackages.PackageClass.ESSENTIAL_SYSTEM_PACKAGE) {
                shouldBlock = false;
            }
            // The kiosk target is the whole point of the profile.
            if (packageName.equals(kioskTarget)) {
                shouldBlock = false;
            }

            boolean criticalPackage = shouldBlock
                    || managed.contains(packageName)
                    || allowed.contains(packageName)
                    || packageName.equals(kioskTarget)
                    || (reconcileEscapeSurfaces
                        && packageClass == LockdownPackages.PackageClass.KIOSK_ESCAPE_SURFACE)
                    || LockdownPackages.isManagementPackage(packageName)
                    || packageName.equals(webViewProvider);
            criticalPackage = criticalPackage
                    || MaintenanceAppPolicy.keepsVisible(packageName, appStoreMaintenanceOpen);
            if (!criticalPackage || !isInstalled(pm, packageName)) {
                continue;
            }

            try {
                boolean wasHidden = dpm.isApplicationHidden(admin, packageName);
                boolean updated = dpm.setApplicationHidden(admin, packageName, shouldBlock);
                boolean hidden = dpm.isApplicationHidden(admin, packageName);
                if (!updated && wasHidden != shouldBlock) {
                    errors.add("package-policy-update-rejected:" + packageName);
                } else if (hidden != shouldBlock) {
                    errors.add("package-policy-state-mismatch:" + packageName);
                }
                if (hidden) {
                    blockedCount++;
                } else {
                    allowedCount++;
                }
            } catch (IllegalArgumentException ignored) {
                // A known package is not installed on this device.
            } catch (RuntimeException exception) {
                errors.add("package-policy:" + packageName + ":"
                        + exception.getClass().getSimpleName());
            }
        }
        // Only drop the restore obligation after a pass that actually completed.
        if (reconcileEscapeSurfaces && (kioskActive || errors.isEmpty())) {
            KioskConfigStore.setEscapeSurfaceHidingApplied(context, kioskActive);
        }
        return new int[]{blockedCount, allowedCount};
    }

    private static String resolveWebViewProvider(PackageManager pm) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            PackageInfo current = WebView.getCurrentWebViewPackage();
            if (current != null) {
                return current.packageName;
            }
        }

        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.P) {
            // Chrome is the standard provider on many Android 8/9 builds. A
            // hidden provider is also invisible to explicit package queries,
            // so return its package name directly to repair the stale state.
            return "com.android.chrome";
        }

        // Recover devices where the active provider was hidden by an older
        // policy revision. Android 8/9 commonly use Chrome as the provider.
        for (String candidate : new String[]{
                "com.android.chrome",
                "com.google.android.webview",
                "com.chrome.beta",
                "com.chrome.dev"
        }) {
            if (isUsableWebViewCandidate(pm, candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private static boolean isUsableWebViewCandidate(PackageManager pm, String packageName) {
        try {
            PackageInfo packageInfo;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                packageInfo = pm.getPackageInfo(
                        packageName,
                        PackageManager.PackageInfoFlags.of(PackageManager.MATCH_DISABLED_COMPONENTS)
                );
            } else {
                //noinspection deprecation
                packageInfo = pm.getPackageInfo(packageName, PackageManager.MATCH_DISABLED_COMPONENTS);
            }
            return packageInfo.applicationInfo != null && packageInfo.applicationInfo.enabled;
        } catch (PackageManager.NameNotFoundException ignored) {
            return false;
        }
    }

    private static void suspendBrowserBackedWebViewIfNeeded(
            Context context,
            DevicePolicyManager dpm,
            ComponentName admin,
            List<String> errors
    ) {
        String provider = resolveWebViewProvider(context.getPackageManager());
        if (provider == null || !LockdownPackages.ALWAYS_BLOCKED.contains(provider)) {
            return;
        }
        try {
            String[] failed = dpm.setPackagesSuspended(admin, new String[]{provider}, true);
            if (failed.length > 0) {
                errors.add("browser-suspension-failed");
            } else if (!dpm.isPackageSuspended(admin, provider)) {
                errors.add("browser-suspension-unverified");
            }
        } catch (PackageManager.NameNotFoundException exception) {
            errors.add(context.getString(R.string.policy_reason_webview_missing));
        } catch (RuntimeException exception) {
            errors.add("browser-suspension:" + exception.getClass().getSimpleName());
        }
    }

    private static void unsuspendBrowserProviders(
            DevicePolicyManager dpm,
            ComponentName admin,
            List<String> errors
    ) {
        for (String packageName : new String[]{
                "com.android.chrome",
                "com.google.android.webview",
                "com.chrome.beta",
                "com.chrome.dev"
        }) {
            try {
                String[] failed = dpm.setPackagesSuspended(admin, new String[]{packageName}, false);
                if (failed.length > 0) {
                    continue;
                }
                if (dpm.isPackageSuspended(admin, packageName)) {
                    errors.add("webview-release-unverified:" + packageName);
                }
            } catch (PackageManager.NameNotFoundException ignored) {
                // Provider is not installed.
            } catch (IllegalArgumentException ignored) {
                // Provider is not installed.
            } catch (RuntimeException exception) {
                errors.add("webview-release:" + exception.getClass().getSimpleName());
            }
        }
    }

    private static boolean isInstalled(PackageManager pm, String packageName) {
        try {
            ApplicationInfo info;
            long flags = PackageManager.MATCH_UNINSTALLED_PACKAGES
                    | PackageManager.MATCH_DISABLED_COMPONENTS;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                info = pm.getApplicationInfo(
                        packageName,
                        PackageManager.ApplicationInfoFlags.of(flags)
                );
            } else {
                //noinspection deprecation
                info = pm.getApplicationInfo(packageName, (int) flags);
            }
            return (info.flags & ApplicationInfo.FLAG_INSTALLED) != 0;
        } catch (PackageManager.NameNotFoundException ignored) {
            return false;
        }
    }

    private static List<ApplicationInfo> getInstalledApplications(PackageManager pm) {
        long flags = PackageManager.MATCH_UNINSTALLED_PACKAGES
                | PackageManager.MATCH_DISABLED_COMPONENTS;
        List<ApplicationInfo> applications;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            applications = pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(flags));
        } else {
            //noinspection deprecation
            applications = pm.getInstalledApplications((int) flags);
        }
        ArrayList<ApplicationInfo> installed = new ArrayList<>();
        for (ApplicationInfo info : applications) {
            if ((info.flags & ApplicationInfo.FLAG_INSTALLED) != 0) {
                installed.add(info);
            }
        }
        return installed;
    }

    private static ComponentName resolveActivity(PackageManager pm, Intent intent) {
        android.content.pm.ResolveInfo resolved;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            resolved = pm.resolveActivity(
                    intent,
                    PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_DEFAULT_ONLY)
            );
        } else {
            //noinspection deprecation
            resolved = pm.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY);
        }
        if (resolved == null || resolved.activityInfo == null) {
            return null;
        }
        return new ComponentName(resolved.activityInfo.packageName, resolved.activityInfo.name);
    }

    private static String summarizeErrors(List<String> errors) {
        if (errors.isEmpty()) {
            return "";
        }
        String first = errors.get(0);
        return errors.size() == 1 ? first : first + " (and " + (errors.size() - 1) + " more)";
    }

    public record PolicyResult(
            boolean deviceOwner,
            boolean applied,
            int blockedPackages,
            int allowedPackages,
            List<String> errors
    ) {
        public PolicyResult {
            errors = List.copyOf(errors);
            if (applied && (!deviceOwner || !errors.isEmpty())) {
                throw new IllegalArgumentException("Applied policy must be owner-verified and error-free");
            }
        }
    }
}
