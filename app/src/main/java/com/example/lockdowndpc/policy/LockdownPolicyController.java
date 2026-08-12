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
import android.os.UserManager;
import android.util.Log;
import android.webkit.WebView;

import com.example.lockdowndpc.R;
import com.example.lockdowndpc.admin.LockdownAdminReceiver;
import com.example.lockdowndpc.kiosk.KioskConfigStore;
import com.example.lockdowndpc.kiosk.KioskAppCatalog;
import com.example.lockdowndpc.kiosk.KioskController;
import com.example.lockdowndpc.kiosk.KioskMode;
import com.example.lockdowndpc.ui.BlockedBrowserActivity;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
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
        applyRestrictions(dpm, admin, errors);
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
        clearRestrictions(dpm, admin, errors);
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

    private static void applyRestrictions(
            DevicePolicyManager dpm,
            ComponentName admin,
            List<String> errors
    ) {
        safeRestriction(dpm, admin, UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES, errors);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            safeRestriction(dpm, admin, UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES_GLOBALLY, errors);
            safeRestriction(dpm, admin, UserManager.DISALLOW_CONFIG_PRIVATE_DNS, errors);
        }
        safeRestriction(dpm, admin, UserManager.DISALLOW_UNINSTALL_APPS, errors);
        safeRestriction(dpm, admin, UserManager.DISALLOW_APPS_CONTROL, errors);
        safeRestriction(dpm, admin, UserManager.DISALLOW_MODIFY_ACCOUNTS, errors);
        safeRestriction(dpm, admin, UserManager.DISALLOW_ADD_USER, errors);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            safeRestriction(dpm, admin, UserManager.DISALLOW_USER_SWITCH, errors);
            safeRestriction(dpm, admin, UserManager.DISALLOW_CONFIG_DATE_TIME, errors);
        }
        safeRestriction(dpm, admin, UserManager.DISALLOW_CONFIG_VPN, errors);
        safeRestriction(dpm, admin, UserManager.DISALLOW_CONFIG_TETHERING, errors);
        safeRestriction(dpm, admin, UserManager.DISALLOW_NETWORK_RESET, errors);
        safeRestriction(dpm, admin, UserManager.DISALLOW_USB_FILE_TRANSFER, errors);
        safeRestriction(dpm, admin, UserManager.DISALLOW_FACTORY_RESET, errors);
        safeRestriction(dpm, admin, UserManager.DISALLOW_SAFE_BOOT, errors);
    }

    private static void clearRestrictions(
            DevicePolicyManager dpm,
            ComponentName admin,
            List<String> errors
    ) {
        ArrayList<String> restrictions = new ArrayList<>(List.of(
                UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES,
                UserManager.DISALLOW_UNINSTALL_APPS,
                UserManager.DISALLOW_APPS_CONTROL,
                UserManager.DISALLOW_MODIFY_ACCOUNTS,
                UserManager.DISALLOW_ADD_USER,
                UserManager.DISALLOW_CONFIG_VPN,
                UserManager.DISALLOW_CONFIG_TETHERING,
                UserManager.DISALLOW_NETWORK_RESET,
                UserManager.DISALLOW_USB_FILE_TRANSFER,
                UserManager.DISALLOW_FACTORY_RESET,
                UserManager.DISALLOW_SAFE_BOOT
        ));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            restrictions.add(UserManager.DISALLOW_USER_SWITCH);
            restrictions.add(UserManager.DISALLOW_CONFIG_DATE_TIME);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            restrictions.add(UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES_GLOBALLY);
            restrictions.add(UserManager.DISALLOW_CONFIG_PRIVATE_DNS);
        }
        for (String restriction : restrictions) {
            try {
                dpm.clearUserRestriction(admin, restriction);
                if (dpm.getUserRestrictions(admin).getBoolean(restriction)) {
                    errors.add("restriction-release-unverified:" + restriction);
                }
            } catch (RuntimeException exception) {
                errors.add("restriction-release:" + restriction + ":" + exception.getClass().getSimpleName());
            }
        }
    }

    private static void safeRestriction(
            DevicePolicyManager dpm,
            ComponentName admin,
            String restriction,
            List<String> errors
    ) {
        try {
            dpm.addUserRestriction(admin, restriction);
            if (!dpm.getUserRestrictions(admin).getBoolean(restriction)) {
                errors.add("restriction-not-applied:" + restriction);
            }
        } catch (RuntimeException exception) {
            errors.add(restriction + ": " + exception.getClass().getSimpleName());
        }
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
        Set<String> adminSelectedSystem = AllowedAppsStore.getAdminSelectedSystemPackages(context);
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
