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
    private static final int LINK_HANDLER_VERIFY_ATTEMPTS = 20;
    private static final long LINK_HANDLER_VERIFY_RETRY_DELAY_MS = 100L;

    private LockdownPolicyController() {}

    public static synchronized PolicyResult apply(Context context) {
        DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
        ComponentName admin = LockdownAdminReceiver.componentName(context);
        boolean deviceOwner = dpm != null && dpm.isDeviceOwnerApp(context.getPackageName());
        HomeFilterPolicy.Settings homeFilter = HomeFilterController.readStored(context);
        boolean filterEnabled = homeFilter != null && homeFilter.enabled();
        String pacUrl = homeFilter != null && homeFilter.configured() ? homeFilter.config().pacUrl() : null;
        BuiltInBlockExemptions.Settings exemptions = BuiltInBlockExemptionsStore.read(context);
        SocialPass social = new SocialPass(context, exemptions);
        boolean chromeInScope = ChromeFilterExemption.inScope(
                Build.VERSION.SDK_INT, resolveWebViewProvider(context.getPackageManager()));
        ChromeFilterExemption.Gateway chromeGateway = deviceOwner && chromeInScope
                ? new AndroidChromeGateway(context, dpm, admin) : null;
        ArrayList<String> errors = new ArrayList<>();
        // The single containment step runs before any early return; every later
        // step may only show a package through the verified path.
        ExemptionPassStart.Start start = ExemptionPassStart.begin(new ExemptionPassStart.Steps() {
            @Override
            public boolean deviceOwner() {
                return deviceOwner;
            }

            @Override
            public boolean homeFilterReadable() {
                return homeFilter != null;
            }

            @Override
            public void containSocial(List<String> containErrors) {
                containUnexemptedSocial(context, dpm, admin, social, containErrors);
            }

            @Override
            public void containWebViewProvider(List<String> containErrors) {
                // The same routine the pass runs later, unchanged: a
                // browser-backed provider is suspended before protection starts.
                suspendBrowserBackedWebViewIfNeeded(context, dpm, admin,
                        homeFilter != null ? homeFilter : HomeFilterPolicy.Settings.OFF, containErrors);
            }

            @Override
            public void recordEarlyReadback(List<String> readbackErrors) {
                readbackErrors.add(HomeFilterController.CORRUPT_CONFIGURATION);
                recordExemptionReadback(context, dpm, admin, exemptions, social,
                        chromeInScope ? ChromeFilterExemption.Decision.FILTER_DISABLED
                                : ChromeFilterExemption.Decision.NOT_AVAILABLE,
                        readbackErrors);
            }

            @Override
            public ChromeFilterExemption.Containment containChrome(List<String> containErrors) {
                return chromeGateway == null ? null : ChromeFilterExemption.contain(
                        exemptions.chrome(), filterEnabled, pacUrl, chromeGateway, containErrors);
            }

            @Override
            public void markApplyStarted() {
                AllowedAppsStore.markApplyStarted(context);
            }

            @Override
            public boolean protectionActive() {
                return AllowedAppsStore.isProtectionEnabled(context);
            }

            @Override
            public ChromeFilterExemption.Decision decideChrome(
                    ChromeFilterExemption.Containment containment,
                    boolean protectionActive,
                    List<String> decideErrors) {
                return ChromeFilterExemption.decide(containment, exemptions.chrome(), protectionActive,
                        filterEnabled, pacUrl, chromeGateway, decideErrors);
            }
        }, errors);
        if (start.stop() == ExemptionPassStart.Stop.CORRUPT_HOME_FILTER) {
            return corruptHomeFilter();
        }
        if (start.stop() == ExemptionPassStart.Stop.NOT_DEVICE_OWNER) {
            String error = "device-owner-required";
            AllowedAppsStore.markApplyFailed(context, error);
            return new PolicyResult(false, false, 0, 0, List.of(error));
        }
        ChromeFilterExemption.Decision chrome = start.chrome();
        SystemPolicyPass systemPolicy = applySystemPolicy(context, dpm, admin, errors);
        // Resolved from this pass's read-back evidence, never from the stored
        // switch: a compatibility mode whose install lock the device did not
        // confirm leaves the Store hidden and the pass unverified.
        PlayStoreCompatibility.State playCompatibility = PlayStoreCompatibility.evaluate(
                PlayStoreCompatibilityStore.isEnabled(context),
                systemPolicy.relaxedByMaintenance(),
                systemPolicy.report());
        if (playCompatibility.faultsProtection()) {
            errors.add(PlayStoreCompatibility.INSTALL_LOCK_UNVERIFIED_ERROR);
        }
        Set<String> trustedManagement = resolveTrustedManagementPackages(context, errors);
        // Kiosk reconciles before the link handlers: turning kiosk off clears
        // every persistent preferred activity of this package, and
        // routeLinks below re-registers the managed-filtering ones.
        KioskController.reconcile(context, dpm, admin, errors);
        if (!chrome.shown()) {
            routeLinks(context, dpm, admin, false, errors);
        }
        protectManagementApps(context, dpm, admin, trustedManagement, errors);
        int[] packageCounts = applyPackagePolicy(context, dpm, admin, trustedManagement,
                playCompatibility, homeFilter, social, chromeInScope, errors);
        suspendBrowserBackedWebViewIfNeeded(context, dpm, admin, homeFilter, errors);
        int errorsBeforeFilter = errors.size();
        HomeFilterController.reconcile(context, dpm, admin, errors);
        if (chromeInScope) {
            // Chrome is released only now, after the home filter's own
            // reconciliation, and only if it reported no error. Links follow
            // the final, verified result rather than the earlier decision.
            boolean filterConfirmed = homeFilter.enabled() && errors.size() == errorsBeforeFilter;
            boolean routedAway = !chrome.shown();
            chrome = ChromeFilterExemption.release(chrome, filterConfirmed, chromeGateway, errors);
            if (chrome.shown()) {
                routeLinks(context, dpm, admin, true, errors);
            } else if (!routedAway) {
                routeLinks(context, dpm, admin, false, errors);
            }
        }
        recordExemptionReadback(context, dpm, admin, exemptions, social, chrome, errors);
        boolean verified = errors.isEmpty();
        if (verified) {
            if (homeFilter.enabled() && conflictsWithHomeFilter(liveMaintenanceWindow(context))) {
                clearMaintenanceWindow(context, "home-filter");
            }
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
        HomeFilterPolicy.Settings homeFilter = HomeFilterController.readStored(context);
        if (homeFilter == null) return corruptHomeFilter();
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
        clearMaintenanceWindow(context, "pause");
        releaseSystemPolicy(context, dpm, admin, errors);
        try {
            dpm.clearPackagePersistentPreferredActivities(admin, context.getPackageName());
        } catch (RuntimeException exception) {
            errors.add("link-block-clear:" + exception.getClass().getSimpleName());
        }
        // Chrome's exemption routing is released with everything else.
        clearChromeRouting(dpm, admin, errors);
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
        if (homeFilter.enabled()) packagesToShow.add(homeFilter.config().vpnPackage());
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
        HomeFilterController.reconcile(context, dpm, admin, errors);
        BuiltInBlockExemptions.Settings exemptions = BuiltInBlockExemptionsStore.read(context);
        recordExemptionReadback(context, dpm, admin, exemptions, new SocialPass(context, exemptions),
                ChromeFilterExemption.Decision.PROTECTION_PAUSED, errors);
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

    private static PolicyResult corruptHomeFilter() {
        return new PolicyResult(false, false, 0, 0,
                List.of(HomeFilterController.CORRUPT_CONFIGURATION));
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
    private static SystemPolicyPass applySystemPolicy(
            Context context,
            DevicePolicyManager dpm,
            ComponentName admin,
            List<String> errors
    ) {
        SystemPolicyProfile profile = SystemPolicyStore.effectiveProfile(context);
        MaintenancePlan plan = maintenancePlanFor(context, profile);
        Map<SystemPolicyControl, Boolean> choices = plan == null
                ? SystemPolicyStore.baseChoices(context)
                : plan.effectiveChoices();
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
        return new SystemPolicyPass(report, plan == null ? Set.of() : plan.relaxed());
    }

    /**
     * What one system policy pass asked for, and what a live window relaxed.
     *
     * <p>The two are kept apart because they mean opposite things to the Google
     * Play compatibility gate: a control the device refused to enforce is a
     * failure that must hide the Store again, while a control an authenticated,
     * bounded, audited window deliberately opened is not.
     *
     * @param report               the read-back evidence of the pass
     * @param relaxedByMaintenance controls a live window legitimately turned off
     */
    private record SystemPolicyPass(
            SystemPolicyReport report,
            Set<SystemPolicyControl> relaxedByMaintenance
    ) {}

    /**
     * The maintenance plan this pass must apply, or {@code null} when no window
     * is live and the base policy stands on its own.
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
    private static MaintenancePlan maintenancePlanFor(
            Context context,
            SystemPolicyProfile profile
    ) {
        MaintenanceWindow window = liveMaintenanceWindow(context);
        if (window == null) {
            return null;
        }
        if (HomeFilterController.isEnabled(context) && conflictsWithHomeFilter(window)) {
            return null;
        }
        // The full liveness evaluation, not a bare expiry check. An expiry-only
        // test reads a pre-reboot window as live — after a restart the monotonic
        // clock is near zero, comfortably below the old deadline — so a boot-time
        // reconcile would re-apply the window's relaxations and record the pass
        // as verified. The state machine's reboot and clock checks are the same
        // ones MaintenanceGuard closes the window with; this pass merely ignores
        // a window the guard would not honour, and leaves the closing (which
        // must be read back and audited) to the guard.
        //
        // The base handed in is SystemPolicyStore.baseChoices, so a window is an
        // exception to the policy this device is actually configured for — the
        // Google Play compatibility floor included — rather than to the raw
        // switches, which would silently drop the floor for the window's duration.
        return MaintenancePlan.forWindow(profile, SystemPolicyStore.baseChoices(context), window);
    }

    /** The stored window only when the state machine would still honour it. */
    private static MaintenanceWindow liveMaintenanceWindow(Context context) {
        return MaintenanceStore.liveWindow(context);
    }

    private static boolean conflictsWithHomeFilter(MaintenanceWindow window) {
        return window != null && !HomeFilterPolicy.permitsRelaxing(window.relaxableControls());
    }

    /** Clears a maintenance record whose policy is handled by the enclosing pass. */
    private static void clearMaintenanceWindow(Context context, String reason) {
        try {
            boolean hadWindow = MaintenanceStore.readWindow(context) != null
                    || MaintenanceStore.restorePending(context);
            MaintenanceStore.clearWindow(context);
            MaintenanceStore.clearRestorePending(context);
            MaintenanceGuard.arm(context, null);
            if (hadWindow) {
                AuditLog.append(context, "maintenance:closed-by-" + reason);
            }
        } catch (RuntimeException exception) {
            // The enclosing policy pass still enforces its own restrictions.
            Log.e(TAG, "Could not clear the maintenance record", exception);
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
                new SystemPolicyDeviceGateway(dpm, admin),
                HomeFilterController.isEnabled(context) ? HomeFilterPolicy.REQUIRED_CONTROLS : Set.of()
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

    /**
     * Routes {@code http} and {@code https} links and reads the routing back.
     *
     * <p>Without the Chrome exemption, links go to {@link BlockedBrowserActivity},
     * as they always have. With it, they go to Chrome's view activity and the
     * blocked-browser component is disabled, so Android's persistent preference
     * resolves to Chrome deterministically. Custom Tabs and Trusted Web
     * Activities that open in Chrome run inside the Chrome package and are
     * governed by its managed configuration.
     *
     * @return whether links were verified to reach Chrome; always {@code false}
     *         when routing to the blocked-browser screen
     */
    private static boolean routeLinks(
            Context context,
            DevicePolicyManager dpm,
            ComponentName admin,
            boolean toChrome,
            List<String> errors
    ) {
        if (toChrome) {
            ComponentName target = resolveBrowserViewActivity(
                    context.getPackageManager(), BuiltInBlockExemptions.CHROME);
            ArrayList<String> routeErrors = new ArrayList<>();
            if (target != null) {
                setBlockedBrowserComponentEnabled(context, false, routeErrors);
                configureLinkHandler(context, dpm, admin, target, routeErrors);
                if (routeErrors.isEmpty()) {
                    return true;
                }
            }
            errors.addAll(routeErrors);
            errors.add("browser-route-unresolved");
        }
        clearChromeRouting(dpm, admin, errors);
        setBlockedBrowserComponentEnabled(context, true, errors);
        configureLinkHandler(context, dpm, admin,
                new ComponentName(admin.getPackageName(), BlockedBrowserActivity.class.getName()),
                errors);
        return false;
    }

    /** Removes link routing that targets Chrome. */
    private static void clearChromeRouting(
            DevicePolicyManager dpm,
            ComponentName admin,
            List<String> errors
    ) {
        try {
            dpm.clearPackagePersistentPreferredActivities(admin, BuiltInBlockExemptions.CHROME);
        } catch (RuntimeException exception) {
            errors.add("browser-route-clear:" + exception.getClass().getSimpleName());
        }
    }

    /** The browser's own activity for an https link, or {@code null}. */
    private static ComponentName resolveBrowserViewActivity(PackageManager pm, String browser) {
        Intent intent = new Intent(Intent.ACTION_VIEW, Uri.parse("https://policy-check.invalid"));
        intent.addCategory(Intent.CATEGORY_BROWSABLE);
        intent.setPackage(browser);
        List<android.content.pm.ResolveInfo> matches;
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                matches = pm.queryIntentActivities(
                        intent,
                        PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_DEFAULT_ONLY));
            } else {
                //noinspection deprecation
                matches = pm.queryIntentActivities(intent, PackageManager.MATCH_DEFAULT_ONLY);
            }
        } catch (RuntimeException exception) {
            return null;
        }
        for (android.content.pm.ResolveInfo match : matches) {
            if (match.activityInfo != null && browser.equals(match.activityInfo.packageName)) {
                return new ComponentName(match.activityInfo.packageName, match.activityInfo.name);
            }
        }
        return null;
    }

    private static void configureLinkHandler(
            Context context,
            DevicePolicyManager dpm,
            ComponentName admin,
            ComponentName target,
            List<String> errors
    ) {
        // Android can apply this policy asynchronously. Register both filters
        // first, then verify their effective resolution with a short bounded
        // retry. A physical Android 13 OEM build also delayed resolver state
        // after enabling this component, so the retry applies to every supported
        // release rather than relying on the platform version. The first probe
        // still returns immediately on the normal path. PolicyUpdateAuditReceiver
        // remains the authoritative backstop for a later conflicting-admin result.
        for (String scheme : new String[]{"http", "https"}) {
            try {
                IntentFilter filter = new IntentFilter(Intent.ACTION_VIEW);
                filter.addCategory(Intent.CATEGORY_DEFAULT);
                filter.addCategory(Intent.CATEGORY_BROWSABLE);
                filter.addDataScheme(scheme);
                dpm.addPersistentPreferredActivity(admin, filter, target);
            } catch (RuntimeException exception) {
                errors.add("link-filter:" + scheme + ":" + exception.getClass().getSimpleName());
            }
        }
        for (String scheme : new String[]{"http", "https"}) {
            try {
                Intent probe = new Intent(Intent.ACTION_VIEW, Uri.parse(scheme + "://policy-check.invalid"));
                probe.addCategory(Intent.CATEGORY_BROWSABLE);
                if (!eventuallyResolvesTo(context.getPackageManager(), probe, target)) {
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
        return BoundedVerificationRetry.verify(
                LINK_HANDLER_VERIFY_ATTEMPTS,
                () -> expected.equals(resolveActivity(pm, intent)),
                () -> SystemClock.sleep(LINK_HANDLER_VERIFY_RETRY_DELAY_MS)
        );
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
            LockdownPackages.SignerVerdict verdict = managementSignerVerdict(context, record);
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

    static LockdownPackages.SignerVerdict managementSignerVerdict(
            Context context, LockdownPackages.ManagementPackage record) {
        return LockdownPackages.verifySigner(
                record, signingCertificateDigests(context, record.packageName()));
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
            PlayStoreCompatibility.State playCompatibility,
            HomeFilterPolicy.Settings homeFilter,
            SocialPass social,
            boolean chromeInScope,
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
        MaintenanceWindow window = liveMaintenanceWindow(context);
        boolean appStoreMaintenanceOpen = MaintenanceAppPolicy.opensApplicationStores(window)
                && !(homeFilter.enabled() && conflictsWithHomeFilter(window));
        boolean playStoreAvailable = playCompatibility.keepsPlayStoreAvailable();
        boolean allowlistConfigured = AllowedAppsStore.isAllowlistConfigured(context);
        AllowedAppsStore.ProtectionMode mode = AllowedAppsStore.getProtectionMode(context);
        String webViewProvider = resolveWebViewProvider(pm);
        KioskConfigStore.Settings kiosk = KioskConfigStore.read(context);
        boolean kioskActive = KioskConfigStore.isContainmentState(kiosk.state());
        String requestedKioskTarget = kioskActive && kiosk.config().mode() == KioskMode.SINGLE_APP
                ? kiosk.config().targetPackage()
                : "";
        String kioskTarget = KioskAppCatalog.isProtectedFromKiosk(requestedKioskTarget, social.verified())
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
        if (homeFilter.enabled()) {
            packageNames.add(homeFilter.config().vpnPackage());
        }
        packageNames.addAll(social.approved());

        for (String packageName : packageNames) {
            // While the Chrome exemption is in scope, ChromeFilterExemption owns
            // Chrome's visibility; otherwise Chrome is handled here, as always.
            if (packageName.equals(context.getPackageName())
                    || (chromeInScope && packageName.equals(BuiltInBlockExemptions.CHROME))) {
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

            // The Google Play compatibility exception: one package, only after an
            // authenticated administrator asked for it, and only once this pass
            // read the installation lock back as in force. Every other store in
            // the built-in catalogue is untouched by it. Containment is unaffected
            // either way: what a kiosk user can reach is the lock-task allowlist
            // and the pinned target, and KioskAppCatalog refuses this package as
            // both, so an available Store is available to dependent applications
            // rather than added to a contained device's surface.
            if (PlayStoreCompatibility.keepsAvailable(packageName, playStoreAvailable)) {
                shouldBlock = false;
            }

            // Administrator exemptions from the built-in catalogues: Chrome,
            // only when this pass granted it, and approved social or messaging
            // applications whose current signer is the one pinned at approval.
            // Never an application store. Kiosk containment below and the
            // lock-task allowlist are unaffected.
            boolean exempted = social.visible(packageName);
            if (exempted) {
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
            boolean homeFilterVpn = homeFilter.keepsVpnVisible(packageName);
            shouldBlock = homeFilter.packageShouldBeHidden(packageName, shouldBlock);

            boolean criticalPackage = shouldBlock
                    || homeFilterVpn
                    || managed.contains(packageName)
                    || allowed.contains(packageName)
                    || packageName.equals(kioskTarget)
                    || (reconcileEscapeSurfaces
                        && packageClass == LockdownPackages.PackageClass.KIOSK_ESCAPE_SURFACE)
                    || LockdownPackages.isManagementPackage(packageName)
                    || packageName.equals(webViewProvider);
            criticalPackage = criticalPackage
                    || MaintenanceAppPolicy.keepsVisible(packageName, appStoreMaintenanceOpen)
                    // Without this the exception would be inert: a package whose
                    // only reason to be touched is that it must be *unhidden*
                    // fails every other criticality test and is skipped.
                    || PlayStoreCompatibility.keepsAvailable(packageName, playStoreAvailable)
                    || exempted;
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
            HomeFilterPolicy.Settings homeFilter,
            List<String> errors
    ) {
        String provider = resolveWebViewProvider(context.getPackageManager());
        if (provider == null || !LockdownPackages.ALWAYS_BLOCKED.contains(provider)) {
            return;
        }
        boolean suspend = !homeFilter.keepsVpnVisible(provider);
        try {
            String[] failed = dpm.setPackagesSuspended(admin, new String[]{provider}, suspend);
            if (failed.length > 0) {
                errors.add("browser-suspension-failed");
            } else if (dpm.isPackageSuspended(admin, provider) != suspend) {
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

    /**
     * The social half of the exemptions for one pass: each approved package's
     * single current signer, read once with the hidden-package query, against
     * the digest pinned at approval. An unreadable signer is not verified, so
     * the package stays hidden.
     */
    private static final class SocialPass {
        private final BuiltInBlockExemptions.Settings settings;
        private final LinkedHashSet<String> verified = new LinkedHashSet<>();
        private final LinkedHashSet<String> signerMismatch = new LinkedHashSet<>();

        SocialPass(Context context, BuiltInBlockExemptions.Settings settings) {
            this.settings = settings;
            PackageManager pm = context.getPackageManager();
            for (String packageName : settings.socialPins().keySet()) {
                if (!isInstalled(pm, packageName)) {
                    continue;
                }
                String signer = PackageIdentity.currentSignerSha256IncludingHidden(pm, packageName);
                if (BuiltInBlockExemptions.socialVisible(packageName, settings, signer)) {
                    verified.add(packageName);
                } else {
                    signerMismatch.add(packageName);
                }
            }
        }

        Set<String> approved() {
            return settings.socialPins().keySet();
        }

        boolean visible(String packageName) {
            return verified.contains(packageName);
        }

        Set<String> verified() {
            return verified;
        }

        Set<String> signerMismatch() {
            return signerMismatch;
        }
    }

    /**
     * The social half of the single containment step: every installed catalogue
     * social package without a verified exemption is hidden and read back. The
     * package sweep would hide them too; doing it here means it also happens on
     * a pass that returns early.
     */
    private static void containUnexemptedSocial(
            Context context,
            DevicePolicyManager dpm,
            ComponentName admin,
            SocialPass social,
            List<String> errors
    ) {
        PackageManager pm = context.getPackageManager();
        for (String packageName : BuiltInBlockExemptions.EXEMPTABLE_SOCIAL) {
            if (social.visible(packageName) || !isInstalled(pm, packageName)) {
                continue;
            }
            try {
                dpm.setApplicationHidden(admin, packageName, true);
                if (!dpm.isApplicationHidden(admin, packageName)) {
                    errors.add("social-contain-unverified:" + packageName);
                }
            } catch (RuntimeException exception) {
                errors.add("social-contain:" + packageName + ":" + exception.getClass().getSimpleName());
            }
        }
    }

    /**
     * Reads back from Android the state of Chrome and every installed catalogue
     * social package, and stores it for the console, bound to the decision it
     * describes. A Chrome change is audited with the observed state. A read
     * that throws is recorded as unknown; it never changes any state.
     */
    private static void recordExemptionReadback(
            Context context,
            DevicePolicyManager dpm,
            ComponentName admin,
            BuiltInBlockExemptions.Settings exemptions,
            SocialPass social,
            ChromeFilterExemption.Decision chrome,
            List<String> errors
    ) {
        PackageManager pm = context.getPackageManager();
        BuiltInBlockExemptions.Observed chromeObserved =
                ChromeFilterExemption.observe(new AndroidChromeGateway(context, dpm, admin));
        java.util.LinkedHashMap<String, BuiltInBlockExemptions.Observed> socialObserved =
                new java.util.LinkedHashMap<>();
        for (String packageName : BuiltInBlockExemptions.EXEMPTABLE_SOCIAL) {
            if (!isInstalled(pm, packageName)) {
                continue;
            }
            BuiltInBlockExemptions.Observed state;
            try {
                state = dpm.isApplicationHidden(admin, packageName)
                        ? BuiltInBlockExemptions.Observed.HIDDEN
                        : dpm.isPackageSuspended(admin, packageName)
                            ? BuiltInBlockExemptions.Observed.SUSPENDED
                            : BuiltInBlockExemptions.Observed.VISIBLE;
            } catch (PackageManager.NameNotFoundException | RuntimeException exception) {
                state = BuiltInBlockExemptions.Observed.UNKNOWN;
            }
            socialObserved.put(packageName, state);
        }
        BuiltInBlockExemptionsStore.Readback previous = BuiltInBlockExemptionsStore.readback(context);
        if (previous != null && previous.chromeObserved() != chromeObserved) {
            AuditLog.append(context, "builtin-exemption: chrome android=" + chromeObserved.name()
                    + " (was " + previous.chromeObserved().name() + ", decision=" + chrome.name() + ")");
        }
        boolean saved = BuiltInBlockExemptionsStore.saveReadback(context,
                new BuiltInBlockExemptionsStore.Readback(exemptions.auditText(), errors.isEmpty(),
                        chrome, chromeObserved, socialObserved, social.signerMismatch()));
        if (!saved) {
            errors.add("builtin-exemption-readback-not-saved");
        }
    }

    /** Chrome as seen through DevicePolicyManager. */
    private static final class AndroidChromeGateway implements ChromeFilterExemption.Gateway {
        private final Context context;
        private final DevicePolicyManager dpm;
        private final ComponentName admin;

        AndroidChromeGateway(Context context, DevicePolicyManager dpm, ComponentName admin) {
            this.context = context;
            this.dpm = dpm;
            this.admin = admin;
        }

        @Override
        public boolean installed() {
            return isInstalled(context.getPackageManager(), BuiltInBlockExemptions.CHROME);
        }

        @Override
        public String currentSignerSha256() {
            return PackageIdentity.currentSignerSha256IncludingHidden(
                    context.getPackageManager(), BuiltInBlockExemptions.CHROME);
        }

        @Override
        @SuppressWarnings("deprecation")
        public Map<String, Object> restrictions() {
            android.os.Bundle bundle = dpm.getApplicationRestrictions(admin, BuiltInBlockExemptions.CHROME);
            java.util.LinkedHashMap<String, Object> values = new java.util.LinkedHashMap<>();
            if (bundle != null) {
                for (String key : bundle.keySet()) {
                    values.put(key, bundle.get(key));
                }
            }
            return values;
        }

        @Override
        public void setRestrictions(Map<String, Object> values) {
            android.os.Bundle bundle = new android.os.Bundle();
            for (Map.Entry<String, Object> entry : values.entrySet()) {
                Object value = entry.getValue();
                if (value instanceof Boolean flag) {
                    bundle.putBoolean(entry.getKey(), flag);
                } else if (value instanceof Integer number) {
                    bundle.putInt(entry.getKey(), number);
                } else if (value instanceof Long number) {
                    bundle.putLong(entry.getKey(), number);
                } else if (value instanceof String text) {
                    bundle.putString(entry.getKey(), text);
                } else if (value instanceof String[] list) {
                    bundle.putStringArray(entry.getKey(), list);
                } else if (value instanceof android.os.Bundle nested) {
                    bundle.putBundle(entry.getKey(), nested);
                } else if (value instanceof android.os.Parcelable[] parcels) {
                    bundle.putParcelableArray(entry.getKey(), parcels);
                }
                // An administrator-set value of another type is not carried over;
                // the read-back below only checks the required keys.
            }
            dpm.setApplicationRestrictions(admin, BuiltInBlockExemptions.CHROME, bundle);
        }

        @Override
        public void setHidden(boolean hidden) {
            dpm.setApplicationHidden(admin, BuiltInBlockExemptions.CHROME, hidden);
        }

        @Override
        public boolean hidden() {
            return dpm.isApplicationHidden(admin, BuiltInBlockExemptions.CHROME);
        }

        @Override
        public void setSuspended(boolean suspended) {
            String[] failed = dpm.setPackagesSuspended(
                    admin, new String[]{BuiltInBlockExemptions.CHROME}, suspended);
            if (failed != null && failed.length > 0) {
                throw new IllegalStateException("suspension-refused");
            }
        }

        @Override
        public boolean suspended() {
            try {
                return dpm.isPackageSuspended(admin, BuiltInBlockExemptions.CHROME);
            } catch (PackageManager.NameNotFoundException exception) {
                throw new IllegalStateException("chrome-missing", exception);
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
