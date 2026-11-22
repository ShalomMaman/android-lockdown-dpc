package com.example.lockdowndpc.policy;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.ProxyInfo;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;

import com.example.lockdowndpc.admin.LockdownAdminReceiver;

import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BooleanSupplier;
import java.util.function.Predicate;
import java.util.function.UnaryOperator;

public final class HomeFilterController {
    static final String CORRUPT_CONFIGURATION = "home-filter:corrupt-configuration";

    private HomeFilterController() {}

    public record Snapshot(HomeFilterPolicy.Settings settings, HomeFilterPolicy.Report report) {}

    /**
     * Turning the filter off or removing its CA was refused: a Chrome approval
     * is saved or unreadable, or Android does not report Chrome contained now.
     */
    public static final class FilterTeardownRefusedException extends IllegalStateException {
        private final BuiltInBlockExemptions.TeardownVerdict verdict;

        private FilterTeardownRefusedException(BuiltInBlockExemptions.TeardownVerdict verdict) {
            super("Home filter teardown refused: " + verdict);
            this.verdict = verdict;
        }

        public BuiltInBlockExemptions.TeardownVerdict verdict() {
            return verdict;
        }
    }

    public static final class CorruptConfigurationException extends IllegalStateException {
        private CorruptConfigurationException() {
            super(CORRUPT_CONFIGURATION);
        }
    }

    public static Snapshot read(Context context) {
        return PolicyReconciliationCoordinator.callOnPolicyThread(() -> {
            HomeFilterPolicy.Settings settings = requireSettings(context);
            HomeFilterPolicy.Report report = HomeFilterPolicy.inspect(
                    settings, Build.VERSION.SDK_INT, gateway(context));
            return new Snapshot(settings, HomeFilterStore.includeApplyEvidence(
                    context, settings.enabled(), report));
        });
    }

    public static Snapshot enable(Context context, AdminAuthority authority,
                                  HomeFilterPolicy.Config config, String ca) {
        return change(context, authority, settings -> {
            if (!HomeFilterPolicy.supportedOn(Build.VERSION.SDK_INT)) {
                throw new UnsupportedOperationException("Home filter requires Android 10 (API 29) or later");
            }
            if (config.routing() == null) {
                throw new IllegalArgumentException("Tailscale routing settings are required");
            }
            if (settings.configured()) {
                throw new IllegalStateException("Home filter configuration is already present");
            }
            if (BuiltInBlockExemptions.isBuiltInBlocked(config.vpnPackage())) {
                // A blocked browser, store or social application entered as the
                // VPN would inherit the VPN's visibility override.
                throw new IllegalArgumentException("A built-in blocked package cannot be the VPN");
            }
            return new HomeFilterPolicy.Settings(config, true, ca, false);
        });
    }

    public static Snapshot installCa(Context context, AdminAuthority authority, String ca) {
        return change(context, authority, settings -> {
            if (!settings.enabled() || settings.ca() != null) {
                throw new IllegalStateException("Remove the old certificate before installing another");
            }
            return new HomeFilterPolicy.Settings(settings.config(), true, ca, false);
        });
    }

    public static Snapshot removeCa(Context context, AdminAuthority authority) {
        return change(context, authority, HomeFilterPolicy.Settings::requestRemoveCa);
    }

    public static Snapshot disable(Context context, AdminAuthority authority) {
        return change(context, authority, HomeFilterPolicy.Settings::requestDisable);
    }

    public static Snapshot retry(Context context, AdminAuthority authority) {
        return change(context, authority, UnaryOperator.identity());
    }

    private static Snapshot change(Context context, AdminAuthority authority,
                                   UnaryOperator<HomeFilterPolicy.Settings> operation) {
        return PolicyReconciliationCoordinator.callOnPolicyThread(() -> {
            DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
            if (!AdminAuthority.permitsLocal(context, authority) || dpm == null
                    || !dpm.isDeviceOwnerApp(context.getPackageName())) {
                throw new SecurityException("An unlocked device owner is required");
            }
            HomeFilterPolicy.Settings before = requireSettings(context);
            HomeFilterPolicy.Settings after = operation.apply(before);
            // Enforced here, before any side effect, from live facts only: no
            // saved (or unreadable) Chrome approval, and Chrome observed
            // contained right now.
            if (BuiltInBlockExemptions.isFilterTeardown(before, after)) {
                BuiltInBlockExemptions.TeardownVerdict verdict = teardownVerdict(context);
                if (verdict != BuiltInBlockExemptions.TeardownVerdict.ALLOWED) {
                    throw new FilterTeardownRefusedException(verdict);
                }
            }
            if (!before.equals(after)) {
                try {
                    if (!AuthorizedPolicyWriter.setHomeFilter(context, authority, after)) {
                        throw new SecurityException("An unlocked device owner is required");
                    }
                } catch (IllegalStateException failedWrite) {
                    // The previous settings were restored in memory; a pass
                    // still runs so every package is contained against them.
                    runPass(context);
                    throw failedWrite;
                }
                AuditLog.append(context, AuditEvent.HOME_FILTER_CHANGED,
                        "Home filter settings changed by administrator");
            }
            runPass(context);
            return read(context);
        });
    }

    private static void runPass(Context context) {
        if (AllowedAppsStore.isProtectionEnabled(context)) {
            LockdownPolicyController.apply(context);
        } else {
            LockdownPolicyController.pause(context);
        }
    }

    /** Device-owner lifecycle entry point. It only reasserts saved administrator intent. */
    static void reconcile(Context context, DevicePolicyManager dpm, ComponentName admin,
                          List<String> errors) {
        HomeFilterPolicy.Settings settings = readStored(context);
        if (settings == null) {
            errors.add(CORRUPT_CONFIGURATION);
            return;
        }
        reconcile(context, dpm, admin, errors, settledFilter(context, settings));
    }

    /**
     * Reconciles the settings a policy pass already settled. A pending teardown
     * (turn off, or CA removal) never finishes while a Chrome approval is saved
     * or Chrome is not observed contained: the filter is kept on with its CA,
     * the request stays pending, and the pass reports why. Boot and retry
     * passes come through here too. System policy and package steps use the
     * same settled value.
     */
    static boolean reconcile(Context context, DevicePolicyManager dpm, ComponentName admin,
                             List<String> errors, BuiltInBlockExemptions.PassFilter pass) {
        HomeFilterPolicy.Settings settings = pass.stored();
        if (settings == null) {
            errors.add(CORRUPT_CONFIGURATION);
            return false;
        }
        if (!settings.configured()) {
            return true;
        }
        boolean held = pass.held();
        HomeFilterPolicy.Settings enforced = pass.effective();
        if (held) {
            errors.add("home-filter:teardown-held:" + pass.hold());
        }
        AndroidGateway gateway = new AndroidGateway(context, dpm, admin);
        try {
            gateway.restoreVpnAvailability(enforced, null);
        } catch (RuntimeException exception) {
            errors.add("home-filter:vpn-availability:" + exception.getClass().getSimpleName());
            return false;
        }
        HomeFilterPolicy.Report report = HomeFilterPolicy.reconcile(enforced, Build.VERSION.SDK_INT, gateway);
        boolean verified = verifyReadback(enforced, report, errors);
        if (held) {
            HomeFilterStore.saveReadback(context, report);
            return verified;
        }
        HomeFilterPolicy.Settings remaining =
                AuthorizedPolicyWriter.finishHomeFilterReadback(context, settings, report);
        if (remaining.configured()) {
            HomeFilterStore.saveReadback(context, report);
        }
        return verified;
    }

    static boolean reconcileRemote(Context context, DevicePolicyManager dpm, ComponentName admin,
                                   HomeFilterPolicy.Settings settings, Predicate<Set<String>> recordReleases,
                                   List<String> errors) {
        AndroidGateway gateway = new AndroidGateway(context, dpm, admin);
        try {
            // A filter application the previous policy hid has to be visible before
            // Android can verify its VPN. The journal learns of that release first,
            // so a pass that does not end verified hides the application again.
            gateway.restoreVpnAvailability(settings, recordReleases);
        } catch (RuntimeException exception) {
            errors.add("home-filter:vpn-availability:" + exception.getClass().getSimpleName());
            return false;
        }
        return reconcileRemote(settings, Build.VERSION.SDK_INT, gateway, HomeFilterStore.retiredCas(context),
                HomeFilterStore.retiredFilters(context),
                () -> AuthorizedPolicyWriter.finishRemoteFilterReadback(context), errors);
    }

    /**
     * The remote pass never leaves the device with less than it had.
     *
     * <p>An enabled filter is brought up and read back before anything older is
     * removed. If any part of it fails after the VPN lockdown or the proxy
     * already moved, the lockdown and proxy that were in force are put back and
     * read back. A teardown removes the PAC proxy and the certificates, then the
     * uninstall block, the routing settings and the profile restrictions, each
     * read back, and releases the VPN lockdown as its last Android call.
     */
    static boolean reconcileRemote(HomeFilterPolicy.Settings settings, int sdk, HomeFilterPolicy.Gateway gateway,
                                   Set<String> retiredCas, Set<HomeFilterPolicy.Config> retiredFilters,
                                   BooleanSupplier finish, List<String> errors) {
        HomeFilterPolicy.Config active = settings.enabled() ? settings.config() : null;
        Set<HomeFilterPolicy.Config> previous = new java.util.LinkedHashSet<>(retiredFilters);
        if (active == null && settings.configured()) {
            previous.add(settings.config());
        }
        boolean verified = true;
        if (active != null) {
            LiveFilter before = LiveFilter.read(gateway, settings.ca());
            if (before == null) {
                // Nothing is changed that could not be put back afterwards.
                errors.add("home-filter:live-state-unreadable");
                return false;
            }
            verified = verifyReadback(settings, HomeFilterPolicy.reconcile(settings, sdk, gateway), errors);
            if (!verified && !before.restore(gateway, settings.ca())) {
                errors.add("home-filter:previous-protection-restore-unverified");
            }
        }
        if (verified) {
            for (HomeFilterPolicy.Config retired : previous) {
                if (!HomeFilterPolicy.retireProxy(retired, active, gateway)) {
                    errors.add("home-filter:previous-config-removal-unverified");
                    verified = false;
                }
            }
        }
        if (verified) {
            for (String certificate : retiredCas) {
                try {
                    if (gateway.hasCa(certificate)) gateway.setCa(certificate, false);
                    if (!gateway.hasCa(certificate)) continue;
                } catch (RuntimeException ignored) {
                    // No positive read-back that the retired CA is gone.
                }
                errors.add("home-filter:previous-ca-removal-unverified");
                verified = false;
            }
        }
        if (verified) {
            for (HomeFilterPolicy.Config retired : previous) {
                if (!HomeFilterPolicy.releaseVpnSettings(retired, active, gateway)) {
                    errors.add("home-filter:previous-config-removal-unverified");
                    verified = false;
                }
            }
        }
        if (verified && active == null && !previous.isEmpty()
                && !HomeFilterPolicy.releaseProfileRestrictions(gateway)) {
            errors.add("home-filter:previous-config-removal-unverified");
            verified = false;
        }
        if (verified) {
            // Everything else is proven gone. Only now does the old VPN lockdown go.
            for (HomeFilterPolicy.Config retired : previous) {
                if (!HomeFilterPolicy.clearVpnLockdown(retired, active, gateway)) {
                    errors.add("home-filter:previous-config-removal-unverified");
                    verified = false;
                }
            }
        }
        if (verified && active == null && settings.configured()) {
            // Read the whole teardown back.
            verified = verifyReadback(settings, HomeFilterPolicy.reconcile(settings, sdk, gateway), errors);
        }
        if (verified && !finish.getAsBoolean()) {
            errors.add("journal-write-failed");
            return false;
        }
        return verified;
    }

    /** The VPN lockdown and proxy in force before a pass, and whether its new certificate was already installed. */
    private record LiveFilter(String vpnPackage, String pacUrl, boolean newCaInstalled) {
        static LiveFilter read(HomeFilterPolicy.Gateway gateway, String newCa) {
            try {
                return new LiveFilter(gateway.alwaysOnPackage(), pac(gateway),
                        newCa != null && gateway.hasCa(newCa));
            } catch (RuntimeException unreadable) {
                return null;
            }
        }

        /**
         * Puts back what a failed attempt moved, withdraws a certificate it added, and reads all of it back.
         * A device that had no filter VPN keeps whatever the attempt reached: that is not less than before.
         */
        boolean restore(HomeFilterPolicy.Gateway gateway, String newCa) {
            if (vpnPackage == null) {
                return true;
            }
            try {
                if (!vpnPackage.equals(gateway.alwaysOnPackage())) {
                    gateway.setVpn(vpnPackage);
                }
                if (!pacUrl.equals(pac(gateway))) {
                    gateway.setProxy(pacUrl.isEmpty() ? null : pacUrl);
                }
                if (newCa != null && !newCaInstalled && gateway.hasCa(newCa)) {
                    gateway.setCa(newCa, false);
                }
                HomeFilterPolicy.VpnState vpn = gateway.vpnState();
                return vpnPackage.equals(vpn.packageName()) && vpn.lockdown() && pacUrl.equals(pac(gateway))
                        && (newCa == null || newCaInstalled || !gateway.hasCa(newCa));
            } catch (RuntimeException refused) {
                return false;
            }
        }

        private static String pac(HomeFilterPolicy.Gateway gateway) {
            String url = gateway.proxyPacUrl();
            return url == null ? "" : url;
        }
    }

    /**
     * The applications behind a filter VPN that may be in force right now: the
     * always-on package Android reports, and every filter this store still owes
     * a cleanup for. A built-in blocked package never qualifies.
     */
    static Set<String> liveFilterVpnPackages(Context context, DevicePolicyManager dpm, ComponentName admin) {
        Set<String> packages = new java.util.LinkedHashSet<>();
        try {
            String alwaysOn = dpm.getAlwaysOnVpnPackage(admin);
            if (alwaysOn != null) packages.add(alwaysOn);
        } catch (RuntimeException unreadable) {
            // The stored filters below still name what this owner configured.
        }
        try {
            for (HomeFilterPolicy.Config retired : HomeFilterStore.retiredFilters(context)) {
                packages.add(retired.vpnPackage());
            }
            HomeFilterPolicy.Settings stored = HomeFilterStore.read(context);
            if (stored.configured()) packages.add(stored.config().vpnPackage());
        } catch (RuntimeException corrupt) {
            // A corrupt store stops the pass elsewhere.
        }
        packages.removeIf(BuiltInBlockExemptions::isBuiltInBlocked);
        packages.remove(context.getPackageName());
        return packages;
    }

    static boolean verifyReadback(HomeFilterPolicy.Settings enforced, HomeFilterPolicy.Report report,
                                  List<String> errors) {
        boolean verified = enforced.enabled() ? report.androidSettingsConfirmed(enforced) : report.removed();
        if (!verified) {
            errors.add("home-filter:vpn=" + report.vpn() + ",proxy=" + report.proxy()
                    + ",ca=" + report.ca() + ",restrictions=" + report.restrictions()
                    + ",private-dns=" + report.privateDns());
        }
        return verified;
    }

    /**
     * The single place that settles which home filter settings policy writers
     * enforce: the stored settings, with a pending teardown held while the
     * teardown guard refuses it. A policy pass (through ExemptionPassStart),
     * maintenance open and restore, and pause all come through here.
     *
     * @return {@code null} when the stored settings cannot be read
     */
    public static BuiltInBlockExemptions.PassFilter settledFilter(
            Context context, HomeFilterPolicy.Settings stored) {
        return stored == null ? null
                : BuiltInBlockExemptions.PassFilter.forPass(stored, () -> teardownVerdict(context));
    }

    public static BuiltInBlockExemptions.PassFilter settledFilter(Context context) {
        return settledFilter(context, readStored(context));
    }

    /** Whether system policy must treat the home filter as on right now; see {@link #settledFilter}. */
    public static boolean enforcedEnabled(Context context) {
        return BuiltInBlockExemptions.PassFilter.enforcedEnabled(settledFilter(context));
    }

    /** The teardown guard's verdict from the raw approval flag and a live observation. */
    static BuiltInBlockExemptions.TeardownVerdict teardownVerdict(Context context) {
        return BuiltInBlockExemptions.teardownVerdict(
                BuiltInBlockExemptionsStore.chromeFlag(context),
                ExemptionObserver.observe(context, BuiltInBlockExemptions.CHROME),
                !ManagementModeStore.read(context).usesLocalPolicy()
                        || AllowedAppsStore.isProtectionEnabled(context));
    }

    public static boolean isEnabled(Context context) {
        HomeFilterPolicy.Settings settings = readStored(context);
        return settings == null || settings.enabled();
    }

    static boolean needsReconciliation(Context context) {
        HomeFilterPolicy.Settings settings = readStored(context);
        return settings == null || settings.configured();
    }

    public static boolean isConfiguredVpn(Context context, String packageName) {
        HomeFilterPolicy.Settings settings = readStored(context);
        if (settings == null) return false;
        return settings.configured() && settings.config().vpnPackage().equals(packageName);
    }

    public static boolean vpnBlocksActiveStatus(Context context) {
        HomeFilterPolicy.Settings settings = readStored(context);
        return settings == null || (settings.enabled()
                && HomeFilterPolicy.inspectVpn(settings, Build.VERSION.SDK_INT, gateway(context))
                    != HomeFilterPolicy.State.CONFIRMED);
    }

    static HomeFilterPolicy.Settings readStored(Context context) {
        return HomeFilterStore.readOrReport(() -> HomeFilterStore.read(context), () -> {
            if (ManagementModeStore.read(context).usesLocalPolicy()
                    && (AllowedAppsStore.getPolicyState(context) != AllowedAppsStore.PolicyState.FAILED
                        || !CORRUPT_CONFIGURATION.equals(AllowedAppsStore.getPolicyError(context)))) {
                AllowedAppsStore.markApplyFailed(context, CORRUPT_CONFIGURATION,
                        AllowedAppsStore.isProtectionEnabled(context));
            }
        });
    }

    private static HomeFilterPolicy.Settings requireSettings(Context context) {
        HomeFilterPolicy.Settings settings = readStored(context);
        if (settings == null) throw new CorruptConfigurationException();
        return settings;
    }

    public static Runnable watch(Context context, Runnable listener) {
        return HomeFilterStore.watch(context, listener);
    }

    private static AndroidGateway gateway(Context context) {
        return new AndroidGateway(context, context.getSystemService(DevicePolicyManager.class),
                LockdownAdminReceiver.componentName(context));
    }

    private record AndroidGateway(Context context, DevicePolicyManager dpm, ComponentName admin)
            implements HomeFilterPolicy.Gateway {

        @SuppressWarnings("deprecation")
        private static final int VPN_PACKAGE_FLAGS =
                PackageManager.MATCH_UNINSTALLED_PACKAGES | PackageManager.MATCH_DISABLED_COMPONENTS;

        /** The filter itself must be launchable before Android can verify its VPN policy. */
        private void restoreVpnAvailability(HomeFilterPolicy.Settings settings,
                                            Predicate<Set<String>> recordRelease) {
            if (!settings.enabled() || !HomeFilterPolicy.supportedOn(Build.VERSION.SDK_INT)) {
                return;
            }
            String packageName = settings.config().vpnPackage();
            if (!settings.keepsVpnVisible(packageName)) {
                return;
            }
            try {
                ApplicationInfo info = context.getPackageManager().getApplicationInfo(packageName, VPN_PACKAGE_FLAGS);
                if ((info.flags & ApplicationInfo.FLAG_INSTALLED) == 0 || !info.enabled) {
                    return;
                }
                boolean hidden = dpm.isApplicationHidden(admin, packageName);
                if ((!hidden && !dpm.isPackageSuspended(admin, packageName))
                        || vpnSignerState(settings.config()) != HomeFilterPolicy.PackageState.INSTALLED) {
                    return;
                }
                if (hidden) {
                    if (recordRelease != null && !recordRelease.test(Set.of(packageName))) {
                        throw new IllegalStateException("The release could not be recorded");
                    }
                    dpm.setApplicationHidden(admin, packageName, false);
                }
                if (!dpm.isApplicationHidden(admin, packageName)
                        && dpm.isPackageSuspended(admin, packageName)) {
                    dpm.setPackagesSuspended(admin, new String[]{packageName}, false);
                }
            } catch (PackageManager.NameNotFoundException ignored) {
                // It disappeared from inventory. VPN read-back will report it missing.
            }
        }

        @Override
        public HomeFilterPolicy.PackageState vpnPackageState(HomeFilterPolicy.Config config) {
            String packageName = config.vpnPackage();
            PackageManager pm = context.getPackageManager();
            try {
                // Hidden packages can be absent from ordinary queries but still installed.
                ApplicationInfo info = pm.getApplicationInfo(packageName, VPN_PACKAGE_FLAGS);
                if ((info.flags & ApplicationInfo.FLAG_INSTALLED) == 0) {
                    return HomeFilterPolicy.PackageState.MISSING;
                }
                if (!info.enabled || dpm.isApplicationHidden(admin, packageName)
                        || dpm.isPackageSuspended(admin, packageName)) {
                    return HomeFilterPolicy.PackageState.HIDDEN;
                }
                return vpnSignerState(config);
            } catch (PackageManager.NameNotFoundException ignored) {
                return HomeFilterPolicy.PackageState.MISSING;
            }
        }

        private HomeFilterPolicy.PackageState vpnSignerState(HomeFilterPolicy.Config config) {
            String packageName = config.vpnPackage();
            Set<String> pins = config.signerPin().isEmpty()
                    ? AllowedAppsStore.getManagementCertificatePins(context).getOrDefault(packageName, Set.of())
                    : Set.of(config.signerPin());
            LockdownPackages.ManagementPackage record = new LockdownPackages.ManagementPackage(packageName, pins);
            return HomeFilterPolicy.installedVpnState(
                    LockdownPolicyController.managementSignerVerdict(context, record, VPN_PACKAGE_FLAGS));
        }

        @Override
        public String alwaysOnPackage() {
            return dpm.getAlwaysOnVpnPackage(admin);
        }

        @Override
        public HomeFilterPolicy.VpnState vpnState() {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
                throw new UnsupportedOperationException("Lockdown read-back requires Android 10");
            }
            Set<String> exemptions = dpm.getAlwaysOnVpnLockdownWhitelist(admin);
            return new HomeFilterPolicy.VpnState(alwaysOnPackage(),
                    dpm.isAlwaysOnVpnLockdownEnabled(admin),
                    exemptions != null && exemptions.isEmpty());
        }

        @Override
        public boolean setVpn(String packageName) {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    dpm.setAlwaysOnVpnPackage(admin, packageName, packageName != null,
                            Collections.emptySet());
                } else {
                    dpm.setAlwaysOnVpnPackage(admin, packageName, packageName != null);
                }
                return true;
            } catch (PackageManager.NameNotFoundException ignored) {
                return false;
            }
        }

        @Override
        public boolean uninstallBlocked(String packageName) {
            return dpm.isUninstallBlocked(admin, packageName);
        }

        @Override
        public boolean setVpnUninstallBlocked(String packageName, boolean blocked) {
            dpm.setUninstallBlocked(admin, packageName, blocked);
            return true;
        }

        @Override
        public boolean retainVpnUninstallBlock(String packageName) {
            if (context.getPackageName().equals(packageName)) return true;
            return LockdownPackages.managementPackages(AllowedAppsStore.getManagementCertificatePins(context))
                    .stream().filter(record -> record.packageName().equals(packageName))
                    .anyMatch(record -> LockdownPackages.grantsManagementTrust(
                            LockdownPolicyController.managementSignerVerdict(context, record)));
        }

        @Override
        @SuppressWarnings("deprecation")
        public Map<String, Object> managedConfig(String packageName) {
            Bundle readback = dpm.getApplicationRestrictions(admin, packageName);
            Map<String, Object> values = new java.util.LinkedHashMap<>();
            for (String key : readback.keySet()) {
                values.put(key, readback.get(key));
            }
            return values;
        }

        @Override
        @SuppressWarnings("deprecation")
        public boolean setManagedConfig(String packageName, Map<String, Object> changes, boolean enabled) {
            Bundle updated = new Bundle(dpm.getApplicationRestrictions(admin, packageName));
            changes.forEach((key, value) -> {
                if (!enabled) {
                    if (value.equals(updated.get(key))) updated.remove(key);
                } else if (value instanceof Boolean flag) {
                    updated.putBoolean(key, flag);
                } else {
                    updated.putString(key, (String) value);
                }
            });
            dpm.setApplicationRestrictions(admin, packageName, updated);
            return true;
        }

        @Override
        public boolean privateDnsOpportunistic() {
            return Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q
                    && dpm.getGlobalPrivateDnsMode(admin) == DevicePolicyManager.PRIVATE_DNS_MODE_OPPORTUNISTIC;
        }

        @Override
        public boolean setPrivateDnsOpportunistic() {
            return Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q
                    && dpm.setGlobalPrivateDnsModeOpportunistic(admin)
                        == DevicePolicyManager.PRIVATE_DNS_SET_NO_ERROR;
        }

        @Override
        public String proxyPacUrl() {
            ConnectivityManager cm = context.getSystemService(ConnectivityManager.class);
            if (cm == null) {
                throw new IllegalStateException("Missing connectivity service");
            }
            ProxyInfo proxy = cm.getDefaultProxy();
            Uri pac = proxy == null ? null : proxy.getPacFileUrl();
            return pac == null ? "" : pac.toString();
        }

        @Override
        public boolean setProxy(String pacUrl) {
            dpm.setRecommendedGlobalProxy(admin,
                    pacUrl == null ? null : ProxyInfo.buildPacProxy(Uri.parse(pacUrl)));
            return true;
        }

        @Override
        public boolean hasCa(String certificate) {
            return dpm.hasCaCertInstalled(admin, Base64.getDecoder().decode(certificate));
        }

        @Override
        public boolean setCa(String certificate, boolean install) {
            byte[] der = Base64.getDecoder().decode(certificate);
            if (install) {
                return dpm.installCaCert(admin, der);
            }
            dpm.uninstallCaCert(admin, der);
            return true;
        }

        @Override
        public boolean restrictionsMatch(boolean enabled) {
            Bundle restrictions = dpm.getUserRestrictions(admin);
            boolean appsProtected = !enabled && AllowedAppsStore.isProtectionEnabled(context);
            Map<SystemPolicyControl, Boolean> choices =
                    appsProtected ? SystemPolicyStore.baseChoices(context) : Map.of();
            SystemPolicyProfile profile = appsProtected ? SystemPolicyStore.effectiveProfile(context) : null;
            for (SystemPolicyControl control : HomeFilterPolicy.REQUIRED_CONTROLS) {
                if (!control.supportedOn(Build.VERSION.SDK_INT)) {
                    if (enabled) {
                        return false;
                    }
                    continue;
                }
                boolean requested = enabled || (appsProtected
                        && SystemPolicyEnforcer.requestedFor(control, profile, choices));
                for (SystemPolicyControl.Restriction restriction :
                        control.supportedRestrictions(Build.VERSION.SDK_INT)) {
                    if (restrictions.getBoolean(restriction.key()) != requested) {
                        return false;
                    }
                }
            }
            for (SystemPolicyControl.Restriction restriction :
                    HomeFilterPolicy.profileRestrictions(Build.VERSION.SDK_INT)) {
                if (restrictions.getBoolean(restriction.key()) != enabled) return false;
            }
            return true;
        }

        @Override
        public boolean setProfileRestrictions(boolean enabled) {
            Bundle restrictions = dpm.getUserRestrictions(admin);
            for (SystemPolicyControl.Restriction restriction :
                    HomeFilterPolicy.profileRestrictions(Build.VERSION.SDK_INT)) {
                String key = restriction.key();
                if (restrictions.getBoolean(key) == enabled) continue;
                if (enabled) {
                    dpm.addUserRestriction(admin, key);
                } else {
                    dpm.clearUserRestriction(admin, key);
                }
            }
            return true;
        }
    }
}
