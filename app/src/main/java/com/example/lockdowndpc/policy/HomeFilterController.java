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
import com.example.lockdowndpc.security.AdminSession;

import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;

public final class HomeFilterController {
    static final String CORRUPT_CONFIGURATION = "home-filter:corrupt-configuration";

    private HomeFilterController() {}

    public record Snapshot(HomeFilterPolicy.Settings settings, HomeFilterPolicy.Report report) {}

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

    public static Snapshot enable(Context context, HomeFilterPolicy.Config config, String ca) {
        return change(context, settings -> {
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

    public static Snapshot installCa(Context context, String ca) {
        return change(context, settings -> {
            if (!settings.enabled() || settings.ca() != null) {
                throw new IllegalStateException("Remove the old certificate before installing another");
            }
            return new HomeFilterPolicy.Settings(settings.config(), true, ca, false);
        });
    }

    public static Snapshot removeCa(Context context) {
        return change(context, HomeFilterPolicy.Settings::requestRemoveCa);
    }

    public static Snapshot disable(Context context) {
        return change(context, HomeFilterPolicy.Settings::requestDisable);
    }

    public static Snapshot retry(Context context) {
        return change(context, UnaryOperator.identity());
    }

    private static Snapshot change(Context context, UnaryOperator<HomeFilterPolicy.Settings> operation) {
        return PolicyReconciliationCoordinator.callOnPolicyThread(() -> {
            DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
            if (!AdminSession.isUnlocked() || dpm == null
                    || !dpm.isDeviceOwnerApp(context.getPackageName())) {
                throw new SecurityException("An unlocked device owner is required");
            }
            HomeFilterPolicy.Settings before = requireSettings(context);
            HomeFilterPolicy.Settings after = operation.apply(before);
            if (!before.equals(after)) {
                HomeFilterStore.write(context, after);
                AuditLog.append(context, "Home filter settings changed by administrator");
            }
            if (AllowedAppsStore.isProtectionEnabled(context)) {
                LockdownPolicyController.apply(context);
            } else {
                LockdownPolicyController.pause(context);
            }
            return read(context);
        });
    }

    /** Device-owner lifecycle entry point. It only reasserts saved administrator intent. */
    static void reconcile(Context context, DevicePolicyManager dpm, ComponentName admin,
                          List<String> errors) {
        HomeFilterPolicy.Settings settings = readStored(context);
        if (settings == null) {
            errors.add(CORRUPT_CONFIGURATION);
            return;
        }
        if (!settings.configured()) {
            return;
        }
        HomeFilterPolicy.Report report = HomeFilterPolicy.reconcile(settings, Build.VERSION.SDK_INT,
                new AndroidGateway(context, dpm, admin));
        boolean verified = settings.enabled()
                ? report.androidSettingsConfirmed(settings) : report.removed();
        if (!verified) {
            errors.add("home-filter:vpn=" + report.vpn() + ",proxy=" + report.proxy()
                    + ",ca=" + report.ca() + ",restrictions=" + report.restrictions()
                    + ",private-dns=" + report.privateDns());
        }
        HomeFilterPolicy.Settings remaining = settings.afterReadback(report);
        if (!remaining.equals(settings)) {
            HomeFilterStore.write(context, remaining);
        }
        if (remaining.configured()) {
            HomeFilterStore.saveReadback(context, report);
        }
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
            if (AllowedAppsStore.getPolicyState(context) != AllowedAppsStore.PolicyState.FAILED
                    || !CORRUPT_CONFIGURATION.equals(AllowedAppsStore.getPolicyError(context))) {
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

        @Override
        public HomeFilterPolicy.PackageState vpnPackageState(HomeFilterPolicy.Config config) {
            String packageName = config.vpnPackage();
            PackageManager pm = context.getPackageManager();
            try {
                // Hidden packages can be absent from ordinary queries but still installed.
                @SuppressWarnings("deprecation")
                ApplicationInfo info = pm.getApplicationInfo(packageName,
                        PackageManager.MATCH_UNINSTALLED_PACKAGES);
                if ((info.flags & ApplicationInfo.FLAG_INSTALLED) == 0) {
                    return HomeFilterPolicy.PackageState.MISSING;
                }
                if (!info.enabled || (info.flags & ApplicationInfo.FLAG_SUSPENDED) != 0
                        || dpm.isApplicationHidden(admin, packageName)) {
                    return HomeFilterPolicy.PackageState.HIDDEN;
                }
                Set<String> pins = config.signerPin().isEmpty()
                        ? AllowedAppsStore.getManagementCertificatePins(context)
                            .getOrDefault(packageName, Set.of())
                        : Set.of(config.signerPin());
                LockdownPackages.ManagementPackage record =
                        new LockdownPackages.ManagementPackage(packageName, pins);
                return HomeFilterPolicy.installedVpnState(
                        LockdownPolicyController.managementSignerVerdict(context, record));
            } catch (PackageManager.NameNotFoundException ignored) {
                return HomeFilterPolicy.PackageState.MISSING;
            }
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
