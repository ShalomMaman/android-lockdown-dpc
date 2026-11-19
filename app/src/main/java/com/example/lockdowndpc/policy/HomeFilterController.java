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
    private HomeFilterController() {}

    public record Snapshot(HomeFilterPolicy.Settings settings, HomeFilterPolicy.Report report) {}

    public static Snapshot read(Context context) {
        return PolicyReconciliationCoordinator.callOnPolicyThread(() -> {
            HomeFilterPolicy.Settings settings = HomeFilterStore.read(context);
            HomeFilterPolicy.Report report = HomeFilterPolicy.inspect(
                    settings, Build.VERSION.SDK_INT, gateway(context));
            return new Snapshot(settings, HomeFilterStore.includeApplyEvidence(
                    context, settings.enabled(), report));
        });
    }

    public static Snapshot enable(Context context, HomeFilterPolicy.Config config, String ca) {
        return change(context, settings -> {
            if (settings.configured()) {
                throw new IllegalStateException("Home filter configuration is already present");
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
            HomeFilterPolicy.Settings before = HomeFilterStore.read(context);
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
        HomeFilterPolicy.Settings settings = HomeFilterStore.read(context);
        if (!settings.configured()) {
            return;
        }
        HomeFilterPolicy.Report report = HomeFilterPolicy.reconcile(settings, Build.VERSION.SDK_INT,
                new AndroidGateway(context, dpm, admin));
        boolean verified = settings.enabled() ? report.active(settings) : report.removed();
        if (!verified) {
            errors.add("home-filter:vpn=" + report.vpn() + ",proxy=" + report.proxy()
                    + ",ca=" + report.ca() + ",restrictions=" + report.restrictions());
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
        return HomeFilterStore.read(context).enabled();
    }

    static boolean needsReconciliation(Context context) {
        return HomeFilterStore.read(context).configured();
    }

    public static boolean isConfiguredVpn(Context context, String packageName) {
        HomeFilterPolicy.Settings settings = HomeFilterStore.read(context);
        return settings.configured() && settings.config().vpnPackage().equals(packageName);
    }

    public static boolean vpnBlocksActiveStatus(Context context) {
        HomeFilterPolicy.Settings settings = HomeFilterStore.read(context);
        return settings.enabled() && HomeFilterPolicy.inspectVpn(settings, Build.VERSION.SDK_INT,
                gateway(context)) != HomeFilterPolicy.State.CONFIRMED;
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
        public HomeFilterPolicy.PackageState vpnPackageState(String packageName) {
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
                for (LockdownPackages.ManagementPackage record : LockdownPackages.managementPackages(
                        AllowedAppsStore.getManagementCertificatePins(context))) {
                    if (record.packageName().equals(packageName) && record.hasPinnedCertificate()
                            && !LockdownPackages.grantsManagementTrust(
                                    LockdownPolicyController.managementSignerVerdict(context, record))) {
                        return HomeFilterPolicy.PackageState.UNTRUSTED;
                    }
                }
                return HomeFilterPolicy.PackageState.INSTALLED;
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
            return true;
        }
    }
}
