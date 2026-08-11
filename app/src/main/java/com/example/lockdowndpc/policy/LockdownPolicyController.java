package com.example.lockdowndpc.policy;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.UserManager;

import com.example.lockdowndpc.admin.LockdownAdminReceiver;
import com.example.lockdowndpc.ui.BlockedBrowserActivity;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public final class LockdownPolicyController {
    private LockdownPolicyController() {}

    public static PolicyResult apply(Context context) {
        DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
        ComponentName admin = LockdownAdminReceiver.componentName(context);
        if (dpm == null || !dpm.isDeviceOwnerApp(context.getPackageName())) {
            return new PolicyResult(false, 0, 0, List.of("האפליקציה אינה Device Owner"));
        }

        ArrayList<String> errors = new ArrayList<>();
        applyRestrictions(dpm, admin, errors);
        setBlockedBrowserComponentEnabled(context, true, errors);
        configureBlockedBrowser(dpm, admin, errors);
        protectManagementApps(context, dpm, admin, errors);
        int[] packageCounts = applyPackagePolicy(context, dpm, admin, errors);
        AllowedAppsStore.setProtectionEnabled(context, true);
        return new PolicyResult(true, packageCounts[0], packageCounts[1], errors);
    }

    public static PolicyResult pause(Context context) {
        DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
        ComponentName admin = LockdownAdminReceiver.componentName(context);
        if (dpm == null || !dpm.isDeviceOwnerApp(context.getPackageName())) {
            return new PolicyResult(false, 0, 0, List.of("האפליקציה אינה Device Owner"));
        }

        ArrayList<String> errors = new ArrayList<>();
        clearRestrictions(dpm, admin, errors);
        try {
            dpm.clearPackagePersistentPreferredActivities(admin, context.getPackageName());
        } catch (RuntimeException exception) {
            errors.add("ניקוי חסימת קישורים: " + exception.getClass().getSimpleName());
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

        int visibleCount = 0;
        for (String packageName : packagesToShow) {
            if (packageName.equals(context.getPackageName())) {
                continue;
            }
            try {
                dpm.setApplicationHidden(admin, packageName, false);
                visibleCount++;
            } catch (IllegalArgumentException ignored) {
                // Known package is not installed on this device.
            } catch (RuntimeException exception) {
                errors.add("שחרור " + packageName + ": " + exception.getClass().getSimpleName());
            }
        }
        protectManagementApps(context, dpm, admin, errors);
        AllowedAppsStore.setProtectionEnabled(context, false);
        return new PolicyResult(true, 0, visibleCount, errors);
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
            } catch (RuntimeException exception) {
                errors.add("שחרור " + restriction + ": " + exception.getClass().getSimpleName());
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
        } catch (RuntimeException exception) {
            errors.add(restriction + ": " + exception.getClass().getSimpleName());
        }
    }

    private static void configureBlockedBrowser(
            DevicePolicyManager dpm,
            ComponentName admin,
            List<String> errors
    ) {
        ComponentName blockedActivity = new ComponentName(admin.getPackageName(), BlockedBrowserActivity.class.getName());
        for (String scheme : new String[]{"http", "https"}) {
            try {
                IntentFilter filter = new IntentFilter(Intent.ACTION_VIEW);
                filter.addCategory(Intent.CATEGORY_DEFAULT);
                filter.addCategory(Intent.CATEGORY_BROWSABLE);
                filter.addDataScheme(scheme);
                dpm.addPersistentPreferredActivity(admin, filter, blockedActivity);
            } catch (RuntimeException exception) {
                errors.add("קישורי " + scheme + ": " + exception.getClass().getSimpleName());
            }
        }
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
        } catch (RuntimeException exception) {
            errors.add("עדכון חסימת קישורים: " + exception.getClass().getSimpleName());
        }
    }

    private static void protectManagementApps(
            Context context,
            DevicePolicyManager dpm,
            ComponentName admin,
            List<String> errors
    ) {
        for (String packageName : new String[]{context.getPackageName(), "com.tailscale.ipn"}) {
            if (!isInstalled(context.getPackageManager(), packageName)) {
                continue;
            }
            try {
                dpm.setUninstallBlocked(admin, packageName, true);
            } catch (RuntimeException exception) {
                errors.add("הגנת הסרה " + packageName + ": " + exception.getClass().getSimpleName());
            }
        }
    }

    private static int[] applyPackagePolicy(
            Context context,
            DevicePolicyManager dpm,
            ComponentName admin,
            List<String> errors
    ) {
        PackageManager pm = context.getPackageManager();
        Set<String> allowed = AllowedAppsStore.getAllowedPackages(context);
        Set<String> managed = AllowedAppsStore.getManagedPackages(context);
        boolean allowlistConfigured = AllowedAppsStore.isAllowlistConfigured(context);
        AllowedAppsStore.ProtectionMode mode = AllowedAppsStore.getProtectionMode(context);
        int blockedCount = 0;
        int allowedCount = 0;

        for (ApplicationInfo info : getInstalledApplications(pm)) {
            String packageName = info.packageName;
            if (packageName.equals(context.getPackageName())) {
                continue;
            }

            boolean shouldBlock = LockdownPackages.ALWAYS_BLOCKED.contains(packageName)
                    || LockdownPackages.KNOWN_BROWSER_AND_SOCIAL.contains(packageName);

            if (!shouldBlock && allowlistConfigured && managed.contains(packageName)) {
                shouldBlock = mode == AllowedAppsStore.ProtectionMode.ALLOW_SELECTED
                        ? !allowed.contains(packageName)
                        : allowed.contains(packageName);
            }

            // Management connectivity must survive policy changes. This is also
            // useful while an administrator is still configuring the device.
            if (packageName.equals("com.tailscale.ipn")) {
                shouldBlock = false;
            }

            try {
                dpm.setApplicationHidden(admin, packageName, shouldBlock);
                if (shouldBlock) {
                    blockedCount++;
                } else {
                    allowedCount++;
                }
            } catch (RuntimeException exception) {
                errors.add("מדיניות " + packageName + ": " + exception.getClass().getSimpleName());
            }
        }
        return new int[]{blockedCount, allowedCount};
    }

    private static boolean isInstalled(PackageManager pm, String packageName) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0));
            } else {
                //noinspection deprecation
                pm.getPackageInfo(packageName, 0);
            }
            return true;
        } catch (PackageManager.NameNotFoundException ignored) {
            return false;
        }
    }

    private static List<ApplicationInfo> getInstalledApplications(PackageManager pm) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return pm.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0));
        }
        //noinspection deprecation
        return pm.getInstalledApplications(0);
    }

    public record PolicyResult(
            boolean applied,
            int blockedPackages,
            int allowedPackages,
            List<String> errors
    ) {}
}
