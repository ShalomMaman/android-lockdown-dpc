package com.example.lockdowndpc.policy;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.UserManager;
import android.util.Log;
import android.webkit.WebView;

import com.example.lockdowndpc.admin.LockdownAdminReceiver;
import com.example.lockdowndpc.ui.BlockedBrowserActivity;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public final class LockdownPolicyController {
    private static final String TAG = "LockdownPolicy";

    private LockdownPolicyController() {}

    public static PolicyResult apply(Context context) {
        AllowedAppsStore.markApplyStarted(context);
        DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
        ComponentName admin = LockdownAdminReceiver.componentName(context);
        if (dpm == null || !dpm.isDeviceOwnerApp(context.getPackageName())) {
            String error = "האפליקציה אינה Device Owner";
            AllowedAppsStore.markApplyFailed(context, error);
            return new PolicyResult(false, false, 0, 0, List.of(error));
        }

        ArrayList<String> errors = new ArrayList<>();
        applyRestrictions(dpm, admin, errors);
        setBlockedBrowserComponentEnabled(context, true, errors);
        configureBlockedBrowser(context, dpm, admin, errors);
        protectManagementApps(context, dpm, admin, errors);
        int[] packageCounts = applyPackagePolicy(context, dpm, admin, errors);
        suspendBrowserBackedWebViewIfNeeded(context, dpm, admin, errors);
        boolean verified = errors.isEmpty();
        if (verified) {
            AllowedAppsStore.markApplySucceeded(context);
            Log.i(TAG, "Policy apply verified; blocked=" + packageCounts[0]
                    + ", allowed=" + packageCounts[1]);
        } else {
            String summary = summarizeErrors(errors);
            AllowedAppsStore.markApplyFailed(context, summary);
            AuditLog.append(context, "החלת המדיניות נכשלה: " + summary);
            Log.e(TAG, "Policy apply failed verification: " + summary);
        }
        return new PolicyResult(true, verified, packageCounts[0], packageCounts[1], errors);
    }

    public static PolicyResult pause(Context context) {
        AllowedAppsStore.markPauseStarted(context);
        DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
        ComponentName admin = LockdownAdminReceiver.componentName(context);
        if (dpm == null || !dpm.isDeviceOwnerApp(context.getPackageName())) {
            String error = "האפליקציה אינה Device Owner";
            AllowedAppsStore.markPauseFailed(context, error);
            return new PolicyResult(false, false, 0, 0, List.of(error));
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
                boolean wasHidden = dpm.isApplicationHidden(admin, packageName);
                boolean updated = dpm.setApplicationHidden(admin, packageName, false);
                boolean hidden = dpm.isApplicationHidden(admin, packageName);
                if (hidden || (!updated && wasHidden)) {
                    errors.add("שחרור " + packageName + " לא אומת");
                } else {
                    visibleCount++;
                }
            } catch (IllegalArgumentException ignored) {
                // Known package is not installed on this device.
            } catch (RuntimeException exception) {
                errors.add("שחרור " + packageName + ": " + exception.getClass().getSimpleName());
            }
        }
        unsuspendBrowserProviders(dpm, admin, errors);
        protectManagementApps(context, dpm, admin, errors);
        boolean verified = errors.isEmpty();
        if (verified) {
            AllowedAppsStore.markPauseSucceeded(context);
            Log.i(TAG, "Policy pause verified; visible=" + visibleCount);
        } else {
            String summary = summarizeErrors(errors);
            AllowedAppsStore.markPauseFailed(context, summary);
            AuditLog.append(context, "השהיית המדיניות נכשלה: " + summary);
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
                    errors.add("שחרור " + restriction + " לא אומת");
                }
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
            if (!dpm.getUserRestrictions(admin).getBoolean(restriction)) {
                errors.add(restriction + ": ההגבלה לא הוחלה");
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
        for (String scheme : new String[]{"http", "https"}) {
            try {
                IntentFilter filter = new IntentFilter(Intent.ACTION_VIEW);
                filter.addCategory(Intent.CATEGORY_DEFAULT);
                filter.addCategory(Intent.CATEGORY_BROWSABLE);
                filter.addDataScheme(scheme);
                dpm.addPersistentPreferredActivity(admin, filter, blockedActivity);
                Intent probe = new Intent(Intent.ACTION_VIEW, Uri.parse(scheme + "://policy-check.invalid"));
                probe.addCategory(Intent.CATEGORY_BROWSABLE);
                if (!blockedActivity.equals(resolveActivity(context.getPackageManager(), probe))) {
                    errors.add("קישורי " + scheme + ": יעד החסימה לא אומת");
                }
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
            if (context.getPackageManager().getComponentEnabledSetting(component) != state) {
                errors.add("עדכון חסימת קישורים לא אומת");
            }
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
                if (!dpm.isUninstallBlocked(admin, packageName)) {
                    errors.add("הגנת הסרה " + packageName + " לא אומתה");
                }
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
        String webViewProvider = resolveWebViewProvider(pm);
        int blockedCount = 0;
        int allowedCount = 0;

        Set<String> packageNames = new LinkedHashSet<>();
        for (ApplicationInfo info : getInstalledApplications(pm)) {
            packageNames.add(info.packageName);
            boolean system = (info.flags
                    & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0;
            if (!system
                    && !info.packageName.equals(context.getPackageName())
                    && !info.packageName.equals("com.tailscale.ipn")) {
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
        packageNames.add("com.tailscale.ipn");
        if (webViewProvider != null) {
            packageNames.add(webViewProvider);
        }

        for (String packageName : packageNames) {
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
            // On some Android releases Chrome is also the system WebView engine.
            // Hiding that package breaks otherwise allowed apps that render HTML.
            if (packageName.equals(webViewProvider)) {
                shouldBlock = false;
            }

            boolean criticalPackage = shouldBlock
                    || managed.contains(packageName)
                    || allowed.contains(packageName)
                    || packageName.equals("com.tailscale.ipn")
                    || packageName.equals(webViewProvider);
            if (!criticalPackage || !isInstalled(pm, packageName)) {
                continue;
            }

            try {
                boolean wasHidden = dpm.isApplicationHidden(admin, packageName);
                boolean updated = dpm.setApplicationHidden(admin, packageName, shouldBlock);
                boolean hidden = dpm.isApplicationHidden(admin, packageName);
                if (!updated && wasHidden != shouldBlock) {
                    errors.add("מדיניות " + packageName + ": Android דחה את העדכון");
                } else if (hidden != shouldBlock) {
                    errors.add("מדיניות " + packageName + ": המצב בפועל אינו תואם");
                }
                if (hidden) {
                    blockedCount++;
                } else {
                    allowedCount++;
                }
            } catch (IllegalArgumentException ignored) {
                // A known package is not installed on this device.
            } catch (RuntimeException exception) {
                errors.add("מדיניות " + packageName + ": " + exception.getClass().getSimpleName());
            }
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
                errors.add("חסימת הפעלת הדפדפן נכשלה");
            } else if (!dpm.isPackageSuspended(admin, provider)) {
                errors.add("חסימת הפעלת הדפדפן לא אומתה");
            }
        } catch (PackageManager.NameNotFoundException exception) {
            errors.add("מנוע WebView לא נמצא לאחר החלת המדיניות");
        } catch (RuntimeException exception) {
            errors.add("חסימת הפעלת הדפדפן: " + exception.getClass().getSimpleName());
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
                    errors.add("שחרור מנוע WebView " + packageName + " לא אומת");
                }
            } catch (PackageManager.NameNotFoundException ignored) {
                // Provider is not installed.
            } catch (IllegalArgumentException ignored) {
                // Provider is not installed.
            } catch (RuntimeException exception) {
                errors.add("שחרור מנוע WebView: " + exception.getClass().getSimpleName());
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
        return errors.size() == 1 ? first : first + " (ועוד " + (errors.size() - 1) + ")";
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
