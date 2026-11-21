package com.example.lockdowndpc.policy;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Build;
import android.provider.AlarmClock;
import android.provider.Settings;
import android.provider.Telephony;
import android.telecom.TelecomManager;
import android.webkit.WebView;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Night and work hours through the Device Owner APIs: the launcher inventory,
 * suspension with read-back, the ownership record and the boundary alarm.
 */
final class ScheduleDeviceGateway implements ScheduleSuspension.Gateway {
    private final Context context;
    private final DevicePolicyManager dpm;
    private final ComponentName admin;

    ScheduleDeviceGateway(Context context, DevicePolicyManager dpm, ComponentName admin) {
        this.context = context;
        this.dpm = dpm;
        this.admin = admin;
    }

    @Override
    public Set<String> launchablePackages() {
        // Not through query(): a failed inventory must reach the pass as an
        // error, never read as "nothing to suspend".
        Intent launcher = new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);
        PackageManager pm = context.getPackageManager();
        List<ResolveInfo> matches;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            matches = pm.queryIntentActivities(launcher, PackageManager.ResolveInfoFlags.of(0));
        } else {
            //noinspection deprecation
            matches = pm.queryIntentActivities(launcher, 0);
        }
        LinkedHashSet<String> packages = new LinkedHashSet<>();
        for (ResolveInfo info : matches) {
            if (info.activityInfo != null) {
                packages.add(info.activityInfo.packageName);
            }
        }
        if (packages.isEmpty()) {
            // Every device has at least Settings in its launcher.
            throw new IllegalStateException("empty-launcher-inventory");
        }
        return packages;
    }

    @Override
    public Boolean suspended(String packageName) {
        try {
            return dpm.isPackageSuspended(admin, packageName);
        } catch (PackageManager.NameNotFoundException exception) {
            return null;
        }
    }

    @Override
    public String[] setSuspended(String[] packageNames, boolean suspended) {
        return dpm.setPackagesSuspended(admin, packageNames, suspended);
    }

    @Override
    public Set<String> owned() {
        return ScheduleStore.readOwned(context);
    }

    @Override
    public boolean saveOwned(Set<String> owned) {
        return ScheduleStore.saveOwned(context, owned);
    }

    @Override
    public void armBoundary(Instant at) {
        ScheduleAlarm.arm(context, at);
    }

    @Override
    public void cancelBoundary() {
        ScheduleAlarm.cancel(context);
    }

    /**
     * The runtime part of the always-available core: the default dialer and SMS
     * app, clock apps, the home launcher, the active input method and the active
     * WebView provider.
     *
     * <p>Dialer, SMS and clock count only when they are system packages, so an
     * installed app cannot escape the night window by declaring an alarm intent
     * or by being made the default SMS app. The home launcher always counts:
     * suspending the one HOME activity would strand the device. When no single
     * default resolves, every HOME handler is kept.
     */
    static Set<String> roleApps(Context context) {
        PackageManager pm = context.getPackageManager();
        LinkedHashSet<String> packages = new LinkedHashSet<>();
        try {
            TelecomManager telecom = context.getSystemService(TelecomManager.class);
            addIfSystem(pm, packages, telecom == null ? null : telecom.getDefaultDialerPackage());
        } catch (RuntimeException ignored) {
            // No telephony role on this device.
        }
        try {
            addIfSystem(pm, packages, Telephony.Sms.getDefaultSmsPackage(context));
        } catch (RuntimeException ignored) {
            // No SMS role on this device.
        }
        for (String action : new String[]{AlarmClock.ACTION_SHOW_ALARMS, AlarmClock.ACTION_SET_ALARM}) {
            for (ResolveInfo info : query(pm, new Intent(action), PackageManager.MATCH_DEFAULT_ONLY)) {
                if (info.activityInfo != null && isSystem(info.activityInfo.applicationInfo)) {
                    packages.add(info.activityInfo.packageName);
                }
            }
        }
        packages.addAll(homePackages(pm));
        String inputMethod = activeInputMethod(context);
        if (inputMethod != null) {
            packages.add(inputMethod);
        }
        try {
            PackageInfo webView = WebView.getCurrentWebViewPackage();
            if (webView != null) {
                packages.add(webView.packageName);
            }
        } catch (RuntimeException ignored) {
            // No WebView provider could be read.
        }
        return packages;
    }

    private static Set<String> homePackages(PackageManager pm) {
        LinkedHashSet<String> packages = new LinkedHashSet<>();
        Intent home = new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME);
        ResolveInfo resolved = null;
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                resolved = pm.resolveActivity(home,
                        PackageManager.ResolveInfoFlags.of(PackageManager.MATCH_DEFAULT_ONLY));
            } else {
                //noinspection deprecation
                resolved = pm.resolveActivity(home, PackageManager.MATCH_DEFAULT_ONLY);
            }
        } catch (RuntimeException ignored) {
            // Fall back to every HOME handler below.
        }
        String resolvedPackage = resolved == null || resolved.activityInfo == null
                ? null : resolved.activityInfo.packageName;
        if (resolvedPackage != null && !"android".equals(resolvedPackage)) {
            packages.add(resolvedPackage);
            return packages;
        }
        // No single default (the chooser resolves to "android"): keep them all.
        for (ResolveInfo info : query(pm, home, PackageManager.MATCH_DEFAULT_ONLY)) {
            if (info.activityInfo != null) {
                packages.add(info.activityInfo.packageName);
            }
        }
        return packages;
    }

    private static String activeInputMethod(Context context) {
        try {
            String flattened = Settings.Secure.getString(
                    context.getContentResolver(), Settings.Secure.DEFAULT_INPUT_METHOD);
            ComponentName component = flattened == null ? null : ComponentName.unflattenFromString(flattened);
            return component == null ? null : component.getPackageName();
        } catch (RuntimeException exception) {
            return null;
        }
    }

    private static void addIfSystem(PackageManager pm, Set<String> packages, String packageName) {
        if (packageName == null || packageName.isEmpty()) {
            return;
        }
        try {
            ApplicationInfo info;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                info = pm.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(0));
            } else {
                //noinspection deprecation
                info = pm.getApplicationInfo(packageName, 0);
            }
            if (isSystem(info)) {
                packages.add(packageName);
            }
        } catch (PackageManager.NameNotFoundException ignored) {
            // Not installed for this user.
        }
    }

    private static boolean isSystem(ApplicationInfo info) {
        return info != null
                && (info.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0;
    }

    private static List<ResolveInfo> query(PackageManager pm, Intent intent, int flags) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                return pm.queryIntentActivities(intent, PackageManager.ResolveInfoFlags.of(flags));
            }
            //noinspection deprecation
            return pm.queryIntentActivities(intent, flags);
        } catch (RuntimeException exception) {
            return List.of();
        }
    }
}
