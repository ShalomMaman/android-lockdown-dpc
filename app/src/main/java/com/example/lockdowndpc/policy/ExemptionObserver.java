package com.example.lockdowndpc.policy;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;

import com.example.lockdowndpc.admin.LockdownAdminReceiver;

/**
 * What Android reports for a package right now. Guards and the console use
 * this, never a stored claim. Anything that cannot be read — no device owner,
 * a failed call — is {@link BuiltInBlockExemptions.Observed#UNKNOWN}, which
 * every guard treats as not contained.
 */
public final class ExemptionObserver {

    private ExemptionObserver() {}

    public static BuiltInBlockExemptions.Observed observe(Context context, String packageName) {
        try {
            DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
            if (dpm == null || !dpm.isDeviceOwnerApp(context.getPackageName())) {
                return BuiltInBlockExemptions.Observed.UNKNOWN;
            }
            ComponentName admin = LockdownAdminReceiver.componentName(context);
            ApplicationInfo info = applicationInfo(context.getPackageManager(), packageName);
            if (info == null || (info.flags & ApplicationInfo.FLAG_INSTALLED) == 0) {
                return BuiltInBlockExemptions.Observed.NOT_INSTALLED;
            }
            if (dpm.isApplicationHidden(admin, packageName)) {
                return BuiltInBlockExemptions.Observed.HIDDEN;
            }
            if (dpm.isPackageSuspended(admin, packageName)) {
                return BuiltInBlockExemptions.Observed.SUSPENDED;
            }
            return info.enabled
                    ? BuiltInBlockExemptions.Observed.VISIBLE
                    : BuiltInBlockExemptions.Observed.DISABLED;
        } catch (PackageManager.NameNotFoundException | RuntimeException exception) {
            return BuiltInBlockExemptions.Observed.UNKNOWN;
        }
    }

    /** {@code null} when the package is not known to Android at all. */
    private static ApplicationInfo applicationInfo(PackageManager pm, String packageName) {
        long flags = PackageManager.MATCH_UNINSTALLED_PACKAGES | PackageManager.MATCH_DISABLED_COMPONENTS;
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                return pm.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(flags));
            }
            //noinspection deprecation
            return pm.getApplicationInfo(packageName, (int) flags);
        } catch (PackageManager.NameNotFoundException exception) {
            return null;
        }
    }
}
