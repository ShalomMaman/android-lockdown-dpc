package com.example.lockdowndpc.receivers;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;

import com.example.lockdowndpc.policy.AllowedAppsStore;
import com.example.lockdowndpc.policy.LockdownPackages;
import com.example.lockdowndpc.policy.LockdownPolicyController;

public final class PolicyRefreshReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        boolean supportedAction = Intent.ACTION_BOOT_COMPLETED.equals(action)
                || Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)
                || Intent.ACTION_PACKAGE_ADDED.equals(action);
        if (Intent.ACTION_PACKAGE_ADDED.equals(action) && intent.getData() != null) {
            rememberNewLaunchableApp(context, intent.getData().getSchemeSpecificPart());
        }
        if (!supportedAction) {
            return;
        }
        if (AllowedAppsStore.isProtectionEnabled(context)) {
            LockdownPolicyController.apply(context);
        } else if (Intent.ACTION_BOOT_COMPLETED.equals(action)
                || Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)) {
            // Reconcile stale hidden-package state while protection is paused.
            LockdownPolicyController.pause(context);
        }
    }

    private static void rememberNewLaunchableApp(Context context, String packageName) {
        if (packageName == null
                || packageName.equals(context.getPackageName())
                || packageName.equals("com.tailscale.ipn")
                || LockdownPackages.ALWAYS_BLOCKED.contains(packageName)
                || LockdownPackages.KNOWN_BROWSER_AND_SOCIAL.contains(packageName)) {
            return;
        }
        try {
            PackageManager pm = context.getPackageManager();
            ApplicationInfo info;
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                info = pm.getApplicationInfo(packageName, PackageManager.ApplicationInfoFlags.of(0));
            } else {
                //noinspection deprecation
                info = pm.getApplicationInfo(packageName, 0);
            }
            boolean system = (info.flags
                    & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0;
            if (!system && pm.getLaunchIntentForPackage(packageName) != null) {
                AllowedAppsStore.addManagedPackage(context, packageName);
            }
        } catch (PackageManager.NameNotFoundException ignored) {
            // The package disappeared before the broadcast was handled.
        }
    }
}
