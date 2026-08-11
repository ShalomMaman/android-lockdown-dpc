package com.example.lockdowndpc.admin;

import android.app.admin.DeviceAdminReceiver;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;

public final class LockdownAdminReceiver extends DeviceAdminReceiver {
    public static ComponentName componentName(Context context) {
        return new ComponentName(context, LockdownAdminReceiver.class);
    }

    @Override
    public void onEnabled(Context context, Intent intent) {
        super.onEnabled(context, intent);
    }

    @Override
    public void onProfileProvisioningComplete(Context context, Intent intent) {
        super.onProfileProvisioningComplete(context, intent);
        DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
        if (dpm != null && dpm.isDeviceOwnerApp(context.getPackageName())) {
            dpm.setProfileName(componentName(context), "מכשיר מוגן");
        }
    }
}
