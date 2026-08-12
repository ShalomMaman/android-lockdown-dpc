package com.example.lockdowndpc.admin;

import android.app.admin.DeviceAdminReceiver;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;

import com.example.lockdowndpc.R;

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
            dpm.setProfileName(componentName(context), context.getString(R.string.admin_profile_name));
        }
    }
}
