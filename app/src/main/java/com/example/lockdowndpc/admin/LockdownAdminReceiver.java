package com.example.lockdowndpc.admin;

import android.app.admin.DeviceAdminReceiver;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import com.example.lockdowndpc.R;
import com.example.lockdowndpc.policy.ManagementModeStore;
import com.example.lockdowndpc.policy.RemoteEnrolmentGate;

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
        if (!RemoteEnrolmentGate.permitsLocalProvisioning(intent)) {
            Log.w("LockdownAdminReceiver", "remote-enrolment-disabled");
            return;
        }
        DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
        if (dpm != null && dpm.isDeviceOwnerApp(context.getPackageName())
                && ManagementModeStore.selectLocal(context)) {
            dpm.setProfileName(componentName(context), context.getString(R.string.admin_profile_name));
        }
    }
}
