package com.example.lockdowndpc.admin;

import android.app.admin.DeviceAdminService;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.util.Log;

import com.example.lockdowndpc.policy.HomeFilterController;
import com.example.lockdowndpc.policy.PolicyReconciliationCoordinator;
import com.example.lockdowndpc.updates.UpdateScheduler;

/**
 * Keeps the device-owner process available for runtime-only package broadcasts.
 *
 * <p>Android 8+ does not deliver most implicit package broadcasts to manifest
 * receivers. {@link DeviceAdminService} is specifically provided for a device
 * owner/profile owner that needs a runtime receiver while its user is running.
 */
public final class LockdownDeviceAdminService extends DeviceAdminService {
    private static final String TAG = "LockdownAdminService";

    private final BroadcastReceiver packageReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (intent.getData() == null) {
                return;
            }
            String packageName = intent.getData().getSchemeSpecificPart();
            if (!Intent.ACTION_PACKAGE_ADDED.equals(intent.getAction())
                    && (!Intent.ACTION_PACKAGE_REMOVED.equals(intent.getAction())
                        || intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)
                        || !HomeFilterController.isConfiguredVpn(context, packageName))) {
                return;
            }
            PolicyReconciliationCoordinator.reconcileAsync(
                    context,
                    intent.getAction() + ":" + packageName,
                    null
            );
        }
    };

    private boolean receiverRegistered;

    @Override
    public void onCreate() {
        super.onCreate();
        IntentFilter filter = new IntentFilter(Intent.ACTION_PACKAGE_ADDED);
        filter.addAction(Intent.ACTION_PACKAGE_REMOVED);
        filter.addDataScheme("package");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(packageReceiver, filter, Context.RECEIVER_NOT_EXPORTED);
        } else {
            //noinspection UnspecifiedRegisterReceiverFlag
            registerReceiver(packageReceiver, filter);
        }
        receiverRegistered = true;

        // Reconcile the entire installed inventory whenever Android rebinds the
        // service. This closes the gap if the process was killed under memory
        // pressure while one or more package broadcasts were in flight.
        PolicyReconciliationCoordinator.reconcileAsync(
                getApplicationContext(),
                "device-admin-service-started",
                null
        );
        UpdateScheduler.schedule(getApplicationContext());
        Log.i(TAG, "Runtime package reconciliation receiver registered");
    }

    @Override
    public void onDestroy() {
        if (receiverRegistered) {
            unregisterReceiver(packageReceiver);
            receiverRegistered = false;
        }
        super.onDestroy();
    }
}
