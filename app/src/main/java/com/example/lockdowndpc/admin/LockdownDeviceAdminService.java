package com.example.lockdowndpc.admin;

import android.app.admin.DeviceAdminService;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Build;
import android.util.Log;

import com.example.lockdowndpc.policy.HomeFilterController;
import com.example.lockdowndpc.policy.ManagementModeStore;
import com.example.lockdowndpc.policy.PolicyReconciliationCoordinator;
import com.example.lockdowndpc.policy.ScheduleAlarm;
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
                        || (ManagementModeStore.read(context).usesLocalPolicy()
                            && !HomeFilterController.isConfiguredVpn(context, packageName)))) {
                return;
            }
            PolicyReconciliationCoordinator.reconcileAsync(
                    context,
                    intent.getAction() + ":" + packageName,
                    null
            );
        }
    };

    /**
     * Night and work hours catch-up: the screen turning on or the device being
     * unlocked is the first moment a missed boundary could matter to the user.
     * These broadcasts reach only runtime receivers. The check runs on the
     * policy thread and queues a pass only when a boundary was missed, so a
     * device without an enforcing schedule reads two preference files and stops.
     */
    private final BroadcastReceiver scheduleReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent == null ? null : intent.getAction();
            if (!Intent.ACTION_SCREEN_ON.equals(action) && !Intent.ACTION_USER_PRESENT.equals(action)) {
                return;
            }
            Context app = context.getApplicationContext();
            PolicyReconciliationCoordinator.runOnPolicyThread(() -> ScheduleAlarm.catchUp(app, action, null));
        }
    };

    private boolean receiverRegistered;
    private boolean scheduleReceiverRegistered;

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

        IntentFilter screen = new IntentFilter(Intent.ACTION_SCREEN_ON);
        screen.addAction(Intent.ACTION_USER_PRESENT);
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                registerReceiver(scheduleReceiver, screen, Context.RECEIVER_NOT_EXPORTED);
            } else {
                //noinspection UnspecifiedRegisterReceiverFlag
                registerReceiver(scheduleReceiver, screen);
            }
            scheduleReceiverRegistered = true;
        } catch (RuntimeException exception) {
            // The boundary alarms and the periodic sweep still run.
            Log.e(TAG, "Schedule catch-up receiver not registered", exception);
        }

        // Reconcile the entire installed inventory whenever Android rebinds the
        // service. This closes the gap if the process was killed under memory
        // pressure while one or more package broadcasts were in flight.
        PolicyReconciliationCoordinator.reconcileAsync(
                getApplicationContext(),
                "device-admin-service-started",
                null
        );
        if (ManagementModeStore.read(this).usesLocalPolicy()) {
            UpdateScheduler.schedule(getApplicationContext());
        }
        Log.i(TAG, "Runtime package reconciliation receiver registered");
    }

    @Override
    public void onDestroy() {
        if (receiverRegistered) {
            unregisterReceiver(packageReceiver);
            receiverRegistered = false;
        }
        if (scheduleReceiverRegistered) {
            unregisterReceiver(scheduleReceiver);
            scheduleReceiverRegistered = false;
        }
        super.onDestroy();
    }
}
