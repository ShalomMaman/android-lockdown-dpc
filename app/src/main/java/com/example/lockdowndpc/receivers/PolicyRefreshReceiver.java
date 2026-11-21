package com.example.lockdowndpc.receivers;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

import com.example.lockdowndpc.maintenance.MaintenanceGuard;
import com.example.lockdowndpc.policy.AllowedAppsStore;
import com.example.lockdowndpc.policy.PolicyReconciliationCoordinator;
import com.example.lockdowndpc.policy.ScheduleAlarm;
import com.example.lockdowndpc.updates.UpdateScheduler;
import com.example.lockdowndpc.updates.SecureUpdateManager;

public final class PolicyRefreshReceiver extends BroadcastReceiver {
    /** Sent by {@code AlarmManager} when exact alarm access is granted or revoked (API 31+). */
    private static final String ACTION_EXACT_ALARM_PERMISSION_CHANGED =
            "android.app.action.SCHEDULE_EXACT_ALARM_PERMISSION_STATE_CHANGED";

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        if (isScheduleTrigger(action)) {
            reconcileForSchedule(context, action);
            return;
        }
        boolean supportedAction = Intent.ACTION_BOOT_COMPLETED.equals(action)
                || Intent.ACTION_MY_PACKAGE_REPLACED.equals(action);
        if (!supportedAction) {
            return;
        }
        UpdateScheduler.schedule(context.getApplicationContext());
        if (Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)) {
            SecureUpdateManager.onPackageReplaced(context.getApplicationContext());
        }
        // A maintenance window never survives a restart, and an upgrade must not
        // be a way to keep one open either. This closes anything that lapsed
        // while the device was off and restores the base policy before the
        // package sweep below re-asserts the rest of it. It is queued on the
        // shared policy thread — it is DevicePolicyManager work — and on a device
        // with nothing open it reads one preference file and returns.
        PolicyReconciliationCoordinator.runOnPolicyThread(
                () -> MaintenanceGuard.refresh(context.getApplicationContext()));
        // An active kiosk is re-asserted first so lock task, the lock-task
        // feature set and the kiosk HOME preference are back before the package
        // sweep runs. This is queued on the shared policy executor rather than
        // performed here: it is DevicePolicyManager work and must not touch the
        // broadcast thread. It cannot enter, leave or change a kiosk profile —
        // it only restores a state that was already persisted as active.
        PolicyReconciliationCoordinator.restoreKioskAsync(context, action);

        // Both branches enumerate packages and make many DevicePolicyManager
        // calls, so neither may run on the broadcast thread.
        PendingResult pendingResult = goAsync();
        boolean dispatched = false;
        try {
            if (AllowedAppsStore.isProtectionEnabled(context)) {
                PolicyReconciliationCoordinator.reconcileAsync(
                        context,
                        action,
                        pendingResult::finish
                );
            } else {
                // Reconcile stale hidden-package state while protection is paused.
                PolicyReconciliationCoordinator.pauseAsync(
                        context,
                        action,
                        pendingResult::finish
                );
            }
            dispatched = true;
        } finally {
            if (!dispatched) {
                pendingResult.finish();
            }
        }
    }

    /**
     * A night or work hours boundary, a wall-clock or timezone change, or a
     * change in exact alarm access. Each one can move the device into or out of
     * a window, so it gets a full policy pass, which recomputes the windows from
     * the clock and re-arms the boundary alarm. Nothing else the boot path does
     * (update scheduling, maintenance refresh, kiosk restore) is repeated here.
     * While protection is paused there is nothing to enforce: the pause pass
     * already released the schedule and cancelled its alarm.
     */
    static boolean isScheduleTrigger(String action) {
        return ScheduleAlarm.ACTION_BOUNDARY.equals(action)
                || Intent.ACTION_TIME_CHANGED.equals(action)
                || Intent.ACTION_TIMEZONE_CHANGED.equals(action)
                || ACTION_EXACT_ALARM_PERMISSION_CHANGED.equals(action);
    }

    private void reconcileForSchedule(Context context, String action) {
        if (!AllowedAppsStore.isProtectionEnabled(context)) {
            return;
        }
        PendingResult pendingResult = goAsync();
        boolean dispatched = false;
        try {
            PolicyReconciliationCoordinator.reconcileAsync(context, action, pendingResult::finish);
            dispatched = true;
        } finally {
            if (!dispatched) {
                pendingResult.finish();
            }
        }
    }
}
