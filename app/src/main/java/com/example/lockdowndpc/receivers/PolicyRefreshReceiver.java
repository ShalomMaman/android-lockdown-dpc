package com.example.lockdowndpc.receivers;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

import com.example.lockdowndpc.policy.AllowedAppsStore;
import com.example.lockdowndpc.policy.PolicyReconciliationCoordinator;
import com.example.lockdowndpc.updates.UpdateScheduler;
import com.example.lockdowndpc.updates.SecureUpdateManager;

public final class PolicyRefreshReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        boolean supportedAction = Intent.ACTION_BOOT_COMPLETED.equals(action)
                || Intent.ACTION_MY_PACKAGE_REPLACED.equals(action);
        if (!supportedAction) {
            return;
        }
        UpdateScheduler.schedule(context.getApplicationContext());
        if (Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)) {
            SecureUpdateManager.onPackageReplaced(context.getApplicationContext());
        }
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
}
