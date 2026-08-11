package com.example.lockdowndpc.receivers;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

import com.example.lockdowndpc.policy.AllowedAppsStore;
import com.example.lockdowndpc.policy.LockdownPolicyController;
import com.example.lockdowndpc.policy.PolicyReconciliationCoordinator;

public final class PolicyRefreshReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        boolean supportedAction = Intent.ACTION_BOOT_COMPLETED.equals(action)
                || Intent.ACTION_MY_PACKAGE_REPLACED.equals(action);
        if (!supportedAction) {
            return;
        }
        if (AllowedAppsStore.isProtectionEnabled(context)) {
            PendingResult pendingResult = goAsync();
            PolicyReconciliationCoordinator.reconcileAsync(
                    context,
                    action,
                    pendingResult::finish
            );
        } else if (Intent.ACTION_BOOT_COMPLETED.equals(action)
                || Intent.ACTION_MY_PACKAGE_REPLACED.equals(action)) {
            // Reconcile stale hidden-package state while protection is paused.
            LockdownPolicyController.pause(context);
        }
    }
}
