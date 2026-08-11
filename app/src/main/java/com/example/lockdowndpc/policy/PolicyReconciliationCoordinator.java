package com.example.lockdowndpc.policy;

import android.content.Context;
import android.util.Log;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

/** Serializes background reconciliation requests from DPC lifecycle events. */
public final class PolicyReconciliationCoordinator {
    private static final String TAG = "PolicyReconciliation";
    private static final ExecutorService EXECUTOR = Executors.newSingleThreadExecutor(
            new ReconciliationThreadFactory()
    );

    private PolicyReconciliationCoordinator() {}

    /**
     * Re-applies the complete policy when protection has been requested.
     *
     * <p>A complete inventory pass is intentional: package broadcasts can be
     * coalesced or missed while the process is under memory pressure. Scanning
     * current state makes every callback idempotent and repairs earlier gaps.
     */
    public static void reconcileAsync(
            Context context,
            String reason,
            Runnable completion
    ) {
        Context appContext = context.getApplicationContext();
        EXECUTOR.execute(() -> {
            try {
                if (!AllowedAppsStore.isProtectionEnabled(appContext)) {
                    Log.i(TAG, "Skipping reconciliation while protection is paused: " + reason);
                    return;
                }
                LockdownPolicyController.PolicyResult result =
                        LockdownPolicyController.apply(appContext);
                if (result.applied()) {
                    Log.i(TAG, "Reconciliation verified: " + reason);
                } else {
                    Log.e(TAG, "Reconciliation failed: " + reason);
                }
            } catch (RuntimeException exception) {
                String message = "Reconciliation crashed (" + reason + "): "
                        + exception.getClass().getSimpleName();
                AllowedAppsStore.markApplyFailed(appContext, message);
                AuditLog.append(appContext, message);
                Log.e(TAG, message, exception);
            } finally {
                if (completion != null) {
                    completion.run();
                }
            }
        });
    }

    private static final class ReconciliationThreadFactory implements ThreadFactory {
        @Override
        public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, "lockdown-policy-reconciliation");
            thread.setDaemon(false);
            return thread;
        }
    }
}
