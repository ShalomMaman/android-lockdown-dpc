package com.example.lockdowndpc.policy;

import android.content.Context;
import android.util.Log;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/** Serializes background reconciliation requests from DPC lifecycle events. */
public final class PolicyReconciliationCoordinator {
    private static final String TAG = "PolicyReconciliation";
    static final String THREAD_NAME = "lockdown-policy-reconciliation";
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
        submit(() -> runGuarded(
                () -> {
                    if (!AllowedAppsStore.isProtectionEnabled(appContext)) {
                        Log.i(TAG, "Skipping reconciliation while protection is paused: " + reason);
                        return false;
                    }
                    return true;
                },
                () -> {
                    LockdownPolicyController.PolicyResult result =
                            LockdownPolicyController.apply(appContext);
                    if (result.applied()) {
                        Log.i(TAG, "Reconciliation verified: " + reason);
                    } else {
                        Log.e(TAG, "Reconciliation failed: " + reason);
                    }
                },
                exception -> {
                    String message = "Reconciliation crashed (" + reason + "): "
                            + exception.getClass().getSimpleName();
                    AllowedAppsStore.markApplyFailed(appContext, message);
                    AuditLog.append(appContext, message);
                    Log.e(TAG, message, exception);
                },
                completion
        ));
    }

    /**
     * Restores managed packages after a lifecycle event while protection is paused.
     *
     * <p>Like {@link #reconcileAsync}, this runs on the shared policy executor.
     * {@link LockdownPolicyController#pause} enumerates every installed package
     * and performs many {@code DevicePolicyManager} calls, which must never
     * happen on the broadcast thread.
     */
    public static void pauseAsync(
            Context context,
            String reason,
            Runnable completion
    ) {
        Context appContext = context.getApplicationContext();
        submit(() -> runGuarded(
                () -> {
                    if (AllowedAppsStore.isProtectionEnabled(appContext)) {
                        Log.i(TAG, "Skipping pause reconciliation while protection is active: "
                                + reason);
                        return false;
                    }
                    return true;
                },
                () -> {
                    LockdownPolicyController.PolicyResult result =
                            LockdownPolicyController.pause(appContext);
                    if (result.applied()) {
                        Log.i(TAG, "Pause reconciliation verified: " + reason);
                    } else {
                        Log.e(TAG, "Pause reconciliation failed: " + reason);
                    }
                },
                exception -> {
                    String message = "Pause reconciliation crashed (" + reason + "): "
                            + exception.getClass().getSimpleName();
                    AllowedAppsStore.markPauseFailed(appContext, message);
                    AuditLog.append(appContext, message);
                    Log.e(TAG, message, exception);
                },
                completion
        ));
    }

    /** Queues work on the single policy thread, preserving submission order. */
    static void submit(Runnable task) {
        EXECUTOR.execute(task);
    }

    /**
     * Runs reconciliation work with the guarantees every caller depends on: the
     * work is skipped when the current protection state no longer matches, a
     * crash is recorded instead of killing the queue silently, and
     * {@code completion} always runs so a broadcast's {@code PendingResult} is
     * finished exactly once.
     */
    static void runGuarded(
            BooleanSupplier shouldRun,
            Runnable work,
            Consumer<RuntimeException> crashHandler,
            Runnable completion
    ) {
        try {
            if (shouldRun.getAsBoolean()) {
                work.run();
            }
        } catch (RuntimeException exception) {
            crashHandler.accept(exception);
        } finally {
            if (completion != null) {
                completion.run();
            }
        }
    }

    private static final class ReconciliationThreadFactory implements ThreadFactory {
        @Override
        public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, THREAD_NAME);
            thread.setDaemon(false);
            return thread;
        }
    }
}
