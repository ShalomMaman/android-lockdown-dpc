package com.example.lockdowndpc.policy;

import android.content.Context;
import android.util.Log;

import com.example.lockdowndpc.kiosk.KioskConfigStore;
import com.example.lockdowndpc.kiosk.KioskController;
import com.example.lockdowndpc.kiosk.KioskStateMachine.KioskState;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.FutureTask;
import java.util.concurrent.ThreadFactory;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Supplier;

/** Serializes background reconciliation requests from DPC lifecycle events. */
public final class PolicyReconciliationCoordinator {
    private static final String TAG = "PolicyReconciliation";
    static final String THREAD_NAME = "lockdown-policy-reconciliation";
    private static final ExecutorService EXECUTOR = Executors.newSingleThreadExecutor(
            new ReconciliationThreadFactory()
    );

    private PolicyReconciliationCoordinator() {}

    /**
     * Runs policy work on the one thread that is allowed to drive
     * {@code DevicePolicyManager}.
     *
     * <p>Exposed so maintenance-mode passes queue behind reconciliation instead
     * of racing it. Two threads writing the same user restrictions is how a
     * device ends up in a state neither of them believes it is in: a restore that
     * interleaves with a reconciliation pass could read back the other's write
     * and report a verified result for a policy it did not apply.
     */
    public static void runOnPolicyThread(Runnable work) {
        EXECUTOR.execute(work);
    }

    /**
     * Runs result-bearing device-policy work on the one policy thread and waits
     * for its verified result.
     *
     * <p>Console actions need a result to render, but using an arbitrary IO
     * dispatcher lets them interleave with maintenance expiry and lifecycle
     * reconciliation. That can make a restore verify and clear its debt just
     * before the console re-applies a stale relaxation. This method preserves
     * the synchronous result contract while putting every writer in the same
     * FIFO queue. Re-entrant calls from the policy thread run directly to avoid
     * self-deadlock.
     */
    public static <T> T callOnPolicyThread(Supplier<T> work) {
        if (Thread.currentThread() == ReconciliationThreadFactory.policyThread) {
            return work.get();
        }
        FutureTask<T> task = new FutureTask<>(work::get);
        EXECUTOR.execute(task);
        try {
            return task.get();
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for policy work", exception);
        } catch (ExecutionException exception) {
            Throwable cause = exception.getCause();
            if (cause instanceof RuntimeException runtimeException) {
                throw runtimeException;
            }
            if (cause instanceof Error error) {
                throw error;
            }
            throw new IllegalStateException("Policy work failed", cause);
        }
    }

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
        reconcileAsyncVerified(context, reason, verified -> {
            if (completion != null) {
                completion.run();
            }
        });
    }

    /** Reconciles and reports whether the complete policy pass was verified. */
    public static void reconcileAsyncVerified(
            Context context,
            String reason,
            Consumer<Boolean> completion
    ) {
        Context appContext = context.getApplicationContext();
        submit(() -> runGuardedVerified(
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
                    // Recorded, not just logged: an unattended pass is the only
                    // evidence a device has that it is still enforcing what it
                    // was told to, and the health report reads it back.
                    ReconciliationRecord.record(
                            appContext,
                            result.applied()
                                    ? ReconciliationRecord.Outcome.VERIFIED
                                    : ReconciliationRecord.Outcome.FAILED,
                            reason,
                            result.applied() ? "" : summarize(result));
                    if (result.applied()) {
                        Log.i(TAG, "Reconciliation verified: " + reason);
                    } else {
                        Log.e(TAG, "Reconciliation failed: " + reason);
                    }
                    return result.applied();
                },
                exception -> {
                    String message = "Reconciliation crashed (" + reason + "): "
                            + exception.getClass().getSimpleName();
                    ReconciliationRecord.record(
                            appContext,
                            ReconciliationRecord.Outcome.CRASHED,
                            reason,
                            exception.getClass().getSimpleName());
                    AllowedAppsStore.markApplyFailed(appContext, message);
                    AuditLog.append(appContext, message);
                    Log.e(TAG, message, exception);
                },
                completion
        ));
    }

    /** The failure summary, as machine tokens rather than prose. */
    private static String summarize(LockdownPolicyController.PolicyResult result) {
        return String.join(",", result.errors());
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

    /**
     * Re-asserts an already-active kiosk after a reboot or an app update.
     *
     * <p>Runs on the same single policy thread as every other reconciliation, so
     * a broadcast receiver never performs lock-task, HOME-preference or package
     * work inline. {@code KioskController.restoreAfterBootOnce} is
     * one-directional and unauthenticated by design: it can only re-assert a
     * state that was persisted as {@code ACTIVE}, so this can never turn kiosk
     * on, off, or into a different profile — a reboot is neither a way in nor a
     * way out.
     *
     * <p>Queued <em>before</em> the ordinary apply/pause pass so lock task and
     * the kiosk HOME preference are back in place before the package sweep runs.
     * The full policy pass {@code restoreAfterBootOnce} queues for itself lands
     * after both, which is harmless because every pass is idempotent.
     */
    public static void restoreKioskAsync(Context context, String reason) {
        Context appContext = context.getApplicationContext();
        submit(() -> runGuarded(
                () -> KioskConfigStore.readState(appContext) == KioskState.ACTIVE,
                () -> {
                    KioskController.Result result =
                            KioskController.restoreAfterBootOnce(appContext);
                    if (result.allowed()) {
                        Log.i(TAG, "Kiosk restored (" + reason + "): " + result.reason());
                    } else {
                        Log.e(TAG, "Kiosk restore refused (" + reason + "): " + result.reason());
                    }
                },
                exception -> {
                    String message = "Kiosk restore crashed (" + reason + "): "
                            + exception.getClass().getSimpleName();
                    AuditLog.append(appContext, message);
                    Log.e(TAG, message, exception);
                },
                null
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

    /** Result-bearing counterpart for callers that distinguish completion from success. */
    static void runGuardedVerified(
            BooleanSupplier shouldRun,
            Supplier<Boolean> work,
            Consumer<RuntimeException> crashHandler,
            Consumer<Boolean> completion
    ) {
        boolean verified = false;
        try {
            verified = shouldRun.getAsBoolean() && Boolean.TRUE.equals(work.get());
        } catch (RuntimeException exception) {
            crashHandler.accept(exception);
        } finally {
            if (completion != null) {
                completion.accept(verified);
            }
        }
    }

    private static final class ReconciliationThreadFactory implements ThreadFactory {
        private static volatile Thread policyThread;

        @Override
        public Thread newThread(Runnable runnable) {
            Thread thread = new Thread(runnable, THREAD_NAME);
            thread.setDaemon(false);
            policyThread = thread;
            return thread;
        }
    }
}
