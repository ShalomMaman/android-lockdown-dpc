package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Covers the execution contract every lifecycle broadcast depends on: policy
 * work never runs on the caller's thread, requests stay serialized, and the
 * completion callback that finishes a broadcast's {@code PendingResult} always
 * runs.
 */
public final class PolicyReconciliationCoordinatorTest {
    private static final long TIMEOUT_SECONDS = 10L;

    @Test
    public void submittedWorkRunsOnThePolicyThreadNotTheCaller() throws Exception {
        CountDownLatch done = new CountDownLatch(1);
        AtomicReference<Thread> worker = new AtomicReference<>();

        PolicyReconciliationCoordinator.submit(() -> {
            worker.set(Thread.currentThread());
            done.countDown();
        });

        assertTrue(done.await(TIMEOUT_SECONDS, TimeUnit.SECONDS));
        assertNotEquals(Thread.currentThread(), worker.get());
        assertEquals("lockdown-policy-reconciliation", worker.get().getName());
    }

    @Test
    public void submittedWorkStaysSerializedInOrder() throws Exception {
        List<String> order = new CopyOnWriteArrayList<>();
        CountDownLatch done = new CountDownLatch(3);

        for (String reason : List.of("boot", "replace", "admin")) {
            PolicyReconciliationCoordinator.submit(() -> {
                order.add(reason);
                done.countDown();
            });
        }

        assertTrue(done.await(TIMEOUT_SECONDS, TimeUnit.SECONDS));
        assertEquals(List.of("boot", "replace", "admin"), order);
    }

    @Test
    public void completionRunsAfterSuccessfulWork() {
        AtomicBoolean worked = new AtomicBoolean();
        AtomicBoolean finished = new AtomicBoolean();

        PolicyReconciliationCoordinator.runGuarded(
                () -> true,
                () -> worked.set(true),
                exception -> {
                    throw new AssertionError("unexpected crash handling", exception);
                },
                () -> finished.set(true)
        );

        assertTrue(worked.get());
        assertTrue(finished.get());
    }

    @Test
    public void completionRunsWhenTheGuardSkipsTheWork() {
        AtomicBoolean worked = new AtomicBoolean();
        AtomicBoolean finished = new AtomicBoolean();

        PolicyReconciliationCoordinator.runGuarded(
                () -> false,
                () -> worked.set(true),
                exception -> {
                    throw new AssertionError("unexpected crash handling", exception);
                },
                () -> finished.set(true)
        );

        assertFalse(worked.get());
        assertTrue(finished.get());
    }

    @Test
    public void crashingWorkIsRecordedAndStillCompletes() {
        RuntimeException failure = new IllegalStateException("policy exploded");
        AtomicReference<RuntimeException> recorded = new AtomicReference<>();
        AtomicBoolean finished = new AtomicBoolean();

        PolicyReconciliationCoordinator.runGuarded(
                () -> true,
                () -> {
                    throw failure;
                },
                recorded::set,
                () -> finished.set(true)
        );

        assertEquals(failure, recorded.get());
        assertTrue(finished.get());
    }

    @Test
    public void crashingGuardStillCompletes() {
        AtomicBoolean finished = new AtomicBoolean();
        AtomicReference<RuntimeException> recorded = new AtomicReference<>();

        PolicyReconciliationCoordinator.runGuarded(
                () -> {
                    throw new IllegalStateException("preferences unavailable");
                },
                () -> {
                    throw new AssertionError("work must not run when the guard fails");
                },
                recorded::set,
                () -> finished.set(true)
        );

        assertTrue(recorded.get() instanceof IllegalStateException);
        assertTrue(finished.get());
    }

    @Test
    public void missingCompletionIsTolerated() {
        AtomicBoolean worked = new AtomicBoolean();

        PolicyReconciliationCoordinator.runGuarded(
                () -> true,
                () -> worked.set(true),
                exception -> {
                    throw new AssertionError("unexpected crash handling", exception);
                },
                null
        );

        assertTrue(worked.get());
    }

    @Test
    public void verifiedCompletionReportsWorkFailure() {
        AtomicReference<Boolean> verified = new AtomicReference<>();

        PolicyReconciliationCoordinator.runGuardedVerified(
                () -> true,
                () -> false,
                exception -> { throw new AssertionError(exception); },
                verified::set
        );

        assertFalse(verified.get());
    }

    @Test
    public void verifiedCompletionReportsCrashAsFailure() {
        AtomicReference<Boolean> verified = new AtomicReference<>();
        AtomicReference<RuntimeException> recorded = new AtomicReference<>();

        PolicyReconciliationCoordinator.runGuardedVerified(
                () -> true,
                () -> { throw new IllegalStateException("boom"); },
                recorded::set,
                verified::set
        );

        assertTrue(recorded.get() instanceof IllegalStateException);
        assertFalse(verified.get());
    }

    @Test
    public void skippedVerifiedWorkDoesNotClaimSuccess() {
        AtomicReference<Boolean> verified = new AtomicReference<>();

        PolicyReconciliationCoordinator.runGuardedVerified(
                () -> false,
                () -> { throw new AssertionError("must not run"); },
                exception -> { throw new AssertionError(exception); },
                verified::set
        );

        assertFalse(verified.get());
    }
}
