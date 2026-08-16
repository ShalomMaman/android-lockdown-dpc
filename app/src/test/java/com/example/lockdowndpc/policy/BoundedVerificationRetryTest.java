package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.concurrent.atomic.AtomicInteger;

public final class BoundedVerificationRetryTest {
    @Test
    public void immediateSuccessDoesNotWait() {
        AtomicInteger probes = new AtomicInteger();
        AtomicInteger waits = new AtomicInteger();

        boolean verified = BoundedVerificationRetry.verify(
                20,
                () -> probes.incrementAndGet() == 1,
                waits::incrementAndGet
        );

        assertTrue(verified);
        assertEquals(1, probes.get());
        assertEquals(0, waits.get());
    }

    @Test
    public void delayedSuccessIsVerifiedWithinTheSamePass() {
        AtomicInteger probes = new AtomicInteger();
        AtomicInteger waits = new AtomicInteger();

        boolean verified = BoundedVerificationRetry.verify(
                20,
                () -> probes.incrementAndGet() == 3,
                waits::incrementAndGet
        );

        assertTrue(verified);
        assertEquals(3, probes.get());
        assertEquals(2, waits.get());
    }

    @Test
    public void exhaustedRetryRemainsFailed() {
        AtomicInteger probes = new AtomicInteger();
        AtomicInteger waits = new AtomicInteger();

        boolean verified = BoundedVerificationRetry.verify(
                4,
                () -> {
                    probes.incrementAndGet();
                    return false;
                },
                waits::incrementAndGet
        );

        assertFalse(verified);
        assertEquals(4, probes.get());
        assertEquals(3, waits.get());
    }

    @Test
    public void retryBudgetMustContainAtLeastOneProbe() {
        assertThrows(
                IllegalArgumentException.class,
                () -> BoundedVerificationRetry.verify(0, () -> true, () -> {})
        );
    }
}
