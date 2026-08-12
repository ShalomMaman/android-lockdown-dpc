package com.example.lockdowndpc.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.security.PinLockoutPolicy.BootId;
import com.example.lockdowndpc.security.PinLockoutPolicy.BootKind;
import com.example.lockdowndpc.security.PinLockoutPolicy.Evaluation;
import com.example.lockdowndpc.security.PinLockoutPolicy.LockoutState;

import org.junit.Test;

public final class PinLockoutPolicyTest {
    private static final long WALL = 1_700_000_000_000L;
    private static final long MINUTE = 60_000L;
    private static final BootId BOOT = BootId.ofBootCount(41);
    private static final BootId NEXT_BOOT = BootId.ofBootCount(42);

    /** Fails five times so the first penalty is armed. */
    private static LockoutState lockedOut(long elapsedRealtime, long wallMillis) {
        LockoutState state = LockoutState.CLEARED;
        for (int attempt = 0; attempt < 5; attempt++) {
            state = PinLockoutPolicy.afterFailure(state, BOOT, elapsedRealtime, wallMillis);
        }
        return state;
    }

    @Test
    public void fifthFailureArmsTheFirstPenaltyOnTheCurrentBoot() {
        LockoutState state = lockedOut(10_000L, WALL);

        assertEquals(5, state.failures());
        assertEquals(MINUTE, state.penaltyMillis());
        assertTrue(state.penaltyArmed());
        assertEquals(BOOT, state.armedBoot());
        assertEquals(10_000L + MINUTE, state.armedElapsedDeadline());
        assertEquals(WALL + MINUTE, state.wallDeadline());
    }

    @Test
    public void earlyFailuresDoNotArmAPenalty() {
        LockoutState state = LockoutState.CLEARED;
        for (int attempt = 1; attempt <= 4; attempt++) {
            state = PinLockoutPolicy.afterFailure(state, BOOT, 10_000L, WALL);
            assertEquals(attempt, state.failures());
            assertEquals(0L, state.penaltyMillis());
            assertFalse(state.penaltyArmed());
        }

        Evaluation evaluation = PinLockoutPolicy.evaluate(state, BOOT, 10_000L, WALL);
        assertFalse(evaluation.locked());
        assertFalse(evaluation.persistRequired());
    }

    /** The reported bypass: move the wall clock forward past the deadline. */
    @Test
    public void wallClockJumpForwardDoesNotShortenAnActiveLockout() {
        LockoutState state = lockedOut(10_000L, WALL);

        Evaluation evaluation = PinLockoutPolicy.evaluate(
                state, BOOT, 11_000L, WALL + (24 * 60 * MINUTE));

        assertTrue(evaluation.locked());
        assertEquals(MINUTE - 1_000L, evaluation.remainingMillis());
        assertFalse(evaluation.persistRequired());
    }

    @Test
    public void wallClockJumpBackwardDoesNotChangeAnActiveLockout() {
        LockoutState state = lockedOut(10_000L, WALL);

        Evaluation evaluation = PinLockoutPolicy.evaluate(
                state, BOOT, 11_000L, WALL - (24 * 60 * MINUTE));

        assertTrue(evaluation.locked());
        assertEquals(MINUTE - 1_000L, evaluation.remainingMillis());
    }

    @Test
    public void monotonicTimeRetiresTheLockoutAndKeepsTheFailureCount() {
        LockoutState state = lockedOut(10_000L, WALL);

        Evaluation evaluation = PinLockoutPolicy.evaluate(
                state, BOOT, 10_000L + MINUTE, WALL + MINUTE);

        assertFalse(evaluation.locked());
        assertTrue(evaluation.persistRequired());
        assertFalse(evaluation.state().penaltyArmed());
        assertEquals(5, evaluation.state().failures());
        assertEquals(0L, evaluation.state().wallDeadline());
    }

    @Test
    public void rebootReArmsAnUnservedPenaltyInsteadOfClearingIt() {
        LockoutState state = lockedOut(10_000L, WALL);

        // Monotonic time restarts at reboot; the wall clock has also moved past
        // the old deadline.
        Evaluation evaluation = PinLockoutPolicy.evaluate(
                state, NEXT_BOOT, 4_000L, WALL + (10 * MINUTE));

        assertTrue(evaluation.locked());
        assertEquals(MINUTE, evaluation.remainingMillis());
        assertTrue(evaluation.persistRequired());
        assertEquals(NEXT_BOOT, evaluation.state().armedBoot());
        assertEquals(4_000L + MINUTE, evaluation.state().armedElapsedDeadline());
        assertEquals(5, evaluation.state().failures());
    }

    @Test
    public void rebootReArmsWithTheFullPenaltyForTheRecordedFailureCount() {
        LockoutState state = LockoutState.CLEARED;
        for (int attempt = 0; attempt < 7; attempt++) {
            state = PinLockoutPolicy.afterFailure(state, BOOT, 10_000L, WALL);
        }
        // Truncated stored duration must not be able to shorten the re-arm.
        LockoutState tampered = new LockoutState(
                state.failures(), BOOT, state.armedElapsedDeadline(), 1L, state.wallDeadline());

        Evaluation evaluation = PinLockoutPolicy.evaluate(tampered, NEXT_BOOT, 4_000L, WALL);

        assertEquals(30 * MINUTE, evaluation.remainingMillis());
    }

    @Test
    public void servedPenaltyIsNotReArmedByALaterReboot() {
        LockoutState state = lockedOut(10_000L, WALL);
        // The administrator waited it out and made an attempt, which persists the
        // penalty-free state.
        LockoutState served = PinLockoutPolicy
                .evaluate(state, BOOT, 10_000L + MINUTE, WALL + MINUTE)
                .state();

        Evaluation afterReboot = PinLockoutPolicy.evaluate(served, NEXT_BOOT, 3_000L, WALL);

        assertFalse(afterReboot.locked());
        assertFalse(afterReboot.persistRequired());
        assertEquals(5, afterReboot.state().failures());
    }

    @Test
    public void legacyWallOnlyStateMigratesToMonotonicTime() {
        LockoutState legacy = new LockoutState(6, BootId.UNKNOWN, 0L, 0L, WALL + (3 * MINUTE));

        Evaluation migration = PinLockoutPolicy.evaluate(legacy, BOOT, 20_000L, WALL);

        assertTrue(migration.locked());
        assertEquals(3 * MINUTE, migration.remainingMillis());
        assertTrue(migration.persistRequired());
        assertEquals(BOOT, migration.state().armedBoot());
        assertEquals(20_000L + (3 * MINUTE), migration.state().armedElapsedDeadline());
        assertEquals(6, migration.state().failures());

        // Once migrated, the wall clock can no longer shorten it.
        Evaluation afterClockJump = PinLockoutPolicy.evaluate(
                migration.state(), BOOT, 21_000L, WALL + (24 * 60 * MINUTE));
        assertTrue(afterClockJump.locked());
        assertEquals((3 * MINUTE) - 1_000L, afterClockJump.remainingMillis());
    }

    /**
     * Documents the behaviour this policy replaces, and the single window that
     * remains: state written before the upgrade is still wall-clock only, so a
     * clock jump made before the first evaluation retires it. Everything armed
     * afterwards is measured with monotonic time.
     */
    @Test
    public void unmigratedLegacyStateIsStillRetiredByAClockJump() {
        LockoutState legacy = new LockoutState(5, BootId.UNKNOWN, 0L, 0L, WALL + MINUTE);

        Evaluation evaluation = PinLockoutPolicy.evaluate(
                legacy, BOOT, 10_000L, WALL + (10 * MINUTE));

        assertFalse(evaluation.locked());
        assertEquals(5, evaluation.state().failures());
    }

    @Test
    public void legacyDeadlineIsClampedToTheLongestPenalty() {
        LockoutState legacy = new LockoutState(
                8, BootId.UNKNOWN, 0L, 0L, WALL + (365L * 24 * 60 * MINUTE));

        Evaluation evaluation = PinLockoutPolicy.evaluate(legacy, BOOT, 20_000L, WALL);

        assertEquals(PinLockoutPolicy.MAX_PENALTY_MILLIS, evaluation.remainingMillis());
    }

    @Test
    public void expiredLegacyStateClearsThePenaltyAndKeepsTheFailureCount() {
        LockoutState legacy = new LockoutState(6, BootId.UNKNOWN, 0L, 0L, WALL - MINUTE);

        Evaluation evaluation = PinLockoutPolicy.evaluate(legacy, BOOT, 20_000L, WALL);

        assertFalse(evaluation.locked());
        assertTrue(evaluation.persistRequired());
        assertEquals(0L, evaluation.state().wallDeadline());
        assertEquals(6, evaluation.state().failures());
    }

    @Test
    public void penaltiesStayProgressiveAcrossExpiry() {
        LockoutState state = lockedOut(10_000L, WALL);
        long elapsed = 10_000L;
        long[] expected = {5 * MINUTE, 30 * MINUTE, 60 * MINUTE, 60 * MINUTE};

        for (long penalty : expected) {
            // Serve the current penalty, then fail once more.
            elapsed += PinLockoutPolicy.MAX_PENALTY_MILLIS;
            state = PinLockoutPolicy.evaluate(state, BOOT, elapsed, WALL).state();
            state = PinLockoutPolicy.afterFailure(state, BOOT, elapsed, WALL);
            assertEquals(penalty, state.penaltyMillis());
        }
        assertEquals(9, state.failures());
    }

    @Test
    public void resetStateStartsTheLadderOver() {
        // A successful verification stores LockoutState.CLEARED.
        assertEquals(0, LockoutState.CLEARED.failures());
        assertFalse(LockoutState.CLEARED.penaltyArmed());
        assertEquals(0L, LockoutState.CLEARED.wallDeadline());

        Evaluation evaluation = PinLockoutPolicy.evaluate(
                LockoutState.CLEARED, BOOT, 500L, WALL);
        assertFalse(evaluation.locked());
        assertFalse(evaluation.persistRequired());

        LockoutState next = PinLockoutPolicy.afterFailure(
                LockoutState.CLEARED, BOOT, 500L, WALL);
        assertEquals(1, next.failures());
        assertEquals(0L, next.penaltyMillis());
    }

    @Test
    public void absurdDeadlineStaysLockedButIsCappedSoItCannotBrickTheAdministrator() {
        LockoutState corrupt = new LockoutState(
                5, BOOT, Long.MAX_VALUE, 10L * PinLockoutPolicy.MAX_PENALTY_MILLIS, 0L);

        Evaluation evaluation = PinLockoutPolicy.evaluate(corrupt, BOOT, 10_000L, WALL);

        assertTrue(evaluation.locked());
        assertEquals(PinLockoutPolicy.MAX_PENALTY_MILLIS, evaluation.remainingMillis());
        assertEquals(10_000L + PinLockoutPolicy.MAX_PENALTY_MILLIS,
                evaluation.state().armedElapsedDeadline());
    }

    @Test
    public void armedPenaltyWithoutAUsableDeadlineIsReArmed() {
        LockoutState corrupt = new LockoutState(6, BOOT, 0L, 5 * MINUTE, 0L);

        Evaluation evaluation = PinLockoutPolicy.evaluate(corrupt, BOOT, 10_000L, WALL);

        assertTrue(evaluation.locked());
        assertEquals(5 * MINUTE, evaluation.remainingMillis());
        assertTrue(evaluation.persistRequired());
    }

    @Test
    public void bootWallFallbackToleratesJitterButTreatsAClockChangeAsAReboot() {
        BootId sampled = BootId.ofBootWallTime(WALL - 30_000L);
        LockoutState state = PinLockoutPolicy.afterFailure(
                new LockoutState(4, BootId.UNKNOWN, 0L, 0L, 0L), sampled, 30_000L, WALL);

        Evaluation sameBoot = PinLockoutPolicy.evaluate(
                state, BootId.ofBootWallTime(WALL - 30_000L + 900L), 31_000L, WALL);
        assertEquals(MINUTE - 1_000L, sameBoot.remainingMillis());

        // Moving the clock changes the derived boot start, which re-arms.
        Evaluation afterClockChange = PinLockoutPolicy.evaluate(
                state, BootId.ofBootWallTime(WALL + (60 * MINUTE)), 31_000L, WALL + (60 * MINUTE));
        assertEquals(MINUTE, afterClockChange.remainingMillis());
        assertTrue(afterClockChange.persistRequired());
    }

    @Test
    public void unknownBootIdentityFallsBackToTheWallDeadlineInsteadOfUnlocking() {
        LockoutState state = PinLockoutPolicy.afterFailure(
                new LockoutState(4, BootId.UNKNOWN, 0L, 0L, 0L), BootId.UNKNOWN, 30_000L, WALL);

        assertEquals(BootKind.NONE, state.armedBoot().kind());
        assertEquals(WALL + MINUTE, state.wallDeadline());

        Evaluation evaluation = PinLockoutPolicy.evaluate(
                state, BootId.UNKNOWN, 31_000L, WALL + 1_000L);
        assertTrue(evaluation.locked());
        assertEquals(MINUTE - 1_000L, evaluation.remainingMillis());
    }

    @Test
    public void penaltyLadderMatchesTheDocumentedTiers() {
        assertEquals(0L, PinLockoutPolicy.penaltyMillis(0));
        assertEquals(0L, PinLockoutPolicy.penaltyMillis(4));
        assertEquals(MINUTE, PinLockoutPolicy.penaltyMillis(5));
        assertEquals(5 * MINUTE, PinLockoutPolicy.penaltyMillis(6));
        assertEquals(30 * MINUTE, PinLockoutPolicy.penaltyMillis(7));
        assertEquals(60 * MINUTE, PinLockoutPolicy.penaltyMillis(8));
        assertEquals(60 * MINUTE, PinLockoutPolicy.penaltyMillis(Integer.MAX_VALUE));
    }
}
