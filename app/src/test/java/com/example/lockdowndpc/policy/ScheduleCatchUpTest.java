package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Set;

/**
 * A catch-up pass is due only when a boundary passed since the last verified
 * pass and no retry backoff is pending, never for a schedule that restricts
 * nothing.
 */
public final class ScheduleCatchUpTest {

    private static final ZoneId JERUSALEM = ZoneId.of("Asia/Jerusalem");

    private static Instant at(int year, int month, int day, int hour, int minute) {
        return ZonedDateTime.of(year, month, day, hour, minute, 0, 0, JERUSALEM).toInstant();
    }

    private static ScheduleSettings on() {
        return new ScheduleSettings(ScheduleSettings.defaultSchedule(JERUSALEM, true), Set.of(), false);
    }

    private static ScheduleCatchUp.State verifiedAt(Instant at) {
        return ScheduleCatchUp.afterVerified(at);
    }

    // 2026-11-22 is a Sunday: night 23:00-06:00 daily, work 09:00-17:00 Sunday to Thursday.

    @Test
    public void noPassIsDueBetweenBoundaries() {
        assertFalse(ScheduleCatchUp.due(on(), verifiedAt(at(2026, 11, 22, 10, 0)), at(2026, 11, 22, 16, 59)));
    }

    @Test
    public void aPassIsDueOnceAWindowStartWasMissed() {
        assertTrue(ScheduleCatchUp.due(on(), verifiedAt(at(2026, 11, 22, 18, 0)), at(2026, 11, 22, 23, 1)));
    }

    @Test
    public void aPassIsDueOnceAWindowEndWasMissed() {
        assertTrue(ScheduleCatchUp.due(on(), verifiedAt(at(2026, 11, 22, 10, 0)), at(2026, 11, 22, 17, 0)));
    }

    @Test
    public void anUnknownLastPassOrAClockMovedBackIsDue() {
        assertTrue(ScheduleCatchUp.due(on(), ScheduleCatchUp.State.UNKNOWN, at(2026, 11, 22, 12, 0)));
        assertTrue(ScheduleCatchUp.due(on(), null, at(2026, 11, 22, 12, 0)));
        assertTrue(ScheduleCatchUp.due(on(), verifiedAt(at(2026, 11, 22, 12, 0)), at(2026, 11, 22, 11, 0)));
    }

    @Test
    public void aScheduleThatRestrictsNothingIsNeverDue() {
        ScheduleSettings disabled = on().withWindowsEnabled(false, JERUSALEM);
        assertFalse(ScheduleCatchUp.due(disabled, null, at(2026, 11, 22, 23, 30)));
        assertFalse(ScheduleCatchUp.due(ScheduleSettings.OFF, null, at(2026, 11, 22, 23, 30)));
        assertFalse(ScheduleCatchUp.due(null, null, at(2026, 11, 22, 23, 30)));
    }

    @Test
    public void theFailClosedScheduleIsCaughtUpForBothWindows() {
        ScheduleSettings unreadable = ScheduleSettings.failClosed(JERUSALEM);
        assertTrue(ScheduleCatchUp.due(unreadable, verifiedAt(at(2026, 11, 22, 22, 0)), at(2026, 11, 22, 23, 5)));
        assertTrue("work hours end", ScheduleCatchUp.due(unreadable,
                verifiedAt(at(2026, 11, 22, 10, 0)), at(2026, 11, 22, 17, 30)));
    }

    // --- Only a verified pass advances; a failed one is retried with backoff -----

    @Test
    public void aFailedPassDoesNotAdvanceTheInstantAMissedBoundaryIsMeasuredFrom() {
        Instant verified = at(2026, 11, 22, 18, 0);
        Instant failed = at(2026, 11, 22, 23, 1);
        ScheduleCatchUp.State state = ScheduleCatchUp.afterFailed(verifiedAt(verified), failed);
        assertEquals(verified, state.lastVerified());
        assertEquals(1, state.failedAttempts());
        assertEquals(failed.plus(ScheduleCatchUp.FIRST_RETRY), state.retryAt());
        // Held back during the backoff, due again once it has passed.
        assertFalse(ScheduleCatchUp.due(on(), state, failed.plusSeconds(30)));
        assertTrue(ScheduleCatchUp.due(on(), state, failed.plus(ScheduleCatchUp.FIRST_RETRY)));
        // The missed boundary stays missed until a pass is verified.
        assertTrue(ScheduleCatchUp.boundaryMissed(on(), state.lastVerified(), at(2026, 11, 22, 23, 30)));
    }

    @Test
    public void aVerifiedPassClearsTheBackoff() {
        ScheduleCatchUp.State failed = ScheduleCatchUp.afterFailed(
                ScheduleCatchUp.State.UNKNOWN, at(2026, 11, 22, 23, 1));
        ScheduleCatchUp.State verified = ScheduleCatchUp.afterVerified(at(2026, 11, 22, 23, 2));
        assertEquals(0, verified.failedAttempts());
        assertNull(verified.retryAt());
        assertTrue(failed.failedAttempts() > verified.failedAttempts());
        assertFalse(ScheduleCatchUp.due(on(), verified, at(2026, 11, 22, 23, 30)));
    }

    @Test
    public void theRetryDelayDoublesUpToTheSweepPeriod() {
        assertEquals(Duration.ofMinutes(1), ScheduleCatchUp.retryDelay(1));
        assertEquals(Duration.ofMinutes(2), ScheduleCatchUp.retryDelay(2));
        assertEquals(Duration.ofMinutes(4), ScheduleCatchUp.retryDelay(3));
        assertEquals(Duration.ofMinutes(8), ScheduleCatchUp.retryDelay(4));
        assertEquals(ScheduleCatchUp.MAX_RETRY, ScheduleCatchUp.retryDelay(5));
        assertEquals(ScheduleCatchUp.MAX_RETRY, ScheduleCatchUp.retryDelay(Integer.MAX_VALUE));
        assertEquals(ScheduleCatchUp.FIRST_RETRY, ScheduleCatchUp.retryDelay(0));
    }

    @Test
    public void repeatedFailuresBackOff() {
        Instant now = at(2026, 11, 22, 23, 1);
        ScheduleCatchUp.State state = ScheduleCatchUp.State.UNKNOWN;
        for (int i = 0; i < 10; i++) {
            state = ScheduleCatchUp.afterFailed(state, now);
        }
        assertEquals(10, state.failedAttempts());
        assertEquals(now.plus(ScheduleCatchUp.MAX_RETRY), state.retryAt());
    }

    @Test
    public void aRetryTimeFurtherAwayThanTheLongestDelayMeansTheClockMovedBack() {
        Instant now = at(2026, 11, 22, 23, 1);
        ScheduleCatchUp.State stale = new ScheduleCatchUp.State(null, 3, now.plus(Duration.ofHours(5)));
        assertTrue(ScheduleCatchUp.due(on(), stale, now));
    }
}
