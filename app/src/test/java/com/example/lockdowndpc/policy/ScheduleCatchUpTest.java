package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Set;

/** A catch-up pass is due only when a boundary passed since the last pass, never for a schedule that restricts nothing. */
public final class ScheduleCatchUpTest {

    private static final ZoneId JERUSALEM = ZoneId.of("Asia/Jerusalem");

    private static Instant at(int year, int month, int day, int hour, int minute) {
        return ZonedDateTime.of(year, month, day, hour, minute, 0, 0, JERUSALEM).toInstant();
    }

    private static ScheduleSettings on() {
        return new ScheduleSettings(ScheduleSettings.defaultSchedule(JERUSALEM, true), Set.of(), false);
    }

    // 2026-11-22 is a Sunday: night 23:00-06:00 daily, work 09:00-17:00 Sunday to Thursday.

    @Test
    public void noPassIsDueBetweenBoundaries() {
        assertFalse(ScheduleCatchUp.due(on(), at(2026, 11, 22, 10, 0), at(2026, 11, 22, 16, 59)));
    }

    @Test
    public void aPassIsDueOnceAWindowStartWasMissed() {
        assertTrue(ScheduleCatchUp.due(on(), at(2026, 11, 22, 18, 0), at(2026, 11, 22, 23, 1)));
    }

    @Test
    public void aPassIsDueOnceAWindowEndWasMissed() {
        assertTrue(ScheduleCatchUp.due(on(), at(2026, 11, 22, 10, 0), at(2026, 11, 22, 17, 0)));
    }

    @Test
    public void anUnknownLastPassOrAClockMovedBackIsDue() {
        assertTrue(ScheduleCatchUp.due(on(), null, at(2026, 11, 22, 12, 0)));
        assertTrue(ScheduleCatchUp.due(on(), at(2026, 11, 22, 12, 0), at(2026, 11, 22, 11, 0)));
    }

    @Test
    public void aScheduleThatRestrictsNothingIsNeverDue() {
        ScheduleSettings disabled = on().withWindowsEnabled(false, JERUSALEM);
        assertFalse(ScheduleCatchUp.due(disabled, null, at(2026, 11, 22, 23, 30)));
        assertFalse(ScheduleCatchUp.due(ScheduleSettings.OFF, null, at(2026, 11, 22, 23, 30)));
        assertFalse(ScheduleCatchUp.due(null, null, at(2026, 11, 22, 23, 30)));
    }

    @Test
    public void theFailClosedNightWindowIsCaughtUpToo() {
        ScheduleSettings unreadable = ScheduleSettings.failClosed(JERUSALEM);
        assertTrue(ScheduleCatchUp.due(unreadable, at(2026, 11, 22, 22, 0), at(2026, 11, 22, 23, 5)));
        assertFalse(ScheduleCatchUp.due(unreadable, at(2026, 11, 22, 10, 0), at(2026, 11, 22, 17, 30)));
    }
}
