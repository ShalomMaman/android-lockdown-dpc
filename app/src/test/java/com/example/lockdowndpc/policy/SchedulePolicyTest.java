package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.policy.SchedulePolicy.Change;
import com.example.lockdowndpc.policy.SchedulePolicy.Schedule;
import com.example.lockdowndpc.policy.SchedulePolicy.Window;

import org.junit.Test;

import java.time.DayOfWeek;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.zone.ZoneOffsetTransition;
import java.time.zone.ZoneRules;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Pure JVM tests for {@link SchedulePolicy} covering schema parsing, boundary evaluation,
 * day-of-week and midnight ownership, 2026 Asia/Jerusalem DST transitions, next transition,
 * and tightening vs. loosening classification.
 */
public final class SchedulePolicyTest {

    private static final ZoneId JERUSALEM = ZoneId.of("Asia/Jerusalem");
    private static final ZoneId UTC = ZoneId.of("UTC");

    private static final String SHARED_JSON = """
            {
              "timezone": "Asia/Jerusalem",
              "night": { "enabled": true, "days": "daily", "start": "23:00", "end": "06:00" },
              "work":  { "enabled": true, "days": "sun-thu", "start": "09:00", "end": "17:00" }
            }
            """;

    // -------------------------------------------------------- schema & round-trip

    @Test
    public void parsesExactSharedJsonAndRoundTripsWithStableKeyOrder() {
        Schedule parsed = SchedulePolicy.parse(SHARED_JSON);

        assertEquals(JERUSALEM, parsed.timezone());
        assertEquals(
                new Window(true, EnumSet.allOf(DayOfWeek.class), LocalTime.of(23, 0), LocalTime.of(6, 0)),
                parsed.night());
        assertEquals(
                new Window(true,
                        EnumSet.of(DayOfWeek.SUNDAY, DayOfWeek.MONDAY, DayOfWeek.TUESDAY,
                                DayOfWeek.WEDNESDAY, DayOfWeek.THURSDAY),
                        LocalTime.of(9, 0), LocalTime.of(17, 0)),
                parsed.work());

        String canonical = SchedulePolicy.toJson(parsed);
        assertEquals(
                "{\"timezone\":\"Asia/Jerusalem\","
                        + "\"night\":{\"enabled\":true,\"days\":\"daily\",\"start\":\"23:00\",\"end\":\"06:00\"},"
                        + "\"work\":{\"enabled\":true,\"days\":\"sun-thu\",\"start\":\"09:00\",\"end\":\"17:00\"}}",
                canonical);
        assertEquals(parsed, SchedulePolicy.parse(canonical));
    }

    @Test
    public void supportsOptionalWindowsAndExplicitDayLists() {
        Schedule empty = SchedulePolicy.parse("{\"timezone\":\"Asia/Jerusalem\"}");
        assertEquals(JERUSALEM, empty.timezone());
        assertNull(empty.night());
        assertNull(empty.work());
        assertFalse(empty.hasEnabledWindow());
        assertEquals("{\"timezone\":\"Asia/Jerusalem\"}", SchedulePolicy.toJson(empty));

        Schedule explicit = SchedulePolicy.parse("""
                {
                  "timezone": "Asia/Jerusalem",
                  "work": { "enabled": true, "days": "tue,thu", "start": "09:00", "end": "17:00" }
                }
                """);
        assertNull(explicit.night());
        assertEquals(Set.of(DayOfWeek.TUESDAY, DayOfWeek.THURSDAY), explicit.work().days());
        assertEquals(
                "{\"timezone\":\"Asia/Jerusalem\","
                        + "\"work\":{\"enabled\":true,\"days\":\"tue,thu\",\"start\":\"09:00\",\"end\":\"17:00\"}}",
                SchedulePolicy.toJson(explicit));
        assertEquals(explicit, SchedulePolicy.parse(SchedulePolicy.toJson(explicit)));
    }

    @Test
    public void rejectsMalformedJsonNullBlocksUnknownKeysAndInvalidFields() {
        List<String> invalidPayloads = List.of(
                "",
                "   ",
                "[]",
                "123",
                "{\"timezone\":\"Asia/Jerusalem\"} trailing",
                "{}",
                "{\"timezone\":null}",
                "{\"timezone\":123}",
                "{\"timezone\":\"\"}",
                "{\"timezone\":\" Asia/Jerusalem\"}",
                "{\"timezone\":\"Mars/Olympus\"}",
                "{\"timezone\":\"Asia/Jerusalem\",\"extra\":{}}",
                "{\"timezone\":\"Asia/Jerusalem\",\"night\":null}",
                "{\"timezone\":\"Asia/Jerusalem\",\"work\":null}",
                "{\"timezone\":\"Asia/Jerusalem\",\"night\":\"daily\"}",
                "{\"timezone\":\"Asia/Jerusalem\",\"night\":{\"enabled\":true,\"days\":\"daily\",\"start\":\"23:00\",\"end\":\"06:00\",\"extra\":1}}",
                "{\"timezone\":\"Asia/Jerusalem\",\"night\":{\"days\":\"daily\",\"start\":\"23:00\",\"end\":\"06:00\"}}",
                "{\"timezone\":\"Asia/Jerusalem\",\"night\":{\"enabled\":null,\"days\":\"daily\",\"start\":\"23:00\",\"end\":\"06:00\"}}",
                "{\"timezone\":\"Asia/Jerusalem\",\"night\":{\"enabled\":\"true\",\"days\":\"daily\",\"start\":\"23:00\",\"end\":\"06:00\"}}",
                "{\"timezone\":\"Asia/Jerusalem\",\"night\":{\"enabled\":true,\"days\":null,\"start\":\"23:00\",\"end\":\"06:00\"}}",
                "{\"timezone\":\"Asia/Jerusalem\",\"night\":{\"enabled\":true,\"days\":\"daily\",\"start\":null,\"end\":\"06:00\"}}",
                "{\"timezone\":\"Asia/Jerusalem\",\"night\":{\"enabled\":true,\"days\":\"daily\",\"start\":\"23:00\",\"end\":null}}",
                "{\"timezone\":\"Asia/Jerusalem\",\"night\":{\"enabled\":true,\"days\":\"daily\",\"start\":\"9:00\",\"end\":\"06:00\"}}",
                "{\"timezone\":\"Asia/Jerusalem\",\"night\":{\"enabled\":true,\"days\":\"daily\",\"start\":\"23:00:00\",\"end\":\"06:00\"}}",
                "{\"timezone\":\"Asia/Jerusalem\",\"night\":{\"enabled\":true,\"days\":\"daily\",\"start\":\"24:00\",\"end\":\"06:00\"}}",
                "{\"timezone\":\"Asia/Jerusalem\",\"night\":{\"enabled\":true,\"days\":\"daily\",\"start\":\"23:60\",\"end\":\"06:00\"}}",
                "{\"timezone\":\"Asia/Jerusalem\",\"night\":{\"enabled\":true,\"days\":\"daily\",\"start\":\"ab:cd\",\"end\":\"06:00\"}}",
                "{\"timezone\":\"Asia/Jerusalem\",\"night\":{\"enabled\":true,\"days\":\"daily\",\"start\":\"23:00\",\"end\":\"23:00\"}}",
                "{\"timezone\":\"Asia/Jerusalem\",\"night\":{\"enabled\":true,\"days\":\"\",\"start\":\"23:00\",\"end\":\"06:00\"}}",
                "{\"timezone\":\"Asia/Jerusalem\",\"night\":{\"enabled\":true,\"days\":\"DAILY\",\"start\":\"23:00\",\"end\":\"06:00\"}}",
                "{\"timezone\":\"Asia/Jerusalem\",\"night\":{\"enabled\":true,\"days\":\"mon-fri\",\"start\":\"23:00\",\"end\":\"06:00\"}}",
                "{\"timezone\":\"Asia/Jerusalem\",\"night\":{\"enabled\":true,\"days\":\"weekdays\",\"start\":\"23:00\",\"end\":\"06:00\"}}",
                "{\"timezone\":\"Asia/Jerusalem\",\"night\":{\"enabled\":true,\"days\":\"Sun\",\"start\":\"23:00\",\"end\":\"06:00\"}}",
                "{\"timezone\":\"Asia/Jerusalem\",\"night\":{\"enabled\":true,\"days\":\"mon,mon\",\"start\":\"23:00\",\"end\":\"06:00\"}}",
                "{\"timezone\":\"Asia/Jerusalem\",\"night\":{\"enabled\":true,\"days\":\"mon,\",\"start\":\"23:00\",\"end\":\"06:00\"}}",
                "{\"timezone\":\"Asia/Jerusalem\",\"night\":{\"enabled\":true,\"days\":\",mon\",\"start\":\"23:00\",\"end\":\"06:00\"}}",
                "{\"timezone\":\"Asia/Jerusalem\",\"night\":{\"enabled\":true,\"days\":\"mon, tue\",\"start\":\"23:00\",\"end\":\"06:00\"}}"
        );

        assertThrows(IllegalArgumentException.class, () -> SchedulePolicy.parse(null));
        for (String payload : invalidPayloads) {
            assertThrows("Expected rejection for: " + payload,
                    IllegalArgumentException.class,
                    () -> SchedulePolicy.parse(payload));
        }
    }

    // ---------------------------------------------------- night boundary instants

    @Test
    public void nightWindowStartIsInclusiveAndEndIsExclusive() {
        Schedule nightOnly = SchedulePolicy.parse("""
                {
                  "timezone": "Asia/Jerusalem",
                  "night": { "enabled": true, "days": "daily", "start": "23:00", "end": "06:00" }
                }
                """);

        LocalDate thursday = LocalDate.of(2026, 6, 11);
        LocalDate friday = thursday.plusDays(1);

        assertEquals(Set.of(), SchedulePolicy.activeWindows(nightOnly, at(thursday, 22, 59, 59, 999)));
        assertEquals(Set.of("night"), SchedulePolicy.activeWindows(nightOnly, at(thursday, 23, 0, 0, 0)));
        assertEquals(Set.of("night"), SchedulePolicy.activeWindows(nightOnly, at(friday, 5, 59, 59, 999)));
        assertEquals(Set.of(), SchedulePolicy.activeWindows(nightOnly, at(friday, 6, 0, 0, 0)));
    }

    // ------------------------------------------- day-of-week & midnight ownership

    @Test
    public void sunThuWorkHoursCoverSunToThuAndStayInactiveOnFriAndSat() {
        Schedule workOnly = SchedulePolicy.parse("""
                {
                  "timezone": "Asia/Jerusalem",
                  "work": { "enabled": true, "days": "sun-thu", "start": "09:00", "end": "17:00" }
                }
                """);

        LocalDate thursday = LocalDate.of(2026, 6, 11);
        LocalDate friday = LocalDate.of(2026, 6, 12);
        LocalDate saturday = LocalDate.of(2026, 6, 13);
        LocalDate sunday = LocalDate.of(2026, 6, 14);

        assertEquals(Set.of(), SchedulePolicy.activeWindows(workOnly, at(thursday, 8, 59, 59, 999)));
        assertEquals(Set.of("work"), SchedulePolicy.activeWindows(workOnly, at(thursday, 9, 0, 0, 0)));
        assertEquals(Set.of("work"), SchedulePolicy.activeWindows(workOnly, at(thursday, 16, 59, 59, 999)));
        assertEquals(Set.of(), SchedulePolicy.activeWindows(workOnly, at(thursday, 17, 0, 0, 0)));

        assertEquals(Set.of(), SchedulePolicy.activeWindows(workOnly, at(friday, 12, 0, 0, 0)));
        assertEquals(Set.of(), SchedulePolicy.activeWindows(workOnly, at(saturday, 12, 0, 0, 0)));
        assertEquals(Set.of("work"), SchedulePolicy.activeWindows(workOnly, at(sunday, 9, 0, 0, 0)));
    }

    @Test
    public void midnightCrossingWindowOnSunThuBelongsToStartDay() {
        Schedule sunThuNight = SchedulePolicy.parse("""
                {
                  "timezone": "Asia/Jerusalem",
                  "night": { "enabled": true, "days": "sun-thu", "start": "23:00", "end": "06:00" }
                }
                """);

        LocalDate thursday = LocalDate.of(2026, 6, 11);
        LocalDate friday = LocalDate.of(2026, 6, 12);
        LocalDate saturday = LocalDate.of(2026, 6, 13);
        LocalDate sunday = LocalDate.of(2026, 6, 14);

        // Thursday 23:00 starts the window; Friday 05:59 is Thursday's morning tail.
        assertEquals(Set.of("night"), SchedulePolicy.activeWindows(sunThuNight, at(thursday, 23, 0, 0, 0)));
        assertEquals(Set.of("night"), SchedulePolicy.activeWindows(sunThuNight, at(friday, 5, 59, 0, 0)));
        assertEquals(Set.of(), SchedulePolicy.activeWindows(sunThuNight, at(friday, 6, 0, 0, 0)));

        // Friday night is not in sun-thu, so Friday 23:00 and Saturday 02:00 are inactive.
        assertEquals(Set.of(), SchedulePolicy.activeWindows(sunThuNight, at(friday, 23, 0, 0, 0)));
        assertEquals(Set.of(), SchedulePolicy.activeWindows(sunThuNight, at(saturday, 2, 0, 0, 0)));

        // Saturday night is not in sun-thu either; Sunday 23:00 resumes.
        assertEquals(Set.of(), SchedulePolicy.activeWindows(sunThuNight, at(sunday, 2, 0, 0, 0)));
        assertEquals(Set.of("night"), SchedulePolicy.activeWindows(sunThuNight, at(sunday, 23, 0, 0, 0)));
    }

    // --------------------------------------------------- 2026 Asia/Jerusalem DST

    @Test
    public void handles2026AsiaJerusalemSpringForwardAndFallBackTransitions() {
        ZoneRules rules = JERUSALEM.getRules();
        ZoneOffsetTransition springForward = rules.nextTransition(
                LocalDate.of(2026, 1, 1).atStartOfDay(JERUSALEM).toInstant());
        assertTrue("Expected spring-forward gap in 2026", springForward.isGap());
        assertEquals(2026, springForward.getDateTimeBefore().getYear());

        ZoneOffsetTransition fallBack = rules.nextTransition(springForward.getInstant());
        assertTrue("Expected fall-back overlap in 2026", fallBack.isOverlap());
        assertEquals(2026, fallBack.getDateTimeBefore().getYear());

        Schedule nightOnly = SchedulePolicy.parse("""
                {
                  "timezone": "Asia/Jerusalem",
                  "night": { "enabled": true, "days": "daily", "start": "23:00", "end": "06:00" }
                }
                """);

        // Spring forward (6-hour night, not 7).
        LocalDate springDate = springForward.getDateTimeBefore().toLocalDate();
        Instant springStart = ZonedDateTime.of(springDate.minusDays(1), LocalTime.of(23, 0), JERUSALEM)
                .toInstant();
        Instant springEnd = ZonedDateTime.of(springDate, LocalTime.of(6, 0), JERUSALEM)
                .toInstant();
        assertEquals(Duration.ofHours(6), Duration.between(springStart, springEnd));
        assertEquals(Optional.of(springEnd), SchedulePolicy.nextTransition(nightOnly, springStart));
        assertEquals(Set.of("night"), SchedulePolicy.activeWindows(nightOnly, springEnd.minusMillis(1)));
        assertEquals(Set.of(), SchedulePolicy.activeWindows(nightOnly, springEnd));

        // Fall back (8-hour night, not 7; both repeated 01:30 instants stay active).
        LocalDate fallDate = fallBack.getDateTimeBefore().toLocalDate();
        Instant fallStart = ZonedDateTime.of(fallDate.minusDays(1), LocalTime.of(23, 0), JERUSALEM)
                .toInstant();
        Instant fallEnd = ZonedDateTime.of(fallDate, LocalTime.of(6, 0), JERUSALEM)
                .toInstant();
        assertEquals(Duration.ofHours(8), Duration.between(fallStart, fallEnd));
        assertEquals(Optional.of(fallEnd), SchedulePolicy.nextTransition(nightOnly, fallStart));

        LocalTime overlapMid = fallBack.getDateTimeAfter().toLocalTime().plusMinutes(30);
        Instant firstOverlap = ZonedDateTime.ofLocal(fallDate.atTime(overlapMid), JERUSALEM, fallBack.getOffsetBefore())
                .toInstant();
        Instant secondOverlap = ZonedDateTime.ofLocal(fallDate.atTime(overlapMid), JERUSALEM, fallBack.getOffsetAfter())
                .toInstant();
        assertTrue(firstOverlap.isBefore(secondOverlap));
        assertEquals(Set.of("night"), SchedulePolicy.activeWindows(nightOnly, firstOverlap));
        assertEquals(Set.of("night"), SchedulePolicy.activeWindows(nightOnly, secondOverlap));
        assertEquals(Set.of(), SchedulePolicy.activeWindows(nightOnly, fallEnd));
    }

    @Test
    public void customWindowLandingInsideDstGapOrOverlapResolvesDeterministically() {
        ZoneRules rules = JERUSALEM.getRules();
        ZoneOffsetTransition springForward = rules.nextTransition(
                LocalDate.of(2026, 1, 1).atStartOfDay(JERUSALEM).toInstant());
        ZoneOffsetTransition fallBack = rules.nextTransition(springForward.getInstant());

        // Start inside the spring-forward gap (02:30 -> resolves to 03:30 IDT).
        LocalDate springDate = springForward.getDateTimeBefore().toLocalDate();
        LocalTime gapStart = springForward.getDateTimeBefore().toLocalTime().plusMinutes(30);
        LocalTime gapEnd = springForward.getDateTimeAfter().toLocalTime().plusHours(1);
        Schedule gapSchedule = new Schedule(
                JERUSALEM,
                null,
                new Window(true, EnumSet.allOf(DayOfWeek.class), gapStart, gapEnd));

        Instant resolvedGapStart = ZonedDateTime.of(springDate, gapStart, JERUSALEM).toInstant();
        Instant resolvedGapEnd = ZonedDateTime.of(springDate, gapEnd, JERUSALEM).toInstant();
        assertTrue(resolvedGapStart.isBefore(resolvedGapEnd));
        assertEquals(Set.of(), SchedulePolicy.activeWindows(gapSchedule, resolvedGapStart.minusMillis(1)));
        assertEquals(Optional.of(resolvedGapStart),
                SchedulePolicy.nextTransition(gapSchedule, resolvedGapStart.minusSeconds(15 * 60)));
        assertEquals(Set.of("work"), SchedulePolicy.activeWindows(gapSchedule, resolvedGapStart));
        assertEquals(Optional.of(resolvedGapEnd), SchedulePolicy.nextTransition(gapSchedule, resolvedGapStart));
        assertEquals(Set.of(), SchedulePolicy.activeWindows(gapSchedule, resolvedGapEnd));

        // Start inside the fall-back overlap (01:30 IDT -> stays active through 01:15 IST without flicker).
        LocalDate fallDate = fallBack.getDateTimeBefore().toLocalDate();
        LocalTime overlapStart = fallBack.getDateTimeAfter().toLocalTime().plusMinutes(30);
        LocalTime overlapEnd = fallBack.getDateTimeBefore().toLocalTime().plusHours(1);
        Schedule overlapSchedule = new Schedule(
                JERUSALEM,
                null,
                new Window(true, EnumSet.allOf(DayOfWeek.class), overlapStart, overlapEnd));

        Instant resolvedOverlapStart = ZonedDateTime.of(fallDate, overlapStart, JERUSALEM).toInstant();
        Instant secondPassEarlierWallTime = ZonedDateTime.ofLocal(
                fallDate.atTime(overlapStart.minusMinutes(15)),
                JERUSALEM,
                fallBack.getOffsetAfter()).toInstant();
        Instant resolvedOverlapEnd = ZonedDateTime.of(fallDate, overlapEnd, JERUSALEM).toInstant();

        assertTrue(resolvedOverlapStart.isBefore(secondPassEarlierWallTime));
        assertEquals(Set.of("work"), SchedulePolicy.activeWindows(overlapSchedule, resolvedOverlapStart));
        assertEquals(Set.of("work"), SchedulePolicy.activeWindows(overlapSchedule, secondPassEarlierWallTime));
        assertEquals(Optional.of(resolvedOverlapEnd),
                SchedulePolicy.nextTransition(overlapSchedule, secondPassEarlierWallTime));
        assertEquals(Set.of(), SchedulePolicy.activeWindows(overlapSchedule, resolvedOverlapEnd));
    }

    // ------------------------------------------------------------ nextTransition

    @Test
    public void nextTransitionFindsEarliestEnabledBoundaryOrEmptyWhenDisabled() {
        Schedule shared = SchedulePolicy.parse(SHARED_JSON);
        LocalDate thursday = LocalDate.of(2026, 6, 11);
        LocalDate friday = LocalDate.of(2026, 6, 12);

        assertEquals(Optional.of(at(thursday, 6, 0, 0, 0)),
                SchedulePolicy.nextTransition(shared, at(thursday, 5, 0, 0, 0)));
        assertEquals(Optional.of(at(thursday, 9, 0, 0, 0)),
                SchedulePolicy.nextTransition(shared, at(thursday, 6, 0, 0, 0)));
        assertEquals(Optional.of(at(thursday, 17, 0, 0, 0)),
                SchedulePolicy.nextTransition(shared, at(thursday, 12, 0, 0, 0)));
        assertEquals(Optional.of(at(thursday, 23, 0, 0, 0)),
                SchedulePolicy.nextTransition(shared, at(thursday, 17, 0, 0, 0)));
        // Friday skips work hours and returns Friday 23:00 night start.
        assertEquals(Optional.of(at(friday, 23, 0, 0, 0)),
                SchedulePolicy.nextTransition(shared, at(friday, 6, 0, 0, 0)));

        Schedule allDisabled = SchedulePolicy.parse("""
                {
                  "timezone": "Asia/Jerusalem",
                  "night": { "enabled": false, "days": "daily", "start": "23:00", "end": "06:00" }
                }
                """);
        assertEquals(Optional.empty(), SchedulePolicy.nextTransition(allDisabled, at(thursday, 12, 0, 0, 0)));

        // Single-day-per-week window finds the occurrence 7 days later.
        Schedule sundayOnly = SchedulePolicy.parse("""
                {
                  "timezone": "Asia/Jerusalem",
                  "work": { "enabled": true, "days": "sun", "start": "09:00", "end": "17:00" }
                }
                """);
        LocalDate sunday = LocalDate.of(2026, 6, 14);
        assertEquals(Optional.of(at(sunday.plusWeeks(1), 9, 0, 0, 0)),
                SchedulePolicy.nextTransition(sundayOnly, at(sunday, 17, 0, 0, 0)));
    }

    // ---------------------------------------------------- classifyChange rules

    @Test
    public void classifyChangeDistinguishesUnchangedTightenLoosenAndMixed() {
        Schedule base = SchedulePolicy.parse(SHARED_JSON);
        assertEquals(Change.UNCHANGED, SchedulePolicy.classifyChange(base, SchedulePolicy.parse(SHARED_JSON)));

        // Editing a disabled window changes no restricted time.
        Schedule disabledA = SchedulePolicy.parse("""
                {
                  "timezone": "Asia/Jerusalem",
                  "night": { "enabled": false, "days": "daily", "start": "23:00", "end": "06:00" }
                }
                """);
        Schedule disabledB = SchedulePolicy.parse("""
                {
                  "timezone": "Asia/Jerusalem",
                  "night": { "enabled": false, "days": "sun-thu", "start": "22:00", "end": "05:00" }
                }
                """);
        assertEquals(Change.UNCHANGED, SchedulePolicy.classifyChange(disabledA, disabledB));

        // Enabling a window -> TIGHTEN.
        assertEquals(Change.TIGHTEN, SchedulePolicy.classifyChange(
                disabledA,
                SchedulePolicy.parse("""
                        {
                          "timezone": "Asia/Jerusalem",
                          "night": { "enabled": true, "days": "daily", "start": "23:00", "end": "06:00" }
                        }
                        """)));

        // Widening hours (same-day and midnight-crossing) -> TIGHTEN.
        assertEquals(Change.TIGHTEN, SchedulePolicy.classifyChange(
                base,
                SchedulePolicy.parse("""
                        {
                          "timezone": "Asia/Jerusalem",
                          "night": { "enabled": true, "days": "daily", "start": "22:30", "end": "06:30" },
                          "work":  { "enabled": true, "days": "sun-thu", "start": "08:30", "end": "17:30" }
                        }
                        """)));

        // Adding days -> TIGHTEN.
        assertEquals(Change.TIGHTEN, SchedulePolicy.classifyChange(
                base,
                SchedulePolicy.parse("""
                        {
                          "timezone": "Asia/Jerusalem",
                          "night": { "enabled": true, "days": "daily", "start": "23:00", "end": "06:00" },
                          "work":  { "enabled": true, "days": "daily", "start": "09:00", "end": "17:00" }
                        }
                        """)));

        // Disabling a window -> LOOSEN.
        assertEquals(Change.LOOSEN, SchedulePolicy.classifyChange(
                base,
                SchedulePolicy.parse("""
                        {
                          "timezone": "Asia/Jerusalem",
                          "night": { "enabled": false, "days": "daily", "start": "23:00", "end": "06:00" },
                          "work":  { "enabled": true, "days": "sun-thu", "start": "09:00", "end": "17:00" }
                        }
                        """)));

        // Narrowing hours -> LOOSEN.
        assertEquals(Change.LOOSEN, SchedulePolicy.classifyChange(
                base,
                SchedulePolicy.parse("""
                        {
                          "timezone": "Asia/Jerusalem",
                          "night": { "enabled": true, "days": "daily", "start": "23:30", "end": "06:00" },
                          "work":  { "enabled": true, "days": "sun-thu", "start": "09:00", "end": "17:00" }
                        }
                        """)));

        // Shifting hours (adds morning, drops afternoon) -> LOOSEN.
        assertEquals(Change.LOOSEN, SchedulePolicy.classifyChange(
                base,
                SchedulePolicy.parse("""
                        {
                          "timezone": "Asia/Jerusalem",
                          "night": { "enabled": true, "days": "daily", "start": "23:00", "end": "06:00" },
                          "work":  { "enabled": true, "days": "sun-thu", "start": "08:00", "end": "16:00" }
                        }
                        """)));

        // Removing days -> LOOSEN.
        assertEquals(Change.LOOSEN, SchedulePolicy.classifyChange(
                base,
                SchedulePolicy.parse("""
                        {
                          "timezone": "Asia/Jerusalem",
                          "night": { "enabled": true, "days": "daily", "start": "23:00", "end": "06:00" },
                          "work":  { "enabled": true, "days": "sun,mon,tue,wed", "start": "09:00", "end": "17:00" }
                        }
                        """)));

        // Changing timezone -> LOOSEN.
        assertEquals(Change.LOOSEN, SchedulePolicy.classifyChange(
                base,
                new Schedule(UTC, base.night(), base.work())));

        // Mixed: widening work hours while removing a work day -> LOOSEN.
        assertEquals(Change.LOOSEN, SchedulePolicy.classifyChange(
                base,
                SchedulePolicy.parse("""
                        {
                          "timezone": "Asia/Jerusalem",
                          "night": { "enabled": true, "days": "daily", "start": "23:00", "end": "06:00" },
                          "work":  { "enabled": true, "days": "sun,mon,tue,wed", "start": "08:00", "end": "18:00" }
                        }
                        """)));

        // Mixed: tightening night while loosening work -> LOOSEN.
        assertEquals(Change.LOOSEN, SchedulePolicy.classifyChange(
                base,
                SchedulePolicy.parse("""
                        {
                          "timezone": "Asia/Jerusalem",
                          "night": { "enabled": true, "days": "daily", "start": "22:00", "end": "06:00" },
                          "work":  { "enabled": true, "days": "sun-thu", "start": "10:00", "end": "17:00" }
                        }
                        """)));
    }

    private static Instant at(LocalDate date, int hour, int minute, int second, int millis) {
        return ZonedDateTime.of(
                date,
                LocalTime.of(hour, minute, second, millis * 1_000_000),
                JERUSALEM).toInstant();
    }
}
