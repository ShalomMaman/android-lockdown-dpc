package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.policy.SchedulePolicy.Change;

import org.junit.Test;

import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Stored settings: default off, fail-closed reads, the switch, and change classification. */
public final class ScheduleSettingsTest {

    private static final ZoneId JERUSALEM = ZoneId.of("Asia/Jerusalem");
    private static final ZoneId UTC = ZoneId.of("UTC");
    private static final String JSON = SchedulePolicy.toJson(ScheduleSettings.defaultSchedule(JERUSALEM, true));

    private static ScheduleSettings on(Set<String> allowlist) {
        return new ScheduleSettings(ScheduleSettings.defaultSchedule(JERUSALEM, true), allowlist, false);
    }

    private static ScheduleSettings off() {
        return new ScheduleSettings(ScheduleSettings.defaultSchedule(JERUSALEM, false), Set.of(), false);
    }

    @Test
    public void nothingStoredIsOffAndNotEnforcing() {
        ScheduleSettings settings = ScheduleSettings.fromStored(null, null, UTC);
        assertEquals(ScheduleSettings.OFF, settings);
        assertFalse(settings.enforcing());
        assertFalse(settings.unreadable());
        assertNull(settings.schedule());
    }

    @Test
    public void aStoredScheduleRoundTrips() {
        ScheduleSettings settings = ScheduleSettings.fromStored(JSON, "com.example.b,com.example.a", UTC);
        assertFalse(settings.unreadable());
        assertTrue(settings.enforcing());
        assertTrue(settings.bothWindowsEnabled());
        assertEquals(Set.of("com.example.a", "com.example.b"), settings.allowlist());
        assertEquals("com.example.a,com.example.b", ScheduleSettings.encodeAllowlist(settings.allowlist()));
    }

    @Test
    public void anythingStoredThatDoesNotParseIsTheFailClosedDefaultSchedule() {
        List<String[]> corrupt = new ArrayList<>();
        corrupt.add(new String[]{"{not json", null});
        corrupt.add(new String[]{"", null});
        corrupt.add(new String[]{null, "com.example.a"});
        corrupt.add(new String[]{null, ""});
        corrupt.add(new String[]{JSON, "not a package"});
        corrupt.add(new String[]{JSON, "com.example.a,com.example.a"});
        corrupt.add(new String[]{JSON.replace("23:00", "24:00"), ""});
        corrupt.add(new String[]{JSON.replace("\"timezone\"", "\"zone\""), ""});
        for (String[] record : corrupt) {
            ScheduleSettings settings = ScheduleSettings.fromStored(record[0], record[1], UTC);
            assertTrue(String.join("|", String.valueOf(record[0]), String.valueOf(record[1])),
                    settings.unreadable());
            assertTrue(settings.enforcing());
            assertEquals(Set.of(), settings.allowlist());
            // Both default windows: a damaged record never restricts less.
            assertEquals(ScheduleSettings.defaultSchedule(UTC, true), settings.schedule());
            assertTrue(settings.bothWindowsEnabled());
        }
    }

    @Test
    public void theAllowlistIsValidatedAndCapped() {
        assertThrows(IllegalArgumentException.class, () -> on(Set.of("bad name")));
        assertThrows(IllegalArgumentException.class,
                () -> new ScheduleSettings(null, Set.of("com.example.a"), false));
        java.util.HashSet<String> tooMany = new java.util.HashSet<>();
        for (int i = 0; i <= ScheduleSettings.MAX_ALLOWLIST; i++) {
            tooMany.add("com.example.app" + i);
        }
        assertThrows(IllegalArgumentException.class, () -> on(tooMany));
    }

    @Test
    public void theSwitchKeepsHoursZoneAndAllowlist() {
        ScheduleSettings custom = new ScheduleSettings(ScheduleSettings.defaultSchedule(UTC, true),
                Set.of("com.example.a"), false);
        ScheduleSettings disabled = custom.withWindowsEnabled(false, JERUSALEM);
        assertFalse(disabled.enforcing());
        assertEquals(UTC, disabled.schedule().timezone());
        assertEquals(Set.of("com.example.a"), disabled.allowlist());
        ScheduleSettings again = disabled.withWindowsEnabled(true, JERUSALEM);
        assertEquals(custom, again);
    }

    @Test
    public void theSwitchOnNothingStoredWritesTheDefaultsInTheDeviceZone() {
        ScheduleSettings first = ScheduleSettings.OFF.withWindowsEnabled(true, JERUSALEM);
        assertEquals(on(Set.of()), first);
        ScheduleSettings repaired = ScheduleSettings.failClosed(UTC).withWindowsEnabled(true, JERUSALEM);
        assertFalse(repaired.unreadable());
        assertEquals(on(Set.of()), repaired);
    }

    @Test
    public void classificationOfStoredChanges() {
        assertEquals(Change.TIGHTEN, ScheduleSettings.classify(ScheduleSettings.OFF, on(Set.of())));
        assertEquals(Change.TIGHTEN, ScheduleSettings.classify(off(), on(Set.of())));
        assertEquals(Change.LOOSEN, ScheduleSettings.classify(on(Set.of()), off()));
        assertEquals(Change.LOOSEN, ScheduleSettings.classify(on(Set.of()), ScheduleSettings.OFF));
        assertEquals(Change.UNCHANGED, ScheduleSettings.classify(ScheduleSettings.OFF, off()));
        assertEquals(Change.LOOSEN, ScheduleSettings.classify(on(Set.of()), on(Set.of("com.example.a"))));
        assertEquals(Change.TIGHTEN, ScheduleSettings.classify(on(Set.of("com.example.a")), on(Set.of())));
        assertEquals(Change.LOOSEN, ScheduleSettings.classify(
                on(Set.of("com.example.a")), on(Set.of("com.example.b"))));
        // A tighter schedule with a bigger allowlist is still a loosening.
        assertEquals(Change.LOOSEN, ScheduleSettings.classify(off(), on(Set.of("com.example.a"))));
        // Moving the zone is a loosening.
        assertEquals(Change.LOOSEN, ScheduleSettings.classify(on(Set.of()),
                new ScheduleSettings(ScheduleSettings.defaultSchedule(UTC, true), Set.of(), false)));
        // The fail-closed record is the full defaults: repairing it with them
        // changes nothing, and turning it off is a loosening.
        assertEquals(Change.UNCHANGED, ScheduleSettings.classify(
                ScheduleSettings.failClosed(JERUSALEM), on(Set.of())));
        assertEquals(Change.LOOSEN, ScheduleSettings.classify(
                ScheduleSettings.failClosed(JERUSALEM), off()));
        assertEquals(Change.LOOSEN, ScheduleSettings.classify(
                ScheduleSettings.failClosed(JERUSALEM), on(Set.of("com.example.a"))));
    }

    @Test
    public void theAuditSummaryCountsAllowlistedPackagesWithoutNamingThem() {
        String summary = on(Set.of("com.example.secret")).auditSummary();
        assertFalse(summary.contains("com.example.secret"));
        assertTrue(summary, summary.contains("allow=1"));
        assertTrue(summary, summary.contains("night=daily/23:00-06:00"));
        assertTrue(summary, summary.contains("work=sun-thu/09:00-17:00"));
        assertEquals("off", ScheduleSettings.OFF.auditSummary());
    }
}
