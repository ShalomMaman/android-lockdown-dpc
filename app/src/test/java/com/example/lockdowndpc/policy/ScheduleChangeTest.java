package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Tightening is immediate; loosening needs a live session at the write; every save is audited. */
public final class ScheduleChangeTest {

    private static final ZoneId JERUSALEM = ZoneId.of("Asia/Jerusalem");

    static final class FakeBoundary implements ScheduleChange.Gateway {
        ScheduleSettings stored;
        boolean unlocked;
        boolean commitFails;
        int sessionChecks;
        final List<ScheduleSettings> commits = new ArrayList<>();
        final List<String> audit = new ArrayList<>();

        FakeBoundary(ScheduleSettings stored) {
            this.stored = stored;
        }

        @Override
        public ScheduleSettings current() {
            return stored;
        }

        @Override
        public boolean sessionUnlocked() {
            sessionChecks++;
            return unlocked;
        }

        @Override
        public boolean commit(ScheduleSettings settings) {
            commits.add(settings);
            if (commitFails) {
                return false;
            }
            stored = settings;
            return true;
        }

        @Override
        public void audit(String line) {
            audit.add(line);
        }
    }

    private static ScheduleSettings on(Set<String> allowlist) {
        return new ScheduleSettings(ScheduleSettings.defaultSchedule(JERUSALEM, true), allowlist, false);
    }

    private static ScheduleSettings off() {
        return new ScheduleSettings(ScheduleSettings.defaultSchedule(JERUSALEM, false), Set.of(), false);
    }

    @Test
    public void tighteningIsSavedWithoutASession() {
        FakeBoundary boundary = new FakeBoundary(ScheduleSettings.OFF);
        ScheduleChange.Outcome outcome = ScheduleChange.apply(on(Set.of()), boundary);
        assertEquals(ScheduleChange.Status.SAVED, outcome.status());
        assertEquals(SchedulePolicy.Change.TIGHTEN, outcome.change());
        assertEquals(on(Set.of()), boundary.stored);
        assertEquals(0, boundary.sessionChecks);
        assertEquals(1, boundary.audit.size());
        assertTrue(boundary.audit.get(0), boundary.audit.get(0).startsWith("schedule:tightened "));
    }

    @Test
    public void shrinkingTheAllowlistIsATighteningWithoutASession() {
        FakeBoundary boundary = new FakeBoundary(on(Set.of("com.example.a")));
        ScheduleChange.Outcome outcome = ScheduleChange.apply(on(Set.of()), boundary);
        assertEquals(ScheduleChange.Status.SAVED, outcome.status());
        assertEquals(SchedulePolicy.Change.TIGHTEN, outcome.change());
    }

    @Test
    public void looseningWithoutASessionWritesAndAuditsNothing() {
        FakeBoundary boundary = new FakeBoundary(on(Set.of()));
        for (ScheduleSettings looser : List.of(off(), on(Set.of("com.example.a")))) {
            ScheduleChange.Outcome outcome = ScheduleChange.apply(looser, boundary);
            assertEquals(ScheduleChange.Status.SESSION_REQUIRED, outcome.status());
            assertEquals(SchedulePolicy.Change.LOOSEN, outcome.change());
        }
        assertEquals(List.of(), boundary.commits);
        assertEquals(List.of(), boundary.audit);
        assertEquals(on(Set.of()), boundary.stored);
    }

    @Test
    public void looseningWithALiveSessionIsSavedAndAudited() {
        FakeBoundary boundary = new FakeBoundary(on(Set.of()));
        boundary.unlocked = true;
        ScheduleChange.Outcome outcome = ScheduleChange.apply(off(), boundary);
        assertEquals(ScheduleChange.Status.SAVED, outcome.status());
        assertEquals(SchedulePolicy.Change.LOOSEN, outcome.change());
        assertEquals(off(), boundary.stored);
        assertEquals(1, boundary.audit.size());
        assertTrue(boundary.audit.get(0), boundary.audit.get(0).startsWith("schedule:loosened night=off work=off"));
    }

    @Test
    public void aCommitThatFailsIsNotAudited() {
        FakeBoundary boundary = new FakeBoundary(ScheduleSettings.OFF);
        boundary.commitFails = true;
        assertEquals(ScheduleChange.Status.NOT_SAVED, ScheduleChange.apply(on(Set.of()), boundary).status());
        assertEquals(List.of(), boundary.audit);
    }

    @Test
    public void anUnchangedRecordIsNotRewritten() {
        FakeBoundary boundary = new FakeBoundary(on(Set.of()));
        assertEquals(ScheduleChange.Status.UNCHANGED, ScheduleChange.apply(on(Set.of()), boundary).status());
        assertEquals(List.of(), boundary.commits);
        FakeBoundary never = new FakeBoundary(ScheduleSettings.OFF);
        assertEquals(ScheduleChange.Status.UNCHANGED, ScheduleChange.apply(ScheduleSettings.OFF, never).status());
        assertEquals(List.of(), never.commits);
    }

    @Test
    public void anUnreadableRecordIsComparedAsTheNightWindowItEnforces() {
        FakeBoundary repair = new FakeBoundary(ScheduleSettings.failClosed(JERUSALEM));
        ScheduleChange.Outcome repaired = ScheduleChange.apply(on(Set.of()), repair);
        assertEquals(ScheduleChange.Status.SAVED, repaired.status());
        assertEquals(SchedulePolicy.Change.TIGHTEN, repaired.change());
        assertTrue(repair.audit.get(0), repair.audit.get(0).endsWith("(was unreadable)"));

        FakeBoundary turnOff = new FakeBoundary(ScheduleSettings.failClosed(JERUSALEM));
        assertEquals(ScheduleChange.Status.SESSION_REQUIRED, ScheduleChange.apply(off(), turnOff).status());
        assertEquals(List.of(), turnOff.commits);
    }

    @Test
    public void turningOffANeverStoredScheduleWritesAndAuditsNothing() {
        FakeBoundary boundary = new FakeBoundary(ScheduleSettings.OFF);
        ScheduleSettings next = ScheduleSettings.OFF.withWindowsEnabled(false, JERUSALEM);
        assertEquals(ScheduleSettings.OFF, next);
        ScheduleChange.Outcome outcome = ScheduleChange.apply(next, boundary);
        assertEquals(ScheduleChange.Status.UNCHANGED, outcome.status());
        assertTrue(boundary.commits.isEmpty());
        assertTrue(boundary.audit.isEmpty());
    }
}
