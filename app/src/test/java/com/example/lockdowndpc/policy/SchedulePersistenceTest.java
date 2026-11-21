package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.time.ZoneId;
import java.util.Set;

/** Synchronous writes with an exact rollback, and fail-closed reads. */
public final class SchedulePersistenceTest {

    private static final ZoneId JERUSALEM = ZoneId.of("Asia/Jerusalem");
    private static final ZoneId UTC = ZoneId.of("UTC");

    /** Android semantics: memory changes on every commit; the result reports the disk. */
    static final class AndroidLikeBacking implements SchedulePersistence.Backing {
        String json;
        String allowlist;
        boolean diskFails;
        boolean wrongType;
        int restores;

        @Override
        public String[] snapshot() {
            if (wrongType) {
                throw new ClassCastException("java.lang.Integer cannot be cast to java.lang.String");
            }
            return new String[]{json, allowlist};
        }

        @Override
        public boolean commit(String json, String allowlist) {
            this.json = json;
            this.allowlist = allowlist;
            return !diskFails;
        }

        @Override
        public void restore(String[] snapshot) {
            restores++;
            json = snapshot[0];
            allowlist = snapshot[1];
        }
    }

    private static ScheduleSettings on(Set<String> allowlist) {
        return new ScheduleSettings(ScheduleSettings.defaultSchedule(JERUSALEM, true), allowlist, false);
    }

    @Test
    public void aWriteIsReadBackExactly() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        assertEquals(ScheduleSettings.OFF, SchedulePersistence.read(backing, UTC));
        assertTrue(SchedulePersistence.write(backing, on(Set.of("com.example.a"))));
        assertEquals(on(Set.of("com.example.a")), SchedulePersistence.read(backing, UTC));
        assertTrue(SchedulePersistence.write(backing, ScheduleSettings.OFF));
        assertEquals(null, backing.json);
        assertEquals(null, backing.allowlist);
        assertEquals(ScheduleSettings.OFF, SchedulePersistence.read(backing, UTC));
    }

    @Test
    public void aFailedCommitRestoresThePreviousRecordInMemory() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        SchedulePersistence.write(backing, on(Set.of()));
        backing.diskFails = true;
        ScheduleSettings looser = on(Set.of()).withWindowsEnabled(false, JERUSALEM);
        assertFalse(SchedulePersistence.write(backing, looser));
        assertEquals("readers keep the previous, enforcing record", on(Set.of()),
                SchedulePersistence.read(backing, UTC));
        assertEquals(1, backing.restores);
    }

    @Test
    public void aFailedCommitOverAnUnreadableRecordLeavesItUnreadable() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        backing.json = "{corrupt";
        backing.allowlist = null;
        backing.diskFails = true;
        assertFalse(SchedulePersistence.write(backing, ScheduleSettings.OFF));
        assertArrayEquals(new String[]{"{corrupt", null}, new String[]{backing.json, backing.allowlist});
        assertTrue(SchedulePersistence.read(backing, UTC).unreadable());
    }

    @Test
    public void aWrongTypedRecordReadsAsTheFailClosedNightWindow() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        backing.wrongType = true;
        ScheduleSettings settings = SchedulePersistence.read(backing, UTC);
        assertTrue(settings.unreadable());
        assertTrue(settings.enforcing());
    }

    @Test
    public void aFailedCommitOverAWrongTypedRecordNeverReadsAsOff() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        backing.wrongType = true;
        backing.diskFails = true;
        assertFalse(SchedulePersistence.write(backing, ScheduleSettings.OFF));
        backing.wrongType = false;
        assertTrue(SchedulePersistence.read(backing, UTC).unreadable());
    }

    @Test
    public void theFailClosedStandInIsNeverWritten() {
        assertThrows(IllegalArgumentException.class,
                () -> SchedulePersistence.write(new AndroidLikeBacking(), ScheduleSettings.failClosed(UTC)));
    }

    @Test
    public void ownedPackagesRoundTripAndDropMalformedEntries() {
        assertEquals(Set.of(), SchedulePersistence.decodeOwned(null));
        assertEquals(Set.of(), SchedulePersistence.decodeOwned(""));
        Set<String> owned = Set.of("com.example.b", "com.example.a");
        assertEquals(owned, SchedulePersistence.decodeOwned(SchedulePersistence.encodeOwned(owned)));
        assertEquals(Set.of("com.example.a"), SchedulePersistence.decodeOwned("com.example.a,,bad name"));
    }
}
