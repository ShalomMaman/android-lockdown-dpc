package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** Synchronous writes with an exact rollback, and fail-closed reads. */
public final class SchedulePersistenceTest {

    private static final ZoneId JERUSALEM = ZoneId.of("Asia/Jerusalem");
    private static final ZoneId UTC = ZoneId.of("UTC");

    /** Android semantics: memory changes on every commit; the result reports the disk. */
    static final class AndroidLikeBacking implements SchedulePersistence.Backing {
        String json;
        String allowlist;
        String format;
        boolean fileExists;
        boolean diskFails;
        boolean wrongType;
        RuntimeException fileCheckFails;
        int restores;

        @Override
        public String[] snapshot() {
            if (wrongType) {
                throw new ClassCastException("java.lang.Integer cannot be cast to java.lang.String");
            }
            return new String[]{json, allowlist, format};
        }

        @Override
        public boolean fileExists() {
            if (fileCheckFails != null) {
                throw fileCheckFails;
            }
            return fileExists;
        }

        @Override
        public boolean commit(String json, String allowlist) {
            this.json = json;
            this.allowlist = allowlist;
            this.format = SchedulePersistence.FORMAT;
            // A failed write can still leave a file behind.
            fileExists = true;
            return !diskFails;
        }

        @Override
        public void restore(String[] snapshot, boolean fileExisted) {
            restores++;
            json = snapshot[0];
            allowlist = snapshot[1];
            format = snapshot[2];
            if (!fileExisted && json == null && allowlist == null && format == null) {
                fileExists = false;
            }
        }

        /** Android loading a damaged file: the file is there, the map is empty. */
        void loadDamaged() {
            json = null;
            allowlist = null;
            format = null;
            fileExists = true;
        }
    }

    /** The ownership record with Android commit semantics. */
    static final class OwnedLikeBacking implements SchedulePersistence.OwnedBacking {
        String value;
        boolean diskFails;
        boolean wrongType;
        final List<String> commits = new ArrayList<>();

        @Override
        public String snapshot() {
            if (wrongType) {
                throw new ClassCastException("wrong type");
            }
            return value;
        }

        @Override
        public boolean commit(String value) {
            commits.add(String.valueOf(value));
            this.value = value;
            return !diskFails;
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

    // --- The format marker ------------------------------------------------------------

    @Test
    public void aDeviceThatNeverStoredAScheduleStaysOff() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        assertEquals(ScheduleSettings.OFF, SchedulePersistence.read(backing, UTC));
    }

    @Test
    public void aDamagedFileLoadedAsEmptyReadsAsTheFailClosedNightWindow() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        assertTrue(SchedulePersistence.write(backing, on(Set.of("com.example.a"))));
        backing.loadDamaged();
        ScheduleSettings settings = SchedulePersistence.read(backing, UTC);
        assertTrue(settings.unreadable());
        assertTrue(settings.enforcing());
    }

    @Test
    public void aDisabledScheduleThatIsLaterEmptiedNeverReadsAsOff() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        assertTrue(SchedulePersistence.write(backing, on(Set.of()).withWindowsEnabled(false, JERUSALEM)));
        assertEquals(SchedulePersistence.FORMAT, backing.format);
        backing.loadDamaged();
        assertTrue(SchedulePersistence.read(backing, UTC).unreadable());
    }

    @Test
    public void aWrittenOffRecordKeepsTheMarkerAndReadsAsOff() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        assertTrue(SchedulePersistence.write(backing, ScheduleSettings.OFF));
        assertEquals(SchedulePersistence.FORMAT, backing.format);
        assertEquals(ScheduleSettings.OFF, SchedulePersistence.read(backing, UTC));
    }

    @Test
    public void valuesWithoutTheMarkerAreUnreadable() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        backing.json = SchedulePolicy.toJson(ScheduleSettings.defaultSchedule(JERUSALEM, false));
        backing.fileExists = true;
        assertTrue(SchedulePersistence.read(backing, UTC).unreadable());
    }

    @Test
    public void anUnknownMarkerIsUnreadable() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        assertTrue(SchedulePersistence.write(backing, on(Set.of())));
        backing.format = "2";
        assertTrue(SchedulePersistence.read(backing, UTC).unreadable());
    }

    @Test
    public void aFailedFileCheckCountsAsAnExistingFile() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        backing.fileCheckFails = new SecurityException("denied");
        assertTrue(SchedulePersistence.read(backing, UTC).unreadable());
    }

    @Test
    public void aFailedFirstSaveLeavesAFreshDeviceOff() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        backing.diskFails = true;
        assertFalse(SchedulePersistence.write(backing, on(Set.of())));
        assertFalse("the file left by the failed write is removed", backing.fileExists);
        assertEquals(ScheduleSettings.OFF, SchedulePersistence.read(backing, UTC));
    }

    @Test
    public void aFailedSaveOverADamagedFileLeavesItUnreadable() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        backing.loadDamaged();
        backing.diskFails = true;
        assertFalse(SchedulePersistence.write(backing, on(Set.of())));
        assertTrue(backing.fileExists);
        assertTrue(SchedulePersistence.read(backing, UTC).unreadable());
    }

    // --- The ownership record ---------------------------------------------------------

    @Test
    public void aFailedOwnershipCommitRestoresThePreviousValueInMemory() {
        OwnedLikeBacking backing = new OwnedLikeBacking();
        assertTrue(SchedulePersistence.saveOwned(backing, Set.of("com.example.a")));
        backing.diskFails = true;
        assertFalse(SchedulePersistence.saveOwned(backing, Set.of("com.example.a", "com.example.b")));
        assertEquals("com.example.a", backing.value);
        assertFalse(SchedulePersistence.saveOwned(backing, Set.of()));
        assertEquals("com.example.a", backing.value);
    }

    @Test
    public void anEmptyOwnershipRecordIsRemoved() {
        OwnedLikeBacking backing = new OwnedLikeBacking();
        backing.value = "com.example.a";
        assertTrue(SchedulePersistence.saveOwned(backing, Set.of()));
        assertEquals(null, backing.value);
    }

    @Test
    public void aFailedCommitOverAWrongTypedOwnershipRecordKeepsTheNewValue() {
        OwnedLikeBacking backing = new OwnedLikeBacking();
        backing.wrongType = true;
        backing.diskFails = true;
        assertFalse(SchedulePersistence.saveOwned(backing, Set.of("com.example.a")));
        assertEquals("may over-report what it holds, never under-report", "com.example.a", backing.value);
        assertEquals(1, backing.commits.size());
    }
}
