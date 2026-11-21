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
        String state;
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
            return new String[]{json, allowlist, format, state};
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
            this.state = json == null ? SchedulePersistence.STATE_OFF : SchedulePersistence.STATE_SCHEDULE;
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
            state = snapshot[3];
            if (!fileExisted && json == null && allowlist == null && format == null && state == null) {
                fileExists = false;
            }
        }

        /** Android loading a damaged file: the file is there, the map is empty. */
        void loadDamaged() {
            json = null;
            allowlist = null;
            format = null;
            state = null;
            fileExists = true;
        }
    }

    /** The ownership record with Android commit semantics. */
    static final class OwnedLikeBacking implements SchedulePersistence.OwnedBacking {
        String value;
        String format;
        boolean fileExists;
        boolean diskFails;
        boolean wrongType;
        final List<String> commits = new ArrayList<>();

        @Override
        public String[] snapshot() {
            if (wrongType) {
                throw new ClassCastException("wrong type");
            }
            return new String[]{value, format};
        }

        @Override
        public boolean fileExists() {
            return fileExists;
        }

        @Override
        public boolean commit(String packages) {
            commits.add(String.valueOf(packages));
            value = packages;
            format = SchedulePersistence.FORMAT;
            fileExists = true;
            return !diskFails;
        }

        @Override
        public void markUnknown(String packages) {
            value = packages;
            format = null;
            fileExists = true;
        }

        /** Android loading a damaged file: the file is there, the map is empty. */
        void loadDamaged() {
            value = null;
            format = null;
            fileExists = true;
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
    public void aWrongTypedRecordReadsAsTheFailClosedDefaultSchedule() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        backing.wrongType = true;
        ScheduleSettings settings = SchedulePersistence.read(backing, UTC);
        assertTrue(settings.unreadable());
        assertTrue(settings.bothWindowsEnabled());
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
    public void ownedPackagesRoundTripAndAnyMalformedEntryIsUnreadable() {
        assertEquals(Set.of(), SchedulePersistence.decodeOwned(""));
        Set<String> owned = Set.of("com.example.b", "com.example.a");
        assertEquals(owned, SchedulePersistence.decodeOwned(SchedulePersistence.encodeOwned(owned)));
        // A dropped entry would be a schedule suspension nobody releases.
        assertThrows(IllegalStateException.class, () -> SchedulePersistence.decodeOwned("com.example.a,,bad name"));
        assertThrows(IllegalStateException.class, () -> SchedulePersistence.decodeOwned("com.example.a,com.example.a"));
    }

    // --- The format marker ------------------------------------------------------------

    @Test
    public void aDeviceThatNeverStoredAScheduleStaysOff() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        assertEquals(ScheduleSettings.OFF, SchedulePersistence.read(backing, UTC));
    }

    @Test
    public void aDamagedFileLoadedAsEmptyReadsAsTheFailClosedDefaultSchedule() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        assertTrue(SchedulePersistence.write(backing, on(Set.of("com.example.a"))));
        backing.loadDamaged();
        ScheduleSettings settings = SchedulePersistence.read(backing, UTC);
        assertTrue(settings.unreadable());
        assertTrue("work hours too, not only night", settings.bothWindowsEnabled());
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
    public void aWrittenOffRecordIsAnExplicitOffAndReadsAsOff() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        assertTrue(SchedulePersistence.write(backing, ScheduleSettings.OFF));
        assertEquals(SchedulePersistence.FORMAT, backing.format);
        assertEquals(SchedulePersistence.STATE_OFF, backing.state);
        assertEquals(ScheduleSettings.OFF, SchedulePersistence.read(backing, UTC));
    }

    @Test
    public void aMarkerWithoutAStatedContentIsUnreadableNotOff() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        backing.format = SchedulePersistence.FORMAT;
        backing.fileExists = true;
        assertTrue(SchedulePersistence.read(backing, UTC).unreadable());
        backing.state = "something-else";
        assertTrue(SchedulePersistence.read(backing, UTC).unreadable());
    }

    @Test
    public void aStateItsValuesContradictIsUnreadable() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        assertTrue(SchedulePersistence.write(backing, on(Set.of())));
        backing.state = SchedulePersistence.STATE_OFF;
        assertTrue("off with a schedule stored", SchedulePersistence.read(backing, UTC).unreadable());
        assertTrue(SchedulePersistence.write(backing, ScheduleSettings.OFF));
        backing.state = SchedulePersistence.STATE_SCHEDULE;
        assertTrue("a schedule state without one", SchedulePersistence.read(backing, UTC).unreadable());
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
    public void aFreshDeviceOwnsNothing() {
        assertEquals(Set.of(), SchedulePersistence.readOwned(new OwnedLikeBacking()));
    }

    @Test
    public void ownershipRoundTripsAndAnEmptyRecordKeepsItsMarker() {
        OwnedLikeBacking backing = new OwnedLikeBacking();
        assertTrue(SchedulePersistence.saveOwned(backing, Set.of("com.example.a", "com.example.b")));
        assertEquals(Set.of("com.example.a", "com.example.b"), SchedulePersistence.readOwned(backing));
        assertTrue(SchedulePersistence.saveOwned(backing, Set.of()));
        assertEquals("", backing.value);
        assertEquals(SchedulePersistence.FORMAT, backing.format);
        assertEquals(Set.of(), SchedulePersistence.readOwned(backing));
    }

    @Test
    public void aDamagedOwnershipFileLoadedAsEmptyIsUnknownNotNone() {
        OwnedLikeBacking backing = new OwnedLikeBacking();
        assertTrue(SchedulePersistence.saveOwned(backing, Set.of("com.example.a")));
        backing.loadDamaged();
        assertThrows(IllegalStateException.class, () -> SchedulePersistence.readOwned(backing));
    }

    @Test
    public void anUnreadableOwnershipRecordThrows() {
        OwnedLikeBacking wrongType = new OwnedLikeBacking();
        wrongType.wrongType = true;
        assertThrows(IllegalStateException.class, () -> SchedulePersistence.readOwned(wrongType));
        OwnedLikeBacking unknownMarker = new OwnedLikeBacking();
        unknownMarker.value = "com.example.a";
        unknownMarker.format = "2";
        assertThrows(IllegalStateException.class, () -> SchedulePersistence.readOwned(unknownMarker));
        OwnedLikeBacking markerOnly = new OwnedLikeBacking();
        markerOnly.format = SchedulePersistence.FORMAT;
        markerOnly.fileExists = true;
        assertThrows(IllegalStateException.class, () -> SchedulePersistence.readOwned(markerOnly));
        OwnedLikeBacking malformed = new OwnedLikeBacking();
        malformed.value = "com.example.a,bad name";
        malformed.format = SchedulePersistence.FORMAT;
        assertThrows(IllegalStateException.class, () -> SchedulePersistence.readOwned(malformed));
    }

    @Test
    public void aFailedOwnershipCommitMarksTheRecordUnknown() {
        OwnedLikeBacking backing = new OwnedLikeBacking();
        assertTrue(SchedulePersistence.saveOwned(backing, Set.of("com.example.a")));
        backing.diskFails = true;
        assertFalse(SchedulePersistence.saveOwned(backing, Set.of("com.example.a", "com.example.b")));
        // Never the previous value, which could under-report what is suspended.
        assertThrows(IllegalStateException.class, () -> SchedulePersistence.readOwned(backing));
        assertEquals("com.example.a,com.example.b", backing.value);
        backing.diskFails = false;
        assertTrue("a later save makes it known again",
                SchedulePersistence.saveOwned(backing, Set.of("com.example.b")));
        assertEquals(Set.of("com.example.b"), SchedulePersistence.readOwned(backing));
    }

    @Test
    public void aFailedFirstOwnershipSaveIsUnknownNotNone() {
        OwnedLikeBacking backing = new OwnedLikeBacking();
        backing.diskFails = true;
        assertFalse(SchedulePersistence.saveOwned(backing, Set.of("com.example.a")));
        assertThrows(IllegalStateException.class, () -> SchedulePersistence.readOwned(backing));
    }
}
