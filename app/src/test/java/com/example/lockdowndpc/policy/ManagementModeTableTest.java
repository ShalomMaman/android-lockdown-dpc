package com.example.lockdowndpc.policy;

import com.example.lockdowndpc.testing.MemoryPreferences;

import org.junit.Test;

import java.util.Map;

import static com.example.lockdowndpc.policy.ManagementModeStore.Marker.ABSENT;
import static com.example.lockdowndpc.policy.ManagementModeStore.Marker.PRESENT;
import static com.example.lockdowndpc.policy.ManagementModeStore.Marker.UNREADABLE;
import static org.junit.Assert.assertEquals;

public class ManagementModeTableTest {
    @Test
    public void resolvesEveryMarkerAndRecordCombination() {
        assertRow(null, ManagementMode.UNDECIDED, ManagementMode.ENROLLING);
        assertRow("invalid", ManagementMode.UNDECIDED, ManagementMode.ENROLLING);
        assertRow("UNDECIDED", ManagementMode.UNDECIDED, ManagementMode.ENROLLING);
        assertRow("LOCAL_PIN", ManagementMode.LOCAL_PIN, ManagementMode.ENROLLING);
        assertRow("ENROLLING", ManagementMode.ENROLLING, ManagementMode.ENROLLING);
        assertRow("REMOTE", ManagementMode.ENROLLING, ManagementMode.REMOTE);
    }

    @Test
    public void onlyAnAbsentKeyAndAbsentFilesProveThereIsNoMarker() {
        var empty = new MemoryPreferences(Map.of()).preferences();
        var falseMarker = new MemoryPreferences(Map.of(ManagementModeStore.MARKER_KEY, false)).preferences();
        var malformed = new MemoryPreferences(Map.of(ManagementModeStore.MARKER_KEY, "bad")).preferences();
        var trueMarker = new MemoryPreferences(Map.of(ManagementModeStore.MARKER_KEY, true)).preferences();

        assertEquals(ABSENT, ManagementModeStore.readMarker(empty, () -> true));
        assertEquals(UNREADABLE, ManagementModeStore.readMarker(empty, () -> false));
        assertEquals(UNREADABLE, ManagementModeStore.readMarker(falseMarker, () -> true));
        assertEquals(UNREADABLE, ManagementModeStore.readMarker(malformed, () -> true));
        assertEquals(PRESENT, ManagementModeStore.readMarker(trueMarker, () -> false));
    }

    private static void assertRow(String record, ManagementMode absent, ManagementMode present) {
        assertEquals(absent, ManagementModeStore.resolve(ABSENT, record));
        assertEquals(present, ManagementModeStore.resolve(PRESENT, record));
        assertEquals(ManagementMode.ENROLLING, ManagementModeStore.resolve(UNREADABLE, record));
    }
}
