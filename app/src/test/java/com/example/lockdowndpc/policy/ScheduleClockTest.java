package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

/** The clock lock night and work hours need on Android 8.0/8.1, and nothing from Android 9. */
public final class ScheduleClockTest {

    private static final int OREO = 26;
    private static final int OREO_MR1 = 27;
    private static final int PIE = 28;

    static final class FakeGate implements ScheduleClock.Gate {
        boolean required;
        boolean automatic;
        boolean requireIgnored;
        boolean requireThrows;
        boolean readThrows;
        final List<String> calls = new ArrayList<>();

        @Override
        public void require() {
            calls.add("require");
            if (requireThrows) {
                throw new SecurityException("not the device owner");
            }
            if (!requireIgnored) {
                // Android turns automatic time on when it is required.
                required = true;
                automatic = true;
            }
        }

        @Override
        public boolean required() {
            calls.add("required");
            if (readThrows) {
                throw new SecurityException("read");
            }
            return required;
        }

        @Override
        public boolean automatic() {
            calls.add("automatic");
            return automatic;
        }
    }

    @Test
    public void fromAndroid9TheDateAndTimeRestrictionCoversItWithoutAnyCall() {
        FakeGate gate = new FakeGate();
        assertTrue(ScheduleClock.lock(PIE, gate));
        assertTrue(ScheduleClock.locked(PIE, gate));
        assertEquals(List.of(), gate.calls);
    }

    @Test
    public void onAndroid8TheLockRequiresAutomaticTimeAndReadsItBack() {
        FakeGate gate = new FakeGate();
        assertFalse(ScheduleClock.locked(OREO, gate));
        assertTrue(ScheduleClock.lock(OREO, gate));
        assertEquals(List.of("required", "require", "required", "automatic"), gate.calls);
        assertTrue(ScheduleClock.locked(OREO_MR1, gate));
    }

    @Test
    public void aRequirementAndroidIgnoresIsNotALock() {
        FakeGate gate = new FakeGate();
        gate.requireIgnored = true;
        assertFalse(ScheduleClock.lock(OREO, gate));
    }

    @Test
    public void requiredButAutomaticTimeOffIsNotALock() {
        FakeGate gate = new FakeGate();
        gate.required = true;
        gate.requireIgnored = true;
        assertFalse(ScheduleClock.lock(OREO_MR1, gate));
    }

    @Test
    public void aRefusedOrUnreadableLockIsNotALock() {
        FakeGate refused = new FakeGate();
        refused.requireThrows = true;
        assertFalse(ScheduleClock.lock(OREO, refused));
        FakeGate unreadable = new FakeGate();
        unreadable.readThrows = true;
        assertFalse(ScheduleClock.lock(OREO, unreadable));
    }
}
