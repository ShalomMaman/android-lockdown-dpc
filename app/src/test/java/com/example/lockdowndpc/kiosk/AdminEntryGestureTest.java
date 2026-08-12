package com.example.lockdowndpc.kiosk;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class AdminEntryGestureTest {

    @Test
    public void completesOnlyAfterTheRequiredTapsInsideTheWindow() {
        AdminEntryGesture gesture = new AdminEntryGesture();

        for (int tap = 1; tap < AdminEntryGesture.REQUIRED_TAPS; tap++) {
            assertFalse("tap " + tap + " must not complete the gesture", gesture.onTap(tap * 100L));
        }
        assertTrue(gesture.onTap(AdminEntryGesture.REQUIRED_TAPS * 100L));
    }

    @Test
    public void aSlowTapRestartsTheWindow() {
        AdminEntryGesture gesture = new AdminEntryGesture();

        for (int tap = 0; tap < AdminEntryGesture.REQUIRED_TAPS - 1; tap++) {
            assertFalse(gesture.onTap(tap * 10L));
        }
        // Past the window: this becomes tap 1 of a fresh attempt, not the last of
        // the old one, so an idle screen cannot accumulate stray touches.
        assertFalse(gesture.onTap(AdminEntryGesture.WINDOW_MILLIS + 1_000L));
        assertFalse(gesture.onTap(AdminEntryGesture.WINDOW_MILLIS + 1_010L));
    }

    @Test
    public void resetsAfterCompletionSoTheNextAttemptStartsClean() {
        AdminEntryGesture gesture = new AdminEntryGesture();

        for (int tap = 0; tap < AdminEntryGesture.REQUIRED_TAPS - 1; tap++) {
            gesture.onTap(tap * 10L);
        }
        assertTrue(gesture.onTap(100L));
        assertFalse(gesture.onTap(110L));
    }

    @Test
    public void toleratesANonMonotonicClockReading() {
        AdminEntryGesture gesture = new AdminEntryGesture();

        gesture.onTap(5_000L);
        assertFalse(gesture.onTap(10L));
        assertTrue(gesture.tapCount() == 1);
    }
}
