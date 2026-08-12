package com.example.lockdowndpc.kiosk;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class AdminEntryCornerTest {

    private static final int WIDTH = 1080;
    private static final int SIZE = 168; // 56 dp at density 3

    @Test
    public void leftToRightPutsTheCornerOnTheLeadingEdge() {
        assertTrue(AdminEntryCorner.contains(4f, 4f, WIDTH, SIZE, false));
        assertTrue(AdminEntryCorner.contains(SIZE, SIZE, WIDTH, SIZE, false));
        assertFalse(AdminEntryCorner.contains(SIZE + 1f, 4f, WIDTH, SIZE, false));
    }

    @Test
    public void rightToLeftMirrorsIt() {
        // "The side the text starts from", which is what both translations of the
        // recovery note say.
        assertTrue(AdminEntryCorner.contains(WIDTH - 4f, 4f, WIDTH, SIZE, true));
        assertTrue(AdminEntryCorner.contains(WIDTH - SIZE, SIZE, WIDTH, SIZE, true));
        assertFalse(AdminEntryCorner.contains(WIDTH - SIZE - 1f, 4f, WIDTH, SIZE, true));
        // The left corner belongs to the page in this direction, not to the gesture.
        assertFalse(AdminEntryCorner.contains(4f, 4f, WIDTH, SIZE, true));
    }

    @Test
    public void theRestOfTheSurfaceIsLeftAlone() {
        // The whole point of the change: a touch anywhere else is not the gesture,
        // and even inside the corner the event is forwarded rather than consumed.
        assertFalse(AdminEntryCorner.contains(WIDTH / 2f, 900f, WIDTH, SIZE, false));
        assertFalse(AdminEntryCorner.contains(4f, SIZE + 1f, WIDTH, SIZE, false));
    }

    @Test
    public void coordinatesOutsideTheViewAreNotTheCorner() {
        assertFalse(AdminEntryCorner.contains(-1f, 4f, WIDTH, SIZE, false));
        assertFalse(AdminEntryCorner.contains(4f, -1f, WIDTH, SIZE, false));
        assertFalse(AdminEntryCorner.contains(WIDTH + 1f, 4f, WIDTH, SIZE, true));
    }

    @Test
    public void anUnmeasuredViewHasNoCorner() {
        // dispatchTouchEvent can run before the first layout pass.
        assertFalse(AdminEntryCorner.contains(4f, 4f, 0, SIZE, false));
        assertFalse(AdminEntryCorner.contains(4f, 4f, WIDTH, 0, false));
    }
}
