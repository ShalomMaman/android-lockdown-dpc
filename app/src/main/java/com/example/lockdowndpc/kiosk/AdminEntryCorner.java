package com.example.lockdowndpc.kiosk;

/**
 * The hit test for the administrator entry corner, as a pure function.
 *
 * <p>0.5.0 implemented the corner as an invisible, click-consuming {@code View}
 * laid on top of the kiosk surface. It swallowed every touch in a 56 dp square at
 * the top of the leading edge — which is precisely where a school portal puts its
 * logo, its home link or its hamburger menu, in either direction. Students saw a
 * menu button that did not respond and no explanation.
 *
 * <p>The counter now observes {@code dispatchTouchEvent} and forwards the event
 * untouched, so the page keeps its own controls and the gesture keeps its target.
 */
public final class AdminEntryCorner {

    /** Edge length of the corner square, in dp. Unchanged from 0.5.0. */
    public static final int SIZE_DP = 56;

    private AdminEntryCorner() {}

    /**
     * Whether a touch belongs to the administrator corner.
     *
     * @param x             touch x, in the coordinate space of the kiosk root view
     * @param y             touch y, in the same space
     * @param width         width of that view, in pixels
     * @param sizePx        {@link #SIZE_DP} converted for this display
     * @param rightToLeft   whether the kiosk surface reads right to left, so the
     *                      corner follows "the side the text starts from" — the
     *                      wording the recovery note uses in both languages
     */
    public static boolean contains(float x, float y, int width, int sizePx, boolean rightToLeft) {
        if (sizePx <= 0 || width <= 0) {
            return false;
        }
        if (y < 0f || y > sizePx || x < 0f || x > width) {
            return false;
        }
        return rightToLeft ? x >= width - sizePx : x <= sizePx;
    }
}
