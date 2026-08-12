package com.example.lockdowndpc.kiosk;

/**
 * The deliberate local gesture that reaches the administrator PIN screen from
 * inside a locked kiosk: {@value #REQUIRED_TAPS} taps on the kiosk header within
 * {@value #WINDOW_MILLIS} ms.
 *
 * <p>This is <em>not</em> a bypass. Completing the gesture only starts the
 * existing console, which begins on the locked PIN screen. Nothing here
 * unlocks, exits lock task or changes policy.
 *
 * <p>Pure and clock-injected so the timing rules are unit tested.
 */
public final class AdminEntryGesture {

    public static final int REQUIRED_TAPS = 7;
    public static final long WINDOW_MILLIS = 3_000L;

    private long windowStartedAt;
    private int taps;

    /**
     * @param elapsedMillis a monotonic clock reading, e.g. {@code SystemClock.elapsedRealtime()}
     * @return {@code true} exactly on the tap that completes the gesture
     */
    public boolean onTap(long elapsedMillis) {
        if (taps == 0 || elapsedMillis - windowStartedAt > WINDOW_MILLIS || elapsedMillis < windowStartedAt) {
            windowStartedAt = elapsedMillis;
            taps = 1;
        } else {
            taps++;
        }
        if (taps >= REQUIRED_TAPS) {
            reset();
            return true;
        }
        return false;
    }

    public void reset() {
        taps = 0;
        windowStartedAt = 0L;
    }

    public int tapCount() {
        return taps;
    }
}
