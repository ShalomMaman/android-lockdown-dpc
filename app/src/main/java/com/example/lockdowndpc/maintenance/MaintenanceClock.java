package com.example.lockdowndpc.maintenance;

/**
 * The two clock readings a maintenance window needs, behind a seam.
 *
 * <p>Both are required, and for different reasons.
 *
 * <ul>
 *   <li>{@link #elapsedSinceBootMillis()} — a monotonic reading that resets to
 *       zero at boot and cannot be moved by a user, an OEM time sync or a
 *       timezone change. It is what expiry is measured against, and a reading
 *       that has gone <em>backwards</em> since the window was last seen is the
 *       evidence that the device rebooted.</li>
 *   <li>{@link #wallClockMillis()} — the ordinary calendar clock. It is what an
 *       operator is shown, and comparing its progress against the monotonic
 *       reading is what catches a device that was powered off across the gap or
 *       a clock that was moved to buy a longer window.</li>
 * </ul>
 *
 * <p>The interface exists so {@link MaintenanceStateMachine} can be proved on the
 * JVM. The device implementation is {@code MaintenanceStore.deviceClock()}, a
 * two-line adapter over {@code System.currentTimeMillis()} and
 * {@code android.os.SystemClock.elapsedRealtime()}; nothing else in this package
 * reads a clock.
 */
public interface MaintenanceClock {

    /** Calendar time, in milliseconds since the epoch. May jump in either direction. */
    long wallClockMillis();

    /**
     * Milliseconds since boot, including deep sleep.
     *
     * <p>Monotonic within one boot and reset by a reboot. Never used as a
     * calendar time, and never trusted across a reboot.
     */
    long elapsedSinceBootMillis();
}
