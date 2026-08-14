package com.example.lockdowndpc.maintenance;

import com.example.lockdowndpc.policy.SystemPolicyControl;

import java.util.Collections;
import java.util.EnumSet;
import java.util.Set;

/**
 * One open maintenance window: what it opened, when it opened, and the two clock
 * readings that let a later pass decide whether it is still legitimate.
 *
 * <p>The record is immutable. {@link #withHeartbeat} returns a copy carrying
 * fresh {@code lastSeen} readings, which is what
 * {@link MaintenanceStateMachine#evaluate} produces every time the window is
 * checked. Those readings are the whole reboot detector: after a restart the
 * monotonic clock is back near zero, so a stored reading from before the restart
 * is in the future and the window is closed.
 *
 * <p>Expiry is measured against the monotonic clock alone. Moving the calendar
 * clock therefore cannot extend a window, and a device that cannot reach a time
 * server does not get an accidentally endless one.
 *
 * @param capabilities         what the administrator opened; never empty, never
 *                             holding {@code null}
 * @param durationMillis       the requested length of the window
 * @param openedAtWallClock    calendar time at open, for the operator's display
 *                             and for the power-off gap check
 * @param openedAtElapsed      monotonic reading at open
 * @param lastSeenWallClock    calendar time at the most recent evaluation
 * @param lastSeenElapsed      monotonic reading at the most recent evaluation
 */
public record MaintenanceWindow(
        Set<MaintenanceCapability> capabilities,
        long durationMillis,
        long openedAtWallClock,
        long openedAtElapsed,
        long lastSeenWallClock,
        long lastSeenElapsed
) {

    public MaintenanceWindow {
        if (capabilities == null || capabilities.isEmpty()) {
            throw new IllegalArgumentException("A maintenance window needs at least one capability");
        }
        if (capabilities.contains(null)) {
            throw new IllegalArgumentException("A maintenance window cannot hold an unknown capability");
        }
        if (durationMillis <= 0) {
            throw new IllegalArgumentException("A maintenance window needs a positive duration");
        }
        if (durationMillis > MaintenanceStateMachine.MAX_DURATION_MILLIS) {
            throw new IllegalArgumentException("A maintenance window cannot exceed the documented maximum");
        }
        // EnumSet keeps the declaration order of MaintenanceCapability, so the
        // audit summary and the console list an identical, stable sequence.
        capabilities = Collections.unmodifiableSet(EnumSet.copyOf(capabilities));
    }

    /** Opens a window from the readings of one clock sample. */
    public static MaintenanceWindow opened(
            Set<MaintenanceCapability> capabilities,
            long durationMillis,
            MaintenanceClock clock
    ) {
        long wall = clock.wallClockMillis();
        long elapsed = clock.elapsedSinceBootMillis();
        return new MaintenanceWindow(capabilities, durationMillis, wall, elapsed, wall, elapsed);
    }

    /** The same window with fresh liveness readings; nothing else can change. */
    public MaintenanceWindow withHeartbeat(long wallClockMillis, long elapsedMillis) {
        return new MaintenanceWindow(
                capabilities,
                durationMillis,
                openedAtWallClock,
                openedAtElapsed,
                wallClockMillis,
                elapsedMillis);
    }

    /** The monotonic deadline. Immune to a moved calendar clock, void after a reboot. */
    public long expiresAtElapsed() {
        return openedAtElapsed + durationMillis;
    }

    /**
     * The calendar time the window is expected to close at.
     *
     * <p>For display and for the audit line only. It is derived from the wall
     * clock at open, so a clock that moves afterwards makes this an estimate —
     * the decision is always taken on the monotonic reading.
     */
    public long expectedCloseWallClock() {
        return openedAtWallClock + durationMillis;
    }

    /** Milliseconds left, floored at zero. */
    public long remainingMillis(long nowElapsed) {
        return Math.max(0L, expiresAtElapsed() - nowElapsed);
    }

    /**
     * Whether the window has run out at this monotonic reading.
     *
     * <p>The boundary belongs to expiry: at exactly {@link #expiresAtElapsed()}
     * the window is over. A window that is "still open for zero more
     * milliseconds" is a window that keeps a debugging transport open on a
     * rounding error.
     */
    public boolean expiredAt(long nowElapsed) {
        return nowElapsed >= expiresAtElapsed();
    }

    public boolean opens(MaintenanceCapability capability) {
        return capabilities.contains(capability);
    }

    /** Whether this window opened anything that carries the stronger warning. */
    public boolean breakGlass() {
        return MaintenanceCapability.anyBreakGlass(capabilities);
    }

    /** Every control this window is permitted to relax, and no other. */
    public Set<SystemPolicyControl> relaxableControls() {
        return MaintenanceCapability.relaxedControls(capabilities);
    }

    /** A stable, non-sensitive capability list for the audit log. */
    public String capabilitySummary() {
        return MaintenanceCapability.summarize(capabilities);
    }
}
