package com.example.lockdowndpc.maintenance;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Every rule about whether a maintenance window may open and whether an open one
 * is still legitimate, in one pure place.
 *
 * <p>No Android types, no clock reads of its own, no storage. That is what makes
 * the cases nobody can stage on a desk — a reboot in the middle of a window, a
 * clock moved backwards, an expiry hit exactly on the boundary — ordinary unit
 * tests rather than hopeful reasoning.
 *
 * <h2>The invariants this class carries</h2>
 *
 * <ul>
 *   <li>A window never opens without an administrator PIN session, without at
 *       least one known capability, or outside
 *       {@code 0 &lt; duration &le;} {@link #MAX_DURATION_MILLIS}.</li>
 *   <li>A window never opens while protection is paused: a paused device has no
 *       policy for a window to make an exception to.</li>
 *   <li>A second window never opens on top of an existing one. Widening or
 *       extending means closing the first — which restores and verifies the
 *       policy — and opening a new one that is audited on its own line.</li>
 *   <li>Expiry, reboot, a suspicious clock and an administrator cancel all
 *       produce the same safety outcome: {@link MaintenanceState#CLOSED} with a
 *       {@link CloseReason}, which the coordinator turns into a restore that is
 *       read back. Only the audit line differs.</li>
 *   <li>Anything the readings cannot explain fails closed. An unreadable or
 *       inconsistent record is never treated as a live window.</li>
 * </ul>
 */
public final class MaintenanceStateMachine {

    /**
     * The longest window this build will grant.
     *
     * <p>Four hours is a service visit, not a posture. The number is a policy
     * choice rather than a platform limit, and it is enforced here — at the only
     * place a window can be created — so no caller can widen it by passing a
     * larger duration.
     */
    public static final long MAX_DURATION_MILLIS = TimeUnit.HOURS.toMillis(4);

    /** What the console offers when an administrator has expressed no preference. */
    public static final long DEFAULT_DURATION_MILLIS = TimeUnit.MINUTES.toMillis(30);

    /** The durations the console offers, shortest first. All within the maximum. */
    public static final List<Long> OFFERED_DURATIONS_MILLIS = List.of(
            TimeUnit.MINUTES.toMillis(15),
            TimeUnit.MINUTES.toMillis(30),
            TimeUnit.HOURS.toMillis(1),
            TimeUnit.HOURS.toMillis(2),
            TimeUnit.HOURS.toMillis(4));

    /**
     * How far the calendar clock may fall back before the window is treated as
     * tampered with.
     *
     * <p>Small backwards steps are ordinary: a time sync correcting drift moves
     * the clock in both directions. Anything larger is not explained by drift,
     * and since the safe response — closing early and restoring the policy —
     * costs an administrator one re-open, the tolerance stays deliberately tight.
     */
    public static final long CLOCK_BACKWARD_TOLERANCE_MILLIS = TimeUnit.SECONDS.toMillis(2);

    /**
     * How far the calendar clock may run ahead of the monotonic clock before the
     * gap is read as a power cycle.
     *
     * <p>While a device is running, both clocks advance together —
     * {@code elapsedRealtime} counts deep sleep too. A calendar clock that has
     * moved much further than the monotonic one means time passed while this
     * boot was not running, which is a reboot the monotonic comparison can miss
     * when the device happens to come back up with a longer uptime than the one
     * recorded. Failing closed on it costs a re-open; missing it leaves a
     * debugging transport open across a restart.
     */
    public static final long BOOT_GAP_TOLERANCE_MILLIS = TimeUnit.MINUTES.toMillis(2);

    private MaintenanceStateMachine() {}

    /** Whether a maintenance window is in force. */
    public enum MaintenanceState {
        /** Nothing is open. The base system policy is the whole policy. */
        CLOSED,
        /** A window is open; the relaxations it declares are in force. */
        OPEN
    }

    /** Why a window stopped being in force. Every value means "restore and verify". */
    public enum CloseReason {
        /** The configured duration ran out. */
        EXPIRED,
        /** The device restarted while the window was open. */
        REBOOT,
        /** An administrator ended the window by hand. */
        ADMINISTRATOR_CANCELLED,
        /** The clock readings could not be trusted, so the window was not trusted either. */
        CLOCK_ANOMALY,
        /** The stored record was unusable, so no window was assumed to exist. */
        UNREADABLE_RECORD,
        /**
         * Opening could not be verified, so the window was undone rather than
         * left half-applied. Recorded as its own reason because "the window was
         * never really open" is a different statement from "an administrator
         * ended it".
         */
        OPEN_FAILED;

        /** A stable, non-sensitive token for the audit log. */
        public String token() {
            return name().toLowerCase(java.util.Locale.ROOT);
        }
    }

    /**
     * A request to open a window.
     *
     * @param capabilities       what the administrator selected
     * @param durationMillis     how long the window should last
     * @param adminAuthenticated whether an administrator PIN session is valid now
     * @param protectionEnabled  whether protection is currently applied rather than
     *                           paused; a window relaxes a policy, and a paused
     *                           device has no policy to relax
     */
    public record OpenRequest(
            Set<MaintenanceCapability> capabilities,
            long durationMillis,
            boolean adminAuthenticated,
            boolean protectionEnabled
    ) {}

    /**
     * The answer to an open request.
     *
     * @param allowed whether a window may be opened
     * @param window  the window to apply and persist, {@code null} when refused
     * @param reason  a stable, non-sensitive token naming the decision
     */
    public record OpenDecision(boolean allowed, MaintenanceWindow window, String reason) {}

    /**
     * The answer to "is this window still in force?".
     *
     * @param state       {@link MaintenanceState#OPEN} only when every check passed
     * @param window      the window carrying refreshed liveness readings when open;
     *                    the window that must be undone when closing; {@code null}
     *                    when there was nothing to evaluate
     * @param closeReason why it closed, {@code null} while it is open or when
     *                    there was no window at all
     * @param reason      a stable, non-sensitive token naming the decision
     */
    public record Evaluation(
            MaintenanceState state,
            MaintenanceWindow window,
            CloseReason closeReason,
            String reason
    ) {

        public boolean open() {
            return state == MaintenanceState.OPEN;
        }

        /** Whether this evaluation obliges the caller to restore the base policy. */
        public boolean needsRestore() {
            return state == MaintenanceState.CLOSED && closeReason != null;
        }
    }

    /**
     * Decides whether a window may open, and builds it from a single clock sample.
     *
     * <p>{@code current} is the window that is already open, or {@code null}. A
     * caller must {@link #evaluate} first and close a lapsed window before
     * asking for a new one: opening on top of a window whose relaxations have
     * not been undone and verified would leave the device relaxed with no record
     * of what to restore.
     */
    public static OpenDecision open(
            MaintenanceWindow current,
            OpenRequest request,
            MaintenanceClock clock
    ) {
        if (request == null) {
            return refused("missing-request");
        }
        if (clock == null) {
            return refused("missing-clock");
        }
        if (!request.adminAuthenticated()) {
            return refused("admin-authentication-required");
        }
        if (!request.protectionEnabled()) {
            // Maintenance is an exception to an enforced policy, not a second way
            // to switch one off. A window opened on a paused device would record
            // relaxations of restrictions that are not in force, and its eventual
            // restore would then re-assert them on a device the console still
            // shows as paused.
            return refused("protection-paused");
        }
        if (current != null) {
            // Not an error the console should paper over by replacing the window:
            // the first one has to be closed, restored and verified on its own
            // audit line before a second is granted.
            return refused("already-open");
        }
        Set<MaintenanceCapability> capabilities = request.capabilities();
        if (capabilities == null || capabilities.isEmpty()) {
            return refused("no-capability-selected");
        }
        if (capabilities.contains(null)) {
            return refused("unknown-capability");
        }
        if (request.durationMillis() <= 0) {
            return refused("non-positive-duration");
        }
        if (request.durationMillis() > MAX_DURATION_MILLIS) {
            return refused("duration-above-maximum");
        }

        MaintenanceWindow window = MaintenanceWindow.opened(
                EnumSet.copyOf(capabilities), request.durationMillis(), clock);
        return new OpenDecision(true, window, "opened");
    }

    /**
     * Re-checks an existing window against the clock.
     *
     * <p>The order of the checks decides which audit line an operator reads, so
     * it is deliberate: a device that rebooted is reported as having rebooted
     * even if the window would also have expired by now, because "the window
     * survived a restart" and "the window ran its course" are different
     * statements about the same device.
     */
    public static Evaluation evaluate(MaintenanceWindow current, MaintenanceClock clock) {
        if (current == null) {
            return new Evaluation(MaintenanceState.CLOSED, null, null, "no-window");
        }
        if (clock == null) {
            // No readings means no evidence the window is still legitimate.
            return closed(current, CloseReason.UNREADABLE_RECORD, "missing-clock");
        }

        long nowWall = clock.wallClockMillis();
        long nowElapsed = clock.elapsedSinceBootMillis();

        if (nowElapsed < current.lastSeenElapsed()) {
            return closed(current, CloseReason.REBOOT, "monotonic-clock-went-backwards");
        }
        if (nowElapsed < current.openedAtElapsed()) {
            // Belt and braces: a record from before a restart, never heartbeated.
            return closed(current, CloseReason.REBOOT, "monotonic-clock-before-open");
        }
        if (nowWall < current.lastSeenWallClock() - CLOCK_BACKWARD_TOLERANCE_MILLIS) {
            return closed(current, CloseReason.CLOCK_ANOMALY, "wall-clock-went-backwards");
        }

        long elapsedProgress = nowElapsed - current.lastSeenElapsed();
        long wallProgress = nowWall - current.lastSeenWallClock();
        if (wallProgress - elapsedProgress > BOOT_GAP_TOLERANCE_MILLIS) {
            return closed(current, CloseReason.REBOOT, "boot-gap-detected");
        }

        if (current.expiredAt(nowElapsed)) {
            return closed(current, CloseReason.EXPIRED, "expired");
        }

        return new Evaluation(
                MaintenanceState.OPEN,
                current.withHeartbeat(nowWall, nowElapsed),
                null,
                "open");
    }

    /**
     * An administrator ending the window by hand.
     *
     * <p>Cancelling nothing is not an error worth shouting about, but it is not a
     * restore either: it reports {@code not-open} with no close reason, so a
     * caller cannot log "policy restored" for a window that never existed.
     */
    public static Evaluation cancel(MaintenanceWindow current) {
        if (current == null) {
            return new Evaluation(MaintenanceState.CLOSED, null, null, "not-open");
        }
        return closed(current, CloseReason.ADMINISTRATOR_CANCELLED, "administrator-cancelled");
    }

    /**
     * The evaluation for a stored record that could not be read back.
     *
     * <p>Called by {@link MaintenanceStore} when persisted values are missing,
     * corrupted or name a capability this build does not know. There is then no
     * window to describe and no capability list to trust, so the only safe
     * reading is "assume something was relaxed and restore the base policy".
     */
    public static Evaluation unreadableRecord() {
        return new Evaluation(
                MaintenanceState.CLOSED,
                null,
                CloseReason.UNREADABLE_RECORD,
                "unreadable-record");
    }

    private static Evaluation closed(
            MaintenanceWindow window,
            CloseReason closeReason,
            String reason
    ) {
        return new Evaluation(MaintenanceState.CLOSED, window, closeReason, reason);
    }

    private static OpenDecision refused(String reason) {
        return new OpenDecision(false, null, reason);
    }
}
