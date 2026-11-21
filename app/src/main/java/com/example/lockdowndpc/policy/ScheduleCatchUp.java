package com.example.lockdowndpc.policy;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Whether a night or work hours boundary passed without a verified policy
 * pass, and when a failed pass is retried, independent of Android.
 *
 * <p>The boundary alarm is the primary trigger. Without exact alarm access it
 * is inexact, and an OEM may drop an alarm altogether, so cheap checks back it
 * up while a schedule is enforcing: the screen turning on or the device being
 * unlocked (while the process runs), a periodic sweep job, and a one-off retry
 * job after a failed pass. Each reads the stored {@link State} and asks for a
 * full pass only when {@link #due} says so; the pass itself recomputes
 * everything from the clock.
 *
 * <p>The recorded instant advances only after a pass that was verified end to
 * end, so a pass whose inventory, ownership save or suspension failed leaves
 * the boundary "missed" and is tried again. Retries back off
 * ({@link #retryDelay}) so a pass that keeps failing does not run on every
 * screen-on. The state is a trigger hint, never a statement about which window
 * is in force, so a missing or unreadable one asks for a pass.
 */
final class ScheduleCatchUp {

    /** The delay before the first retry of a failed pass. */
    static final Duration FIRST_RETRY = Duration.ofMinutes(1);

    /** The longest retry delay, the sweep job's own period. */
    static final Duration MAX_RETRY = Duration.ofMinutes(15);

    /** Attempts are counted up to here; the delay is long capped by then. */
    private static final int MAX_COUNTED_ATTEMPTS = 1_000;

    /**
     * @param lastVerified   the instant the last verified pass evaluated the
     *                       schedule at, or {@code null} when unknown
     * @param failedAttempts failed passes since then
     * @param retryAt        no catch-up trigger runs a pass before this, or
     *                       {@code null} when there is no backoff
     */
    record State(Instant lastVerified, int failedAttempts, Instant retryAt) {
        static final State UNKNOWN = new State(null, 0, null);

        State {
            failedAttempts = Math.max(0, failedAttempts);
        }
    }

    private ScheduleCatchUp() {}

    /**
     * Whether a catch-up trigger should run a pass now: the last pass did not
     * verify, or a boundary was missed ({@link #boundaryMissed}), and no
     * backoff is pending. A failed pass is retried inside the same window, with
     * no boundary in between. A retry time further away than
     * {@link #MAX_RETRY} can only come from a clock moved back, and does not
     * hold the pass back.
     */
    static boolean due(ScheduleSettings settings, State state, Instant now) {
        State current = state == null ? State.UNKNOWN : state;
        if (settings == null || now == null || !settings.enforcing()) {
            return false;
        }
        if (current.failedAttempts() == 0 && !boundaryMissed(settings, current.lastVerified(), now)) {
            return false;
        }
        Instant retryAt = current.retryAt();
        return retryAt == null || !now.isBefore(retryAt) || retryAt.isAfter(now.plus(MAX_RETRY));
    }

    /**
     * @param lastVerified the instant the last verified pass evaluated the
     *                     schedule at, or {@code null} when unknown
     * @return whether a boundary passed since {@code lastVerified}, the clock
     *         moved back past it, or it is unknown. Never for a schedule that
     *         restricts nothing.
     */
    static boolean boundaryMissed(ScheduleSettings settings, Instant lastVerified, Instant now) {
        if (settings == null || now == null || !settings.enforcing()) {
            return false;
        }
        if (lastVerified == null || now.isBefore(lastVerified)) {
            return true;
        }
        Optional<Instant> next = SchedulePolicy.nextTransition(settings.schedule(), lastVerified);
        return next.isPresent() && !next.get().isAfter(now);
    }

    /** The state after a verified pass that evaluated the schedule at {@code at}. */
    static State afterVerified(Instant at) {
        return new State(at, 0, null);
    }

    /** The state after a failed pass at {@code now}: one more attempt, the next retry time. */
    static State afterFailed(State previous, Instant now) {
        State current = previous == null ? State.UNKNOWN : previous;
        int attempts = Math.min(current.failedAttempts() + 1, MAX_COUNTED_ATTEMPTS);
        return new State(current.lastVerified(), attempts, now.plus(retryDelay(attempts)));
    }

    /** The delay before retry {@code attempt} (from 1): 1, 2, 4 and 8 minutes, then 15. */
    static Duration retryDelay(int attempt) {
        if (attempt <= 1) {
            return FIRST_RETRY;
        }
        int doublings = Math.min(attempt - 1, 4);
        Duration delay = FIRST_RETRY.multipliedBy(1L << doublings);
        return delay.compareTo(MAX_RETRY) > 0 ? MAX_RETRY : delay;
    }
}
