package com.example.lockdowndpc.policy;

import java.time.Instant;
import java.util.Optional;

/**
 * Whether a night or work hours boundary passed without a policy pass,
 * independent of Android.
 *
 * <p>The boundary alarm is the primary trigger. Without exact alarm access it
 * is inexact, and an OEM may drop an alarm altogether, so two cheap checks back
 * it up while a schedule is enforcing: the screen turning on or the device
 * being unlocked (while the process runs), and a periodic job. Each reads the
 * instant the last pass evaluated the schedule at and asks for a full pass
 * only when a boundary has passed since then; the pass itself recomputes
 * everything from the clock. The recorded instant is a trigger hint, never a
 * statement about which window is in force, so a missing or unreadable one
 * asks for a pass.
 */
final class ScheduleCatchUp {

    private ScheduleCatchUp() {}

    /**
     * @param lastReconciled the instant the last pass evaluated the schedule
     *                       at, or {@code null} when unknown
     * @return whether a pass is due: a boundary passed since
     *         {@code lastReconciled}, the clock moved back past it, or it is
     *         unknown. Never for a schedule that restricts nothing.
     */
    static boolean due(ScheduleSettings settings, Instant lastReconciled, Instant now) {
        if (settings == null || now == null || !settings.enforcing()) {
            return false;
        }
        if (lastReconciled == null || now.isBefore(lastReconciled)) {
            return true;
        }
        Optional<Instant> next = SchedulePolicy.nextTransition(settings.schedule(), lastReconciled);
        return next.isPresent() && !next.get().isAfter(now);
    }
}
