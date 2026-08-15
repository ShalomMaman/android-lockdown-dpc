package com.example.lockdowndpc.ui

import com.example.lockdowndpc.maintenance.MaintenanceCapability
import com.example.lockdowndpc.maintenance.MaintenanceCoordinator.MaintenanceOutcome
import com.example.lockdowndpc.maintenance.MaintenanceCoordinator.MaintenanceStatus
import com.example.lockdowndpc.maintenance.MaintenanceCoordinator.Phase
import com.example.lockdowndpc.maintenance.MaintenanceStateMachine
import com.example.lockdowndpc.maintenance.MaintenanceWindow
import com.example.lockdowndpc.policy.SystemPolicyControl

/**
 * Pure decisions and formatting for the timed maintenance console.
 *
 * Free of Android and Compose types on purpose, exactly like [KioskConsoleLogic]
 * and [ManagementIdentityLogic]. The parts of this screen worth proving are the
 * ones that decide how much privilege leaves the device and for how long — which
 * confirmation an operator still has to pass, whether the open action may be
 * offered at all, how much time is honestly left, and what a coordinator outcome
 * actually means — and every one of those is an ordinary value that a plain JVM
 * test can pin down.
 *
 * Resource identifiers deliberately stay out of this file, the same way they stay
 * out of `MaintenanceCapability` and `MaintenanceStateMachine`. The enums below
 * are mapped to `maintenance_strings.xml` inside the composable, which keeps every
 * operator-facing word where the locale parity check can see it and keeps this
 * file loadable without the Android framework.
 *
 * Nothing here formats a secret. The values it handles are capability keys,
 * control keys, a duration and a clock reading — never a PIN, a recovery code or
 * a kiosk URL.
 */

// ------------------------------------------------------------------ the draft

/**
 * The steps between "nothing is selected" and "the device has been asked to open
 * a window", in the order they are passed.
 *
 * The break-glass step is a step of its own rather than a paragraph inside
 * [CONFIRM]. A technician who wants a Settings screen and a technician who wants a
 * privileged debugging transport are making different decisions, and the second
 * one is not allowed to arrive as small print under the first.
 */
internal enum class MaintenanceStep {
    /** Choosing capabilities and a duration. Nothing has been asserted yet. */
    SELECT,

    /** What is about to be opened, for how long, and until when. */
    CONFIRM,

    /** The separate warning shown only when a break-glass capability is selected. */
    CONFIRM_BREAK_GLASS,

    /** Every confirmation has been passed; the open request may be sent. */
    READY,
}

/**
 * What the administrator has selected so far.
 *
 * The default is deliberately an empty capability set: maintenance opens nothing
 * a person did not name. The default duration is the state machine's own, so the
 * console cannot offer a length the engine would refuse.
 */
internal data class MaintenanceDraft(
    val capabilities: Set<MaintenanceCapability> = emptySet(),
    val durationMillis: Long = MaintenanceStateMachine.DEFAULT_DURATION_MILLIS,
    val step: MaintenanceStep = MaintenanceStep.SELECT,
) {
    /** Whether anything selected exposes a privileged transport. */
    val breakGlass: Boolean get() = MaintenanceCapability.anyBreakGlass(capabilities)

    /** Whether every confirmation this selection requires has been passed. */
    val confirmed: Boolean get() = step == MaintenanceStep.READY
}

/**
 * Adds or removes one capability, and sends the draft back to the start.
 *
 * Returning to [MaintenanceStep.SELECT] on every change is the rule that makes
 * the break-glass warning unskippable: a selection cannot be widened after a
 * confirmation was passed, because widening it discards the confirmation.
 */
internal fun MaintenanceDraft.withCapability(
    capability: MaintenanceCapability,
    selected: Boolean,
): MaintenanceDraft {
    val updated = if (selected) capabilities + capability else capabilities - capability
    if (updated == capabilities) {
        return this
    }
    return copy(capabilities = updated, step = MaintenanceStep.SELECT)
}

/** Changes the requested length, and — for the same reason — restarts the flow. */
internal fun MaintenanceDraft.withDuration(millis: Long): MaintenanceDraft =
    if (millis == durationMillis) {
        this
    } else {
        copy(durationMillis = millis, step = MaintenanceStep.SELECT)
    }

/**
 * The step that follows [step] for this selection.
 *
 * [MaintenanceStep.CONFIRM_BREAK_GLASS] is skipped when nothing break-glass is
 * selected, and is never skipped when something is.
 */
internal fun MaintenanceDraft.nextStep(): MaintenanceStep = when (step) {
    MaintenanceStep.SELECT -> MaintenanceStep.CONFIRM
    MaintenanceStep.CONFIRM ->
        if (breakGlass) MaintenanceStep.CONFIRM_BREAK_GLASS else MaintenanceStep.READY

    MaintenanceStep.CONFIRM_BREAK_GLASS -> MaintenanceStep.READY
    MaintenanceStep.READY -> MaintenanceStep.READY
}

/** The draft advanced one step. */
internal fun MaintenanceDraft.advanced(): MaintenanceDraft = copy(step = nextStep())

/**
 * The step a "back" lands on.
 *
 * Backing out of the break-glass warning returns to the ordinary confirmation
 * rather than to the selection, so the operator can re-read what else is in the
 * window; backing out of that returns to the selection.
 */
internal fun MaintenanceDraft.previousStep(): MaintenanceStep = when (step) {
    MaintenanceStep.SELECT -> MaintenanceStep.SELECT
    MaintenanceStep.CONFIRM -> MaintenanceStep.SELECT
    MaintenanceStep.CONFIRM_BREAK_GLASS -> MaintenanceStep.CONFIRM
    MaintenanceStep.READY ->
        if (breakGlass) MaintenanceStep.CONFIRM_BREAK_GLASS else MaintenanceStep.CONFIRM
}

/** The draft moved one step back. */
internal fun MaintenanceDraft.retreated(): MaintenanceDraft = copy(step = previousStep())

// ------------------------------------------------------- offering the choices

/**
 * The capabilities the selection list offers, break-glass excluded.
 *
 * Enum order, which is the order the audit summary uses, so the screen and the
 * log read the same way.
 */
internal fun standardCapabilities(): List<MaintenanceCapability> =
    MaintenanceCapability.values().filterNot { it.breakGlass() }

/** The break-glass capabilities, rendered in their own card with their own warning. */
internal fun breakGlassCapabilities(): List<MaintenanceCapability> =
    MaintenanceCapability.values().filter { it.breakGlass() }

/** The durations the console offers, shortest first; the engine's own list. */
internal fun offeredDurations(): List<Long> =
    MaintenanceStateMachine.OFFERED_DURATIONS_MILLIS.map { it }

// ------------------------------------------------------ may the window open?

/**
 * Why the open action is not available, worst first.
 *
 * [SESSION_EXPIRED] is checked before anything else because the screen's answer
 * to a lapsed administrator session is to refuse, never to ask for a PIN and
 * carry on with the request that was already in flight.
 */
internal enum class OpenBlocker {
    /** No administrator session, so nothing may be requested. */
    SESSION_EXPIRED,

    /** This build is not the device owner, so no restriction can be relaxed. */
    NOT_DEVICE_OWNER,

    /** A window is already open; it has to be closed and verified first. */
    ALREADY_OPEN,

    /** Nothing was selected. Maintenance never opens a default. */
    NO_CAPABILITY,

    /** The requested length is outside what the state machine will grant. */
    INVALID_DURATION,

    /** A request is in flight. */
    WORKING,

    /** The action may be offered. */
    NONE,
}

/**
 * Whether an open request may be offered, and if not, why.
 *
 * This mirrors the refusals `MaintenanceStateMachine.open` would produce rather
 * than replacing them: the state machine still decides, and it still refuses a
 * request this screen wrongly allowed. What the duplicate buys is an explanation
 * an operator can act on before they tap something that cannot work.
 */
internal fun openBlockerOf(
    draft: MaintenanceDraft,
    adminAuthenticated: Boolean,
    deviceOwner: Boolean,
    windowOpen: Boolean,
    working: Boolean,
): OpenBlocker = when {
    !adminAuthenticated -> OpenBlocker.SESSION_EXPIRED
    !deviceOwner -> OpenBlocker.NOT_DEVICE_OWNER
    windowOpen -> OpenBlocker.ALREADY_OPEN
    draft.capabilities.isEmpty() -> OpenBlocker.NO_CAPABILITY
    draft.durationMillis <= 0L -> OpenBlocker.INVALID_DURATION
    draft.durationMillis > MaintenanceStateMachine.MAX_DURATION_MILLIS ->
        OpenBlocker.INVALID_DURATION
    working -> OpenBlocker.WORKING
    else -> OpenBlocker.NONE
}

/** Whether the primary action may be tapped at all. */
internal fun openActionEnabled(
    draft: MaintenanceDraft,
    adminAuthenticated: Boolean,
    deviceOwner: Boolean,
    windowOpen: Boolean,
    working: Boolean,
): Boolean =
    openBlockerOf(draft, adminAuthenticated, deviceOwner, windowOpen, working) == OpenBlocker.NONE

/**
 * Whether the close action may be tapped.
 *
 * Deliberately not conditioned on the administrator session. Closing a window
 * removes privilege from the device, and the coordinator restores the base policy
 * whether or not anyone is authenticated; refusing to close because a session
 * lapsed would leave a debugging transport open to protect a screen.
 */
internal fun closeActionEnabled(windowOpen: Boolean, working: Boolean): Boolean =
    windowOpen && !working

// -------------------------------------------------------------- time on screen

/** Hours and whole minutes, both floored. */
internal data class DurationParts(val hours: Long, val minutes: Long) {
    val showsHours: Boolean get() = hours > 0L
}

/**
 * Splits a length into hours and minutes, rounding **down**.
 *
 * Down, not up, everywhere in this file. A window is a period during which the
 * device is less protected than the administrator configured, so the honest error
 * is the one that understates how much of it is left.
 */
internal fun durationPartsOf(millis: Long): DurationParts {
    val totalMinutes = if (millis <= 0L) 0L else millis / 60_000L
    return DurationParts(hours = totalMinutes / 60L, minutes = totalMinutes % 60L)
}

/** Which sentence the remaining-time line uses. */
internal enum class RemainingShape {
    /** The window has run out; the next liveness pass will close and restore it. */
    EXPIRED,

    /** Less than a whole minute is left, which is not worth naming as "0 minutes". */
    UNDER_ONE_MINUTE,

    MINUTES,
    HOURS_AND_MINUTES,
}

internal data class RemainingTime(
    val shape: RemainingShape,
    val hours: Long,
    val minutes: Long,
) {
    val expired: Boolean get() = shape == RemainingShape.EXPIRED
}

/**
 * How much of a window is left, in the terms the open card states.
 *
 * The boundary belongs to expiry, exactly as it does in
 * `MaintenanceWindow.expiredAt`: zero milliseconds left is a closed window, not a
 * window with a moment in it.
 */
internal fun remainingTimeOf(remainingMillis: Long): RemainingTime {
    if (remainingMillis <= 0L) {
        return RemainingTime(RemainingShape.EXPIRED, 0L, 0L)
    }
    if (remainingMillis < 60_000L) {
        return RemainingTime(RemainingShape.UNDER_ONE_MINUTE, 0L, 0L)
    }
    val parts = durationPartsOf(remainingMillis)
    val shape = if (parts.showsHours) RemainingShape.HOURS_AND_MINUTES else RemainingShape.MINUTES
    return RemainingTime(shape, parts.hours, parts.minutes)
}

/**
 * The calendar time a window opened now would be expected to close at.
 *
 * An estimate, and labelled as one on screen. Expiry is decided on the monotonic
 * clock, so a calendar clock that moves afterwards changes this number and
 * changes nothing about when the window actually ends.
 */
internal fun previewCloseWallClock(nowWallClock: Long, durationMillis: Long): Long =
    nowWallClock + durationMillis

// -------------------------------------------------- what an outcome means

/**
 * What the console shows after one coordinator call.
 *
 * The distinctions are the ones an operator has to act on differently, which is
 * why "opening failed" is two constants rather than one: a failed open whose
 * restore was verified leaves a device that is exactly as protected as before,
 * and a failed open whose restore was not leaves a device that may still be
 * relaxed with nobody watching.
 */
internal enum class MaintenanceResultKind {
    /** Requested, applied, and read back. The only state that reads as open. */
    OPENED,

    /** Refused before anything was sent to the device. */
    OPEN_REFUSED,

    /** Opening could not be verified; the previous policy is back and proven. */
    OPEN_FAILED_RESTORED,

    /** Opening could not be verified and neither could the restore. */
    OPEN_FAILED_RESTORE_FAILED,

    /** The window is closed and the base policy has been read back in force. */
    CLOSED_RESTORE_VERIFIED,

    /** The window is over, but this device did not confirm the base policy. */
    CLOSE_RESTORE_FAILED,

    /** A liveness pass that changed nothing and left the window open. */
    STILL_OPEN,

    /** There was nothing to close. */
    NOT_OPEN,
}

/** How loudly a result is drawn. */
internal enum class MaintenanceResultTone { OPEN, NEUTRAL, FAILED }

internal val MaintenanceResultKind.tone: MaintenanceResultTone
    get() = when (this) {
        MaintenanceResultKind.OPENED, MaintenanceResultKind.STILL_OPEN -> MaintenanceResultTone.OPEN
        MaintenanceResultKind.CLOSED_RESTORE_VERIFIED,
        MaintenanceResultKind.NOT_OPEN,
        -> MaintenanceResultTone.NEUTRAL

        MaintenanceResultKind.OPEN_REFUSED,
        MaintenanceResultKind.OPEN_FAILED_RESTORED,
        MaintenanceResultKind.OPEN_FAILED_RESTORE_FAILED,
        MaintenanceResultKind.CLOSE_RESTORE_FAILED,
        -> MaintenanceResultTone.FAILED
    }

/** Whether the inline banner is drawn as an error. */
internal val MaintenanceResultKind.isError: Boolean
    get() = tone == MaintenanceResultTone.FAILED

/**
 * Whether this result means the device may still be carrying relaxations nobody
 * has undone.
 *
 * This is the one state the screen must never present quietly: the record was
 * kept because a restore is owed, and an operator has to be told to retry it.
 */
internal val MaintenanceResultKind.restoreOwed: Boolean
    get() = this == MaintenanceResultKind.OPEN_FAILED_RESTORE_FAILED ||
        this == MaintenanceResultKind.CLOSE_RESTORE_FAILED

/**
 * Reads one [MaintenanceOutcome] in the console's vocabulary.
 *
 * Nothing here infers. Every branch is taken from what the coordinator reported —
 * the phase, the verified status, whether a window came back and whether it came
 * back with a close reason — so a result can only read as open when the
 * coordinator applied it and read it back.
 */
internal fun maintenanceResultKindOf(outcome: MaintenanceOutcome): MaintenanceResultKind =
    when (outcome.phase()) {
        Phase.OPEN -> when {
            outcome.status() == MaintenanceStatus.REFUSED -> MaintenanceResultKind.OPEN_REFUSED
            outcome.status() == MaintenanceStatus.APPLIED && outcome.windowOpen() ->
                MaintenanceResultKind.OPENED

            outcome.restoreOwed() -> MaintenanceResultKind.OPEN_FAILED_RESTORE_FAILED
            else -> MaintenanceResultKind.OPEN_FAILED_RESTORED
        }

        Phase.RESTORE ->
            if (outcome.restoreVerified()) {
                MaintenanceResultKind.CLOSED_RESTORE_VERIFIED
            } else {
                MaintenanceResultKind.CLOSE_RESTORE_FAILED
            }

        Phase.REFRESH ->
            if (outcome.windowOpen()) {
                MaintenanceResultKind.STILL_OPEN
            } else {
                MaintenanceResultKind.NOT_OPEN
            }
    }

/**
 * The window the screen may present as open after this outcome, or `null`.
 *
 * A window returned together with a close reason is a record of relaxations that
 * may still be on the device, not a live window, and this is where that
 * distinction is enforced for the console.
 */
internal fun openWindowAfter(outcome: MaintenanceOutcome): MaintenanceWindow? =
    if (outcome.windowOpen()) outcome.window() else null

/**
 * The failure summaries an outcome carries, deduplicated and in report order.
 *
 * These are the coordinator's non-sensitive control summaries; the screen shows
 * them verbatim because a support call needs the exact token, not a paraphrase.
 */
internal fun failureLinesOf(outcome: MaintenanceOutcome): List<String> =
    outcome.failures().filter { it.isNotBlank() }.distinct()

/** The controls a successful open actually turned off, or an empty list. */
internal fun relaxedControlsOf(outcome: MaintenanceOutcome): List<SystemPolicyControl> =
    outcome.plan()?.relaxed()?.toList().orEmpty()

/**
 * Controls the base policy still enforces that will keep a selected capability
 * from working.
 *
 * Reported, never opened. A technician who is told "still blocked by all package
 * installation" can decide to open that capability too; a technician who is told
 * nothing just watches an install fail inside a window that claims to be open.
 */
internal fun residualBlockersOf(outcome: MaintenanceOutcome): List<SystemPolicyControl> =
    outcome.plan()?.residualBlockers()?.toList().orEmpty()
