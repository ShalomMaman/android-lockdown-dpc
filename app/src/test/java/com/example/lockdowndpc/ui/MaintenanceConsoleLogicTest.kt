package com.example.lockdowndpc.ui

import com.example.lockdowndpc.maintenance.MaintenanceCapability
import com.example.lockdowndpc.maintenance.MaintenanceCoordinator.MaintenanceOutcome
import com.example.lockdowndpc.maintenance.MaintenanceCoordinator.MaintenanceStatus
import com.example.lockdowndpc.maintenance.MaintenanceCoordinator.Phase
import com.example.lockdowndpc.maintenance.MaintenancePlan
import com.example.lockdowndpc.maintenance.MaintenanceStateMachine
import com.example.lockdowndpc.maintenance.MaintenanceStateMachine.CloseReason
import com.example.lockdowndpc.maintenance.MaintenanceWindow
import com.example.lockdowndpc.policy.SystemPolicyControl
import com.example.lockdowndpc.policy.SystemPolicyProfile
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.EnumSet
import java.util.concurrent.TimeUnit

/**
 * The presentation decisions of the timed maintenance console.
 *
 * Compose is never touched here. What is worth proving is how much privilege the
 * screen is willing to let out of the device and on what evidence: that nothing
 * is selected by default, that the break-glass confirmation cannot be routed
 * around, that a lapsed session refuses ahead of every other complaint, that the
 * remaining-time line never claims time the window does not have, and that only
 * an outcome the coordinator applied and read back can read as open.
 */
class MaintenanceConsoleLogicTest {

    private val thirtyMinutes = TimeUnit.MINUTES.toMillis(30)

    // ------------------------------------------------------------- the draft

    @Test
    fun aFreshDraftOpensNothing() {
        val draft = MaintenanceDraft()

        assertEquals(emptySet<MaintenanceCapability>(), draft.capabilities)
        assertFalse("a fresh draft is never break-glass", draft.breakGlass)
        assertEquals(MaintenanceStep.SELECT, draft.step)
        assertEquals(OpenBlocker.NO_CAPABILITY, blockerFor(draft))
    }

    @Test
    fun theDefaultDurationIsTheOneTheEngineOffers() {
        assertEquals(
            MaintenanceStateMachine.DEFAULT_DURATION_MILLIS,
            MaintenanceDraft().durationMillis,
        )
        assertTrue(
            "the default has to be a duration the state machine would grant",
            MaintenanceDraft().durationMillis <= MaintenanceStateMachine.MAX_DURATION_MILLIS,
        )
    }

    @Test
    fun anOrdinaryCapabilityNeedsOneConfirmation() {
        val draft = MaintenanceDraft().withCapability(MaintenanceCapability.SELECTED_SETTINGS, true)

        assertFalse("a selection on its own is not a confirmation", draft.confirmed)
        assertEquals(MaintenanceStep.CONFIRM, draft.nextStep())
        assertEquals(MaintenanceStep.READY, draft.advanced().nextStep())
        assertTrue(draft.advanced().advanced().confirmed)
    }

    @Test
    fun breakGlassInsertsItsOwnConfirmationStep() {
        // The whole point of the separate step: an ADB window can never be opened
        // by the same tap that would have opened an ordinary one.
        val draft = MaintenanceDraft().withCapability(MaintenanceCapability.ADB_DEBUGGING, true)

        assertTrue(draft.breakGlass)
        val confirm = draft.advanced()
        assertEquals(MaintenanceStep.CONFIRM, confirm.step)
        assertEquals(MaintenanceStep.CONFIRM_BREAK_GLASS, confirm.nextStep())
        assertEquals(MaintenanceStep.READY, confirm.advanced().nextStep())
        assertFalse(
            "passing the ordinary confirmation alone never confirms a break-glass window",
            confirm.advanced().confirmed,
        )
        assertTrue(confirm.advanced().advanced().confirmed)
    }

    @Test
    fun addingBreakGlassAfterAConfirmationDiscardsThatConfirmation() {
        val confirmed = MaintenanceDraft()
            .withCapability(MaintenanceCapability.SELECTED_SETTINGS, true)
            .advanced()
        assertEquals(MaintenanceStep.CONFIRM, confirmed.step)

        val widened = confirmed.withCapability(MaintenanceCapability.ADB_DEBUGGING, true)

        assertEquals(
            "widening a confirmed selection restarts the flow",
            MaintenanceStep.SELECT,
            widened.step,
        )
        assertEquals(MaintenanceStep.CONFIRM, widened.nextStep())
    }

    @Test
    fun changingTheDurationAlsoRestartsTheFlow() {
        val confirmed = MaintenanceDraft()
            .withCapability(MaintenanceCapability.USB_FILE_TRANSFER, true)
            .advanced()

        val relengthened = confirmed.withDuration(TimeUnit.HOURS.toMillis(4))

        assertEquals(MaintenanceStep.SELECT, relengthened.step)
        assertEquals(TimeUnit.HOURS.toMillis(4), relengthened.durationMillis)
    }

    @Test
    fun aChangeThatChangesNothingKeepsTheStep() {
        val confirmed = MaintenanceDraft()
            .withCapability(MaintenanceCapability.USB_FILE_TRANSFER, true)
            .advanced()

        assertEquals(
            MaintenanceStep.CONFIRM,
            confirmed.withCapability(MaintenanceCapability.ADB_DEBUGGING, false).step,
        )
        assertEquals(
            MaintenanceStep.CONFIRM,
            confirmed.withDuration(confirmed.durationMillis).step,
        )
    }

    @Test
    fun goingBackFromTheBreakGlassWarningReturnsToTheOrdinaryConfirmation() {
        val warned = MaintenanceDraft()
            .withCapability(MaintenanceCapability.ADB_DEBUGGING, true)
            .advanced()
            .advanced()
        assertEquals(MaintenanceStep.CONFIRM_BREAK_GLASS, warned.step)

        assertEquals(MaintenanceStep.CONFIRM, warned.retreated().step)
        assertEquals(MaintenanceStep.SELECT, warned.retreated().retreated().step)
        assertEquals(MaintenanceStep.SELECT, MaintenanceDraft().retreated().step)
    }

    @Test
    fun deselectingBreakGlassRemovesItsStep() {
        val draft = MaintenanceDraft()
            .withCapability(MaintenanceCapability.ADB_DEBUGGING, true)
            .withCapability(MaintenanceCapability.SELECTED_SETTINGS, true)
            .withCapability(MaintenanceCapability.ADB_DEBUGGING, false)

        assertFalse(draft.breakGlass)
        assertEquals(MaintenanceStep.READY, draft.advanced().nextStep())
    }

    // ------------------------------------------------------ may it open at all

    @Test
    fun aLapsedSessionRefusesAheadOfEveryOtherComplaint() {
        // The screen refuses rather than prompting: a request built before the
        // session lapsed must not be completed by re-authenticating afterwards.
        val draft = MaintenanceDraft().withCapability(MaintenanceCapability.ADB_DEBUGGING, true)

        assertEquals(
            OpenBlocker.SESSION_EXPIRED,
            blockerFor(draft, authenticated = false, owner = false, open = true, working = true),
        )
        assertFalse(
            openActionEnabled(
                draft = draft,
                adminAuthenticated = false,
                deviceOwner = true,
                windowOpen = false,
                working = false,
            ),
        )
    }

    @Test
    fun everyOtherRefusalHasItsOwnAnswer() {
        val ready = MaintenanceDraft().withCapability(MaintenanceCapability.SELECTED_SETTINGS, true)

        assertEquals(OpenBlocker.NOT_DEVICE_OWNER, blockerFor(ready, owner = false))
        assertEquals(OpenBlocker.ALREADY_OPEN, blockerFor(ready, open = true))
        assertEquals(OpenBlocker.WORKING, blockerFor(ready, working = true))
        assertEquals(OpenBlocker.NONE, blockerFor(ready))
        assertTrue(
            openActionEnabled(
                draft = ready,
                adminAuthenticated = true,
                deviceOwner = true,
                windowOpen = false,
                working = false,
            ),
        )
    }

    @Test
    fun aDurationOutsideWhatTheEngineGrantsIsRefusedBeforeItIsSent() {
        val tooLong = MaintenanceDraft(
            capabilities = setOf(MaintenanceCapability.SELECTED_SETTINGS),
            durationMillis = MaintenanceStateMachine.MAX_DURATION_MILLIS + 1L,
        )
        val notPositive = MaintenanceDraft(
            capabilities = setOf(MaintenanceCapability.SELECTED_SETTINGS),
            durationMillis = 0L,
        )

        assertEquals(OpenBlocker.INVALID_DURATION, blockerFor(tooLong))
        assertEquals(OpenBlocker.INVALID_DURATION, blockerFor(notPositive))
    }

    @Test
    fun closingIsOfferedWheneverAWindowIsOpen() {
        // Deliberately independent of the administrator session: closing takes
        // privilege away, and refusing it would leave the device relaxed.
        assertTrue(closeActionEnabled(windowOpen = true, working = false))
        assertFalse(closeActionEnabled(windowOpen = true, working = true))
        assertFalse(closeActionEnabled(windowOpen = false, working = false))
    }

    // --------------------------------------------------------- what is offered

    @Test
    fun theBreakGlassCapabilityIsNeverInTheOrdinaryList() {
        assertFalse(MaintenanceCapability.ADB_DEBUGGING in standardCapabilities())
        assertEquals(listOf(MaintenanceCapability.ADB_DEBUGGING), breakGlassCapabilities())
        assertEquals(
            "every capability is offered exactly once",
            MaintenanceCapability.values().size,
            standardCapabilities().size + breakGlassCapabilities().size,
        )
    }

    @Test
    fun everyOfferedDurationIsOneTheEngineWouldGrant() {
        val offered = offeredDurations()

        assertEquals(MaintenanceStateMachine.OFFERED_DURATIONS_MILLIS, offered)
        assertEquals("the list is shortest first", offered.sorted(), offered)
        offered.forEach { millis ->
            assertTrue("$millis is not positive", millis > 0L)
            assertTrue(
                "$millis is longer than the documented maximum",
                millis <= MaintenanceStateMachine.MAX_DURATION_MILLIS,
            )
        }
    }

    // ------------------------------------------------------------ time on screen

    @Test
    fun remainingTimeIsFlooredSoItNeverOverstatesTheWindow() {
        assertEquals(RemainingShape.EXPIRED, remainingTimeOf(0L).shape)
        assertEquals(RemainingShape.EXPIRED, remainingTimeOf(-1L).shape)
        assertTrue(remainingTimeOf(0L).expired)

        assertEquals(RemainingShape.UNDER_ONE_MINUTE, remainingTimeOf(1L).shape)
        assertEquals(RemainingShape.UNDER_ONE_MINUTE, remainingTimeOf(59_999L).shape)

        val oneMinute = remainingTimeOf(60_000L)
        assertEquals(RemainingShape.MINUTES, oneMinute.shape)
        assertEquals(1L, oneMinute.minutes)

        // 59 minutes and 59 seconds is 59 minutes, never an hour.
        val underAnHour = remainingTimeOf(TimeUnit.MINUTES.toMillis(60) - 1L)
        assertEquals(RemainingShape.MINUTES, underAnHour.shape)
        assertEquals(59L, underAnHour.minutes)
        assertEquals(0L, underAnHour.hours)

        val overAnHour = remainingTimeOf(TimeUnit.MINUTES.toMillis(90) + 59_999L)
        assertEquals(RemainingShape.HOURS_AND_MINUTES, overAnHour.shape)
        assertEquals(1L, overAnHour.hours)
        assertEquals(30L, overAnHour.minutes)
    }

    @Test
    fun durationPartsFloorTheSameWay() {
        assertEquals(DurationParts(0L, 0L), durationPartsOf(-5L))
        assertEquals(DurationParts(0L, 0L), durationPartsOf(59_999L))
        assertEquals(DurationParts(0L, 30L), durationPartsOf(thirtyMinutes))
        assertEquals(DurationParts(4L, 0L), durationPartsOf(TimeUnit.HOURS.toMillis(4)))
        assertFalse(durationPartsOf(thirtyMinutes).showsHours)
        assertTrue(durationPartsOf(TimeUnit.HOURS.toMillis(1)).showsHours)
    }

    @Test
    fun theExpectedClosingTimeIsTheClockPlusTheLength() {
        assertEquals(1_000L + thirtyMinutes, previewCloseWallClock(1_000L, thirtyMinutes))
    }

    // ------------------------------------------------ reading a device outcome

    @Test
    fun onlyAnAppliedAndVerifiedOpenReadsAsOpen() {
        val window = window(MaintenanceCapability.SELECTED_SETTINGS)
        val opened =
            outcome(Phase.OPEN, MaintenanceStatus.APPLIED, window = window, reason = "opened")

        assertEquals(MaintenanceResultKind.OPENED, maintenanceResultKindOf(opened))
        assertSame(window, openWindowAfter(opened))
        assertFalse(MaintenanceResultKind.OPENED.isError)
        assertFalse(MaintenanceResultKind.OPENED.restoreOwed)
    }

    @Test
    fun anOpenThatFailedAndWasRestoredIsAFailureAndNotAWindow() {
        val failed = outcome(
            Phase.OPEN,
            MaintenanceStatus.FAILED,
            window = null,
            closeReason = CloseReason.OPEN_FAILED,
            restoreProven = true,
            failures = listOf("maintenance-not-relaxed:app_control_settings"),
            reason = "open-failed-policy-restored",
        )

        assertEquals(MaintenanceResultKind.OPEN_FAILED_RESTORED, maintenanceResultKindOf(failed))
        assertNull("a failed open must never present a window", openWindowAfter(failed))
        assertTrue(MaintenanceResultKind.OPEN_FAILED_RESTORED.isError)
        assertFalse(
            "the restore was verified, so nothing is owed",
            MaintenanceResultKind.OPEN_FAILED_RESTORED.restoreOwed,
        )
    }

    @Test
    fun anOpenWhoseRestoreCouldNotBeProvedIsTheLoudestState() {
        // The window comes back with a close reason: it is a record of what may
        // still be relaxed, not a live window, and the screen has to say so.
        val failed = outcome(
            Phase.OPEN,
            MaintenanceStatus.FAILED,
            window = window(MaintenanceCapability.ADB_DEBUGGING),
            closeReason = CloseReason.OPEN_FAILED,
            failures = listOf("developer_options_and_adb:FAILED"),
            reason = "open-failed-restore-failed",
        )

        assertEquals(
            MaintenanceResultKind.OPEN_FAILED_RESTORE_FAILED,
            maintenanceResultKindOf(failed),
        )
        assertNull(openWindowAfter(failed))
        assertTrue(MaintenanceResultKind.OPEN_FAILED_RESTORE_FAILED.restoreOwed)
        assertEquals(
            MaintenanceResultTone.FAILED,
            MaintenanceResultKind.OPEN_FAILED_RESTORE_FAILED.tone,
        )
    }

    @Test
    fun aRefusalDoesNotCloseAWindowItNeverTouched() {
        // The coordinator hands a refusal the window that is already open. The
        // console reports the refusal and keeps showing the live window, because
        // nothing was sent to the device.
        val open = window(MaintenanceCapability.USB_FILE_TRANSFER)
        val refused = outcome(
            Phase.OPEN,
            MaintenanceStatus.REFUSED,
            window = open,
            reason = "already-open",
        )

        assertEquals(MaintenanceResultKind.OPEN_REFUSED, maintenanceResultKindOf(refused))
        assertSame(open, openWindowAfter(refused))
        assertTrue(MaintenanceResultKind.OPEN_REFUSED.isError)
    }

    @Test
    fun aRefusalWithNothingOpenPresentsNoWindow() {
        val refused = outcome(
            Phase.OPEN,
            MaintenanceStatus.REFUSED,
            window = null,
            reason = "admin-authentication-required",
        )

        assertEquals(MaintenanceResultKind.OPEN_REFUSED, maintenanceResultKindOf(refused))
        assertNull(openWindowAfter(refused))
    }

    @Test
    fun aCloseIsOnlyDoneWhenTheRestoreWasReadBack() {
        val verified = outcome(
            Phase.RESTORE,
            MaintenanceStatus.APPLIED,
            window = null,
            closeReason = CloseReason.ADMINISTRATOR_CANCELLED,
            restoreProven = true,
            reason = "restore-verified",
        )
        val unverified = outcome(
            Phase.RESTORE,
            MaintenanceStatus.FAILED,
            window = window(MaintenanceCapability.ADB_DEBUGGING),
            closeReason = CloseReason.EXPIRED,
            failures = listOf("developer_options_and_adb:FAILED"),
            reason = "restore-failed",
        )

        assertEquals(
            MaintenanceResultKind.CLOSED_RESTORE_VERIFIED,
            maintenanceResultKindOf(verified),
        )
        assertFalse(MaintenanceResultKind.CLOSED_RESTORE_VERIFIED.isError)
        assertFalse(MaintenanceResultKind.CLOSED_RESTORE_VERIFIED.restoreOwed)

        assertEquals(
            MaintenanceResultKind.CLOSE_RESTORE_FAILED,
            maintenanceResultKindOf(unverified),
        )
        assertTrue(MaintenanceResultKind.CLOSE_RESTORE_FAILED.isError)
        assertTrue(
            "a restore that was not read back leaves work owed",
            MaintenanceResultKind.CLOSE_RESTORE_FAILED.restoreOwed,
        )
        assertNull("the retained record is not a live window", openWindowAfter(unverified))
    }

    @Test
    fun aLivenessPassSaysWhetherAnythingIsStillOpen() {
        val open = window(MaintenanceCapability.SELECTED_SETTINGS)
        val stillOpen =
            outcome(Phase.REFRESH, MaintenanceStatus.UNCHANGED, window = open, reason = "open")
        val nothing = outcome(
            Phase.REFRESH,
            MaintenanceStatus.UNCHANGED,
            window = null,
            reason = "no-window",
        )

        assertEquals(MaintenanceResultKind.STILL_OPEN, maintenanceResultKindOf(stillOpen))
        assertSame(open, openWindowAfter(stillOpen))
        assertEquals(MaintenanceResultTone.OPEN, MaintenanceResultKind.STILL_OPEN.tone)

        assertEquals(MaintenanceResultKind.NOT_OPEN, maintenanceResultKindOf(nothing))
        assertNull(openWindowAfter(nothing))
        assertEquals(MaintenanceResultTone.NEUTRAL, MaintenanceResultKind.NOT_OPEN.tone)
    }

    @Test
    fun everyResultKindHasATone() {
        // A kind added later without a tone is a compile error in the `when`; this
        // checks the mapping is also complete in the direction that matters, so no
        // failure state is drawn as an ordinary one.
        MaintenanceResultKind.values().forEach { kind ->
            assertTrue(
                "$kind is drawn as an error only when its tone says so",
                (kind.tone == MaintenanceResultTone.FAILED) == kind.isError,
            )
        }
        assertTrue(
            "every state that owes a restore is an error state",
            MaintenanceResultKind.values().filter { it.restoreOwed }.all { it.isError },
        )
    }

    @Test
    fun failureLinesAreDeduplicatedAndNeverBlank() {
        val noisy = outcome(
            Phase.RESTORE,
            MaintenanceStatus.FAILED,
            window = null,
            closeReason = CloseReason.EXPIRED,
            failures = listOf("a:FAILED", "a:FAILED", "  ", "b:FAILED"),
            reason = "restore-failed",
        )

        assertEquals(listOf("a:FAILED", "b:FAILED"), failureLinesOf(noisy))
    }

    @Test
    fun anOutcomeWithNoPlanReportsNoControls() {
        val refused = outcome(
            Phase.OPEN,
            MaintenanceStatus.REFUSED,
            window = null,
            reason = "already-open",
        )

        assertEquals(emptyList<SystemPolicyControl>(), relaxedControlsOf(refused))
        assertEquals(emptyList<SystemPolicyControl>(), residualBlockersOf(refused))
    }

    @Test
    fun aPlanReportsWhatItTurnedOffAndWhatStillBlocksTheTask() {
        // Installing a local package while all package installation is enforced:
        // one control comes off, and the neighbour that still blocks the task is
        // reported rather than opened.
        val base = mapOf(
            SystemPolicyControl.UNKNOWN_SOURCE_INSTALLS to true,
            SystemPolicyControl.APP_STORES_AND_INSTALLERS to true,
        )
        val plan = MaintenancePlan.forWindow(
            SystemPolicyProfile.PRODUCTION,
            base,
            window(MaintenanceCapability.LOCAL_APK_INSTALL),
        )
        val opened = outcome(
            Phase.OPEN,
            MaintenanceStatus.APPLIED,
            window = window(MaintenanceCapability.LOCAL_APK_INSTALL),
            plan = plan,
            reason = "opened",
        )

        assertEquals(listOf(SystemPolicyControl.UNKNOWN_SOURCE_INSTALLS), relaxedControlsOf(opened))
        assertEquals(
            listOf(SystemPolicyControl.APP_STORES_AND_INSTALLERS),
            residualBlockersOf(opened),
        )
    }

    // ------------------------------------------------------------------ fixtures

    /** The blocker for a draft on an ordinary, authenticated, idle console. */
    private fun blockerFor(
        draft: MaintenanceDraft,
        authenticated: Boolean = true,
        owner: Boolean = true,
        open: Boolean = false,
        working: Boolean = false,
    ) = openBlockerOf(draft, authenticated, owner, open, working)

    private fun window(vararg capabilities: MaintenanceCapability) = MaintenanceWindow(
        EnumSet.copyOf(capabilities.toList()),
        thirtyMinutes,
        1_700_000_000_000L,
        60_000L,
        1_700_000_000_000L,
        60_000L,
    )

    private fun outcome(
        phase: Phase,
        status: MaintenanceStatus,
        window: MaintenanceWindow?,
        closeReason: CloseReason? = null,
        plan: MaintenancePlan? = null,
        restoreProven: Boolean = false,
        failures: List<String> = emptyList(),
        reason: String,
    ) = MaintenanceOutcome(
        phase,
        status,
        window,
        closeReason,
        restoreProven,
        plan,
        null,
        failures,
        reason,
    )
}
