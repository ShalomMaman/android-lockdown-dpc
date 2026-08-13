package com.example.lockdowndpc.maintenance;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.maintenance.MaintenanceStateMachine.CloseReason;
import com.example.lockdowndpc.maintenance.MaintenanceStateMachine.Evaluation;
import com.example.lockdowndpc.maintenance.MaintenanceStateMachine.MaintenanceState;
import com.example.lockdowndpc.maintenance.MaintenanceStateMachine.OpenDecision;
import com.example.lockdowndpc.maintenance.MaintenanceStateMachine.OpenRequest;

import org.junit.Test;

import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * The cases nobody can stage on a desk.
 *
 * <p>A maintenance window is the one feature here that deliberately makes a
 * managed device weaker, so the interesting tests are not the happy path but the
 * ways a window could outlive its authorisation: a reboot the device does not
 * announce, a clock moved to buy more time, an expiry landing exactly on the
 * boundary. Each one must fail closed, because the alternative is a debugging
 * transport left open on a device nobody is standing next to.
 */
public final class MaintenanceStateMachineTest {

    private static final long OPEN_WALL = 1_700_000_000_000L;
    private static final long OPEN_ELAPSED = 60_000L;
    private static final long HALF_HOUR = TimeUnit.MINUTES.toMillis(30);

    @Test
    public void aWindowOpensOnlyWithAnAuthenticatedAdministrator() {
        FakeClock clock = new FakeClock(OPEN_WALL, OPEN_ELAPSED);

        OpenDecision decision = MaintenanceStateMachine.open(
                null,
                new OpenRequest(EnumSet.of(MaintenanceCapability.USB_FILE_TRANSFER), HALF_HOUR, false),
                clock);

        assertFalse(decision.allowed());
        assertNull(decision.window());
        assertEquals("admin-authentication-required", decision.reason());
    }

    @Test
    public void aWindowOpensWithTheClockReadingsItWillLaterBeJudgedBy() {
        FakeClock clock = new FakeClock(OPEN_WALL, OPEN_ELAPSED);

        OpenDecision decision = MaintenanceStateMachine.open(null, request(HALF_HOUR), clock);

        assertTrue(decision.allowed());
        assertEquals("opened", decision.reason());
        MaintenanceWindow window = decision.window();
        assertNotNull(window);
        assertEquals(OPEN_WALL, window.openedAtWallClock());
        assertEquals(OPEN_ELAPSED, window.openedAtElapsed());
        assertEquals(OPEN_ELAPSED, window.lastSeenElapsed());
        assertEquals(OPEN_ELAPSED + HALF_HOUR, window.expiresAtElapsed());
        assertTrue(window.breakGlass());
    }

    @Test
    public void aSecondWindowIsRefusedRatherThanReplacingTheFirst() {
        // Replacing it would discard the record of what the first window relaxed,
        // which is the only thing that says what has to be restored.
        FakeClock clock = new FakeClock(OPEN_WALL, OPEN_ELAPSED);
        MaintenanceWindow open = MaintenanceStateMachine.open(null, request(HALF_HOUR), clock).window();

        OpenDecision second = MaintenanceStateMachine.open(open, request(HALF_HOUR), clock);

        assertFalse(second.allowed());
        assertEquals("already-open", second.reason());
    }

    @Test
    public void anEmptyOrUnknownCapabilitySelectionIsRefused() {
        FakeClock clock = new FakeClock(OPEN_WALL, OPEN_ELAPSED);

        assertEquals(
                "no-capability-selected",
                MaintenanceStateMachine.open(
                        null,
                        new OpenRequest(Set.of(), HALF_HOUR, true),
                        clock).reason());

        // A HashSet, unlike an EnumSet, will carry a null through to here.
        Set<MaintenanceCapability> withNull = new HashSet<>();
        withNull.add(MaintenanceCapability.USB_FILE_TRANSFER);
        withNull.add(null);
        assertEquals(
                "unknown-capability",
                MaintenanceStateMachine.open(
                        null,
                        new OpenRequest(withNull, HALF_HOUR, true),
                        clock).reason());

        assertEquals(
                "no-capability-selected",
                MaintenanceStateMachine.open(
                        null,
                        new OpenRequest(null, HALF_HOUR, true),
                        clock).reason());
    }

    @Test
    public void aDurationOutsideTheDocumentedBoundsIsRefused() {
        FakeClock clock = new FakeClock(OPEN_WALL, OPEN_ELAPSED);

        assertEquals("non-positive-duration",
                MaintenanceStateMachine.open(null, request(0L), clock).reason());
        assertEquals("non-positive-duration",
                MaintenanceStateMachine.open(null, request(-1L), clock).reason());
        assertEquals("duration-above-maximum",
                MaintenanceStateMachine.open(
                        null,
                        request(MaintenanceStateMachine.MAX_DURATION_MILLIS + 1),
                        clock).reason());

        // The maximum itself is allowed; the refusal is strictly above it.
        assertTrue(MaintenanceStateMachine.open(
                null,
                request(MaintenanceStateMachine.MAX_DURATION_MILLIS),
                clock).allowed());
    }

    @Test
    public void everyOfferedDurationIsWithinTheEnforcedMaximum() {
        for (long duration : MaintenanceStateMachine.OFFERED_DURATIONS_MILLIS) {
            assertTrue("offered duration above the maximum: " + duration,
                    duration > 0 && duration <= MaintenanceStateMachine.MAX_DURATION_MILLIS);
        }
        assertTrue(MaintenanceStateMachine.OFFERED_DURATIONS_MILLIS
                .contains(MaintenanceStateMachine.DEFAULT_DURATION_MILLIS));
    }

    @Test
    public void anOpenWindowStaysOpenAndCarriesFreshLivenessReadings() {
        MaintenanceWindow window = openWindow(HALF_HOUR);
        FakeClock later = new FakeClock(OPEN_WALL + 60_000L, OPEN_ELAPSED + 60_000L);

        Evaluation evaluation = MaintenanceStateMachine.evaluate(window, later);

        assertTrue(evaluation.open());
        assertFalse(evaluation.needsRestore());
        assertNull(evaluation.closeReason());
        assertEquals(OPEN_ELAPSED + 60_000L, evaluation.window().lastSeenElapsed());
        // The open readings never move, so expiry cannot be pushed out by a heartbeat.
        assertEquals(OPEN_ELAPSED, evaluation.window().openedAtElapsed());
        assertEquals(OPEN_ELAPSED + HALF_HOUR, evaluation.window().expiresAtElapsed());
    }

    @Test
    public void theExpiryBoundaryBelongsToExpiry() {
        MaintenanceWindow window = openWindow(HALF_HOUR);
        long deadline = window.expiresAtElapsed();

        Evaluation justBefore = MaintenanceStateMachine.evaluate(
                window, new FakeClock(OPEN_WALL + HALF_HOUR - 1, deadline - 1));
        assertTrue(justBefore.open());
        assertEquals(1L, justBefore.window().remainingMillis(deadline - 1));

        Evaluation exactly = MaintenanceStateMachine.evaluate(
                window, new FakeClock(OPEN_WALL + HALF_HOUR, deadline));
        assertFalse(exactly.open());
        assertEquals(CloseReason.EXPIRED, exactly.closeReason());
        assertTrue(exactly.needsRestore());
        assertEquals(0L, window.remainingMillis(deadline));
    }

    @Test
    public void aRebootClosesTheWindowEvenWhileTimeRemains() {
        // The monotonic clock restarts at boot, so a stored reading that is now in
        // the future is the reboot nobody reported.
        MaintenanceWindow window = openWindow(HALF_HOUR);

        Evaluation evaluation = MaintenanceStateMachine.evaluate(
                window, new FakeClock(OPEN_WALL + 120_000L, 5_000L));

        assertFalse(evaluation.open());
        assertEquals(CloseReason.REBOOT, evaluation.closeReason());
        assertEquals("monotonic-clock-went-backwards", evaluation.reason());
        assertTrue(evaluation.needsRestore());
        assertNotNull("the window must survive the evaluation so it can be undone",
                evaluation.window());
    }

    @Test
    public void aPowerCycleThatComesBackWithALongerUptimeIsStillARestart() {
        // The device was off for an hour and came back reporting more uptime than
        // before, so the monotonic comparison alone would miss it. The calendar
        // clock ran an hour further than the monotonic one, and that gap is the
        // evidence.
        MaintenanceWindow window = openWindow(MaintenanceStateMachine.MAX_DURATION_MILLIS);

        Evaluation evaluation = MaintenanceStateMachine.evaluate(
                window,
                new FakeClock(OPEN_WALL + TimeUnit.HOURS.toMillis(1), OPEN_ELAPSED + 30_000L));

        assertFalse(evaluation.open());
        assertEquals(CloseReason.REBOOT, evaluation.closeReason());
        assertEquals("boot-gap-detected", evaluation.reason());
    }

    @Test
    public void aCalendarClockMovedBackwardsClosesTheWindow() {
        MaintenanceWindow window = openWindow(HALF_HOUR);

        Evaluation evaluation = MaintenanceStateMachine.evaluate(
                window,
                new FakeClock(
                        OPEN_WALL - MaintenanceStateMachine.CLOCK_BACKWARD_TOLERANCE_MILLIS - 1,
                        OPEN_ELAPSED + 1_000L));

        assertFalse(evaluation.open());
        assertEquals(CloseReason.CLOCK_ANOMALY, evaluation.closeReason());
        assertTrue(evaluation.needsRestore());
    }

    @Test
    public void ordinaryTimeSyncDriftDoesNotCloseTheWindow() {
        // A window that closes every time NTP corrects a second of drift is a
        // window an operator learns to distrust.
        MaintenanceWindow window = openWindow(HALF_HOUR);

        Evaluation evaluation = MaintenanceStateMachine.evaluate(
                window,
                new FakeClock(
                        OPEN_WALL - MaintenanceStateMachine.CLOCK_BACKWARD_TOLERANCE_MILLIS + 1,
                        OPEN_ELAPSED + 1_000L));

        assertTrue(evaluation.open());
    }

    @Test
    public void aCalendarClockPushedForwardCannotExtendTheWindow() {
        // Expiry is measured on the monotonic reading alone, so moving the
        // calendar clock forward only trips the power-off gap check. Either way
        // the window closes; it never gains time.
        MaintenanceWindow window = openWindow(HALF_HOUR);

        Evaluation evaluation = MaintenanceStateMachine.evaluate(
                window,
                new FakeClock(OPEN_WALL + TimeUnit.DAYS.toMillis(1), OPEN_ELAPSED + 1_000L));

        assertFalse(evaluation.open());
        assertEquals(CloseReason.REBOOT, evaluation.closeReason());
    }

    @Test
    public void aMissingClockIsTreatedAsNoEvidenceRatherThanAsAnOpenWindow() {
        MaintenanceWindow window = openWindow(HALF_HOUR);

        Evaluation evaluation = MaintenanceStateMachine.evaluate(window, null);

        assertFalse(evaluation.open());
        assertEquals(CloseReason.UNREADABLE_RECORD, evaluation.closeReason());
        assertTrue(evaluation.needsRestore());
    }

    @Test
    public void evaluatingNothingIsNotARestore() {
        Evaluation evaluation = MaintenanceStateMachine.evaluate(
                null, new FakeClock(OPEN_WALL, OPEN_ELAPSED));

        assertEquals(MaintenanceState.CLOSED, evaluation.state());
        assertFalse("nothing was open, so nothing was restored", evaluation.needsRestore());
        assertNull(evaluation.closeReason());
        assertEquals("no-window", evaluation.reason());
    }

    @Test
    public void cancellingAnOpenWindowRequiresARestoreAndCancellingNothingDoesNot() {
        MaintenanceWindow window = openWindow(HALF_HOUR);

        Evaluation cancelled = MaintenanceStateMachine.cancel(window);
        assertEquals(CloseReason.ADMINISTRATOR_CANCELLED, cancelled.closeReason());
        assertTrue(cancelled.needsRestore());
        assertEquals(window, cancelled.window());

        Evaluation nothing = MaintenanceStateMachine.cancel(null);
        assertFalse(nothing.needsRestore());
        assertEquals("not-open", nothing.reason());
    }

    @Test
    public void anUnreadableRecordAssumesTheDeviceWasRelaxed() {
        Evaluation evaluation = MaintenanceStateMachine.unreadableRecord();

        assertFalse(evaluation.open());
        assertEquals(CloseReason.UNREADABLE_RECORD, evaluation.closeReason());
        assertTrue("a record we cannot read must still trigger a restore",
                evaluation.needsRestore());
        assertNull(evaluation.window());
    }

    @Test
    public void everyCloseReasonHasAStableNonSensitiveToken() {
        for (CloseReason reason : CloseReason.values()) {
            assertEquals(reason.name().toLowerCase(java.util.Locale.ROOT), reason.token());
        }
    }

    @Test
    public void aWindowCannotBeConstructedOutsideTheRulesTheMachineEnforces() {
        // The record is the last line of defence for a value that reached storage
        // some other way, so it refuses the same things the state machine does.
        assertThrows(IllegalArgumentException.class, () -> new MaintenanceWindow(
                EnumSet.noneOf(MaintenanceCapability.class),
                HALF_HOUR, OPEN_WALL, OPEN_ELAPSED, OPEN_WALL, OPEN_ELAPSED));
        assertThrows(IllegalArgumentException.class, () -> new MaintenanceWindow(
                EnumSet.of(MaintenanceCapability.USB_FILE_TRANSFER),
                0L, OPEN_WALL, OPEN_ELAPSED, OPEN_WALL, OPEN_ELAPSED));
        assertThrows(IllegalArgumentException.class, () -> new MaintenanceWindow(
                EnumSet.of(MaintenanceCapability.USB_FILE_TRANSFER),
                MaintenanceStateMachine.MAX_DURATION_MILLIS + 1,
                OPEN_WALL, OPEN_ELAPSED, OPEN_WALL, OPEN_ELAPSED));
    }

    @Test
    public void breakGlassIsNeverImpliedByAnotherCapability() {
        for (MaintenanceCapability capability : MaintenanceCapability.values()) {
            if (capability == MaintenanceCapability.ADB_DEBUGGING) {
                continue;
            }
            assertFalse(capability + " must not be break-glass", capability.breakGlass());
            assertFalse(
                    capability + " must not relax debugging",
                    capability.relaxes().contains(
                            com.example.lockdowndpc.policy.SystemPolicyControl
                                    .DEVELOPER_OPTIONS_AND_ADB));
        }
        assertTrue(MaintenanceCapability.ADB_DEBUGGING.breakGlass());
    }

    @Test
    public void theCapabilitySummaryIsStableAndCarriesNoSecret() {
        MaintenanceWindow window = MaintenanceWindow.opened(
                EnumSet.of(
                        MaintenanceCapability.ADB_DEBUGGING,
                        MaintenanceCapability.APP_STORE_ACCESS),
                HALF_HOUR,
                new FakeClock(OPEN_WALL, OPEN_ELAPSED));

        // Enum declaration order, not selection order, so two identical windows
        // produce one identical audit line.
        assertEquals("app_store_access,adb_debugging", window.capabilitySummary());
        assertEquals("", MaintenanceCapability.summarize(Set.of()));
        assertEquals("", MaintenanceCapability.summarize(null));
    }

    @Test
    public void storageKeysRoundTripAndAnUnknownKeyIsNull() {
        for (MaintenanceCapability capability : MaintenanceCapability.values()) {
            assertEquals(capability,
                    MaintenanceCapability.fromStorageKey(capability.storageKey()));
        }
        assertNull(MaintenanceCapability.fromStorageKey("capability_from_a_later_release"));
        assertNull(MaintenanceCapability.fromStorageKey(""));
    }

    private static OpenRequest request(long durationMillis) {
        return new OpenRequest(
                EnumSet.of(MaintenanceCapability.ADB_DEBUGGING),
                durationMillis,
                true);
    }

    private static MaintenanceWindow openWindow(long durationMillis) {
        return MaintenanceStateMachine.open(
                null,
                request(durationMillis),
                new FakeClock(OPEN_WALL, OPEN_ELAPSED)).window();
    }

    /** Two readings that move only when a test moves them. */
    private static final class FakeClock implements MaintenanceClock {

        private final long wall;
        private final long elapsed;

        FakeClock(long wall, long elapsed) {
            this.wall = wall;
            this.elapsed = elapsed;
        }

        @Override
        public long wallClockMillis() {
            return wall;
        }

        @Override
        public long elapsedSinceBootMillis() {
            return elapsed;
        }
    }
}
