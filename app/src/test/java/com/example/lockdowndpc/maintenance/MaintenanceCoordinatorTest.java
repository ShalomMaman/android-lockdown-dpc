package com.example.lockdowndpc.maintenance;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.maintenance.MaintenanceCoordinator.MaintenanceOutcome;
import com.example.lockdowndpc.maintenance.MaintenanceCoordinator.MaintenanceStatus;
import com.example.lockdowndpc.maintenance.MaintenanceCoordinator.Phase;
import com.example.lockdowndpc.maintenance.MaintenanceStateMachine.CloseReason;
import com.example.lockdowndpc.maintenance.MaintenanceStateMachine.OpenRequest;
import com.example.lockdowndpc.policy.SystemPolicyControl;
import com.example.lockdowndpc.policy.SystemPolicyGateway;
import com.example.lockdowndpc.policy.SystemPolicyProfile;

import org.junit.Test;

import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Maintenance against a device that answers back.
 *
 * <p>The rule this class exists to keep is the engine's oldest one: nothing is
 * reported as in force until it has been read back. Applied to maintenance it
 * cuts both ways, and the dangerous direction is the second — a window that
 * cannot be closed leaves a device relaxed, so a close is only ever "done"
 * because the restrictions read back as restored.
 */
public final class MaintenanceCoordinatorTest {

    private static final int ANDROID_TEN = 29;
    private static final long OPEN_WALL = 1_700_000_000_000L;
    private static final long OPEN_ELAPSED = 60_000L;
    private static final long HALF_HOUR = TimeUnit.MINUTES.toMillis(30);
    private static final String DEBUGGING = "no_debugging_features";
    private static final String USB = "no_usb_file_transfer";
    private static final String UNKNOWN_SOURCES = "no_install_unknown_sources";
    private static final String UNKNOWN_SOURCES_GLOBAL = "no_install_unknown_sources_globally";

    @Test
    public void openingRelaxesTheDeviceAndReadsTheResultBack() {
        FakeGateway gateway = new FakeGateway();
        FakeClock clock = new FakeClock(OPEN_WALL, OPEN_ELAPSED);
        MaintenanceCoordinator coordinator = production(gateway, clock);

        MaintenanceOutcome outcome = coordinator.open(null, request(MaintenanceCapability.ADB_DEBUGGING));

        assertEquals(Phase.OPEN, outcome.phase());
        assertEquals(MaintenanceStatus.APPLIED, outcome.status());
        assertTrue(outcome.windowOpen());
        assertTrue(outcome.windowMustBeStored());
        assertFalse(outcome.failed());
        assertFalse("debugging must actually be off on the device", gateway.inForce.contains(DEBUGGING));
        // Everything the window did not open stays enforced.
        assertTrue(gateway.inForce.contains(USB));
        assertTrue(outcome.plan().relaxesDebugging());
    }

    @Test
    public void aRefusedOpenSendsNothingAndForgetsNothing() {
        FakeGateway gateway = new FakeGateway();
        MaintenanceCoordinator coordinator =
                production(gateway, new FakeClock(OPEN_WALL, OPEN_ELAPSED));
        MaintenanceWindow existing = coordinator
                .open(null, request(MaintenanceCapability.USB_FILE_TRANSFER))
                .window();
        gateway.touched.clear();

        MaintenanceOutcome refused =
                coordinator.open(existing, request(MaintenanceCapability.ADB_DEBUGGING));

        assertEquals(MaintenanceStatus.REFUSED, refused.status());
        assertEquals("already-open", refused.reason());
        assertTrue("a refusal must not touch device policy", gateway.touched.isEmpty());
        assertEquals("the open window must survive a refusal", existing, refused.window());
        assertTrue(refused.windowOpen());
    }

    @Test
    public void anAdministratorWithoutASessionIsRefusedBeforeAnythingIsSent() {
        FakeGateway gateway = new FakeGateway();
        MaintenanceCoordinator coordinator =
                production(gateway, new FakeClock(OPEN_WALL, OPEN_ELAPSED));

        MaintenanceOutcome refused = coordinator.open(
                null,
                new OpenRequest(EnumSet.of(MaintenanceCapability.ADB_DEBUGGING), HALF_HOUR, false));

        assertEquals(MaintenanceStatus.REFUSED, refused.status());
        assertEquals("admin-authentication-required", refused.reason());
        assertTrue(gateway.touched.isEmpty());
        assertNull(refused.window());
    }

    @Test
    public void anOpenThatTheDeviceIgnoresIsUndoneRatherThanReportedAsOpen() {
        // The restriction will not come off. The device is safer than asked for,
        // but the technician was promised a capability that does not exist, so
        // the window is undone and the failure is reported.
        FakeGateway gateway = new FakeGateway();
        gateway.refuseClear.add(DEBUGGING);
        MaintenanceCoordinator coordinator =
                production(gateway, new FakeClock(OPEN_WALL, OPEN_ELAPSED));

        MaintenanceOutcome outcome =
                coordinator.open(null, request(MaintenanceCapability.ADB_DEBUGGING));

        assertEquals(MaintenanceStatus.FAILED, outcome.status());
        assertFalse(outcome.windowOpen());
        assertNull("the restore was verified, so there is nothing left to undo", outcome.window());
        assertEquals(CloseReason.OPEN_FAILED, outcome.closeReason());
        assertEquals("open-failed-policy-restored", outcome.reason());
        assertFalse(outcome.failures().isEmpty());
        assertTrue(gateway.inForce.contains(DEBUGGING));
    }

    @Test
    public void anOpenThatFailsAndCannotBeUndoneKeepsTheRecordForTheNextPass() {
        // The worst case: the device may be partly relaxed. Losing the window
        // here would lose the only record that something has to be restored.
        //
        // Sideloading is two restrictions on Android 10. The global one will not
        // come off, so the open cannot be honoured; the per-user one will not go
        // back on, so the restore cannot be proved either.
        FakeGateway gateway = new FakeGateway();
        gateway.refuseClear.add(UNKNOWN_SOURCES_GLOBAL);
        gateway.ignoreAdd.add(UNKNOWN_SOURCES);
        MaintenanceCoordinator coordinator =
                production(gateway, new FakeClock(OPEN_WALL, OPEN_ELAPSED));

        MaintenanceOutcome outcome =
                coordinator.open(null, request(MaintenanceCapability.LOCAL_APK_INSTALL));

        assertEquals(MaintenanceStatus.FAILED, outcome.status());
        assertEquals("open-failed-restore-failed", outcome.reason());
        assertNotNull("a device that may still be relaxed keeps its window", outcome.window());
        assertTrue(outcome.windowMustBeStored());
        assertFalse("a window with a close reason is not an open window", outcome.windowOpen());
        assertFalse(outcome.restoreVerified());
    }

    @Test
    public void aLiveWindowIsRefreshedWithoutTouchingDevicePolicy() {
        FakeGateway gateway = new FakeGateway();
        MutableClock clock = new MutableClock(OPEN_WALL, OPEN_ELAPSED);
        MaintenanceCoordinator coordinator = production(gateway, clock);
        MaintenanceWindow window =
                coordinator.open(null, request(MaintenanceCapability.ADB_DEBUGGING)).window();
        gateway.touched.clear();

        clock.advance(60_000L);
        MaintenanceOutcome outcome = coordinator.refresh(window);

        assertEquals(Phase.REFRESH, outcome.phase());
        assertEquals(MaintenanceStatus.UNCHANGED, outcome.status());
        assertTrue(outcome.windowOpen());
        assertTrue("a liveness check must not re-send policy", gateway.touched.isEmpty());
        assertEquals(OPEN_ELAPSED + 60_000L, outcome.window().lastSeenElapsed());
    }

    @Test
    public void expiryRestoresTheBasePolicyAndVerifiesIt() {
        FakeGateway gateway = new FakeGateway();
        MutableClock clock = new MutableClock(OPEN_WALL, OPEN_ELAPSED);
        MaintenanceCoordinator coordinator = production(gateway, clock);
        MaintenanceWindow window =
                coordinator.open(null, request(MaintenanceCapability.ADB_DEBUGGING)).window();
        assertFalse(gateway.inForce.contains(DEBUGGING));

        clock.advance(HALF_HOUR);
        MaintenanceOutcome outcome = coordinator.refresh(window);

        assertEquals(Phase.RESTORE, outcome.phase());
        assertEquals(MaintenanceStatus.APPLIED, outcome.status());
        assertEquals(CloseReason.EXPIRED, outcome.closeReason());
        assertTrue(outcome.restoreVerified());
        assertNull("a verified restore leaves nothing to store", outcome.window());
        assertTrue("debugging must be back in force after expiry", gateway.inForce.contains(DEBUGGING));
    }

    @Test
    public void aRebootClosesTheWindowAndPutsTheBasePolicyBack() {
        FakeGateway gateway = new FakeGateway();
        MutableClock clock = new MutableClock(OPEN_WALL, OPEN_ELAPSED);
        MaintenanceCoordinator coordinator = production(gateway, clock);
        MaintenanceWindow window =
                coordinator.open(null, request(MaintenanceCapability.ADB_DEBUGGING)).window();

        clock.reboot(120_000L);
        MaintenanceOutcome outcome = coordinator.refresh(window);

        assertEquals(CloseReason.REBOOT, outcome.closeReason());
        assertTrue(outcome.restoreVerified());
        assertTrue(gateway.inForce.contains(DEBUGGING));
    }

    @Test
    public void aRestoreThatCannotBeProvedIsNeverReportedAsDone() {
        FakeGateway gateway = new FakeGateway();
        MutableClock clock = new MutableClock(OPEN_WALL, OPEN_ELAPSED);
        MaintenanceCoordinator coordinator = production(gateway, clock);
        MaintenanceWindow window =
                coordinator.open(null, request(MaintenanceCapability.ADB_DEBUGGING)).window();

        // The platform now accepts the restore call and does nothing.
        gateway.ignoreAdd.add(DEBUGGING);
        clock.advance(HALF_HOUR);
        MaintenanceOutcome outcome = coordinator.refresh(window);

        assertEquals(MaintenanceStatus.FAILED, outcome.status());
        assertFalse(outcome.restoreVerified());
        assertEquals("restore-failed", outcome.reason());
        assertEquals(CloseReason.EXPIRED, outcome.closeReason());
        assertNotNull("the window stays stored so the next pass retries", outcome.window());
        assertFalse(outcome.failures().isEmpty());
    }

    @Test
    public void cancellingRestoresAndCancellingNothingTouchesNothing() {
        FakeGateway gateway = new FakeGateway();
        MutableClock clock = new MutableClock(OPEN_WALL, OPEN_ELAPSED);
        MaintenanceCoordinator coordinator = production(gateway, clock);
        MaintenanceWindow window =
                coordinator.open(null, request(MaintenanceCapability.ADB_DEBUGGING)).window();

        MaintenanceOutcome cancelled = coordinator.cancel(window);
        assertEquals(CloseReason.ADMINISTRATOR_CANCELLED, cancelled.closeReason());
        assertTrue(cancelled.restoreVerified());
        assertTrue(gateway.inForce.contains(DEBUGGING));

        gateway.touched.clear();
        MaintenanceOutcome nothing = coordinator.cancel(null);
        assertEquals(MaintenanceStatus.UNCHANGED, nothing.status());
        assertNull(nothing.window());
        assertTrue(gateway.touched.isEmpty());
    }

    @Test
    public void refreshingNothingIsNotARestore() {
        FakeGateway gateway = new FakeGateway();
        MaintenanceCoordinator coordinator =
                production(gateway, new FakeClock(OPEN_WALL, OPEN_ELAPSED));

        MaintenanceOutcome outcome = coordinator.refresh(null);

        assertEquals(MaintenanceStatus.UNCHANGED, outcome.status());
        assertNull(outcome.window());
        assertTrue(gateway.touched.isEmpty());
    }

    @Test
    public void anUnreadableRecordStillRestoresTheBasePolicy() {
        // Nothing is known about what was opened, so the only safe reading is
        // that something was, and the base policy is re-applied and read back.
        FakeGateway gateway = new FakeGateway();
        gateway.inForce.remove(DEBUGGING);
        MaintenanceCoordinator coordinator =
                production(gateway, new FakeClock(OPEN_WALL, OPEN_ELAPSED));

        MaintenanceOutcome outcome =
                coordinator.restore(null, CloseReason.UNREADABLE_RECORD);

        assertEquals(Phase.RESTORE, outcome.phase());
        assertTrue(outcome.restoreVerified());
        assertTrue(gateway.inForce.contains(DEBUGGING));
        assertEquals(CloseReason.UNREADABLE_RECORD, outcome.closeReason());
    }

    @Test
    public void theAuditLineCarriesTheDecisionAndNoSecret() {
        FakeGateway gateway = new FakeGateway();
        MaintenanceCoordinator coordinator =
                production(gateway, new FakeClock(OPEN_WALL, OPEN_ELAPSED));

        String summary = coordinator
                .open(null, request(MaintenanceCapability.ADB_DEBUGGING))
                .auditSummary();

        assertEquals(
                "maintenance:open:applied:opened"
                        + ";capabilities=adb_debugging"
                        + ";duration-ms=" + HALF_HOUR
                        + ";relaxed=developer_options_and_adb",
                summary);
        // Stable machine tokens only: no free text an operator could have typed,
        // and nothing derived from a PIN, a recovery code or a kiosk address.
        assertTrue(summary.matches("[A-Za-z0-9:;=,_|/.\\-]+"));
    }

    @Test
    public void theAuditLineNamesAFailedRestoreExplicitly() {
        FakeGateway gateway = new FakeGateway();
        MutableClock clock = new MutableClock(OPEN_WALL, OPEN_ELAPSED);
        MaintenanceCoordinator coordinator = production(gateway, clock);
        MaintenanceWindow window =
                coordinator.open(null, request(MaintenanceCapability.ADB_DEBUGGING)).window();

        gateway.ignoreAdd.add(DEBUGGING);
        clock.advance(HALF_HOUR);
        String summary = coordinator.refresh(window).auditSummary();

        assertTrue(summary, summary.startsWith("maintenance:restore:failed:restore-failed"));
        assertTrue(summary, summary.contains(";close=expired"));
        assertTrue(summary, summary.contains(";failures="));
    }

    @Test
    public void aCoordinatorRefusesToExistWithoutItsSeams() {
        FakeGateway gateway = new FakeGateway();
        FakeClock clock = new FakeClock(OPEN_WALL, OPEN_ELAPSED);
        for (Runnable construction : new Runnable[] {
                () -> new MaintenanceCoordinator(ANDROID_TEN, null, Map.of(), gateway, clock),
                () -> new MaintenanceCoordinator(
                        ANDROID_TEN, SystemPolicyProfile.PILOT, Map.of(), null, clock),
                () -> new MaintenanceCoordinator(
                        ANDROID_TEN, SystemPolicyProfile.PILOT, Map.of(), gateway, null)
        }) {
            org.junit.Assert.assertThrows(IllegalArgumentException.class, construction::run);
        }
    }

    private static MaintenanceCoordinator production(
            SystemPolicyGateway gateway,
            MaintenanceClock clock
    ) {
        return new MaintenanceCoordinator(
                ANDROID_TEN, SystemPolicyProfile.PRODUCTION, Map.of(), gateway, clock);
    }

    private static OpenRequest request(MaintenanceCapability capability) {
        return new OpenRequest(EnumSet.of(capability), HALF_HOUR, true);
    }

    /** Readings that never move. */
    private static class FakeClock implements MaintenanceClock {

        long wall;
        long elapsed;

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

    /** Readings a test can move, together or apart. */
    private static final class MutableClock extends FakeClock {

        MutableClock(long wall, long elapsed) {
            super(wall, elapsed);
        }

        /** Ordinary passage of time: both clocks advance together. */
        void advance(long millis) {
            wall += millis;
            elapsed += millis;
        }

        /** A restart: the monotonic reading goes back to a fresh uptime. */
        void reboot(long newElapsed) {
            wall += TimeUnit.MINUTES.toMillis(5);
            elapsed = newElapsed;
        }
    }

    /**
     * The same in-memory device {@code SystemPolicyEnforcerTest} uses, so
     * maintenance is proved against the behaviour the enforcer is proved against.
     */
    private static final class FakeGateway implements SystemPolicyGateway {

        final Set<String> inForce = new LinkedHashSet<>();
        final Set<String> touched = new LinkedHashSet<>();
        final Set<String> refuseAdd = new HashSet<>();
        final Set<String> refuseClear = new HashSet<>();
        final Set<String> ignoreAdd = new HashSet<>();

        FakeGateway() {
            // A production device starts with its hardened policy already in force.
            inForce.addAll(SystemPolicyControl.allRestrictionKeys(ANDROID_TEN));
        }

        @Override
        public void addRestriction(String key) {
            touched.add(key);
            if (refuseAdd.contains(key)) {
                throw new SecurityException("refused " + key);
            }
            if (ignoreAdd.contains(key)) {
                return;
            }
            inForce.add(key);
        }

        @Override
        public void clearRestriction(String key) {
            touched.add(key);
            if (refuseClear.contains(key)) {
                throw new SecurityException("refused " + key);
            }
            inForce.remove(key);
        }

        @Override
        public boolean isRestrictionInForce(String key) {
            return inForce.contains(key);
        }
    }
}
