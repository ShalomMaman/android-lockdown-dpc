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
import java.util.List;
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
    private static final String INSTALL_APPS = "no_install_apps";
    private static final String PLAY_STORE = "com.android.vending";

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
    public void applicationStoreAccessIsVisibleOnlyAfterCapabilityReadBack() {
        FakeGateway gateway = new FakeGateway();
        FakeCapabilityGateway capabilities = new FakeCapabilityGateway();
        MaintenanceCoordinator coordinator = production(
                gateway,
                capabilities,
                new FakeClock(OPEN_WALL, OPEN_ELAPSED));

        MaintenanceOutcome opened = coordinator.open(
                null,
                request(MaintenanceCapability.APP_STORE_ACCESS));

        assertEquals(MaintenanceStatus.APPLIED, opened.status());
        assertTrue("the verified window must expose stores", capabilities.storesVisible);

        MaintenanceOutcome closed = coordinator.cancel(opened.window());
        assertTrue(closed.restoreVerified());
        assertFalse("closing must verify stores are hidden again", capabilities.storesVisible);
    }

    @Test
    public void aStoreThatCannotBeShownMakesOpeningFailAndRestoresProtection() {
        FakeGateway gateway = new FakeGateway();
        FakeCapabilityGateway capabilities = new FakeCapabilityGateway();
        capabilities.failOpen = true;
        MaintenanceCoordinator coordinator = production(
                gateway,
                capabilities,
                new FakeClock(OPEN_WALL, OPEN_ELAPSED));

        MaintenanceOutcome outcome = coordinator.open(
                null,
                request(MaintenanceCapability.APP_STORE_ACCESS));

        assertEquals(MaintenanceStatus.FAILED, outcome.status());
        assertTrue(outcome.restoreProven());
        assertFalse(capabilities.storesVisible);
        assertTrue(outcome.failures().contains("maintenance-store-state-mismatch:test.store"));
    }

    @Test
    public void aStoreThatCannotBeHiddenKeepsTheRestoreDebt() {
        FakeGateway gateway = new FakeGateway();
        FakeCapabilityGateway capabilities = new FakeCapabilityGateway();
        MaintenanceCoordinator coordinator = production(
                gateway,
                capabilities,
                new FakeClock(OPEN_WALL, OPEN_ELAPSED));
        MaintenanceWindow window = coordinator.open(
                null,
                request(MaintenanceCapability.APP_STORE_ACCESS)).window();
        capabilities.failRestore = true;

        MaintenanceOutcome outcome = coordinator.cancel(window);

        assertEquals(MaintenanceStatus.FAILED, outcome.status());
        assertFalse(outcome.restoreVerified());
        assertNotNull("an unverified store restore must remain retryable", outcome.window());
        assertNull("a failed close must not persist a live authorization",
                outcome.windowForPersistence());
        assertTrue(capabilities.storesVisible);
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
                new OpenRequest(EnumSet.of(MaintenanceCapability.ADB_DEBUGGING), HALF_HOUR, false, true));

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
        // Proven, though the phase is OPEN: the phase-specific restoreVerified()
        // once hid this, so the pending-restore flag survived a verified restore
        // and the next pass re-restored a device already proven clean.
        assertTrue(outcome.restoreProven());
        assertFalse(outcome.restoreVerified());
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
        assertFalse("an unproven restore is never a proven one", outcome.restoreProven());
        assertTrue("a failed-open window remains available as failure evidence",
                outcome.windowMustBeStored());
        assertNull(outcome.windowForPersistence());
        assertTrue(outcome.restoreOwed());
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
        assertNotNull("the old window remains available as failure evidence", outcome.window());
        assertNull("expiry failure must leave debt without a reopenable window",
                outcome.windowForPersistence());
        assertTrue(outcome.restoreOwed());
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
    public void aFailedDebtOnlyRestoreIsNeverMistakenForProof() {
        FakeGateway gateway = new FakeGateway();
        FakeCapabilityGateway capabilities = new FakeCapabilityGateway();
        capabilities.failRestore = true;
        MaintenanceCoordinator coordinator = production(
                gateway,
                capabilities,
                new FakeClock(OPEN_WALL, OPEN_ELAPSED));

        MaintenanceOutcome outcome =
                coordinator.restore(null, CloseReason.UNREADABLE_RECORD);

        assertEquals(Phase.RESTORE, outcome.phase());
        assertEquals(MaintenanceStatus.FAILED, outcome.status());
        assertNull(outcome.window());
        assertFalse(outcome.restoreProven());
        assertTrue(outcome.restoreOwed());
        assertNull(outcome.windowForPersistence());
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
                () -> new MaintenanceCoordinator(
                        ANDROID_TEN, null, Map.of(), gateway, new FakeCapabilityGateway(), clock),
                () -> new MaintenanceCoordinator(
                        ANDROID_TEN, SystemPolicyProfile.PILOT, Map.of(), null,
                        new FakeCapabilityGateway(), clock),
                () -> new MaintenanceCoordinator(
                        ANDROID_TEN, SystemPolicyProfile.PILOT, Map.of(), gateway, null, clock),
                () -> new MaintenanceCoordinator(
                        ANDROID_TEN, SystemPolicyProfile.PILOT, Map.of(), gateway,
                        new FakeCapabilityGateway(), null)
        }) {
            org.junit.Assert.assertThrows(IllegalArgumentException.class, construction::run);
        }
    }

    @Test
    public void restoreProofCannotBeAttachedToAnOpenOrUnverifiedOutcome() {
        MaintenanceWindow open = new MaintenanceWindow(
                EnumSet.of(MaintenanceCapability.ADB_DEBUGGING),
                HALF_HOUR,
                OPEN_WALL,
                OPEN_ELAPSED,
                OPEN_WALL,
                OPEN_ELAPSED);

        org.junit.Assert.assertThrows(IllegalArgumentException.class, () ->
                new MaintenanceOutcome(
                        Phase.OPEN,
                        MaintenanceStatus.APPLIED,
                        open,
                        null,
                        true,
                        null,
                        null,
                        List.of(),
                        "invalid-proof"));
        org.junit.Assert.assertThrows(IllegalArgumentException.class, () ->
                new MaintenanceOutcome(
                        Phase.RESTORE,
                        MaintenanceStatus.FAILED,
                        null,
                        CloseReason.UNREADABLE_RECORD,
                        true,
                        null,
                        null,
                        List.of("restore-failed"),
                        "invalid-proof"));
    }

    // ------------------------------------------- precondition ordering (#64)

    @Test
    public void thePreconditionRunsBeforeAnyRestrictionIsRelaxed() {
        // The exposure this ordering closes is the Google Play Store's own
        // interface and network surface, which no installation restriction shuts.
        // Proving it needs the order, not the end state: a Store hidden after the
        // relaxations still leaves an interval in which both are live.
        List<String> log = new java.util.ArrayList<>();
        FakeGateway gateway = new FakeGateway(log);
        OrderedCapabilityGateway capabilities = new OrderedCapabilityGateway(log);

        MaintenanceOutcome outcome = production(gateway, capabilities, new FakeClock(OPEN_WALL, OPEN_ELAPSED))
                .open(null, request(MaintenanceCapability.LOCAL_APK_INSTALL));

        assertEquals(MaintenanceStatus.APPLIED, outcome.status());
        assertEquals("prepare", log.get(0));
        assertTrue(
                "no restriction may be touched before the precondition: " + log,
                log.indexOf("prepare") < log.indexOf("clear:" + UNKNOWN_SOURCES));
        assertTrue(
                "store visibility is applied after the restrictions: " + log,
                log.indexOf("clear:" + UNKNOWN_SOURCES) < log.indexOf("open"));
    }

    @Test
    public void storeAccessStillRelaxesRestrictionsBeforeUnhidingStores() {
        // The other ordering, unchanged: a store must not become visible while the
        // installation controls it needs are still in force.
        List<String> log = new java.util.ArrayList<>();
        FakeGateway gateway = new FakeGateway(log);
        OrderedCapabilityGateway capabilities = new OrderedCapabilityGateway(log);

        MaintenanceOutcome outcome = production(gateway, capabilities, new FakeClock(OPEN_WALL, OPEN_ELAPSED))
                .open(null, request(MaintenanceCapability.APP_STORE_ACCESS));

        assertEquals(MaintenanceStatus.APPLIED, outcome.status());
        assertTrue(capabilities.storesVisible);
        assertTrue(
                "restrictions come off before the stores appear: " + log,
                log.indexOf("clear:" + INSTALL_APPS) < log.indexOf("open"));
    }

    @Test
    public void aPreconditionFailureRefusesTheWindowWithNothingRelaxed() {
        // Fail-closed and complete: no window, no relaxation, no report to imply
        // one, and the failure carried through so the console can name it.
        List<String> log = new java.util.ArrayList<>();
        FakeGateway gateway = new FakeGateway(log);
        OrderedCapabilityGateway capabilities = new OrderedCapabilityGateway(log);
        capabilities.failPrepare = true;

        MaintenanceOutcome outcome = production(gateway, capabilities, new FakeClock(OPEN_WALL, OPEN_ELAPSED))
                .open(null, request(MaintenanceCapability.LOCAL_APK_INSTALL));

        assertEquals(Phase.OPEN, outcome.phase());
        assertEquals(MaintenanceStatus.REFUSED, outcome.status());
        assertEquals("precondition-unverified", outcome.reason());
        assertNull(outcome.window());
        assertFalse(outcome.windowOpen());
        assertFalse(outcome.windowMustBeStored());
        assertNull(outcome.plan());
        assertTrue(outcome.report().statuses().isEmpty());
        assertEquals(List.of("maintenance-precondition:test-store-not-hidden"), outcome.failures());
        assertEquals("nothing may be sent to the restriction gateway: " + log, List.of("prepare"), log);
        assertTrue(gateway.touched.isEmpty());
    }

    @Test
    public void aRefusedPreconditionDoesNotForgetAnAlreadyOpenWindow() {
        // A refusal must never be a way to lose an authorization that is live.
        FakeClock clock = new FakeClock(OPEN_WALL, OPEN_ELAPSED);
        OrderedCapabilityGateway capabilities = new OrderedCapabilityGateway(new java.util.ArrayList<>());
        MaintenanceCoordinator coordinator = production(new FakeGateway(), capabilities, clock);
        MaintenanceWindow current =
                coordinator.open(null, request(MaintenanceCapability.USB_FILE_TRANSFER)).window();
        assertNotNull(current);

        capabilities.failPrepare = true;
        MaintenanceOutcome outcome =
                coordinator.open(current, request(MaintenanceCapability.LOCAL_APK_INSTALL));

        assertEquals(MaintenanceStatus.REFUSED, outcome.status());
        assertEquals(current, outcome.window());
        // windowMustBeStored keeps the caller's restore debt owed for the window
        // that is genuinely open, which is what MaintenanceGuard.open reads.
        assertTrue(outcome.windowMustBeStored());
    }

    // ------------------------------- the saved-off-without-apply transition (#64)

    /**
     * The reported P1, end to end, through the real capability gateway.
     *
     * <p>Seeded exactly as the device is after the transition: compatibility was
     * enabled <em>and applied</em>, so {@code com.android.vending} is visible on
     * the device; the administrator has since saved the switch back to off
     * <em>without</em> applying, so the base policy no longer pins the
     * installation lock. Opening a local-APK window in that state used to leave
     * the already visible Store beside cleared unknown-source restrictions, with
     * no application-store authorisation anywhere in the transaction.
     *
     * <p>No preference is passed to anything here, which is the fix: the
     * precondition is a property of the window.
     */
    @Test
    public void aVisibleStoreIsHiddenBeforeAnyRestrictionIsClearedAfterCompatibilityIsSavedOff() {
        List<String> log = new java.util.ArrayList<>();
        FakeGateway gateway = new FakeGateway(log);
        // The Store is visible: compatibility was applied before it was saved off.
        FakeStoreDevice store = new FakeStoreDevice(log, false);
        MaintenanceCoordinator coordinator = new MaintenanceCoordinator(
                ANDROID_TEN,
                SystemPolicyProfile.PRODUCTION,
                // The base policy no longer pins the installation lock, because
                // the compatibility floor is gone the moment the switch is saved.
                Map.of(),
                gateway,
                new AndroidMaintenanceCapabilityGateway(store),
                new FakeClock(OPEN_WALL, OPEN_ELAPSED));

        MaintenanceOutcome outcome =
                coordinator.open(null, request(MaintenanceCapability.LOCAL_APK_INSTALL));

        assertEquals(MaintenanceStatus.APPLIED, outcome.status());
        assertTrue("the Store must end up hidden", store.playStoreHidden());

        int hiddenAt = log.indexOf("store-hidden:" + PLAY_STORE);
        assertTrue("the Store was never hidden: " + log, hiddenAt >= 0);
        for (int index = 0; index < log.size(); index++) {
            String entry = log.get(index);
            if (entry.startsWith("clear:") || entry.startsWith("add:")) {
                assertTrue(
                        "restriction " + entry + " was written before the Store was hidden: " + log,
                        index > hiddenAt);
            }
        }
        // And the read-back is part of the precondition, not an afterthought.
        assertTrue(
                "the hide must be read back before any restriction write: " + log,
                log.indexOf("store-read:" + PLAY_STORE + ":true") > hiddenAt
                        && log.indexOf("store-read:" + PLAY_STORE + ":true")
                                < firstRestrictionWrite(log));
    }

    @Test
    public void aStoreThatCannotBeHiddenRefusesTheWindowBeforeAnyRestrictionIsCleared() {
        List<String> log = new java.util.ArrayList<>();
        FakeGateway gateway = new FakeGateway(log);
        FakeStoreDevice store = new FakeStoreDevice(log, false);
        store.refuseWrites = true;
        MaintenanceCoordinator coordinator = new MaintenanceCoordinator(
                ANDROID_TEN,
                SystemPolicyProfile.PRODUCTION,
                Map.of(),
                gateway,
                new AndroidMaintenanceCapabilityGateway(store),
                new FakeClock(OPEN_WALL, OPEN_ELAPSED));

        MaintenanceOutcome outcome =
                coordinator.open(null, request(MaintenanceCapability.LOCAL_APK_INSTALL));

        assertEquals(MaintenanceStatus.REFUSED, outcome.status());
        assertEquals("precondition-unverified", outcome.reason());
        assertNull(outcome.window());
        assertFalse(store.playStoreHidden());
        assertTrue(
                "no restriction may be written when the precondition failed: " + log,
                log.stream().noneMatch(entry ->
                        entry.startsWith("clear:") || entry.startsWith("add:")));
        assertTrue(gateway.touched.isEmpty());
    }

    @Test
    public void anAbsentStoreDoesNotBlockALocalApkWindow() {
        List<String> log = new java.util.ArrayList<>();
        FakeStoreDevice store = new FakeStoreDevice(log, false);
        store.installed = false;
        MaintenanceCoordinator coordinator = new MaintenanceCoordinator(
                ANDROID_TEN,
                SystemPolicyProfile.PRODUCTION,
                Map.of(),
                new FakeGateway(log),
                new AndroidMaintenanceCapabilityGateway(store),
                new FakeClock(OPEN_WALL, OPEN_ELAPSED));

        MaintenanceOutcome outcome =
                coordinator.open(null, request(MaintenanceCapability.LOCAL_APK_INSTALL));

        assertEquals(MaintenanceStatus.APPLIED, outcome.status());
    }

    @Test
    public void storeAccessThroughTheRealGatewayUnhidesOnlyAfterTheRestrictions() {
        // The other ordering, through the production gateway: a store must not
        // become visible while the installation controls it needs are in force.
        List<String> log = new java.util.ArrayList<>();
        FakeStoreDevice store = new FakeStoreDevice(log, true);
        MaintenanceCoordinator coordinator = new MaintenanceCoordinator(
                ANDROID_TEN,
                SystemPolicyProfile.PRODUCTION,
                Map.of(SystemPolicyControl.APP_STORES_AND_INSTALLERS, true),
                new FakeGateway(log),
                new AndroidMaintenanceCapabilityGateway(store),
                new FakeClock(OPEN_WALL, OPEN_ELAPSED));

        MaintenanceOutcome outcome =
                coordinator.open(null, request(MaintenanceCapability.APP_STORE_ACCESS));

        assertEquals(MaintenanceStatus.APPLIED, outcome.status());
        assertFalse("the Store is visible for the window", store.playStoreHidden());
        assertTrue(
                "the installation lock comes off before the Store appears: " + log,
                log.indexOf("clear:" + INSTALL_APPS)
                        < log.indexOf("store-shown:" + PLAY_STORE));
    }

    /** The index of the first restriction write, or {@code log.size()} when none. */
    private static int firstRestrictionWrite(List<String> log) {
        for (int index = 0; index < log.size(); index++) {
            String entry = log.get(index);
            if (entry.startsWith("clear:") || entry.startsWith("add:")) {
                return index;
            }
        }
        return log.size();
    }

    private static MaintenanceCoordinator production(
            SystemPolicyGateway gateway,
            MaintenanceClock clock
    ) {
        return production(gateway, new FakeCapabilityGateway(), clock);
    }

    private static MaintenanceCoordinator production(
            SystemPolicyGateway gateway,
            MaintenanceCapabilityGateway capabilityGateway,
            MaintenanceClock clock
    ) {
        return new MaintenanceCoordinator(
                ANDROID_TEN,
                SystemPolicyProfile.PRODUCTION,
                Map.of(),
                gateway,
                capabilityGateway,
                clock);
    }

    private static OpenRequest request(MaintenanceCapability capability) {
        return new OpenRequest(EnumSet.of(capability), HALF_HOUR, true, true);
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
        /** Every call in order, shared with the capability gateway for ordering proofs. */
        final List<String> log;

        FakeGateway() {
            this(new java.util.ArrayList<>());
        }

        FakeGateway(List<String> log) {
            this.log = log;
            // A production device starts with its hardened policy already in force.
            inForce.addAll(SystemPolicyControl.allRestrictionKeys(ANDROID_TEN));
        }

        @Override
        public void addRestriction(String key) {
            touched.add(key);
            log.add("add:" + key);
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
            log.add("clear:" + key);
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

    private static final class FakeCapabilityGateway implements MaintenanceCapabilityGateway {
        boolean storesVisible;
        boolean failOpen;
        boolean failRestore;

        @Override
        public List<String> prepare(MaintenanceWindow window) {
            return List.of();
        }

        @Override
        public List<String> open(MaintenanceWindow window) {
            if (!MaintenanceAppPolicy.opensApplicationStores(window)) {
                return List.of();
            }
            if (failOpen) {
                return List.of("maintenance-store-state-mismatch:test.store");
            }
            storesVisible = true;
            return List.of();
        }

        @Override
        public List<String> restore() {
            if (failRestore) {
                return List.of("maintenance-store-state-mismatch:test.store");
            }
            storesVisible = false;
            return List.of();
        }
    }

    /**
     * A device that models Play Store visibility, sharing the restriction gateway's
     * log so the order of the two boundaries is provable.
     *
     * <p>Used with the production {@link AndroidMaintenanceCapabilityGateway}
     * rather than a stub, so these cases exercise the real precondition rather
     * than a test double's idea of it.
     */
    private static final class FakeStoreDevice
            implements AndroidMaintenanceCapabilityGateway.StoreVisibilityDevice {

        private final List<String> log;
        private final Set<String> hiddenPackages = new LinkedHashSet<>();
        boolean installed = true;
        boolean refuseWrites;

        /** @param playStoreHidden the Play Store's visibility before the window */
        FakeStoreDevice(List<String> log, boolean playStoreHidden) {
            this.log = log;
            if (playStoreHidden) {
                hiddenPackages.add(PLAY_STORE);
            }
        }

        /** Whether the Play Store — the package under test — is hidden right now. */
        boolean playStoreHidden() {
            return hiddenPackages.contains(PLAY_STORE);
        }

        @Override
        public boolean isInstalled(String packageName) {
            return installed;
        }

        @Override
        public boolean isHidden(String packageName) {
            boolean hidden = hiddenPackages.contains(packageName);
            log.add("store-read:" + packageName + ":" + hidden);
            return hidden;
        }

        @Override
        public boolean setHidden(String packageName, boolean hide) {
            if (refuseWrites) {
                log.add("store-write-refused:" + packageName);
                return false;
            }
            if (hide) {
                hiddenPackages.add(packageName);
            } else {
                hiddenPackages.remove(packageName);
            }
            log.add((hide ? "store-hidden:" : "store-shown:") + packageName);
            return true;
        }
    }

    /**
     * The same fake, writing each call into a log shared with {@link FakeGateway}.
     *
     * <p>Ordering is the property under test, not the end state, so the proof has
     * to be a sequence: a Store hidden after the relaxations lands in the same
     * final state as one hidden before them, and only one of the two is safe.
     */
    private static final class OrderedCapabilityGateway implements MaintenanceCapabilityGateway {

        private final List<String> log;
        boolean storesVisible;
        boolean failPrepare;

        OrderedCapabilityGateway(List<String> log) {
            this.log = log;
        }

        @Override
        public List<String> prepare(MaintenanceWindow window) {
            log.add("prepare");
            return failPrepare
                    ? List.of("maintenance-precondition:test-store-not-hidden")
                    : List.of();
        }

        @Override
        public List<String> open(MaintenanceWindow window) {
            log.add("open");
            if (MaintenanceAppPolicy.opensApplicationStores(window)) {
                storesVisible = true;
            }
            return List.of();
        }

        @Override
        public List<String> restore() {
            log.add("restore");
            storesVisible = false;
            return List.of();
        }
    }
}
