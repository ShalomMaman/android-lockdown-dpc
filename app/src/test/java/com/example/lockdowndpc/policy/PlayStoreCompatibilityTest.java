package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.kiosk.KioskAppCatalog;
import com.example.lockdowndpc.maintenance.MaintenanceCapability;
import com.example.lockdowndpc.maintenance.MaintenancePlan;
import com.example.lockdowndpc.maintenance.MaintenanceWindow;

import org.junit.Test;

import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * The Google Play compatibility exception (Issue #64).
 *
 * <p>Three properties are what this file exists to pin, because each of them is
 * a way the feature could quietly become a hole rather than an exception:
 *
 * <ul>
 *   <li>Strict is the default and nothing infers the opt-in.</li>
 *   <li>The Store is made available only after this pass read the installation
 *       lock back from the device; a refusal hides it again <em>and</em> faults
 *       protection.</li>
 *   <li>A maintenance window relaxes the floor for its duration and the restore
 *       puts the floor back — not the administrator's raw switches, which would
 *       end a window with the Store available and installs unlocked.</li>
 * </ul>
 *
 * <p>The verified cases drive the real {@link SystemPolicyEnforcer} through a
 * fake gateway rather than hand-building a report, so a change to how a control
 * is applied or read back reaches this file instead of passing silently.
 */
public final class PlayStoreCompatibilityTest {

    private static final int ANDROID_THIRTEEN = 33;
    private static final long HALF_HOUR = TimeUnit.MINUTES.toMillis(30);

    private static final String DISALLOW_INSTALL_APPS = "no_install_apps";
    private static final String PLAY_STORE = PlayStoreCompatibility.PLAY_STORE_PACKAGE;

    // ------------------------------------------------------------ strict default

    @Test
    public void strictIsTheDefaultAndTheStoreStaysHidden() {
        Map<SystemPolicyControl, Boolean> stored =
                Map.of(SystemPolicyControl.WIFI_CONFIGURATION, true);

        assertEquals(stored, PlayStoreCompatibility.baseChoices(false, stored));
        assertEquals(
                PlayStoreCompatibility.State.STRICT,
                PlayStoreCompatibility.evaluateOutcomes(false, Set.of(), allApplied()));
        assertFalse(PlayStoreCompatibility.State.STRICT.keepsPlayStoreAvailable());
        assertFalse(PlayStoreCompatibility.keepsAvailable(PLAY_STORE, false));
    }

    @Test
    public void theOptInIsNeverInferred() {
        // The only input that can turn the exception on is the administrator's
        // stored decision. A device whose installation controls happen to be
        // enforced, and verified, is still strict.
        assertEquals(
                PlayStoreCompatibility.State.STRICT,
                PlayStoreCompatibility.evaluateOutcomes(false, Set.of(), allApplied()));
        assertEquals(
                Map.of(SystemPolicyControl.APP_STORES_AND_INSTALLERS, true),
                PlayStoreCompatibility.baseChoices(
                        false, Map.of(SystemPolicyControl.APP_STORES_AND_INSTALLERS, true)));
    }

    @Test
    public void aPilotThatNeverTouchesTheScreenEnforcesWhatItEnforcedBefore() {
        // The exception adds no SystemPolicyControl and moves no default, so the
        // opt-in installation lock stays opt-in for everyone who did not ask.
        assertFalse(SystemPolicyControl.APP_STORES_AND_INSTALLERS
                .defaultRequested(SystemPolicyProfile.PILOT));
        assertFalse(SystemPolicyControl.APP_STORES_AND_INSTALLERS
                .defaultRequested(SystemPolicyProfile.PRODUCTION));
    }

    // -------------------------------------------------------------- the floor

    @Test
    public void optingInPinsTheInstallationControlsOn() {
        Map<SystemPolicyControl, Boolean> stored = new LinkedHashMap<>();
        stored.put(SystemPolicyControl.APP_STORES_AND_INSTALLERS, false);
        stored.put(SystemPolicyControl.UNKNOWN_SOURCE_INSTALLS, false);

        Map<SystemPolicyControl, Boolean> base = PlayStoreCompatibility.baseChoices(true, stored);

        for (SystemPolicyControl control : PlayStoreCompatibility.REQUIRED_INSTALL_CONTROLS) {
            assertTrue(
                    control + " must be pinned on by the compatibility floor",
                    SystemPolicyEnforcer.requestedFor(control, SystemPolicyProfile.PILOT, base));
            assertTrue(PlayStoreCompatibility.locksControl(control, true));
            assertFalse(PlayStoreCompatibility.locksControl(control, false));
        }
    }

    @Test
    public void theFloorTouchesNothingElse() {
        Map<SystemPolicyControl, Boolean> stored = new LinkedHashMap<>();
        stored.put(SystemPolicyControl.DEVELOPER_OPTIONS_AND_ADB, false);
        stored.put(SystemPolicyControl.WIFI_CONFIGURATION, true);

        Map<SystemPolicyControl, Boolean> base = PlayStoreCompatibility.baseChoices(true, stored);

        assertEquals(Boolean.FALSE, base.get(SystemPolicyControl.DEVELOPER_OPTIONS_AND_ADB));
        assertEquals(Boolean.TRUE, base.get(SystemPolicyControl.WIFI_CONFIGURATION));
        assertFalse(PlayStoreCompatibility.locksControl(
                SystemPolicyControl.DEVELOPER_OPTIONS_AND_ADB, true));
        assertFalse(PlayStoreCompatibility.locksControl(
                SystemPolicyControl.APP_UNINSTALL, true));
        assertFalse(PlayStoreCompatibility.locksControl(null, true));
    }

    // ------------------------------------------------- verified, and fail-closed

    @Test
    public void aVerifiedInstallLockMakesExactlyOnePackageAvailable() {
        FakeGateway gateway = new FakeGateway();

        SystemPolicyReport report = enforceWithCompatibility(gateway);
        PlayStoreCompatibility.State state =
                PlayStoreCompatibility.evaluate(true, Set.of(), report);

        assertEquals(PlayStoreCompatibility.State.ACTIVE, state);
        assertFalse(state.faultsProtection());
        assertTrue(gateway.inForce.contains(DISALLOW_INSTALL_APPS));
        assertTrue(gateway.inForce.contains("no_install_unknown_sources"));
        assertFalse(report.faulted());

        assertTrue(PlayStoreCompatibility.keepsAvailable(PLAY_STORE, true));
        for (String otherStore : new String[]{
                "com.sec.android.app.samsungapps",
                "com.xiaomi.mipicks",
                "com.huawei.appmarket",
                "com.amazon.venezia",
                "com.android.chrome"
        }) {
            assertFalse(
                    otherStore + " must stay blocked",
                    PlayStoreCompatibility.keepsAvailable(otherStore, true));
        }
    }

    @Test
    public void aSilentlyIgnoredInstallLockKeepsTheStoreHidden() {
        // The platform accepts addUserRestriction and changes nothing — the exact
        // case in which a saved switch would imply an enforcement that is not there.
        FakeGateway gateway = new FakeGateway();
        gateway.ignoreAdd.add(DISALLOW_INSTALL_APPS);

        SystemPolicyReport report = enforceWithCompatibility(gateway);
        PlayStoreCompatibility.State state =
                PlayStoreCompatibility.evaluate(true, Set.of(), report);

        assertEquals(PlayStoreCompatibility.State.INSTALL_LOCK_UNVERIFIED, state);
        assertFalse(state.keepsPlayStoreAvailable());
        assertFalse(PlayStoreCompatibility.keepsAvailable(
                PLAY_STORE, state.keepsPlayStoreAvailable()));
        assertTrue(state.faultsProtection());
        // The critical control faults protection on its own as well, so the pass
        // can never be reported as active over an unverified installation lock.
        assertTrue(report.faulted());
    }

    @Test
    public void anUnreadableInstallLockKeepsTheStoreHidden() {
        FakeGateway gateway = new FakeGateway();
        gateway.unreadable.add(DISALLOW_INSTALL_APPS);

        PlayStoreCompatibility.State state = PlayStoreCompatibility.evaluate(
                true, Set.of(), enforceWithCompatibility(gateway));

        assertEquals(PlayStoreCompatibility.State.INSTALL_LOCK_UNVERIFIED, state);
        assertFalse(state.keepsPlayStoreAvailable());
    }

    @Test
    public void aRefusedUnknownSourceLockAlsoKeepsTheStoreHidden() {
        // Both required controls count. Blocking stores while unknown sources stay
        // open would leave a device with the Store available and a working
        // sideload path, which is the weaker half of the pair, not the safer one.
        FakeGateway gateway = new FakeGateway();
        gateway.refuseAdd.add("no_install_unknown_sources");

        assertEquals(
                PlayStoreCompatibility.State.INSTALL_LOCK_UNVERIFIED,
                PlayStoreCompatibility.evaluate(true, Set.of(), enforceWithCompatibility(gateway)));
    }

    @Test
    public void anAbsentVerdictIsNotEnforcement() {
        // A control with no recorded outcome — a fresh opt-in the console has not
        // applied yet — is the absence of evidence, not evidence of a lock.
        assertEquals(
                PlayStoreCompatibility.State.INSTALL_LOCK_UNVERIFIED,
                PlayStoreCompatibility.evaluateOutcomes(true, Set.of(), Map.of()));
        assertEquals(
                PlayStoreCompatibility.State.INSTALL_LOCK_UNVERIFIED,
                PlayStoreCompatibility.evaluateOutcomes(
                        true,
                        Set.of(),
                        Map.of(
                                SystemPolicyControl.APP_STORES_AND_INSTALLERS,
                                SystemPolicyOutcome.REQUESTED,
                                SystemPolicyControl.UNKNOWN_SOURCE_INSTALLS,
                                SystemPolicyOutcome.APPLIED)));
    }

    // ---------------------------------------------------------- maintenance

    @Test
    public void aWindowThatOpensInstallsIsNotAFailedInstallLock() {
        Map<SystemPolicyControl, Boolean> base =
                PlayStoreCompatibility.baseChoices(true, Map.of());
        MaintenancePlan plan = planFor(base, MaintenanceCapability.APP_STORE_ACCESS);

        FakeGateway gateway = new FakeGateway();
        SystemPolicyReport report = SystemPolicyEnforcer.enforce(
                ANDROID_THIRTEEN, SystemPolicyProfile.PILOT, plan.effectiveChoices(), gateway);

        assertTrue(plan.relaxed().contains(SystemPolicyControl.APP_STORES_AND_INSTALLERS));
        assertFalse(gateway.inForce.contains(DISALLOW_INSTALL_APPS));

        PlayStoreCompatibility.State state =
                PlayStoreCompatibility.evaluate(true, plan.relaxed(), report);
        assertEquals(PlayStoreCompatibility.State.RELAXED_BY_MAINTENANCE, state);
        assertTrue(state.keepsPlayStoreAvailable());
        assertFalse(state.faultsProtection());
    }

    @Test
    public void aRestorePutsTheFloorBackRatherThanTheRawSwitches() {
        // The regression this guards: restoring SystemPolicyStore.explicitChoices
        // after a window would end maintenance with the Store available and no
        // installation lock at all, because the administrator never toggled it.
        Map<SystemPolicyControl, Boolean> base =
                PlayStoreCompatibility.baseChoices(true, Map.of());

        MaintenancePlan restore = MaintenancePlan.restore(SystemPolicyProfile.PILOT, base);

        FakeGateway gateway = new FakeGateway();
        SystemPolicyReport report = SystemPolicyEnforcer.enforce(
                ANDROID_THIRTEEN, SystemPolicyProfile.PILOT, restore.effectiveChoices(), gateway);

        assertTrue(gateway.inForce.contains(DISALLOW_INSTALL_APPS));
        assertEquals(
                PlayStoreCompatibility.State.ACTIVE,
                PlayStoreCompatibility.evaluate(true, Set.of(), report));
    }

    @Test
    public void aLocalApkWindowDoesNotBuyStoreAvailability() {
        // The authorisation boundary this case exists to hold: LOCAL_APK_INSTALL
        // relaxes unknown sources and nothing else. An administrator who
        // authorised a local APK install did not authorise an application store,
        // so the Store is withheld for the window rather than handed over on the
        // strength of an excusal meant for APP_STORE_ACCESS.
        Map<SystemPolicyControl, Boolean> base =
                PlayStoreCompatibility.baseChoices(true, Map.of());
        MaintenancePlan plan = planFor(base, MaintenanceCapability.LOCAL_APK_INSTALL);

        FakeGateway gateway = new FakeGateway();
        SystemPolicyReport report = SystemPolicyEnforcer.enforce(
                ANDROID_THIRTEEN, SystemPolicyProfile.PILOT, plan.effectiveChoices(), gateway);

        assertEquals(
                Set.of(SystemPolicyControl.UNKNOWN_SOURCE_INSTALLS),
                new java.util.LinkedHashSet<>(plan.relaxed()));
        // The store lock is untouched by this window and still verified in force.
        assertTrue(gateway.inForce.contains(DISALLOW_INSTALL_APPS));
        assertFalse(gateway.inForce.contains("no_install_unknown_sources"));

        PlayStoreCompatibility.State state =
                PlayStoreCompatibility.evaluate(true, plan.relaxed(), report);

        assertEquals(PlayStoreCompatibility.State.WITHHELD_DURING_MAINTENANCE, state);
        assertFalse(state.keepsPlayStoreAvailable());
        assertFalse(PlayStoreCompatibility.keepsAvailable(
                PLAY_STORE, state.keepsPlayStoreAvailable()));
    }

    @Test
    public void withholdingTheStoreForAnAuthorisedWindowIsNotAFault() {
        // Nothing failed: the device is stricter than the compatibility mode
        // wants, on the strength of an authorisation the administrator gave.
        // Faulting here would paint an authorised service action as a breach.
        Map<SystemPolicyControl, Boolean> base =
                PlayStoreCompatibility.baseChoices(true, Map.of());
        MaintenancePlan plan = planFor(base, MaintenanceCapability.LOCAL_APK_INSTALL);

        SystemPolicyReport report = SystemPolicyEnforcer.enforce(
                ANDROID_THIRTEEN,
                SystemPolicyProfile.PILOT,
                plan.effectiveChoices(),
                new FakeGateway());
        PlayStoreCompatibility.State state =
                PlayStoreCompatibility.evaluate(true, plan.relaxed(), report);

        assertFalse(state.faultsProtection());
        assertFalse("an authorised window is not a policy failure", report.faulted());
    }

    @Test
    public void anExcusedUnknownSourceLockNeverMasksAFailedStoreLock() {
        // The excusal is per control. A window that opened unknown sources must
        // not carry a refused DISALLOW_INSTALL_APPS through as if it too had been
        // authorised: that is a real failure and still hides the Store and faults.
        Map<SystemPolicyControl, Boolean> base =
                PlayStoreCompatibility.baseChoices(true, Map.of());
        MaintenancePlan plan = planFor(base, MaintenanceCapability.LOCAL_APK_INSTALL);

        FakeGateway gateway = new FakeGateway();
        gateway.ignoreAdd.add(DISALLOW_INSTALL_APPS);
        SystemPolicyReport report = SystemPolicyEnforcer.enforce(
                ANDROID_THIRTEEN, SystemPolicyProfile.PILOT, plan.effectiveChoices(), gateway);

        PlayStoreCompatibility.State state =
                PlayStoreCompatibility.evaluate(true, plan.relaxed(), report);

        assertEquals(PlayStoreCompatibility.State.INSTALL_LOCK_UNVERIFIED, state);
        assertTrue(state.faultsProtection());
        assertTrue(report.faulted());
    }

    @Test
    public void onlyTheStoreControlCanGrantAvailabilityThroughAWindow() {
        // Stated directly against the rule rather than through a window, so the
        // boundary survives a future capability that relaxes something else.
        assertEquals(
                SystemPolicyControl.APP_STORES_AND_INSTALLERS,
                PlayStoreCompatibility.STORE_INSTALL_CONTROL);
        assertEquals(
                PlayStoreCompatibility.State.RELAXED_BY_MAINTENANCE,
                PlayStoreCompatibility.evaluateOutcomes(
                        true,
                        Set.of(PlayStoreCompatibility.STORE_INSTALL_CONTROL),
                        allApplied()));
        for (SystemPolicyControl control : PlayStoreCompatibility.REQUIRED_INSTALL_CONTROLS) {
            if (control == PlayStoreCompatibility.STORE_INSTALL_CONTROL) {
                continue;
            }
            assertEquals(
                    control + " must not buy store availability",
                    PlayStoreCompatibility.State.WITHHELD_DURING_MAINTENANCE,
                    PlayStoreCompatibility.evaluateOutcomes(true, Set.of(control), allApplied()));
        }
    }

    @Test
    public void aWindowThatOpensBothControlsStillGrantsAvailability() {
        // APP_STORE_ACCESS plus LOCAL_APK_INSTALL: the store authorisation is
        // present, so maintenance owns store visibility for the duration.
        MaintenancePlan plan = planFor(
                PlayStoreCompatibility.baseChoices(true, Map.of()),
                MaintenanceCapability.APP_STORE_ACCESS,
                MaintenanceCapability.LOCAL_APK_INSTALL);

        PlayStoreCompatibility.State state = PlayStoreCompatibility.evaluateOutcomes(
                true, plan.relaxed(), Map.of());

        assertEquals(PlayStoreCompatibility.State.RELAXED_BY_MAINTENANCE, state);
        assertTrue(state.keepsPlayStoreAvailable());
        assertFalse(state.faultsProtection());
    }

    @Test
    public void aLocalApkWindowStillReportsTheInstallLockAsAResidualBlocker() {
        // With the floor on, DISALLOW_INSTALL_APPS blocks a local APK install that
        // only opened unknown sources. The console has to say so rather than let a
        // technician watch an "open" window fail.
        MaintenancePlan plan = planFor(
                PlayStoreCompatibility.baseChoices(true, Map.of()),
                MaintenanceCapability.LOCAL_APK_INSTALL);

        assertTrue(plan.residualBlockers()
                .contains(SystemPolicyControl.APP_STORES_AND_INSTALLERS));
    }

    // ------------------------------------------------------- catalogue and kiosk

    @Test
    public void theStoreStaysInTheBlockedCatalogue() {
        // The exception is applied at the policy pass, not carved out of the
        // catalogue, so every other consumer of ALWAYS_BLOCKED keeps its rule.
        assertTrue(LockdownPackages.ALWAYS_BLOCKED.contains(PLAY_STORE));
    }

    @Test
    public void theStoreIsNeverPartOfAContainedDeviceSurface() {
        // Kiosk containment is decided by the lock-task allowlist and the kiosk
        // target rule. Neither can ever name the Store, so an available package
        // stays off the surface a contained user can reach.
        assertTrue(KioskAppCatalog.isProtectedFromKiosk(PLAY_STORE));
        assertFalse(KioskAppCatalog.isSelectable(new KioskAppCatalog.Candidate(
                PLAY_STORE, "Play Store", true, true, true, false)));
    }

    @Test
    public void playServicesAndTheWebViewProviderAreProtectedIndependently() {
        assertTrue(LockdownPackages.ESSENTIAL_SYSTEM.contains("com.google.android.gms"));
        assertTrue(LockdownPackages.ESSENTIAL_SYSTEM.contains("com.google.android.webview"));
        // And the exception does not reach them: it answers for one package only,
        // so it can neither widen nor narrow their protection.
        assertFalse(PlayStoreCompatibility.keepsAvailable("com.google.android.gms", true));
        assertFalse(PlayStoreCompatibility.keepsAvailable("com.google.android.webview", true));
        assertFalse(PlayStoreCompatibility.keepsAvailable(null, true));
    }

    // ------------------------------------------------------------------ helpers

    private static SystemPolicyReport enforceWithCompatibility(FakeGateway gateway) {
        return SystemPolicyEnforcer.enforce(
                ANDROID_THIRTEEN,
                SystemPolicyProfile.PILOT,
                PlayStoreCompatibility.baseChoices(true, Map.of()),
                gateway);
    }

    private static Map<SystemPolicyControl, SystemPolicyOutcome> allApplied() {
        LinkedHashMap<SystemPolicyControl, SystemPolicyOutcome> outcomes = new LinkedHashMap<>();
        for (SystemPolicyControl control : PlayStoreCompatibility.REQUIRED_INSTALL_CONTROLS) {
            outcomes.put(control, SystemPolicyOutcome.APPLIED);
        }
        return outcomes;
    }

    private static MaintenancePlan planFor(
            Map<SystemPolicyControl, Boolean> baseChoices,
            MaintenanceCapability... capabilities
    ) {
        MaintenanceWindow window = new MaintenanceWindow(
                EnumSet.copyOf(java.util.Arrays.asList(capabilities)),
                HALF_HOUR,
                1_700_000_000_000L,
                60_000L,
                1_700_000_000_000L,
                60_000L);
        return MaintenancePlan.forWindow(SystemPolicyProfile.PILOT, baseChoices, window);
    }

    /** The same seam {@code SystemPolicyEnforcerTest} drives, kept local to this file. */
    private static final class FakeGateway implements SystemPolicyGateway {

        final Set<String> inForce = new LinkedHashSet<>();
        final Set<String> refuseAdd = new HashSet<>();
        /** Accepts the call and changes nothing, like an OEM build that no-ops. */
        final Set<String> ignoreAdd = new HashSet<>();
        final Set<String> unreadable = new HashSet<>();

        @Override
        public void addRestriction(String key) {
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
            inForce.remove(key);
        }

        @Override
        public boolean isRestrictionInForce(String key) {
            if (unreadable.contains(key)) {
                throw new IllegalStateException("unreadable " + key);
            }
            return inForce.contains(key);
        }
    }
}
