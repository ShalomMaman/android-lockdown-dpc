package com.example.lockdowndpc.maintenance;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.policy.SystemPolicyControl;
import com.example.lockdowndpc.policy.SystemPolicyEnforcer;
import com.example.lockdowndpc.policy.SystemPolicyProfile;

import org.junit.Test;

import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * What a window is allowed to change, and what it must leave alone.
 *
 * <p>The three properties worth proving are that a plan is <em>additive</em> (it
 * can only turn a control off), <em>bounded</em> (only controls the selected
 * capabilities declare), and <em>reversible</em> (the restore is the
 * administrator's own choices, not an attempt to invert whatever the window
 * did). Together they are what stops "open the store for ten minutes" from
 * becoming a general pause of protection.
 */
public final class MaintenancePlanTest {

    private static final long HALF_HOUR = TimeUnit.MINUTES.toMillis(30);

    @Test
    public void aWindowRelaxesOnlyTheControlsItsCapabilitiesDeclare() {
        // Sideloading is on by default since the pilot, so opening local APK
        // installation has something to relax.
        MaintenancePlan plan = planFor(
                SystemPolicyProfile.PILOT, Map.of(), MaintenanceCapability.LOCAL_APK_INSTALL);

        assertEquals(Set.of(SystemPolicyControl.UNKNOWN_SOURCE_INSTALLS), plan.relaxed());
        assertFalse(requested(plan, SystemPolicyControl.UNKNOWN_SOURCE_INSTALLS));

        // Everything else keeps exactly the answer the base policy gave.
        for (SystemPolicyControl control : SystemPolicyControl.values()) {
            if (control == SystemPolicyControl.UNKNOWN_SOURCE_INSTALLS) {
                continue;
            }
            assertEquals(
                    control + " must be untouched by an unrelated capability",
                    plan.baseRequests(control),
                    requested(plan, control));
        }
    }

    @Test
    public void aPlanCanOnlyTurnAControlOffAndNeverOn() {
        MaintenancePlan plan = planFor(
                SystemPolicyProfile.PRODUCTION, Map.of(), MaintenanceCapability.ADB_DEBUGGING);

        for (SystemPolicyControl control : SystemPolicyControl.values()) {
            if (plan.baseRequests(control)) {
                continue;
            }
            assertFalse(
                    "maintenance must never enforce something the base policy does not: " + control,
                    requested(plan, control));
        }
    }

    @Test
    public void relaxingSomethingTheBasePolicyDoesNotEnforceChangesNothing() {
        // Application stores are opt-in, so on a device where the administrator
        // never turned that control on, opening the capability is honest about
        // having had no effect rather than claiming one.
        MaintenancePlan plan = planFor(
                SystemPolicyProfile.PILOT, Map.of(), MaintenanceCapability.APP_STORE_ACCESS);

        assertTrue(plan.relaxed().isEmpty());
        assertFalse(plan.relaxesAnything());
        assertEquals("", plan.relaxedSummary());
        // And it must not start managing a control nobody asked it to manage.
        assertFalse(plan.effectiveChoices().containsKey(SystemPolicyControl.APP_STORES_AND_INSTALLERS));
    }

    @Test
    public void debuggingIsRelaxedOnlyWhenTheBaseProfileEnforcesIt() {
        // Pilot devices keep ADB as the documented recovery path, so there is
        // nothing for break-glass to open there.
        MaintenancePlan onPilot = planFor(
                SystemPolicyProfile.PILOT, Map.of(), MaintenanceCapability.ADB_DEBUGGING);
        assertFalse(onPilot.relaxesDebugging());
        assertTrue(onPilot.relaxed().isEmpty());

        MaintenancePlan onProduction = planFor(
                SystemPolicyProfile.PRODUCTION, Map.of(), MaintenanceCapability.ADB_DEBUGGING);
        assertTrue(onProduction.relaxesDebugging());
        assertEquals(Set.of(SystemPolicyControl.DEVELOPER_OPTIONS_AND_ADB), onProduction.relaxed());
        assertEquals("developer_options_and_adb", onProduction.relaxedSummary());
    }

    @Test
    public void aStillEnforcedNeighbourIsReportedRatherThanQuietlyOpened() {
        // DISALLOW_INSTALL_APPS blocks every installation path, so an
        // administrator who turned it on and then opens local APK installation
        // would otherwise watch the install fail with no explanation.
        Map<SystemPolicyControl, Boolean> choices = new LinkedHashMap<>();
        choices.put(SystemPolicyControl.APP_STORES_AND_INSTALLERS, true);

        MaintenancePlan plan = planFor(
                SystemPolicyProfile.PILOT, choices, MaintenanceCapability.LOCAL_APK_INSTALL);

        assertEquals(Set.of(SystemPolicyControl.APP_STORES_AND_INSTALLERS), plan.residualBlockers());
        assertTrue(
                "a residual blocker is reported, never relaxed",
                requested(plan, SystemPolicyControl.APP_STORES_AND_INSTALLERS));
    }

    @Test
    public void aNeighbourTheAdministratorAlsoOpenedIsNotReportedAsBlocking() {
        Map<SystemPolicyControl, Boolean> choices = new LinkedHashMap<>();
        choices.put(SystemPolicyControl.APP_STORES_AND_INSTALLERS, true);

        MaintenancePlan plan = planFor(
                SystemPolicyProfile.PILOT,
                choices,
                MaintenanceCapability.LOCAL_APK_INSTALL,
                MaintenanceCapability.APP_STORE_ACCESS);

        assertTrue(plan.residualBlockers().isEmpty());
        assertEquals(
                EnumSet.of(
                        SystemPolicyControl.UNKNOWN_SOURCE_INSTALLS,
                        SystemPolicyControl.APP_STORES_AND_INSTALLERS),
                EnumSet.copyOf(plan.relaxed()));
    }

    @Test
    public void severalCapabilitiesRelaxTheUnionAndNothingBeyondIt() {
        MaintenancePlan plan = planFor(
                SystemPolicyProfile.PRODUCTION,
                Map.of(),
                MaintenanceCapability.ADB_DEBUGGING,
                MaintenanceCapability.USB_FILE_TRANSFER,
                MaintenanceCapability.SELECTED_SETTINGS);

        assertEquals(
                EnumSet.of(
                        SystemPolicyControl.DEVELOPER_OPTIONS_AND_ADB,
                        SystemPolicyControl.USB_FILE_TRANSFER,
                        SystemPolicyControl.APP_CONTROL_SETTINGS),
                EnumSet.copyOf(plan.relaxed()));

        Set<SystemPolicyControl> ceiling = MaintenanceCapability.relaxedControls(EnumSet.of(
                MaintenanceCapability.ADB_DEBUGGING,
                MaintenanceCapability.USB_FILE_TRANSFER,
                MaintenanceCapability.SELECTED_SETTINGS));
        assertTrue("a plan may never relax outside the declared ceiling",
                ceiling.containsAll(plan.relaxed()));
    }

    @Test
    public void theRestoreIsTheAdministratorsOwnChoicesRatherThanAnInverse() {
        // A window that was only half applied still has to restore to the same
        // place, which is why restore rebuilds the base rather than undoing
        // whatever the device happens to be carrying.
        Map<SystemPolicyControl, Boolean> choices = new LinkedHashMap<>();
        choices.put(SystemPolicyControl.WIFI_CONFIGURATION, true);
        choices.put(SystemPolicyControl.TETHERING, false);

        MaintenancePlan restore = MaintenancePlan.restore(SystemPolicyProfile.PRODUCTION, choices);

        assertEquals(choices, restore.effectiveChoices());
        assertEquals(choices, restore.baseChoices());
        assertTrue(restore.relaxed().isEmpty());
        assertTrue(restore.residualBlockers().isEmpty());
        assertFalse(restore.relaxesAnything());
        assertFalse(restore.relaxesDebugging());
    }

    @Test
    public void aWindowNeverEditsTheStoredBaseChoices() {
        Map<SystemPolicyControl, Boolean> choices = new LinkedHashMap<>();
        choices.put(SystemPolicyControl.UNKNOWN_SOURCE_INSTALLS, true);

        MaintenancePlan plan = planFor(
                SystemPolicyProfile.PILOT, choices, MaintenanceCapability.LOCAL_APK_INSTALL);

        assertEquals(
                "the administrator's own record must survive the window unchanged",
                Boolean.TRUE,
                plan.baseChoices().get(SystemPolicyControl.UNKNOWN_SOURCE_INSTALLS));
        assertEquals(
                Boolean.TRUE,
                choices.get(SystemPolicyControl.UNKNOWN_SOURCE_INSTALLS));
        assertThrows(
                UnsupportedOperationException.class,
                () -> plan.baseChoices().put(SystemPolicyControl.SAFE_BOOT, false));
    }

    @Test
    public void aPlanThatContradictsItselfCannotBeConstructed() {
        // The invariant the record exists to hold: something listed as relaxed
        // cannot still be requested.
        assertThrows(IllegalArgumentException.class, () -> new MaintenancePlan(
                SystemPolicyProfile.PILOT,
                Map.of(SystemPolicyControl.USB_FILE_TRANSFER, true),
                Map.of(SystemPolicyControl.USB_FILE_TRANSFER, true),
                Set.of(SystemPolicyControl.USB_FILE_TRANSFER),
                Set.of()));

        assertThrows(IllegalArgumentException.class, () -> new MaintenancePlan(
                null, Map.of(), Map.of(), Set.of(), Set.of()));
    }

    @Test
    public void aPlanNeedsAWindowRatherThanAGuess() {
        assertThrows(
                IllegalArgumentException.class,
                () -> MaintenancePlan.forWindow(SystemPolicyProfile.PILOT, Map.of(), null));
    }

    private static boolean requested(MaintenancePlan plan, SystemPolicyControl control) {
        return SystemPolicyEnforcer.requestedFor(control, plan.profile(), plan.effectiveChoices());
    }

    private static MaintenancePlan planFor(
            SystemPolicyProfile profile,
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
        return MaintenancePlan.forWindow(profile, baseChoices, window);
    }
}
