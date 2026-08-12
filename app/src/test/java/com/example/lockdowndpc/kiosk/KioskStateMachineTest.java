package com.example.lockdowndpc.kiosk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.kiosk.KioskStateMachine.KioskAction;
import com.example.lockdowndpc.kiosk.KioskStateMachine.KioskState;
import com.example.lockdowndpc.kiosk.KioskStateMachine.Outcome;
import com.example.lockdowndpc.kiosk.KioskStateMachine.Request;

import org.junit.Test;

public final class KioskStateMachineTest {

    private static Outcome go(KioskState from, KioskAction action, boolean admin, boolean valid) {
        return KioskStateMachine.transition(new Request(from, action, admin, valid));
    }

    @Test
    public void anUpgradeCannotEnableKiosk() {
        // The starting point of an upgraded device is OFF, and nothing but an
        // explicit authenticated CONFIGURE moves it.
        assertFalse(go(KioskState.OFF, KioskAction.ENTER, true, true).allowed());
        assertFalse(go(KioskState.OFF, KioskAction.BOOT_RESTORE, false, true).allowed());
        assertFalse(go(KioskState.OFF, KioskAction.FAULT, false, true).allowed());
    }

    @Test
    public void everyOperatorTransitionRequiresAnAuthenticatedAdministrator() {
        for (KioskState from : KioskState.values()) {
            for (KioskAction action : new KioskAction[]{
                    KioskAction.CONFIGURE, KioskAction.ENTER, KioskAction.EXIT, KioskAction.CLEAR}) {
                Outcome outcome = go(from, action, false, true);
                assertFalse(from + "/" + action + " must require admin", outcome.allowed());
                assertEquals("admin-authentication-required", outcome.reason());
                assertEquals("a denied transition must not move state", from, outcome.state());
            }
        }
    }

    @Test
    public void configuringArmsRatherThanEntering() {
        Outcome outcome = go(KioskState.OFF, KioskAction.CONFIGURE, true, true);

        assertTrue(outcome.allowed());
        assertEquals(KioskState.ARMED, outcome.state());
    }

    @Test
    public void reconfiguringAnActiveKioskReArmsInsteadOfSwappingSilently() {
        assertEquals(KioskState.ARMED, go(KioskState.ACTIVE, KioskAction.CONFIGURE, true, true).state());
    }

    @Test
    public void configuringRejectsAnInvalidConfiguration() {
        Outcome outcome = go(KioskState.OFF, KioskAction.CONFIGURE, true, false);

        assertFalse(outcome.allowed());
        assertEquals("invalid-configuration", outcome.reason());
    }

    @Test
    public void enteringRequiresAnArmedValidConfiguration() {
        assertTrue(go(KioskState.ARMED, KioskAction.ENTER, true, true).allowed());
        assertFalse(go(KioskState.ARMED, KioskAction.ENTER, true, false).allowed());
        assertFalse(go(KioskState.OFF, KioskAction.ENTER, true, true).allowed());
    }

    @Test
    public void exitingIsOnlyPossibleFromActiveOrFault() {
        assertEquals(KioskState.ARMED, go(KioskState.ACTIVE, KioskAction.EXIT, true, true).state());
        assertEquals(KioskState.ARMED, go(KioskState.FAULT, KioskAction.EXIT, true, true).state());
        assertFalse(go(KioskState.ARMED, KioskAction.EXIT, true, true).allowed());
        assertFalse(go(KioskState.OFF, KioskAction.EXIT, true, true).allowed());
    }

    @Test
    public void exitingDoesNotRequireTheConfigurationToStillBeValid() {
        // An administrator must always be able to leave a broken kiosk.
        assertTrue(go(KioskState.FAULT, KioskAction.EXIT, true, false).allowed());
    }

    @Test
    public void rebootRestoresActiveWithoutAuthentication() {
        Outcome outcome = go(KioskState.ACTIVE, KioskAction.BOOT_RESTORE, false, true);

        assertTrue(outcome.allowed());
        assertEquals(KioskState.ACTIVE, outcome.state());
    }

    @Test
    public void rebootIsNotAWayOutOfKiosk() {
        // BOOT_RESTORE can only ever reach ACTIVE or FAULT, never ARMED or OFF.
        for (KioskState from : KioskState.values()) {
            Outcome outcome = go(from, KioskAction.BOOT_RESTORE, false, true);
            if (outcome.allowed()) {
                assertTrue(outcome.state() == KioskState.ACTIVE || outcome.state() == KioskState.FAULT);
            } else {
                assertEquals(from, outcome.state());
            }
        }
        assertFalse(go(KioskState.ARMED, KioskAction.BOOT_RESTORE, false, true).allowed());
        assertFalse(go(KioskState.FAULT, KioskAction.BOOT_RESTORE, false, true).allowed());
    }

    @Test
    public void rebootWithAStaleConfigurationFallsIntoFaultNotIntoALauncher() {
        Outcome outcome = go(KioskState.ACTIVE, KioskAction.BOOT_RESTORE, false, false);

        assertTrue(outcome.allowed());
        assertEquals(KioskState.FAULT, outcome.state());
        assertEquals("configuration-no-longer-valid", outcome.reason());
    }

    @Test
    public void clearingReturnsToManagedFilteringOnly() {
        assertEquals(KioskState.OFF, go(KioskState.ACTIVE, KioskAction.CLEAR, true, true).state());
        assertEquals(KioskState.OFF, go(KioskState.FAULT, KioskAction.CLEAR, true, false).state());
    }

    @Test
    public void faultIsReachableFromAnyConfiguredState() {
        assertEquals(KioskState.FAULT, go(KioskState.ACTIVE, KioskAction.FAULT, false, false).state());
        assertEquals(KioskState.FAULT, go(KioskState.ARMED, KioskAction.FAULT, false, false).state());
        assertFalse(go(KioskState.OFF, KioskAction.FAULT, false, false).allowed());
    }

    @Test
    public void corruptedStoredStateFailsClosedToFaultAndCorruptedModeToOff() {
        assertEquals(KioskState.FAULT, KioskState.fromStoredName("ACTIVE_ISH"));
        assertEquals(KioskState.OFF, KioskState.fromStoredName(null));
        assertEquals(KioskMode.OFF, KioskMode.fromStoredName("SINGLE_EVERYTHING"));
        assertEquals(KioskMode.OFF, KioskMode.fromStoredName(null));
    }

    @Test
    public void missingInputsAreRefused() {
        assertFalse(KioskStateMachine.transition(null).allowed());
        assertFalse(go(KioskState.ACTIVE, null, true, true).allowed());
    }
}
