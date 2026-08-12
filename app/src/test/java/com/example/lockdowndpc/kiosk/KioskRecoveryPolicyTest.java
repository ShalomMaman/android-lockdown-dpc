package com.example.lockdowndpc.kiosk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.kiosk.KioskRecoveryPolicy.HostSurface;
import com.example.lockdowndpc.kiosk.KioskStateMachine.KioskState;

import org.junit.Test;

/**
 * The rules that decide whether an administrator can still reach the PIN screen
 * from inside a locked kiosk.
 */
public final class KioskRecoveryPolicyTest {

    @Test
    public void singleAppGetsTheHomeKeyOnceThisDpcOwnsHome() {
        assertTrue(KioskRecoveryPolicy.allowHomeKey(KioskState.ACTIVE, KioskMode.SINGLE_APP, true));
    }

    @Test
    public void homeIsNeverEnabledWithoutTheKioskHomePreference() {
        // The interlock: HOME without a launcher of ours registered is the one
        // configuration where the key could land somewhere we did not choose, and
        // is also what the platform refuses outright.
        assertFalse(KioskRecoveryPolicy.allowHomeKey(KioskState.ACTIVE, KioskMode.SINGLE_APP, false));
    }

    @Test
    public void singleSiteAndManagedFilteringKeepTheMinimalFeatureSet() {
        // The single-site host is the foreground activity, so the corner gesture is
        // already on screen and HOME would buy nothing.
        assertFalse(KioskRecoveryPolicy.allowHomeKey(KioskState.ACTIVE, KioskMode.SINGLE_SITE, true));
        assertFalse(KioskRecoveryPolicy.allowHomeKey(KioskState.ACTIVE, KioskMode.OFF, true));
        assertFalse(KioskRecoveryPolicy.allowHomeKey(KioskState.ACTIVE, null, true));
    }

    @Test
    public void faultNeverEnablesHomeEvenForARegisteredSingleAppHost() {
        assertFalse(KioskRecoveryPolicy.allowHomeKey(KioskState.FAULT, KioskMode.SINGLE_APP, true));
    }

    @Test
    public void containmentPredicateIncludesActiveAndFaultOnly() {
        assertTrue(KioskConfigStore.isContainmentState(KioskState.ACTIVE));
        assertTrue(KioskConfigStore.isContainmentState(KioskState.FAULT));
        assertFalse(KioskConfigStore.isContainmentState(KioskState.ARMED));
        assertFalse(KioskConfigStore.isContainmentState(KioskState.OFF));
        assertFalse(KioskConfigStore.isContainmentState(null));
    }

    @Test
    public void aFreshSingleAppHostStartsItsTarget() {
        assertEquals(
                HostSurface.LAUNCH_TARGET,
                KioskRecoveryPolicy.surfaceFor(KioskMode.SINGLE_APP, true, false));
    }

    @Test
    public void comingBackToASingleAppHostLandsOnTheContainedKioskHome() {
        // This is the fix for a target that traps Back: HOME returns here, and the
        // host must not bounce straight back into the pinned app or the corner
        // gesture is unreachable for as long as the app is running.
        assertEquals(
                HostSurface.RECOVERY_HOME,
                KioskRecoveryPolicy.surfaceFor(KioskMode.SINGLE_APP, true, true));
    }

    @Test
    public void anUnusableConfigurationAlwaysShowsTheSafeErrorState() {
        for (KioskMode mode : KioskMode.values()) {
            assertEquals(
                    "mode " + mode,
                    HostSurface.ERROR,
                    KioskRecoveryPolicy.surfaceFor(mode, false, false));
            assertEquals(
                    "mode " + mode,
                    HostSurface.ERROR,
                    KioskRecoveryPolicy.surfaceFor(mode, false, true));
        }
    }

    @Test
    public void singleSiteRendersItsOwnViewWhicheverPassThisIs() {
        assertEquals(
                HostSurface.SITE,
                KioskRecoveryPolicy.surfaceFor(KioskMode.SINGLE_SITE, true, false));
        assertEquals(
                HostSurface.SITE,
                KioskRecoveryPolicy.surfaceFor(KioskMode.SINGLE_SITE, true, true));
    }

    @Test
    public void managedFilteringNeverRendersAKioskSurface() {
        assertEquals(
                HostSurface.ERROR,
                KioskRecoveryPolicy.surfaceFor(KioskMode.OFF, true, false));
        assertEquals(
                HostSurface.ERROR,
                KioskRecoveryPolicy.surfaceFor(null, true, false));
    }
}
