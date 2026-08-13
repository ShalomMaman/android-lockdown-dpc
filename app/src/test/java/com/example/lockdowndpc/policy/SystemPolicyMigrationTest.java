package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * The migration guarantee for devices already in the field.
 *
 * <p>Pilot 0.5.1 devices are reachable over ADB deliberately: the signed
 * self-update drill has not been completed on hardware, so USB debugging is
 * still the documented recovery path. An upgrade that turned
 * {@code DISALLOW_DEBUGGING_FEATURES} on by default would remove that path from
 * a running device with no administrator action and no way back short of
 * re-provisioning it.
 *
 * <p>These tests pin the two halves of the guarantee: a pilot's defaults are the
 * 0.5.1 restriction set exactly — no additions, no removals — and debugging is
 * defaulted on only for the separately provisioned production identity.
 */
public final class SystemPolicyMigrationTest {

    /**
     * The complete set of restrictions Pilot 0.5.1 applied unconditionally on
     * Android 10, transcribed from the {@code applyRestrictions} this change
     * replaced. This literal is the contract; if it stops matching, an upgrade
     * has changed what a fielded device enforces.
     */
    private static final Set<String> PILOT_0_5_1_ON_ANDROID_TEN = Set.of(
            "no_install_unknown_sources",
            "no_install_unknown_sources_globally",
            "disallow_config_private_dns",
            "no_uninstall_apps",
            "no_control_apps",
            "no_modify_accounts",
            "no_add_user",
            "no_user_switch",
            "no_config_date_time",
            "no_config_vpn",
            "no_config_tethering",
            "no_network_reset",
            "no_usb_file_transfer",
            "no_factory_reset",
            "no_safe_boot"
    );

    /** The same set on Android 8, where the API 28 and 29 keys do not exist. */
    private static final Set<String> PILOT_0_5_1_ON_ANDROID_EIGHT = Set.of(
            "no_install_unknown_sources",
            "no_uninstall_apps",
            "no_control_apps",
            "no_modify_accounts",
            "no_add_user",
            "no_config_vpn",
            "no_config_tethering",
            "no_network_reset",
            "no_usb_file_transfer",
            "no_factory_reset",
            "no_safe_boot"
    );

    @Test
    public void anUpgradedPilotEnforcesExactlyWhatPilotFiveOneEnforced() {
        assertEquals(
                PILOT_0_5_1_ON_ANDROID_TEN,
                defaultEnabledKeys(SystemPolicyProfile.PILOT, 29));
        assertEquals(
                PILOT_0_5_1_ON_ANDROID_EIGHT,
                defaultEnabledKeys(SystemPolicyProfile.PILOT, 26));
    }

    @Test
    public void debuggingIsNeverWithdrawnFromAPilotByDefault() {
        assertFalse(
                SystemPolicyControl.DEVELOPER_OPTIONS_AND_ADB
                        .defaultRequested(SystemPolicyProfile.PILOT));
        assertFalse(defaultEnabledKeys(SystemPolicyProfile.PILOT, 36)
                .contains("no_debugging_features"));
    }

    @Test
    public void productionHardensDebuggingByDefault() {
        assertTrue(
                SystemPolicyControl.DEVELOPER_OPTIONS_AND_ADB
                        .defaultRequested(SystemPolicyProfile.PRODUCTION));
        assertTrue(defaultEnabledKeys(SystemPolicyProfile.PRODUCTION, 29)
                .contains("no_debugging_features"));
    }

    @Test
    public void productionDiffersFromPilotOnlyByDebugging() {
        Set<String> pilot = new LinkedHashSet<>(defaultEnabledKeys(SystemPolicyProfile.PILOT, 29));
        Set<String> production =
                new LinkedHashSet<>(defaultEnabledKeys(SystemPolicyProfile.PRODUCTION, 29));
        production.removeAll(pilot);
        assertEquals(Set.of("no_debugging_features"), production);
    }

    @Test
    public void installBlockingIsNeverADefaultOnEitherProfile() {
        // DISALLOW_INSTALL_APPS also stops the device owner installing packages,
        // which is how Device Guard installs its own signed update. Defaulting it
        // on would disable the very recovery path that has to work before ADB can
        // be withdrawn, so it stays an explicit administrator choice everywhere.
        for (SystemPolicyProfile profile : SystemPolicyProfile.values()) {
            assertFalse(
                    profile + " defaults package installation off",
                    SystemPolicyControl.APP_STORES_AND_INSTALLERS.defaultRequested(profile));
            assertFalse(
                    profile + " defaults Wi-Fi configuration off",
                    SystemPolicyControl.WIFI_CONFIGURATION.defaultRequested(profile));
        }
    }

    @Test
    public void theProfileIsTheApplicationIdTheProductionBuildAssigns() {
        // gradle/production-identity.gradle assigns this ID, and only an explicit
        // production build applies it. Android refuses to change an application ID
        // on an in-place update, so a provisioned pilot cannot become production.
        assertEquals(
                SystemPolicyProfile.PRODUCTION,
                SystemPolicyProfile.detect("il.co.shalommaman.deviceguard"));
        assertEquals(
                SystemPolicyProfile.PILOT,
                SystemPolicyProfile.detect("com.example.lockdowndpc"));
    }

    @Test
    public void anUnrecognisedBuildIsTreatedAsAPilot() {
        assertEquals(SystemPolicyProfile.PILOT, SystemPolicyProfile.detect(null));
        assertEquals(SystemPolicyProfile.PILOT, SystemPolicyProfile.detect(""));
        assertEquals(
                SystemPolicyProfile.PILOT,
                SystemPolicyProfile.detect("il.co.shalommaman.deviceguard.debug"));
        assertEquals(
                SystemPolicyProfile.PILOT,
                SystemPolicyProfile.detect("com.someone.whitelabel"));
    }

    @Test
    public void aDeviceThatWasEverAPilotIsNeverPromoted() {
        // The pinned record is the evidence that this device has been relying on
        // the recovery path. Any disagreement resolves to the weaker default.
        assertEquals(
                SystemPolicyProfile.PILOT,
                SystemPolicyProfile.safest(SystemPolicyProfile.PILOT, SystemPolicyProfile.PRODUCTION));
        assertEquals(
                SystemPolicyProfile.PILOT,
                SystemPolicyProfile.safest(SystemPolicyProfile.PRODUCTION, SystemPolicyProfile.PILOT));
        assertEquals(
                SystemPolicyProfile.PRODUCTION,
                SystemPolicyProfile.safest(
                        SystemPolicyProfile.PRODUCTION, SystemPolicyProfile.PRODUCTION));
        assertEquals(
                SystemPolicyProfile.PILOT,
                SystemPolicyProfile.safest(SystemPolicyProfile.PILOT, SystemPolicyProfile.PILOT));
    }

    @Test
    public void anExplicitChoiceOverridesTheProfileDefaultInBothDirections() {
        // A pilot administrator who has finished the update drill can withdraw
        // debugging, and a production administrator can restore it for service.
        assertTrue(SystemPolicyEnforcer.requestedFor(
                SystemPolicyControl.DEVELOPER_OPTIONS_AND_ADB,
                SystemPolicyProfile.PILOT,
                java.util.Map.of(SystemPolicyControl.DEVELOPER_OPTIONS_AND_ADB, true)));
        assertFalse(SystemPolicyEnforcer.requestedFor(
                SystemPolicyControl.DEVELOPER_OPTIONS_AND_ADB,
                SystemPolicyProfile.PRODUCTION,
                java.util.Map.of(SystemPolicyControl.DEVELOPER_OPTIONS_AND_ADB, false)));
    }

    @Test
    public void anAbsentChoiceIsNotTheSameAsOff() {
        // The whole migration rests on this: an upgraded pilot arrives with an
        // empty store, and an empty store must mean "the 0.5.1 posture", not
        // "release every restriction".
        assertTrue(SystemPolicyEnforcer.requestedFor(
                SystemPolicyControl.FACTORY_RESET,
                SystemPolicyProfile.PILOT,
                java.util.Map.of()));
        assertTrue(SystemPolicyEnforcer.requestedFor(
                SystemPolicyControl.FACTORY_RESET,
                SystemPolicyProfile.PILOT,
                null));
    }

    private static Set<String> defaultEnabledKeys(SystemPolicyProfile profile, int sdkInt) {
        LinkedHashSet<String> keys = new LinkedHashSet<>();
        for (SystemPolicyControl control : SystemPolicyControl.values()) {
            if (!control.defaultRequested(profile)) {
                continue;
            }
            for (SystemPolicyControl.Restriction restriction
                    : control.supportedRestrictions(sdkInt)) {
                keys.add(restriction.key());
            }
        }
        return keys;
    }
}
