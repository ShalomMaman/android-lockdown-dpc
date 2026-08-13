package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * The capability and version mapping, pinned as data.
 *
 * <p>Two mistakes this catches, neither of which a device would report: a
 * restriction bound to the wrong {@code UserManager} constant, which silently
 * enforces something other than what the console says; and a version gate that
 * lets a restriction be sent to a release that does not implement it, which is
 * the difference between an honest "not available" and a switch that appears to
 * work and does nothing.
 */
public final class SystemPolicyCapabilityTest {

    /** The exact wire values Android matches on. A typo here is unenforced policy. */
    @Test
    public void everyControlIsBoundToTheDocumentedRestrictionKeys() {
        assertEquals(
                List.of("no_debugging_features"),
                keysOf(SystemPolicyControl.DEVELOPER_OPTIONS_AND_ADB));
        assertEquals(
                List.of("no_usb_file_transfer"),
                keysOf(SystemPolicyControl.USB_FILE_TRANSFER));
        assertEquals(
                List.of("no_install_unknown_sources", "no_install_unknown_sources_globally"),
                keysOf(SystemPolicyControl.UNKNOWN_SOURCE_INSTALLS));
        assertEquals(
                List.of("no_install_apps"),
                keysOf(SystemPolicyControl.APP_STORES_AND_INSTALLERS));
        assertEquals(
                List.of("no_modify_accounts"),
                keysOf(SystemPolicyControl.ACCOUNT_MODIFICATION));
        assertEquals(List.of("no_config_vpn"), keysOf(SystemPolicyControl.VPN_CONFIGURATION));
        assertEquals(List.of("no_network_reset"), keysOf(SystemPolicyControl.NETWORK_RESET));
        assertEquals(List.of("no_config_tethering"), keysOf(SystemPolicyControl.TETHERING));
        assertEquals(List.of("no_config_wifi"), keysOf(SystemPolicyControl.WIFI_CONFIGURATION));
        assertEquals(List.of("disallow_config_private_dns"), keysOf(SystemPolicyControl.PRIVATE_DNS));
        assertEquals(List.of("no_config_date_time"), keysOf(SystemPolicyControl.DATE_AND_TIME));
        assertEquals(List.of("no_safe_boot"), keysOf(SystemPolicyControl.SAFE_BOOT));
        assertEquals(List.of("no_factory_reset"), keysOf(SystemPolicyControl.FACTORY_RESET));
        assertEquals(
                List.of("no_add_user", "no_user_switch"),
                keysOf(SystemPolicyControl.USER_AND_PROFILE_CREATION));
        assertEquals(List.of("no_uninstall_apps"), keysOf(SystemPolicyControl.APP_UNINSTALL));
        assertEquals(List.of("no_control_apps"), keysOf(SystemPolicyControl.APP_CONTROL_SETTINGS));
    }

    @Test
    public void everyControlCoversTheIssueScopeExactlyOnce() {
        // Each control appears in exactly one console section, so nothing is
        // unreachable from the screen and nothing is offered twice.
        LinkedHashSet<SystemPolicyControl> rendered = new LinkedHashSet<>();
        int rows = 0;
        for (SystemPolicyLabels.Section section : SystemPolicyLabels.Section.values()) {
            for (SystemPolicyControl control : section.controls()) {
                rendered.add(control);
                rows++;
            }
        }
        assertEquals("a control is listed in two sections", rows, rendered.size());
        assertEquals(Set.of(SystemPolicyControl.values()), rendered);
    }

    @Test
    public void androidNineGatesDateTimeAndUserSwitching() {
        assertFalse(SystemPolicyControl.DATE_AND_TIME.supportedOn(27));
        assertTrue(SystemPolicyControl.DATE_AND_TIME.supportedOn(28));
        assertEquals(28, SystemPolicyControl.DATE_AND_TIME.minSdk());

        // A control is supported as soon as any part of it is, so adding users is
        // still enforced on Android 8 even though switching users is not.
        assertTrue(SystemPolicyControl.USER_AND_PROFILE_CREATION.supportedOn(26));
        assertEquals(
                List.of("no_add_user"),
                keysOf(SystemPolicyControl.USER_AND_PROFILE_CREATION.supportedRestrictions(26)));
        assertEquals(
                List.of("no_user_switch"),
                keysOf(SystemPolicyControl.USER_AND_PROFILE_CREATION.unsupportedRestrictions(26)));
        assertEquals(
                List.of("no_add_user", "no_user_switch"),
                keysOf(SystemPolicyControl.USER_AND_PROFILE_CREATION.supportedRestrictions(28)));
    }

    @Test
    public void androidTenGatesGlobalUnknownSourcesAndPrivateDns() {
        assertEquals(
                List.of("no_install_unknown_sources"),
                keysOf(SystemPolicyControl.UNKNOWN_SOURCE_INSTALLS.supportedRestrictions(28)));
        assertEquals(
                List.of("no_install_unknown_sources", "no_install_unknown_sources_globally"),
                keysOf(SystemPolicyControl.UNKNOWN_SOURCE_INSTALLS.supportedRestrictions(29)));

        // Private DNS is a whole control rather than a part of one, so on Android 9
        // it reports as unavailable instead of quietly doing nothing.
        assertFalse(SystemPolicyControl.PRIVATE_DNS.supportedOn(28));
        assertTrue(SystemPolicyControl.PRIVATE_DNS.supportedOn(29));
    }

    @Test
    public void nothingIsGatedAboveTheReleasesThisBuildSupports() {
        // minSdk 26. A control no supported device can honour would be a switch
        // that never does anything on any device this build runs on.
        for (SystemPolicyControl control : SystemPolicyControl.values()) {
            assertTrue(
                    control + " is unreachable on every supported release",
                    control.supportedOn(36));
        }
        assertTrue(SystemPolicyControl.allRestrictionKeys(26).size() >= 11);
    }

    @Test
    public void releaseSweepCollectsOnlyKeysThisReleaseImplements() {
        List<String> onAndroidEight = SystemPolicyControl.allRestrictionKeys(26);
        assertFalse(onAndroidEight.contains("no_config_date_time"));
        assertFalse(onAndroidEight.contains("no_user_switch"));
        assertFalse(onAndroidEight.contains("disallow_config_private_dns"));
        assertFalse(onAndroidEight.contains("no_install_unknown_sources_globally"));

        List<String> onAndroidTen = SystemPolicyControl.allRestrictionKeys(29);
        assertTrue(onAndroidTen.contains("no_config_date_time"));
        assertTrue(onAndroidTen.contains("no_user_switch"));
        assertTrue(onAndroidTen.contains("disallow_config_private_dns"));
        assertTrue(onAndroidTen.contains("no_install_unknown_sources_globally"));
        assertEquals(
                "the sweep must not repeat a key",
                onAndroidTen.size(),
                new LinkedHashSet<>(onAndroidTen).size());
    }

    @Test
    public void storageKeysAreStableAndUnique() {
        LinkedHashSet<String> keys = new LinkedHashSet<>();
        for (SystemPolicyControl control : SystemPolicyControl.values()) {
            assertTrue(keys.add(control.storageKey()));
            assertEquals(control, SystemPolicyControl.fromStorageKey(control.storageKey()));
        }
        assertNotNull(SystemPolicyControl.fromStorageKey("developer_options_and_adb"));
        assertNull(SystemPolicyControl.fromStorageKey("not_a_control"));
    }

    @Test
    public void onlyWifiConfigurationIsAdvisory() {
        // Everything the pilot already enforced stays critical, so this change
        // cannot weaken a failure that used to fault protection.
        for (SystemPolicyControl control : SystemPolicyControl.values()) {
            boolean advisory = control.criticality() == SystemPolicyControl.Criticality.ADVISORY;
            assertEquals(
                    control + " criticality",
                    control == SystemPolicyControl.WIFI_CONFIGURATION,
                    advisory);
        }
    }

    private static List<String> keysOf(SystemPolicyControl control) {
        return keysOf(control.restrictions());
    }

    private static List<String> keysOf(List<SystemPolicyControl.Restriction> restrictions) {
        return restrictions.stream().map(SystemPolicyControl.Restriction::key).toList();
    }
}
