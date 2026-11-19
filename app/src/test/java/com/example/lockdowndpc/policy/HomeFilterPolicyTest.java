package com.example.lockdowndpc.policy;

import org.junit.Test;

import java.util.Map;
import java.util.Set;

import static com.example.lockdowndpc.policy.HomeFilterPolicy.State.CONFIRMED;
import static com.example.lockdowndpc.policy.HomeFilterPolicy.State.HIDDEN_VPN;
import static com.example.lockdowndpc.policy.HomeFilterPolicy.State.MISSING_VPN;
import static com.example.lockdowndpc.policy.HomeFilterPolicy.State.NOT_REQUESTED;
import static com.example.lockdowndpc.policy.HomeFilterPolicy.State.REFUSED;
import static com.example.lockdowndpc.policy.HomeFilterPolicy.State.UNCONFIRMED;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class HomeFilterPolicyTest {
    private static final String PACKAGE = "com.tailscale.ipn";
    private static final String PAC = "https://filter.example/home.pac";
    private static final HomeFilterPolicy.Settings REQUEST = new HomeFilterPolicy.Settings(
            new HomeFilterPolicy.Config("", PAC), true, "selected-ca", false);

    @Test
    public void acceptsDefaultOrExplicitPackageAndHttpOrHttpsPac() {
        assertEquals(PACKAGE, REQUEST.config().vpnPackage());
        HomeFilterPolicy.Config config = new HomeFilterPolicy.Config(
                "org.example.vpn", " HTTP://filter.example/home.pac ");
        assertEquals("org.example.vpn", config.vpnPackage());
        assertEquals("http://filter.example/home.pac", config.pacUrl());
    }

    @Test
    public void rejectsMalformattedPackageAndUnsafePacUrls() {
        assertThrows(IllegalArgumentException.class, () -> new HomeFilterPolicy.Config("bad", PAC));
        for (String url : Set.of("", "ftp://filter.example/home.pac", "https:/relative",
                "https://name:secret@filter.example/home.pac", PAC + "#fragment",
                "http://filter.example:99999/home.pac", "http://filter.example:/home.pac")) {
            assertThrows(url, IllegalArgumentException.class,
                    () -> new HomeFilterPolicy.Config(PACKAGE, url));
        }
    }

    @Test
    public void optsInAllSixControlsWithoutChangingStoredChoices() {
        Map<SystemPolicyControl, Boolean> choices = Map.of(
                SystemPolicyControl.PRIVATE_DNS, false, SystemPolicyControl.TETHERING, false);
        Map<SystemPolicyControl, Boolean> effective = HomeFilterPolicy.requireControls(choices);
        assertEquals(Set.of(SystemPolicyControl.VPN_CONFIGURATION, SystemPolicyControl.PRIVATE_DNS,
                        SystemPolicyControl.NETWORK_RESET, SystemPolicyControl.SAFE_BOOT,
                        SystemPolicyControl.FACTORY_RESET, SystemPolicyControl.USER_AND_PROFILE_CREATION),
                HomeFilterPolicy.REQUIRED_CONTROLS);
        HomeFilterPolicy.REQUIRED_CONTROLS.forEach(control -> assertTrue(effective.get(control)));
        assertFalse(effective.get(SystemPolicyControl.TETHERING));
        assertFalse(choices.get(SystemPolicyControl.PRIVATE_DNS));
    }

    @Test
    public void offDoesNotMutateAndroid() {
        FakeGateway device = new FakeGateway();
        HomeFilterPolicy.Report report = HomeFilterPolicy.reconcile(HomeFilterPolicy.Settings.OFF, 36, device);
        assertEquals(NOT_REQUESTED, report.vpn());
        assertFalse(report.active(HomeFilterPolicy.Settings.OFF));
        assertEquals(0, device.writes);
    }

    @Test
    public void needsFreshConfirmationOfThePackageLockdownExemptionsAndOtherSettings() {
        FakeGateway device = new FakeGateway();
        assertTrue(HomeFilterPolicy.reconcile(REQUEST, 29, device).active(REQUEST));
        assertEquals(PACKAGE, device.vpnPackage);
        assertEquals(PAC, device.pacUrl);
        assertTrue(device.hasCa);

        device.lockdown = false;
        assertInactiveVpn(device);
        device.lockdown = true;
        device.noExemptions = false;
        assertInactiveVpn(device);
        device.noExemptions = true;
        device.vpnPackage = "org.example.other";
        assertInactiveVpn(device);
        device.vpnPackage = PACKAGE;
        device.vpnUnreadable = true;
        assertInactiveVpn(device);
        device.vpnUnreadable = false;
        device.pacUrl = "";
        HomeFilterPolicy.Report read = HomeFilterPolicy.inspect(REQUEST, 29, device);
        assertEquals(CONFIRMED, read.vpn());
        assertEquals(UNCONFIRMED, read.proxy());
        assertFalse(read.active(REQUEST));
        device.pacUrl = PAC;
        device.restrictions = false;
        read = HomeFilterPolicy.inspect(REQUEST, 29, device);
        assertEquals(UNCONFIRMED, read.restrictions());
        assertFalse(read.active(REQUEST));
    }

    @Test
    public void missingOrHiddenVpnNeverReportsActiveEvenWithMatchingSettings() {
        FakeGateway device = new FakeGateway();
        assertTrue(HomeFilterPolicy.reconcile(REQUEST, 36, device).active(REQUEST));
        device.writes = 0;
        device.packageState = HomeFilterPolicy.PackageState.MISSING;
        HomeFilterPolicy.Report missing = HomeFilterPolicy.reconcile(REQUEST, 36, device);
        assertEquals(MISSING_VPN, missing.vpn());
        assertFalse(missing.active(REQUEST));
        device.packageState = HomeFilterPolicy.PackageState.HIDDEN;
        assertEquals(HIDDEN_VPN, HomeFilterPolicy.reconcile(REQUEST, 36, device).vpn());
        device.packageState = HomeFilterPolicy.PackageState.UNTRUSTED;
        HomeFilterPolicy.Report untrusted = HomeFilterPolicy.reconcile(REQUEST, 36, device);
        assertEquals(HomeFilterPolicy.State.UNTRUSTED_VPN, untrusted.vpn());
        assertFalse(untrusted.active(REQUEST));
        assertEquals(0, device.writes);
    }

    @Test
    public void preAndroid10AttemptsLockdownButRemainsUnconfirmed() {
        FakeGateway device = new FakeGateway();
        device.vpnUnreadable = true;
        HomeFilterPolicy.Report report = HomeFilterPolicy.reconcile(REQUEST, 28, device);
        assertEquals(UNCONFIRMED, report.vpn());
        assertEquals(PACKAGE, device.vpnPackage);
        assertTrue(device.lockdown);
        assertFalse(report.active(REQUEST));
    }

    @Test
    public void vpnRefusalDoesNotInstallTheProxyOrCa() {
        FakeGateway device = new FakeGateway();
        device.refuseVpn = true;
        HomeFilterPolicy.Report report = HomeFilterPolicy.reconcile(REQUEST, 36, device);
        assertEquals(REFUSED, report.vpn());
        assertEquals(1, device.writes);
        assertFalse(report.active(REQUEST));
        device.refuseVpn = false;
        device.ignoreVpn = true;
        report = HomeFilterPolicy.reconcile(REQUEST, 36, device);
        assertEquals(UNCONFIRMED, report.vpn());
        assertFalse(report.active(REQUEST));
        assertEquals(2, device.writes);
    }

    @Test
    public void matchingNetworkProxyDoesNotConcealARefusedGlobalProxyWrite() {
        FakeGateway device = new FakeGateway();
        device.pacUrl = PAC;
        device.refuseProxy = true;
        HomeFilterPolicy.Report result = HomeFilterPolicy.reconcile(REQUEST, 36, device);
        assertEquals(REFUSED, result.proxy());
        assertFalse(result.active(REQUEST));
        HomeFilterPolicy.Report fresh = HomeFilterPolicy.inspect(REQUEST, 36, device)
                .withProxyApplyEvidence(result.proxy());
        assertEquals(REFUSED, fresh.proxy());
        assertFalse(fresh.active(REQUEST));
    }

    @Test
    public void canRemoveCaWhileVpnIsMissingAndRetryIfAndroidRefuses() {
        FakeGateway device = new FakeGateway();
        assertTrue(HomeFilterPolicy.reconcile(REQUEST, 36, device).active(REQUEST));
        device.packageState = HomeFilterPolicy.PackageState.MISSING;
        HomeFilterPolicy.Settings removal = REQUEST.requestRemoveCa();
        device.refuseCa = true;
        HomeFilterPolicy.Report refused = HomeFilterPolicy.reconcile(removal, 36, device);
        assertEquals(REFUSED, refused.ca());
        assertEquals(removal, removal.afterReadback(refused));
        device.refuseCa = false;
        HomeFilterPolicy.Report verified = HomeFilterPolicy.reconcile(removal, 36, device);
        assertEquals(CONFIRMED, verified.ca());
        assertFalse(device.hasCa);
        HomeFilterPolicy.Settings remaining = removal.afterReadback(verified);
        assertNull(remaining.ca());
        assertTrue(remaining.enabled());
    }

    @Test
    public void disableKeepsPendingRequestUntilTheConfiguredSettingsAreRemoved() {
        FakeGateway device = new FakeGateway();
        HomeFilterPolicy.reconcile(REQUEST, 36, device);
        HomeFilterPolicy.Settings disable = REQUEST.requestDisable();
        device.refuseVpn = true;
        HomeFilterPolicy.Report pending = HomeFilterPolicy.reconcile(disable, 36, device);
        assertFalse(pending.removed());
        assertFalse(pending.active(disable));
        assertEquals(REQUEST.config(), disable.afterReadback(pending).config());
        device.refuseVpn = false;
        HomeFilterPolicy.Report removed = HomeFilterPolicy.reconcile(disable, 36, device);
        assertTrue(removed.removed());
        assertEquals(HomeFilterPolicy.Settings.OFF, disable.afterReadback(removed));
    }

    @Test
    public void disableDoesNotRemoveUnrelatedVpnOrPac() {
        FakeGateway device = new FakeGateway();
        device.vpnPackage = "org.example.other";
        device.pacUrl = "https://other.example/network.pac";
        HomeFilterPolicy.Settings disable = REQUEST.requestDisable();
        assertTrue(HomeFilterPolicy.reconcile(disable, 36, device).removed());
        assertEquals(0, device.writes);
    }

    @Test
    public void disableDoesNotClearNetworkSettingsThatCannotBeRead() {
        FakeGateway device = new FakeGateway();
        device.vpnUnreadable = true;
        device.proxyUnreadable = true;
        HomeFilterPolicy.Report pending = HomeFilterPolicy.reconcile(REQUEST.requestDisable(), 36, device);
        assertEquals(UNCONFIRMED, pending.vpn());
        assertEquals(UNCONFIRMED, pending.proxy());
        assertEquals(0, device.writes);
    }

    @Test
    public void disableRemainsPendingUntilOrdinaryRestrictionsAreRestored() {
        FakeGateway device = new FakeGateway();
        device.restrictions = false;
        HomeFilterPolicy.Settings disable = REQUEST.requestDisable();
        HomeFilterPolicy.Report pending = HomeFilterPolicy.reconcile(disable, 36, device);
        assertEquals(UNCONFIRMED, pending.restrictions());
        assertFalse(pending.removed());
        assertTrue(disable.afterReadback(pending).configured());
    }

    private static void assertInactiveVpn(FakeGateway device) {
        HomeFilterPolicy.Report report = HomeFilterPolicy.inspect(REQUEST, 29, device);
        assertEquals(UNCONFIRMED, report.vpn());
        assertFalse(report.active(REQUEST));
    }

    private static final class FakeGateway implements HomeFilterPolicy.Gateway {
        HomeFilterPolicy.PackageState packageState = HomeFilterPolicy.PackageState.INSTALLED;
        String vpnPackage;
        String pacUrl;
        boolean lockdown;
        boolean noExemptions;
        boolean restrictions = true;
        boolean hasCa;
        boolean refuseVpn;
        boolean ignoreVpn;
        boolean refuseCa;
        boolean refuseProxy;
        boolean vpnUnreadable;
        boolean proxyUnreadable;
        int writes;

        @Override
        public HomeFilterPolicy.PackageState vpnPackageState(String packageName) {
            return packageState;
        }

        @Override
        public String alwaysOnPackage() {
            if (vpnUnreadable) {
                throw new SecurityException();
            }
            return vpnPackage;
        }

        @Override
        public HomeFilterPolicy.VpnState vpnState() {
            if (vpnUnreadable) {
                throw new SecurityException();
            }
            return new HomeFilterPolicy.VpnState(vpnPackage, lockdown, noExemptions);
        }

        @Override
        public boolean setVpn(String packageName) {
            writes++;
            if (refuseVpn) {
                return false;
            }
            if (!ignoreVpn) {
                vpnPackage = packageName;
                lockdown = packageName != null;
                noExemptions = true;
            }
            return true;
        }

        @Override
        public String proxyPacUrl() {
            if (proxyUnreadable) {
                throw new SecurityException();
            }
            return pacUrl;
        }

        @Override
        public boolean setProxy(String url) {
            writes++;
            if (refuseProxy) {
                return false;
            }
            pacUrl = url;
            return true;
        }

        @Override
        public boolean hasCa(String certificate) {
            return hasCa;
        }

        @Override
        public boolean setCa(String certificate, boolean install) {
            writes++;
            if (refuseCa) {
                return false;
            }
            hasCa = install;
            return true;
        }

        @Override
        public boolean restrictionsMatch(boolean enabled) {
            return restrictions;
        }
    }
}
