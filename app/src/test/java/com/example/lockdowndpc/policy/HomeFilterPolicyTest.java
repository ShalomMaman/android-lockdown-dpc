package com.example.lockdowndpc.policy;

import org.junit.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static com.example.lockdowndpc.policy.HomeFilterPolicy.State.CONFIRMED;
import static com.example.lockdowndpc.policy.HomeFilterPolicy.State.HIDDEN_VPN;
import static com.example.lockdowndpc.policy.HomeFilterPolicy.State.MISSING_VPN;
import static com.example.lockdowndpc.policy.HomeFilterPolicy.State.NOT_REQUESTED;
import static com.example.lockdowndpc.policy.HomeFilterPolicy.State.REFUSED;
import static com.example.lockdowndpc.policy.HomeFilterPolicy.State.UNCONFIRMED;
import static com.example.lockdowndpc.policy.HomeFilterPolicy.State.UNTRUSTED_VPN;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class HomeFilterPolicyTest {
    private static final String PACKAGE = "com.tailscale.ipn";
    private static final String PAC = "https://filter.example/home.pac";
    private static final HomeFilterPolicy.Routing ROUTING = new HomeFilterPolicy.Routing(
            "T123456CNTRL", HomeFilterPolicy.DEFAULT_LOGIN_URL, "n123456CNTRL", "Family");
    private static final HomeFilterPolicy.Settings REQUEST = new HomeFilterPolicy.Settings(
            new HomeFilterPolicy.Config("", PAC, "", ROUTING, null), true, "selected-ca", false);

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
    public void requiresInstallUninstallAndTimeControlsAndKeepsThemOnPause() {
        Map<SystemPolicyControl, Boolean> choices = Map.of(
                SystemPolicyControl.PRIVATE_DNS, false, SystemPolicyControl.TETHERING, false);
        Map<SystemPolicyControl, Boolean> effective = HomeFilterPolicy.requireControls(choices);
        assertEquals(Set.of(SystemPolicyControl.VPN_CONFIGURATION, SystemPolicyControl.PRIVATE_DNS,
                        SystemPolicyControl.NETWORK_RESET, SystemPolicyControl.SAFE_BOOT,
                        SystemPolicyControl.FACTORY_RESET, SystemPolicyControl.USER_AND_PROFILE_CREATION,
                        SystemPolicyControl.DATE_AND_TIME, SystemPolicyControl.APP_UNINSTALL,
                        SystemPolicyControl.APP_CONTROL_SETTINGS, SystemPolicyControl.UNKNOWN_SOURCE_INSTALLS,
                        SystemPolicyControl.APP_STORES_AND_INSTALLERS),
                HomeFilterPolicy.REQUIRED_CONTROLS);
        HomeFilterPolicy.REQUIRED_CONTROLS.forEach(control -> assertTrue(effective.get(control)));
        assertFalse(effective.get(SystemPolicyControl.TETHERING));
        assertFalse(choices.get(SystemPolicyControl.PRIVATE_DNS));
        Set<String> inForce = new HashSet<>();
        SystemPolicyReport released = SystemPolicyEnforcer.release(35, new SystemPolicyGateway() {
            @Override
            public void addRestriction(String key) { inForce.add(key); }

            @Override
            public void clearRestriction(String key) { inForce.remove(key); }

            @Override
            public boolean isRestrictionInForce(String key) { return inForce.contains(key); }
        }, HomeFilterPolicy.REQUIRED_CONTROLS);
        assertTrue(released.failures().isEmpty());
        assertTrue(inForce.containsAll(List.of("no_config_date_time", "no_uninstall_apps",
                "no_control_apps", "no_install_apps", "no_install_unknown_sources",
                "no_install_unknown_sources_globally")));
        assertFalse(HomeFilterPolicy.permitsRelaxing(Set.of(SystemPolicyControl.APP_CONTROL_SETTINGS)));
        assertTrue(HomeFilterPolicy.permitsRelaxing(Set.of(SystemPolicyControl.USB_FILE_TRANSFER)));
    }

    @Test
    public void profileRestrictionsGatePrivateSpaceAtApi35AndRequireReadback() {
        assertEquals(List.of("no_add_managed_profile"), profileKeys(29));
        assertEquals(List.of("no_add_managed_profile"), profileKeys(34));
        assertEquals(List.of("no_add_managed_profile", "no_add_private_profile"), profileKeys(35));
        FakeGateway device = new FakeGateway();
        device.profileRestrictions = false;
        device.ignoreProfileRestrictions = true;
        HomeFilterPolicy.Report unconfirmed = HomeFilterPolicy.reconcile(REQUEST, 35, device);
        assertEquals(UNCONFIRMED, unconfirmed.restrictions());
        assertFalse(unconfirmed.androidSettingsConfirmed(REQUEST));
        device.ignoreProfileRestrictions = false;
        assertTrue(HomeFilterPolicy.reconcile(REQUEST, 35, device).androidSettingsConfirmed(REQUEST));
        assertTrue(device.profileRestrictions);
        assertTrue(HomeFilterPolicy.reconcile(REQUEST.requestDisable(), 35, device).removed());
        assertFalse(device.profileRestrictions);
    }

    private static List<String> profileKeys(int sdk) {
        return HomeFilterPolicy.profileRestrictions(sdk).stream()
                .map(SystemPolicyControl.Restriction::key).toList();
    }

    @Test
    public void allowSelectedCannotHideTheEnabledVpnEvenWhenItWouldBeBlocked() {
        assertFalse(REQUEST.packageShouldBeHidden(PACKAGE, true));
        assertTrue(REQUEST.packageShouldBeHidden("org.example.unselected", true));
        assertTrue(REQUEST.requestDisable().packageShouldBeHidden(PACKAGE, true));
        assertTrue(HomeFilterPolicy.Settings.OFF.packageShouldBeHidden(PACKAGE, true));
    }

    @Test
    public void offDoesNotMutateAndroid() {
        FakeGateway device = new FakeGateway();
        HomeFilterPolicy.Report report = HomeFilterPolicy.reconcile(HomeFilterPolicy.Settings.OFF, 36, device);
        assertEquals(NOT_REQUESTED, report.vpn());
        assertFalse(report.androidSettingsConfirmed(HomeFilterPolicy.Settings.OFF));
        assertEquals(0, device.writes);
    }

    @Test
    public void needsFreshConfirmationOfThePackageLockdownExemptionsAndOtherSettings() {
        FakeGateway device = new FakeGateway();
        assertTrue(HomeFilterPolicy.reconcile(REQUEST, 29, device).androidSettingsConfirmed(REQUEST));
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
        assertFalse(read.androidSettingsConfirmed(REQUEST));
        device.pacUrl = PAC;
        device.restrictions = false;
        read = HomeFilterPolicy.inspect(REQUEST, 29, device);
        assertEquals(UNCONFIRMED, read.restrictions());
        assertFalse(read.androidSettingsConfirmed(REQUEST));
    }

    @Test
    public void missingOrHiddenVpnNeverReportsActiveEvenWithMatchingSettings() {
        FakeGateway device = new FakeGateway();
        assertTrue(HomeFilterPolicy.reconcile(REQUEST, 36, device).androidSettingsConfirmed(REQUEST));
        device.writes = 0;
        device.packageState = HomeFilterPolicy.PackageState.MISSING;
        HomeFilterPolicy.Report missing = HomeFilterPolicy.reconcile(REQUEST, 36, device);
        assertEquals(MISSING_VPN, missing.vpn());
        assertFalse(missing.androidSettingsConfirmed(REQUEST));
        device.packageState = HomeFilterPolicy.PackageState.HIDDEN;
        assertEquals(HIDDEN_VPN, HomeFilterPolicy.reconcile(REQUEST, 36, device).vpn());
        device.packageState = HomeFilterPolicy.PackageState.UNTRUSTED;
        HomeFilterPolicy.Report untrusted = HomeFilterPolicy.reconcile(REQUEST, 36, device);
        assertEquals(UNTRUSTED_VPN, untrusted.vpn());
        assertFalse(untrusted.androidSettingsConfirmed(REQUEST));
        assertEquals(0, device.writes);
    }

    @Test
    public void preAndroid10RefusesWithoutWritingNetworkSettings() {
        FakeGateway device = new FakeGateway();
        HomeFilterPolicy.Report report = HomeFilterPolicy.reconcile(REQUEST, 28, device);
        assertEquals(REFUSED, report.vpn());
        assertEquals(0, device.writes);
        assertFalse(report.androidSettingsConfirmed(REQUEST));
        assertFalse(HomeFilterPolicy.supportedOn(28));
        assertTrue(HomeFilterPolicy.supportedOn(29));
    }

    @Test
    public void missingPinDoesNotTrustAnInstalledVpnWithAnObservedSigner() {
        String signer = "ab".repeat(32);
        var unpinned = new LockdownPackages.ManagementPackage(PACKAGE, Set.of());
        var pinned = unpinned.withPins(Set.of(signer));
        FakeGateway device = new FakeGateway();
        device.packageState = HomeFilterPolicy.installedVpnState(
                LockdownPackages.verifySigner(unpinned, Set.of(signer)));
        assertEquals(HomeFilterPolicy.PackageState.UNTRUSTED, device.packageState);
        assertEquals(UNTRUSTED_VPN, HomeFilterPolicy.reconcile(REQUEST, 35, device).vpn());
        assertEquals(0, device.writes);
        assertEquals(HomeFilterPolicy.PackageState.UNTRUSTED, HomeFilterPolicy.installedVpnState(
                LockdownPackages.verifySigner(pinned, Set.of("cd".repeat(32)))));
        assertEquals(HomeFilterPolicy.PackageState.INSTALLED, HomeFilterPolicy.installedVpnState(
                LockdownPackages.verifySigner(pinned, Set.of(signer))));
    }

    @Test
    public void uninstallBlockMustReadBackTrueEvenIfLockdownWasAlreadyConfigured() {
        FakeGateway device = new FakeGateway();
        assertTrue(HomeFilterPolicy.reconcile(REQUEST, 35, device).androidSettingsConfirmed(REQUEST));
        device.blocked = false;
        device.ignoreUninstallBlock = true;
        HomeFilterPolicy.Report report = HomeFilterPolicy.reconcile(REQUEST, 35, device);
        assertEquals(UNCONFIRMED, report.vpn());
        assertFalse(report.androidSettingsConfirmed(REQUEST));
        assertEquals(UNCONFIRMED, HomeFilterPolicy.inspect(REQUEST, 35, device).vpn());
        device.ignoreUninstallBlock = false;
        assertTrue(HomeFilterPolicy.reconcile(REQUEST, 35, device).androidSettingsConfirmed(REQUEST));
        assertTrue(device.blocked);
    }

    @Test
    public void managedVpnRequiresAllExpectedKeysTypesAndValuesOnEveryReadback() {
        FakeGateway device = new FakeGateway();
        device.managed.put("OtherPolicy", "untouched");
        assertTrue(HomeFilterPolicy.reconcile(REQUEST, 35, device).androidSettingsConfirmed(REQUEST));
        assertEquals(Map.of("ForceEnabled", true, "Tailnet", "required:T123456CNTRL",
                "LoginURL", HomeFilterPolicy.DEFAULT_LOGIN_URL, "ExitNodeID", "n123456CNTRL",
                "ExitNodesPicker", "hide", "ExitNodeAllowLANAccess", "never",
                "ManagedByOrganizationName", "Family", "OtherPolicy", "untouched"), device.managed);
        device.managed.put("ExitNodeAllowLANAccess", "user-decides");
        assertEquals(UNCONFIRMED, HomeFilterPolicy.inspect(REQUEST, 35, device).vpn());
        assertTrue(HomeFilterPolicy.reconcile(REQUEST, 35, device).androidSettingsConfirmed(REQUEST));
        device.managed.put("ForceEnabled", "true");
        assertEquals(UNCONFIRMED, HomeFilterPolicy.inspect(REQUEST, 35, device).vpn());
        device.ignoreManagedConfig = true;
        assertFalse(HomeFilterPolicy.reconcile(REQUEST, 35, device).androidSettingsConfirmed(REQUEST));
        device.ignoreManagedConfig = false;
        assertTrue(HomeFilterPolicy.reconcile(REQUEST, 35, device).androidSettingsConfirmed(REQUEST));
        assertTrue(HomeFilterPolicy.reconcile(REQUEST.requestDisable(), 35, device).removed());
        assertEquals(Map.of("OtherPolicy", "untouched"), device.managed);
        assertFalse(device.blocked);
    }

    @Test
    public void existingConfigWithoutManagedRoutingRemainsUnconfirmedAndCanBeRemoved() {
        FakeGateway device = new FakeGateway();
        var legacy = new HomeFilterPolicy.Settings(new HomeFilterPolicy.Config(PACKAGE, PAC),
                true, null, false);
        assertEquals(UNCONFIRMED, HomeFilterPolicy.reconcile(legacy, 35, device).vpn());
        assertNull(device.vpnPackage);
        assertTrue(HomeFilterPolicy.reconcile(legacy.requestDisable(), 35, device).removed());
    }

    @Test
    public void privateDnsMustReadBackOpportunisticOnAndroid10AndLater() {
        FakeGateway device = new FakeGateway();
        device.ignorePrivateDns = true;
        HomeFilterPolicy.Report report = HomeFilterPolicy.reconcile(REQUEST, 29, device);
        assertEquals(UNCONFIRMED, report.privateDns());
        assertFalse(report.androidSettingsConfirmed(REQUEST));
        device.ignorePrivateDns = false;
        assertTrue(HomeFilterPolicy.reconcile(REQUEST, 29, device).androidSettingsConfirmed(REQUEST));
        device.privateDns = false;
        assertEquals(UNCONFIRMED, HomeFilterPolicy.inspect(REQUEST, 29, device).privateDns());
    }

    @Test
    public void activeRequiresFreshAndroidReadbackAndPassingConfiguredProbe() {
        FakeGateway device = new FakeGateway();
        var canary = new HomeFilterPolicy.Canary("https://canary.example/check", "filter-ok");
        var withProbe = new HomeFilterPolicy.Settings(
                new HomeFilterPolicy.Config(PACKAGE, PAC, "", ROUTING, canary), true, null, false);
        var confirmed = HomeFilterPolicy.reconcile(withProbe, 35, device);
        assertEquals(HomeFilterPolicy.Status.ANDROID_SETTINGS_CONFIRMED,
                confirmed.status(REQUEST, HomeFilterPolicy.ProbeState.PASSED));
        assertEquals(HomeFilterPolicy.Status.PROBE_PENDING,
                confirmed.status(withProbe, HomeFilterPolicy.ProbeState.NOT_RUN));
        assertEquals(HomeFilterPolicy.Status.PROBE_FAILED,
                confirmed.status(withProbe, HomeFilterPolicy.ProbeState.FAILED));
        assertEquals(HomeFilterPolicy.Status.FILTER_ACTIVE,
                confirmed.status(withProbe, HomeFilterPolicy.ProbeState.PASSED));
        device.lockdown = false;
        assertEquals(HomeFilterPolicy.Status.SETTINGS_UNCONFIRMED,
                HomeFilterPolicy.inspect(withProbe, 35, device)
                        .status(withProbe, HomeFilterPolicy.ProbeState.PASSED));
    }

    @Test
    public void vpnRefusalDoesNotInstallTheProxyOrCa() {
        FakeGateway device = new FakeGateway();
        device.refuseVpn = true;
        HomeFilterPolicy.Report report = HomeFilterPolicy.reconcile(REQUEST, 36, device);
        assertEquals(REFUSED, report.vpn());
        assertNull(device.pacUrl);
        assertFalse(device.hasCa);
        assertFalse(report.androidSettingsConfirmed(REQUEST));
        device.refuseVpn = false;
        device.ignoreVpn = true;
        report = HomeFilterPolicy.reconcile(REQUEST, 36, device);
        assertEquals(UNCONFIRMED, report.vpn());
        assertFalse(report.androidSettingsConfirmed(REQUEST));
    }

    @Test
    public void allowedAppStaysHiddenWhenVpnLockdownCannotBeVerified() {
        FakeGateway device = new FakeGateway();
        device.refuseVpn = true;
        List<String> errors = new ArrayList<>();
        boolean networkVerified = HomeFilterController.verifyReadback(
                REQUEST, HomeFilterPolicy.reconcile(REQUEST, 36, device), errors);
        assertFalse(networkVerified);
        assertTrue(errors.get(0).startsWith("home-filter:vpn=REFUSED"));

        AtomicBoolean hidden = new AtomicBoolean(true);
        assertTrue(LockdownPolicyController.reconcilePackageVisibility(
                "com.example.allowed", false, networkVerified, hidden::get, hide -> {
                    hidden.set(hide);
                    assertTrue("An unverified pass must never attempt to show the app", hide);
                    return true;
                }, errors));
        assertTrue(hidden.get());

        hidden.set(false);
        assertTrue(LockdownPolicyController.reconcilePackageVisibility(
                "com.example.blocked", true, networkVerified, hidden::get, hide -> {
                    hidden.set(hide);
                    return true;
                }, errors));
        assertTrue(hidden.get());
    }

    @Test
    public void matchingNetworkProxyDoesNotConcealARefusedGlobalProxyWrite() {
        FakeGateway device = new FakeGateway();
        device.pacUrl = PAC;
        device.refuseProxy = true;
        HomeFilterPolicy.Report result = HomeFilterPolicy.reconcile(REQUEST, 36, device);
        assertEquals(REFUSED, result.proxy());
        assertFalse(result.androidSettingsConfirmed(REQUEST));
        HomeFilterPolicy.Report fresh = HomeFilterPolicy.inspect(REQUEST, 36, device)
                .withProxyApplyEvidence(result.proxy());
        assertEquals(REFUSED, fresh.proxy());
        assertFalse(fresh.androidSettingsConfirmed(REQUEST));
    }

    @Test
    public void canRemoveCaWhileVpnIsMissingAndRetryIfAndroidRefuses() {
        FakeGateway device = new FakeGateway();
        assertTrue(HomeFilterPolicy.reconcile(REQUEST, 36, device).androidSettingsConfirmed(REQUEST));
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
        assertFalse(pending.androidSettingsConfirmed(disable));
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
        assertFalse(report.androidSettingsConfirmed(REQUEST));
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
        Boolean profileRestrictions;
        boolean ignoreProfileRestrictions;
        boolean blocked;
        boolean ignoreUninstallBlock;
        boolean ignoreManagedConfig;
        boolean privateDns;
        boolean ignorePrivateDns;
        Map<String, Object> managed = new HashMap<>();
        int writes;

        @Override
        public HomeFilterPolicy.PackageState vpnPackageState(HomeFilterPolicy.Config config) {
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
        public boolean uninstallBlocked(String packageName) {
            return blocked;
        }

        @Override
        public boolean setVpnUninstallBlocked(String packageName, boolean requested) {
            writes++;
            if (!ignoreUninstallBlock) blocked = requested;
            return true;
        }

        @Override
        public boolean retainVpnUninstallBlock(String packageName) {
            return false;
        }

        @Override
        public Map<String, Object> managedConfig(String packageName) {
            return Map.copyOf(managed);
        }

        @Override
        public boolean setManagedConfig(String packageName, Map<String, Object> changes, boolean enabled) {
            writes++;
            if (!ignoreManagedConfig) {
                if (enabled) managed.putAll(changes);
                else changes.forEach(managed::remove);
            }
            return true;
        }

        @Override
        public boolean privateDnsOpportunistic() {
            return privateDns;
        }

        @Override
        public boolean setPrivateDnsOpportunistic() {
            writes++;
            if (!ignorePrivateDns) privateDns = true;
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
            return restrictions && (profileRestrictions == null || profileRestrictions == enabled);
        }

        @Override
        public boolean setProfileRestrictions(boolean enabled) {
            if (profileRestrictions != null && !ignoreProfileRestrictions) profileRestrictions = enabled;
            return true;
        }
    }
}
