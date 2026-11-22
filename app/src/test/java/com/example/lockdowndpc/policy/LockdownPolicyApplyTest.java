package com.example.lockdowndpc.policy;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.ProxyInfo;
import android.net.Uri;

import com.example.lockdowndpc.admin.LockdownAdminReceiver;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;
import org.robolectric.annotation.Implementation;
import org.robolectric.annotation.Implements;
import org.robolectric.shadow.api.Shadow;
import org.robolectric.shadows.ShadowConnectivityManager;
import org.robolectric.shadows.ShadowDevicePolicyManager;
import org.robolectric.shadows.ShadowPackageManager;
import org.robolectric.shadows.ShadowSigningInfo;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 32, shadows = LockdownPolicyApplyTest.FilterDevicePolicy.class)
public class LockdownPolicyApplyTest {
    private static final String VPN = "com.example.filter";
    private static final String ALLOWED = "com.example.allowed";
    private static final String BLOCKED = "com.example.blocked";
    private static final String SOCIAL = "com.whatsapp";
    private static final byte[] SIGNER = {1, 2, 3};
    private static final String WRONG_PIN = "00".repeat(32);

    private Context context;
    private ComponentName admin;
    private DevicePolicyManager dpm;
    private FilterDevicePolicy devicePolicy;

    @Before
    public void setUp() throws Exception {
        context = RuntimeEnvironment.getApplication();
        admin = LockdownAdminReceiver.componentName(context);
        dpm = context.getSystemService(DevicePolicyManager.class);
        devicePolicy = Shadow.extract(dpm);
        assertTrue(devicePolicy.setDeviceOwner(admin));

        install(VPN);
        install(ALLOWED);
        install(BLOCKED);
        assertTrue(AllowedAppsStore.setProtectionMode(context, AllowedAppsStore.ProtectionMode.ALLOW_SELECTED));
        assertTrue(AllowedAppsStore.setAllowedPackages(
                context, Set.of(ALLOWED), Set.of(ALLOWED, BLOCKED, VPN), Set.of()));
        assertTrue(dpm.setApplicationHidden(admin, ALLOWED, true));
        HomeFilterStore.write(context, filterSettings(VPN, signerDigest(), true));
    }

    @Test
    public void applyRestoresHiddenFilterVpnBeforeNetworkVerification() throws Exception {
        assertTrue(dpm.setApplicationHidden(admin, VPN, true));

        assertVpnRecoveredInOnePass();
    }

    @Test
    public void applyRestoresFilterVpnSuspendedByScheduleBeforeNetworkVerification() throws Exception {
        assertEquals(0, dpm.setPackagesSuspended(admin, new String[]{VPN}, true).length);
        assertTrue(dpm.isPackageSuspended(admin, VPN));
        assertTrue(ScheduleStore.saveOwned(context, Set.of(VPN)));

        assertVpnRecoveredInOnePass();
        assertTrue(ScheduleStore.readOwned(context).isEmpty());
    }

    @Test
    public void corruptFilterKeepsNetworkEnforcedInLocalMode() throws Exception {
        assertTrue(ManagementModeStore.selectLocal(context));
        assertCorruptFilterKeepsNetworkEnforced(ManagementMode.LOCAL_PIN);
    }

    @Test
    public void corruptFilterKeepsNetworkEnforcedDuringEnrollment() throws Exception {
        setRemoteMarker();
        assertCorruptFilterKeepsNetworkEnforced(ManagementMode.ENROLLING);
    }

    @Test
    public void corruptFilterKeepsNetworkEnforcedInRemoteMode() throws Exception {
        setRemoteMarker();
        assertTrue(context.getSharedPreferences(ManagementModeStore.MODE_PREFS, Context.MODE_PRIVATE)
                .edit().putString(ManagementModeStore.MODE_KEY, ManagementMode.REMOTE.name()).commit());
        assertCorruptFilterKeepsNetworkEnforced(ManagementMode.REMOTE);
    }

    private void setRemoteMarker() {
        assertTrue(context.createDeviceProtectedStorageContext()
                .getSharedPreferences(ManagementModeStore.MARKER_PREFS, Context.MODE_PRIVATE)
                .edit().putBoolean(ManagementModeStore.MARKER_KEY, true).commit());
    }

    private void assertCorruptFilterKeepsNetworkEnforced(ManagementMode mode) throws Exception {
        assertEquals(mode, ManagementModeStore.read(context));
        Set<String> exemptions = Set.of(context.getPackageName());
        ProxyInfo proxy = ProxyInfo.buildPacProxy(Uri.parse("https://filter.example/proxy.pac"));
        byte[] certificate = {4, 5, 6};
        dpm.setAlwaysOnVpnPackage(admin, VPN, true, exemptions);
        dpm.setRecommendedGlobalProxy(admin, proxy);
        assertTrue(dpm.installCaCert(admin, certificate));
        ConnectivityManager connectivity = context.getSystemService(ConnectivityManager.class);
        assertEquals(proxy, connectivity.getDefaultProxy());
        assertTrue(context.getSharedPreferences("home_filter", Context.MODE_PRIVATE)
                .edit().remove("pac_url").commit());

        var result = mode.usesLocalPolicy() ? LockdownPolicyController.apply(context)
                : LockdownPolicyController.applyRemoteContainment(context);

        assertFalse(result.applied());
        assertTrue(result.errors().contains(HomeFilterController.CORRUPT_CONFIGURATION));
        assertEquals(VPN, dpm.getAlwaysOnVpnPackage(admin));
        assertTrue(dpm.isAlwaysOnVpnLockdownEnabled(admin));
        assertEquals(exemptions, dpm.getAlwaysOnVpnLockdownWhitelist(admin));
        assertFalse(dpm.isApplicationHidden(admin, VPN));
        assertFalse(dpm.isPackageSuspended(admin, VPN));
        assertEquals(proxy, connectivity.getDefaultProxy());
        assertTrue(dpm.hasCaCertInstalled(admin, certificate));
    }

    @Test
    public void reconcileKeepsHiddenVpnHiddenWhenSignerDoesNotMatch() {
        assertHiddenVpnStaysHidden(filterSettings(VPN, WRONG_PIN, true));
    }

    @Test
    public void reconcileKeepsSuspendedVpnSuspendedWhenSignerDoesNotMatch() throws Exception {
        assertSuspendedVpnStaysSuspended(filterSettings(VPN, WRONG_PIN, true));
    }

    @Test
    public void reconcileKeepsHiddenVpnHiddenWhenFilterIsOff() throws Exception {
        assertHiddenVpnStaysHidden(filterSettings(VPN, signerDigest(), false));
    }

    @Test
    public void reconcileKeepsSuspendedVpnSuspendedWhenFilterIsOff() throws Exception {
        assertSuspendedVpnStaysSuspended(filterSettings(VPN, signerDigest(), false));
    }

    @Test
    public void reconcileKeepsHiddenVpnHiddenWhenAnotherPackageIsConfigured() throws Exception {
        assertHiddenVpnStaysHidden(filterSettings(BLOCKED, signerDigest(), true));
        assertEquals(BLOCKED, dpm.getAlwaysOnVpnPackage(admin));
    }

    @Test
    public void reconcileKeepsSuspendedVpnSuspendedWhenAnotherPackageIsConfigured() throws Exception {
        assertSuspendedVpnStaysSuspended(filterSettings(BLOCKED, signerDigest(), true));
        assertEquals(BLOCKED, dpm.getAlwaysOnVpnPackage(admin));
    }

    @Test
    public void applyVerifiesNetworkBeforeSweepingPackagesAndKeepsAppsContainedOnVpnFailure() throws Exception {
        install(SOCIAL);
        assertTrue(BuiltInBlockExemptionsStore.write(context,
                new BuiltInBlockExemptions.Settings(false, Map.of(SOCIAL, signerDigest()))));
        assertEquals(0, dpm.setPackagesSuspended(admin, new String[]{SOCIAL}, true).length);
        assertTrue(dpm.isPackageSuspended(admin, SOCIAL));
        devicePolicy.beforeVpnWrite = () -> {
            // The ordinary package sweep also hides BLOCKED. Its state at the
            // VPN write checks the order even if an early sweep refuses releases.
            assertFalse(dpm.isApplicationHidden(admin, BLOCKED));
            assertTrue(dpm.isApplicationHidden(admin, ALLOWED));
        };
        devicePolicy.refuseVpn = true;

        LockdownPolicyController.PolicyResult result = LockdownPolicyController.apply(context);

        assertFalse(result.applied());
        assertTrue(result.errors().toString(),
                result.errors().stream().anyMatch(error -> error.startsWith("home-filter:vpn=REFUSED,")));
        assertTrue(dpm.isApplicationHidden(admin, BLOCKED));
        assertTrue(dpm.isApplicationHidden(admin, ALLOWED));
        assertFalse(dpm.isApplicationHidden(admin, SOCIAL));
        assertTrue(dpm.isPackageSuspended(admin, SOCIAL));
    }

    private static HomeFilterPolicy.Settings filterSettings(String packageName, String signerPin, boolean enabled) {
        HomeFilterPolicy.Routing routing = new HomeFilterPolicy.Routing(
                "T123", "https://vpn.example", "node", "Test");
        HomeFilterPolicy.Config config = new HomeFilterPolicy.Config(
                packageName, "https://filter.example/proxy.pac", signerPin, routing, null);
        return new HomeFilterPolicy.Settings(config, enabled, null, false);
    }

    private void assertHiddenVpnStaysHidden(HomeFilterPolicy.Settings settings) {
        assertTrue(dpm.setApplicationHidden(admin, VPN, true));
        assertTrue(dpm.isApplicationHidden(admin, VPN));
        reconcileFilter(settings);
        assertTrue(dpm.isApplicationHidden(admin, VPN));
    }

    private void assertSuspendedVpnStaysSuspended(HomeFilterPolicy.Settings settings) throws Exception {
        assertEquals(0, dpm.setPackagesSuspended(admin, new String[]{VPN}, true).length);
        assertTrue(dpm.isPackageSuspended(admin, VPN));
        reconcileFilter(settings);
        assertTrue(dpm.isPackageSuspended(admin, VPN));
    }

    private void reconcileFilter(HomeFilterPolicy.Settings settings) {
        // Exercise availability recovery without the package sweep re-hiding a released app.
        List<String> errors = new ArrayList<>();
        HomeFilterController.reconcile(context, dpm, admin, errors,
                new BuiltInBlockExemptions.PassFilter(settings, settings, null));
        assertFalse(errors.toString(), errors.stream().anyMatch(error -> error.startsWith("home-filter:vpn-availability:")));
    }

    private void assertVpnRecoveredInOnePass() throws Exception {
        LockdownPolicyController.PolicyResult result = LockdownPolicyController.apply(context);

        assertFalse(result.errors().toString(),
                result.errors().stream().anyMatch(error -> error.startsWith("home-filter:")));
        assertEquals(VPN, dpm.getAlwaysOnVpnPackage(admin));
        assertFalse(dpm.isApplicationHidden(admin, VPN));
        assertFalse(dpm.isPackageSuspended(admin, VPN));
        // This ordinary app can only be shown once networkVerified is true.
        assertFalse(dpm.isApplicationHidden(admin, ALLOWED));
    }

    private void install(String name) {
        PackageInfo info = new PackageInfo();
        info.packageName = name;
        info.applicationInfo = new ApplicationInfo();
        info.applicationInfo.packageName = name;
        info.applicationInfo.enabled = true;
        info.signingInfo = Shadow.newInstanceOf(SigningInfo.class);
        ShadowSigningInfo signingInfo = Shadow.extract(info.signingInfo);
        signingInfo.setSignatures(new Signature[]{new Signature(SIGNER)});
        ShadowPackageManager packages = Shadow.extract(context.getPackageManager());
        packages.installPackage(info);
    }

    private static String signerDigest() throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(SIGNER));
    }

    /** Adds the filter-specific Android calls to Robolectric's package policy. */
    @Implements(DevicePolicyManager.class)
    public static class FilterDevicePolicy extends ShadowDevicePolicyManager {
        private String alwaysOnVpn;
        private boolean lockdown;
        private Set<String> exemptions;
        private final Set<String> caCertificates = new HashSet<>();
        boolean refuseVpn;
        Runnable beforeVpnWrite = () -> {};
        boolean refuseProxyChange;
        /** Packages Android refuses to make visible. */
        final Set<String> refuseUnhide = new HashSet<>();
        /** Runs after a package became visible, to fail or stop a pass between two releases. */
        java.util.function.Consumer<String> afterUnhide = packageName -> {};

        @Implementation
        protected boolean setApplicationHidden(ComponentName admin, String packageName, boolean hidden) {
            if (!hidden && refuseUnhide.contains(packageName)) {
                return false;
            }
            boolean wasHidden = isApplicationHidden(admin, packageName);
            boolean changed = super.setApplicationHidden(admin, packageName, hidden);
            if (!hidden && wasHidden) {
                afterUnhide.accept(packageName);
            }
            return changed;
        }

        @Implementation
        protected void setAlwaysOnVpnPackage(ComponentName admin, String packageName, boolean lockdown,
                                             Set<String> exemptions) throws PackageManager.NameNotFoundException {
            beforeVpnWrite.run();
            if (packageName != null) {
                assertFalse(isApplicationHidden(admin, packageName));
                assertFalse(isPackageSuspended(admin, packageName));
            }
            if (refuseVpn) {
                throw new SecurityException("VPN refused");
            }
            alwaysOnVpn = packageName;
            this.lockdown = lockdown;
            this.exemptions = exemptions;
        }

        private final android.os.Bundle userRestrictions = new android.os.Bundle();

        @Implementation
        protected void addUserRestriction(ComponentName admin, String key) {
            userRestrictions.putBoolean(key, true);
        }

        @Implementation
        protected void clearUserRestriction(ComponentName admin, String key) {
            userRestrictions.remove(key);
        }

        @Implementation
        protected android.os.Bundle getUserRestrictions(ComponentName admin) {
            return new android.os.Bundle(userRestrictions);
        }

        @Implementation
        protected String getAlwaysOnVpnPackage(ComponentName admin) {
            return alwaysOnVpn;
        }

        @Implementation
        protected boolean isAlwaysOnVpnLockdownEnabled(ComponentName admin) {
            return lockdown;
        }

        @Implementation
        protected Set<String> getAlwaysOnVpnLockdownWhitelist(ComponentName admin) {
            return exemptions;
        }

        @Implementation
        protected void setRecommendedGlobalProxy(ComponentName admin, ProxyInfo proxy) {
            if (refuseProxyChange) {
                throw new SecurityException("Proxy refused");
            }
            ConnectivityManager cm = RuntimeEnvironment.getApplication().getSystemService(ConnectivityManager.class);
            Network network = cm.getActiveNetwork();
            cm.bindProcessToNetwork(network);
            ShadowConnectivityManager connectivity = Shadow.extract(cm);
            connectivity.setProxyForNetwork(network, proxy);
        }

        @Implementation
        protected boolean installCaCert(ComponentName admin, byte[] certificate) {
            return caCertificates.add(HexFormat.of().formatHex(certificate));
        }

        @Implementation
        protected boolean hasCaCertInstalled(ComponentName admin, byte[] certificate) {
            return caCertificates.contains(HexFormat.of().formatHex(certificate));
        }

        @Implementation
        protected void uninstallCaCert(ComponentName admin, byte[] certificate) {
            caCertificates.remove(HexFormat.of().formatHex(certificate));
        }

        @Implementation
        protected int getGlobalPrivateDnsMode(ComponentName admin) {
            return DevicePolicyManager.PRIVATE_DNS_MODE_OPPORTUNISTIC;
        }
    }
}
