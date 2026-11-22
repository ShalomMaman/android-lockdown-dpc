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
import java.util.HexFormat;
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
        HomeFilterPolicy.Routing routing = new HomeFilterPolicy.Routing(
                "T123", "https://vpn.example", "node", "Test");
        HomeFilterPolicy.Config config = new HomeFilterPolicy.Config(
                VPN, "https://filter.example/proxy.pac", signerDigest(), routing, null);
        HomeFilterStore.write(context, new HomeFilterPolicy.Settings(config, true, null, false));
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
        boolean refuseVpn;
        Runnable beforeVpnWrite = () -> {};

        @Implementation
        protected void setAlwaysOnVpnPackage(ComponentName admin, String packageName, boolean lockdown,
                                             Set<String> exemptions) throws PackageManager.NameNotFoundException {
            beforeVpnWrite.run();
            assertFalse(isApplicationHidden(admin, packageName));
            assertFalse(isPackageSuspended(admin, packageName));
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
            ConnectivityManager cm = RuntimeEnvironment.getApplication().getSystemService(ConnectivityManager.class);
            Network network = cm.getActiveNetwork();
            cm.bindProcessToNetwork(network);
            ShadowConnectivityManager connectivity = Shadow.extract(cm);
            connectivity.setProxyForNetwork(network, proxy);
        }

        @Implementation
        protected int getGlobalPrivateDnsMode(ComponentName admin) {
            return DevicePolicyManager.PRIVATE_DNS_MODE_OPPORTUNISTIC;
        }
    }
}
