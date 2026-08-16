package com.example.lockdowndpc.maintenance;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.maintenance.MaintenanceStateMachine.OpenRequest;
import com.example.lockdowndpc.policy.LockdownPackages;
import com.example.lockdowndpc.policy.SystemAppClassifier;

import org.junit.Test;

import java.util.EnumSet;
import java.util.concurrent.TimeUnit;

public final class MaintenanceAppPolicyTest {

    @Test
    public void reversibleStoreSetContainsPlayButNeverBrowsersOrInstallers() {
        assertTrue(MaintenanceAppPolicy.managedStorePackages().contains("com.android.vending"));
        assertFalse(MaintenanceAppPolicy.managedStorePackages().contains("com.android.chrome"));
        assertFalse(MaintenanceAppPolicy.managedStorePackages()
                .contains("com.android.packageinstaller"));
        assertTrue(LockdownPackages.ALWAYS_BLOCKED.contains("com.android.vending"));
        assertTrue(SystemAppClassifier.STORE_PACKAGES.contains("com.android.vending"));
    }

    @Test
    public void onlyAnExplicitStoreWindowOverridesTheHiddenStoreRule() {
        MaintenanceWindow stores = window(MaintenanceCapability.APP_STORE_ACCESS);
        MaintenanceWindow debugging = window(MaintenanceCapability.ADB_DEBUGGING);

        assertTrue(MaintenanceAppPolicy.opensApplicationStores(stores));
        assertTrue(MaintenanceAppPolicy.keepsVisible("com.android.vending", true));
        assertFalse(MaintenanceAppPolicy.opensApplicationStores(debugging));
        assertFalse(MaintenanceAppPolicy.keepsVisible("com.android.vending", false));
        assertFalse(MaintenanceAppPolicy.keepsVisible("com.android.chrome", true));
    }

    private static MaintenanceWindow window(MaintenanceCapability capability) {
        MaintenanceClock clock = new MaintenanceClock() {
            @Override public long wallClockMillis() { return 1_700_000_000_000L; }
            @Override public long elapsedSinceBootMillis() { return 60_000L; }
        };
        OpenRequest request = new OpenRequest(
                EnumSet.of(capability),
                TimeUnit.MINUTES.toMillis(30),
                true,
                true);
        return MaintenanceStateMachine.open(null, request, clock).window();
    }
}
