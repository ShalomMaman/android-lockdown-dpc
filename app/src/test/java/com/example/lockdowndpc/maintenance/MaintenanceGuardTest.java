package com.example.lockdowndpc.maintenance;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.EnumSet;
import java.util.concurrent.TimeUnit;

/** Pure proof for the guard-level restore-debt authorization boundary. */
public final class MaintenanceGuardTest {

    @Test
    public void restoreDebtBlocksANewWindowAtTheGuardBoundary() {
        assertTrue(MaintenanceGuard.restoreDebtBlocksOpen(true, null));
        assertFalse(MaintenanceGuard.restoreDebtBlocksOpen(false, null));

        MaintenanceWindow existing = new MaintenanceWindow(
                EnumSet.of(MaintenanceCapability.APP_STORE_ACCESS),
                TimeUnit.MINUTES.toMillis(30),
                1_700_000_000_000L,
                60_000L,
                1_700_000_000_000L,
                60_000L);
        assertFalse(
                "an existing window is refused by the state machine as already open",
                MaintenanceGuard.restoreDebtBlocksOpen(true, existing));
    }
}
