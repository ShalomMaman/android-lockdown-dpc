package com.example.lockdowndpc.maintenance;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** Pure checks for the process-bound authorization gate used before preferences are parsed. */
public final class MaintenanceStoreTest {

    @Test
    public void onlyTheCurrentSchemaAndProcessMayReuseAStoredWindow() {
        assertTrue(MaintenanceStore.belongsToCurrentProcess(2, "current", "current"));
        assertFalse(MaintenanceStore.belongsToCurrentProcess(1, "current", "current"));
        assertFalse(MaintenanceStore.belongsToCurrentProcess(2, "stale", "current"));
        assertFalse(MaintenanceStore.belongsToCurrentProcess(2, null, "current"));
    }
}
