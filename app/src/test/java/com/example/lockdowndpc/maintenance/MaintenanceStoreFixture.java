package com.example.lockdowndpc.maintenance;

import android.content.Context;

/** Seeds a previously opened window without sending maintenance commands. */
public final class MaintenanceStoreFixture {
    private MaintenanceStoreFixture() {}

    public static boolean saveWindow(Context context, MaintenanceWindow window) {
        return MaintenanceStore.saveWindow(context, window);
    }
}
