package com.example.lockdowndpc.maintenance;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Android implementation of the maintenance application-visibility boundary. */
final class AndroidMaintenanceCapabilityGateway implements MaintenanceCapabilityGateway {
    private final DevicePolicyManager dpm;
    private final ComponentName admin;
    private final PackageManager packageManager;

    AndroidMaintenanceCapabilityGateway(
            DevicePolicyManager dpm,
            ComponentName admin,
            PackageManager packageManager
    ) {
        this.dpm = dpm;
        this.admin = admin;
        this.packageManager = packageManager;
    }

    @Override
    public List<String> open(MaintenanceWindow window) {
        if (!MaintenanceAppPolicy.opensApplicationStores(window)) {
            return List.of();
        }
        return setStoresHidden(false);
    }

    @Override
    public List<String> restore() {
        return setStoresHidden(true);
    }

    private List<String> setStoresHidden(boolean hidden) {
        ArrayList<String> failures = new ArrayList<>();
        for (String packageName : MaintenanceAppPolicy.managedStorePackages()) {
            if (!isInstalled(packageName)) {
                continue;
            }
            try {
                boolean wasHidden = dpm.isApplicationHidden(admin, packageName);
                boolean updated = dpm.setApplicationHidden(admin, packageName, hidden);
                boolean observedHidden = dpm.isApplicationHidden(admin, packageName);
                if (!updated && wasHidden != hidden) {
                    failures.add("maintenance-store-update-rejected:" + packageName);
                } else if (observedHidden != hidden) {
                    failures.add("maintenance-store-state-mismatch:" + packageName);
                }
            } catch (IllegalArgumentException ignored) {
                // A catalogue entry is not installed on this device.
            } catch (RuntimeException exception) {
                failures.add("maintenance-store-policy:" + packageName + ":"
                        + exception.getClass().getSimpleName());
            }
        }
        return Collections.unmodifiableList(failures);
    }

    private boolean isInstalled(String packageName) {
        try {
            ApplicationInfo info;
            long flags = PackageManager.MATCH_UNINSTALLED_PACKAGES
                    | PackageManager.MATCH_DISABLED_COMPONENTS;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                info = packageManager.getApplicationInfo(
                        packageName,
                        PackageManager.ApplicationInfoFlags.of(flags));
            } else {
                //noinspection deprecation
                info = packageManager.getApplicationInfo(packageName, (int) flags);
            }
            return (info.flags & ApplicationInfo.FLAG_INSTALLED) != 0;
        } catch (PackageManager.NameNotFoundException ignored) {
            return false;
        }
    }
}
