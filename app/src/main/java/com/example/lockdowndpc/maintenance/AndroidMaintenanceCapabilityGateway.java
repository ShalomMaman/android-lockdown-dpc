package com.example.lockdowndpc.maintenance;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Build;

import com.example.lockdowndpc.policy.PlayStoreCompatibility;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Android implementation of the maintenance application-visibility boundary. */
final class AndroidMaintenanceCapabilityGateway implements MaintenanceCapabilityGateway {
    interface StoreVisibilityDevice {
        boolean isInstalled(String packageName);
        boolean isHidden(String packageName);
        boolean setHidden(String packageName, boolean hidden);
    }

    private final StoreVisibilityDevice device;

    /**
     * Whether an administrator has opted into Google Play compatibility.
     *
     * <p>Captured when the coordinator is built, which is once per maintenance
     * operation, so a window is judged against the decision that was on file
     * when it was requested.
     */
    private final boolean playCompatibilityEnabled;

    AndroidMaintenanceCapabilityGateway(
            DevicePolicyManager dpm,
            ComponentName admin,
            PackageManager packageManager,
            boolean playCompatibilityEnabled
    ) {
        this(new AndroidStoreVisibilityDevice(dpm, admin, packageManager), playCompatibilityEnabled);
    }

    AndroidMaintenanceCapabilityGateway(
            StoreVisibilityDevice device,
            boolean playCompatibilityEnabled
    ) {
        if (device == null) {
            throw new IllegalArgumentException("A store visibility device is required");
        }
        this.device = device;
        this.playCompatibilityEnabled = playCompatibilityEnabled;
    }

    /**
     * Hides the Google Play Store before a window that withholds it is allowed to
     * relax anything, and proves it is hidden.
     *
     * <p>Only the one package the compatibility exception makes available. The
     * other managed stores are already hidden by the base policy, and a window
     * that opens application-store access is handled by {@link #open} instead —
     * which runs after the restrictions are relaxed, preserving that ordering.
     */
    @Override
    public List<String> prepare(MaintenanceWindow window) {
        if (window == null
                || !PlayStoreCompatibility.withholdsStoreDuring(
                        playCompatibilityEnabled, window.relaxableControls())) {
            return List.of();
        }
        ArrayList<String> failures = new ArrayList<>();
        for (String failure : setHidden(List.of(PlayStoreCompatibility.PLAY_STORE_PACKAGE), true)) {
            // Named as a precondition so an audit line cannot be mistaken for a
            // restore that failed after the device had already been relaxed.
            failures.add("maintenance-precondition:" + failure);
        }
        return Collections.unmodifiableList(failures);
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
        return setHidden(MaintenanceAppPolicy.managedStorePackages(), hidden);
    }

    private List<String> setHidden(Iterable<String> packages, boolean hidden) {
        ArrayList<String> failures = new ArrayList<>();
        for (String packageName : packages) {
            if (!device.isInstalled(packageName)) {
                continue;
            }
            try {
                boolean wasHidden = device.isHidden(packageName);
                boolean updated = device.setHidden(packageName, hidden);
                boolean observedHidden = device.isHidden(packageName);
                if (!updated && wasHidden != hidden) {
                    failures.add("maintenance-store-update-rejected:" + packageName);
                } else if (observedHidden != hidden) {
                    failures.add("maintenance-store-state-mismatch:" + packageName);
                }
            } catch (RuntimeException exception) {
                // Presence was proved immediately above. A package-lifecycle
                // race or an OEM DevicePolicyManager refusal is therefore not
                // evidence that the requested state was reached. Keep the
                // restore debt and retry rather than silently clearing it.
                failures.add(policyFailure(packageName, exception));
            }
        }
        return Collections.unmodifiableList(failures);
    }

    private static String policyFailure(String packageName, RuntimeException exception) {
        return "maintenance-store-policy:" + packageName + ":"
                + exception.getClass().getSimpleName();
    }

    private static final class AndroidStoreVisibilityDevice implements StoreVisibilityDevice {
        private final DevicePolicyManager dpm;
        private final ComponentName admin;
        private final PackageManager packageManager;

        private AndroidStoreVisibilityDevice(
                DevicePolicyManager dpm,
                ComponentName admin,
                PackageManager packageManager
        ) {
            this.dpm = dpm;
            this.admin = admin;
            this.packageManager = packageManager;
        }

        @Override
        public boolean isInstalled(String packageName) {
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

        @Override
        public boolean isHidden(String packageName) {
            return dpm.isApplicationHidden(admin, packageName);
        }

        @Override
        public boolean setHidden(String packageName, boolean hidden) {
            return dpm.setApplicationHidden(admin, packageName, hidden);
        }
    }
}
