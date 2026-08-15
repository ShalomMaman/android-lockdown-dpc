package com.example.lockdowndpc.maintenance;

import com.example.lockdowndpc.policy.LockdownPackages;
import com.example.lockdowndpc.policy.SystemAppClassifier;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/** Pure package decisions shared by maintenance and ordinary reconciliation. */
public final class MaintenanceAppPolicy {
    private static final Set<String> MANAGED_STORE_PACKAGES = managedStorePackages();

    private MaintenanceAppPolicy() {}

    /** Whether this live window explicitly grants application-store access. */
    public static boolean opensApplicationStores(MaintenanceWindow window) {
        return window != null
                && window.capabilities().contains(MaintenanceCapability.APP_STORE_ACCESS);
    }

    /**
     * Stores whose normal protected state is known to be hidden.
     *
     * <p>The inventory's store facet also contains Android package installers,
     * which are essential system components and are never hidden. The
     * intersection is therefore the reversible set: every package here is both
     * a store and part of Device Guard's built-in hidden catalogue.
     */
    public static Set<String> managedStorePackages() {
        LinkedHashSet<String> packages = new LinkedHashSet<>(LockdownPackages.ALWAYS_BLOCKED);
        packages.retainAll(SystemAppClassifier.STORE_PACKAGES);
        return Collections.unmodifiableSet(packages);
    }

    /** Whether maintenance must override the ordinary hidden-store rule. */
    public static boolean keepsVisible(String packageName, boolean storeAccessOpen) {
        return storeAccessOpen && MANAGED_STORE_PACKAGES.contains(packageName);
    }
}
