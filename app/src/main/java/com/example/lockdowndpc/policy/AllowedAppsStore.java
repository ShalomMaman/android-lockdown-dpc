package com.example.lockdowndpc.policy;

import android.content.Context;
import android.content.SharedPreferences;

import com.example.lockdowndpc.security.AppLabelSanitizer;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public final class AllowedAppsStore {
    private static final String PREFS = "lockdown_policy";
    private static final String KEY_ALLOWED = "allowed_packages";
    private static final String KEY_ENABLED = "protection_enabled";
    private static final String KEY_POLICY_STATE = "policy_state";
    private static final String KEY_POLICY_ERROR = "policy_error";
    private static final String KEY_ALLOWLIST_CONFIGURED = "allowlist_configured";
    private static final String KEY_MANAGED_PACKAGES = "managed_packages";
    private static final String KEY_MODE = "protection_mode";
    private static final String KEY_LABEL_PREFIX = "app_label:";
    private static final String KEY_ADMIN_SELECTED_SYSTEM = "admin_selected_system_packages";
    private static final String KEY_MANAGEMENT_PIN_PREFIX = "management_cert:";

    private AllowedAppsStore() {}

    /**
     * The saved selection of the blocking method that is currently in force.
     *
     * <p>Each method keeps its own list. "Block the apps I select" and "allow only
     * the apps I select" are different sets, and up to 0.5.0 changing the method
     * deleted the stored one outright — an administrator who had hand-picked
     * thirty packages and then tapped the other radio button to read what it does
     * lost all thirty on Save, with no warning anywhere. Switching is now
     * reversible: neither list is touched, and the one belonging to the chosen
     * method comes back exactly as it was left.
     */
    public static Set<String> getAllowedPackages(Context context) {
        SharedPreferences preferences = prefs(context);
        ProtectionMode mode = currentMode(preferences);
        migrateLegacySelection(preferences, mode);
        Set<String> stored =
                preferences.getStringSet(allowedKey(mode), Collections.emptySet());
        HashSet<String> result = new HashSet<>(stored);
        result.add(context.getPackageName());
        result.addAll(LockdownPackages.managementPackageNames());
        return result;
    }

    private static String allowedKey(ProtectionMode mode) {
        return KEY_ALLOWED + ":" + mode.name();
    }

    private static String configuredKey(ProtectionMode mode) {
        return KEY_ALLOWLIST_CONFIGURED + ":" + mode.name();
    }

    private static ProtectionMode currentMode(SharedPreferences preferences) {
        String stored = preferences.getString(KEY_MODE, ProtectionMode.BLOCK_SELECTED.name());
        try {
            return ProtectionMode.valueOf(stored);
        } catch (IllegalArgumentException ignored) {
            return ProtectionMode.BLOCK_SELECTED;
        }
    }

    /**
     * Moves the older single selection onto the method it was saved under.
     *
     * <p>Runs before every read and write of the per-method entries, and only
     * while the legacy entry is still present, so an upgrade keeps the list an
     * administrator already curated instead of asking them to rebuild it.
     * {@code commit} rather than {@code apply}: the very next statement of the
     * caller reads the keys this writes.
     */
    private static void migrateLegacySelection(
            SharedPreferences preferences,
            ProtectionMode mode
    ) {
        if (!preferences.contains(KEY_ALLOWED) && !preferences.contains(KEY_ALLOWLIST_CONFIGURED)) {
            return;
        }
        SharedPreferences.Editor editor = preferences.edit();
        if (!preferences.contains(allowedKey(mode))) {
            editor.putStringSet(
                    allowedKey(mode),
                    new HashSet<>(preferences.getStringSet(KEY_ALLOWED, Collections.emptySet()))
            );
            editor.putBoolean(
                    configuredKey(mode),
                    preferences.getBoolean(KEY_ALLOWLIST_CONFIGURED, false)
            );
        }
        editor.remove(KEY_ALLOWED).remove(KEY_ALLOWLIST_CONFIGURED).commit();
    }

    /**
     * System packages an administrator explicitly opted into managing.
     *
     * <p>Empty by default. Device Guard does not enumerate and hide every system
     * package: that is unrecoverable on many OEM builds. An operator who needs a
     * specific system app under allow/block control names it here.
     */
    public static Set<String> getAdminSelectedSystemPackages(Context context) {
        return new HashSet<>(
                prefs(context).getStringSet(KEY_ADMIN_SELECTED_SYSTEM, Collections.emptySet())
        );
    }

    public static void setAdminSelectedSystemPackages(Context context, Set<String> packages) {
        HashSet<String> selected = new HashSet<>(packages);
        // Protected packages can never be opted in; this guard belongs here so
        // no caller can turn an app store or kiosk escape surface into an
        // ordinary administrator-selected system package.
        selected.removeAll(LockdownPackages.ESSENTIAL_SYSTEM);
        selected.removeAll(LockdownPackages.ALWAYS_BLOCKED);
        selected.removeAll(LockdownPackages.KIOSK_ESCAPE_SURFACES);
        prefs(context).edit().putStringSet(KEY_ADMIN_SELECTED_SYSTEM, selected).commit();
    }

    /**
     * Administrator-configured signing-certificate pins for management packages,
     * keyed by package name. Absent means "not proven", which
     * {@link LockdownPackages#verifySigner} reports as an explicit gap rather
     * than as a pass.
     */
    public static Map<String, Set<String>> getManagementCertificatePins(Context context) {
        HashMap<String, Set<String>> pins = new HashMap<>();
        for (String packageName : LockdownPackages.managementPackageNames()) {
            Set<String> stored = prefs(context).getStringSet(
                    KEY_MANAGEMENT_PIN_PREFIX + packageName,
                    Collections.emptySet()
            );
            if (stored != null && !stored.isEmpty()) {
                pins.put(packageName, new HashSet<>(stored));
            }
        }
        return pins;
    }

    public static void setManagementCertificatePins(
            Context context,
            String packageName,
            Set<String> digests
    ) {
        if (!LockdownPackages.isManagementPackage(packageName)) {
            throw new IllegalArgumentException("Not a management package: " + packageName);
        }
        HashSet<String> normalized = new HashSet<>();
        for (String digest : digests) {
            String value = LockdownPackages.normalizeDigest(digest);
            if (!value.isEmpty()) {
                normalized.add(value);
            }
        }
        prefs(context).edit()
                .putStringSet(KEY_MANAGEMENT_PIN_PREFIX + packageName, normalized)
                .commit();
    }

    /** Saves the selection against the blocking method it was made under. */
    public static void setAllowedPackages(
            Context context,
            Set<String> packages,
            Set<String> managedPackages
    ) {
        SharedPreferences preferences = prefs(context);
        ProtectionMode mode = currentMode(preferences);
        migrateLegacySelection(preferences, mode);
        preferences.edit()
                .putStringSet(allowedKey(mode), new HashSet<>(packages))
                .putStringSet(KEY_MANAGED_PACKAGES, new HashSet<>(managedPackages))
                .putBoolean(configuredKey(mode), true)
                .apply();
    }

    public static Set<String> getManagedPackages(Context context) {
        return new HashSet<>(prefs(context).getStringSet(KEY_MANAGED_PACKAGES, Collections.emptySet()));
    }

    public static void addManagedPackage(Context context, String packageName) {
        rememberManagedPackage(context, packageName, null);
    }

    public static void rememberManagedPackage(
            Context context,
            String packageName,
            String label
    ) {
        HashSet<String> managed = new HashSet<>(getManagedPackages(context));
        managed.add(packageName);
        SharedPreferences.Editor editor = prefs(context).edit()
                .putStringSet(KEY_MANAGED_PACKAGES, managed);
        String sanitizedLabel = AppLabelSanitizer.sanitize(label);
        if (sanitizedLabel != null && !sanitizedLabel.isBlank()) {
            editor.putString(KEY_LABEL_PREFIX + packageName, sanitizedLabel);
        }
        editor.apply();
    }

    public static String getRememberedLabel(Context context, String packageName) {
        return AppLabelSanitizer.sanitize(
                prefs(context).getString(KEY_LABEL_PREFIX + packageName, packageName));
    }

    /** Whether the method currently in force has a saved selection of its own. */
    public static boolean isAllowlistConfigured(Context context) {
        SharedPreferences preferences = prefs(context);
        ProtectionMode mode = currentMode(preferences);
        migrateLegacySelection(preferences, mode);
        return preferences.getBoolean(configuredKey(mode), false);
    }

    public static ProtectionMode getProtectionMode(Context context) {
        return currentMode(prefs(context));
    }

    /**
     * Records the blocking method. Non-destructive: the selection saved under the
     * method being left stays exactly where it is, and the one saved under the
     * method being entered comes back untouched.
     */
    public static void setProtectionMode(Context context, ProtectionMode mode) {
        SharedPreferences preferences = prefs(context);
        // Bind a legacy single selection to the method it was saved under before
        // the current method moves off it.
        migrateLegacySelection(preferences, currentMode(preferences));
        preferences.edit().putString(KEY_MODE, mode.name()).apply();
    }

    public static boolean isProtectionEnabled(Context context) {
        return prefs(context).getBoolean(KEY_ENABLED, false);
    }

    public static PolicyState getPolicyState(Context context) {
        SharedPreferences preferences = prefs(context);
        String fallback = preferences.getBoolean(KEY_ENABLED, false)
                ? PolicyState.ACTIVE.name()
                : PolicyState.INACTIVE.name();
        String stored = preferences.getString(KEY_POLICY_STATE, fallback);
        try {
            return PolicyState.valueOf(stored);
        } catch (IllegalArgumentException ignored) {
            return PolicyState.FAILED;
        }
    }

    public static String getPolicyError(Context context) {
        return prefs(context).getString(KEY_POLICY_ERROR, "");
    }

    public static void markApplyStarted(Context context) {
        prefs(context).edit()
                .putBoolean(KEY_ENABLED, true)
                .putString(KEY_POLICY_STATE, PolicyState.APPLYING.name())
                .remove(KEY_POLICY_ERROR)
                .commit();
    }

    public static void markApplySucceeded(Context context) {
        prefs(context).edit()
                .putBoolean(KEY_ENABLED, true)
                .putString(KEY_POLICY_STATE, PolicyState.ACTIVE.name())
                .remove(KEY_POLICY_ERROR)
                .commit();
    }

    public static void markApplyFailed(Context context, String error) {
        prefs(context).edit()
                .putBoolean(KEY_ENABLED, true)
                .putString(KEY_POLICY_STATE, PolicyState.FAILED.name())
                .putString(KEY_POLICY_ERROR, error)
                .commit();
    }

    public static void markPauseStarted(Context context) {
        prefs(context).edit()
                .putBoolean(KEY_ENABLED, false)
                .putString(KEY_POLICY_STATE, PolicyState.APPLYING.name())
                .remove(KEY_POLICY_ERROR)
                .commit();
    }

    public static void markPauseSucceeded(Context context) {
        prefs(context).edit()
                .putBoolean(KEY_ENABLED, false)
                .putString(KEY_POLICY_STATE, PolicyState.INACTIVE.name())
                .remove(KEY_POLICY_ERROR)
                .commit();
    }

    public static void markPauseFailed(Context context, String error) {
        prefs(context).edit()
                .putBoolean(KEY_ENABLED, false)
                .putString(KEY_POLICY_STATE, PolicyState.FAILED.name())
                .putString(KEY_POLICY_ERROR, error)
                .commit();
    }

    private static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public enum ProtectionMode {
        BLOCK_SELECTED,
        ALLOW_SELECTED
    }

    public enum PolicyState {
        INACTIVE,
        APPLYING,
        ACTIVE,
        FAILED
    }
}
