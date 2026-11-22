package com.example.lockdowndpc.policy;

import android.content.Context;
import android.content.SharedPreferences;

import com.example.lockdowndpc.security.AppLabelSanitizer;
import com.example.lockdowndpc.security.DurablePreferences;

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
    private static final String KEY_POLICY_VERIFIED_AT = "policy_verified_at";
    private static final String KEY_ALLOWLIST_CONFIGURED = "allowlist_configured";
    private static final String KEY_MANAGED_PACKAGES = "managed_packages";
    private static final String KEY_MODE = "protection_mode";
    private static final String KEY_LABEL_PREFIX = "app_label:";
    private static final String KEY_ADMIN_SELECTED_SYSTEM = "admin_selected_system_packages";
    private static final String KEY_MANAGEMENT_PIN_PREFIX = "management_cert:";
    private static final String KEY_SYSTEM_RISK_SIGNER_PREFIX = "system_risk_signer:";
    private static final String KEY_SYSTEM_RISK_VERSION_PREFIX = "system_risk_version:";
    private static final String KEY_SYSTEM_RISK_PRIOR_STATE_PREFIX = "system_risk_prior_state:";
    private static final String KEY_SYSTEM_RISK_FIRMWARE_PREFIX = "system_risk_firmware:";
    private static final String KEY_SYSTEM_RISK_AT_PREFIX = "system_risk_at:";

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
    public static synchronized Set<String> getAllowedPackages(Context context) {
        SharedPreferences preferences = prefs(context);
        ProtectionMode mode = currentMode(preferences);
        Set<String> stored =
                preferences.getStringSet(usesLegacySelection(preferences, mode)
                        ? KEY_ALLOWED : allowedKey(mode), Collections.emptySet());
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

    private static boolean usesLegacySelection(SharedPreferences preferences, ProtectionMode mode) {
        return !preferences.contains(allowedKey(mode))
                && (preferences.contains(KEY_ALLOWED) || preferences.contains(KEY_ALLOWLIST_CONFIGURED));
    }

    /**
     * System packages an administrator explicitly opted into managing.
     *
     * <p>Empty by default. Device Guard does not enumerate and hide every system
     * package: that is unrecoverable on many OEM builds. An operator who needs a
     * specific system app under allow/block control names it here.
     */
    public static synchronized Set<String> getAdminSelectedSystemPackages(Context context) {
        return new HashSet<>(
                prefs(context).getStringSet(KEY_ADMIN_SELECTED_SYSTEM, Collections.emptySet())
        );
    }

    private static Set<String> guardedSystemSelection(Set<String> packages) {
        HashSet<String> selected = new HashSet<>(packages);
        // Protected packages can never be opted in; this guard belongs here so
        // no caller can turn an app store or kiosk escape surface into an
        // ordinary administrator-selected system package.
        selected.removeAll(LockdownPackages.ESSENTIAL_SYSTEM);
        selected.removeAll(LockdownPackages.ALWAYS_BLOCKED);
        selected.removeAll(LockdownPackages.KIOSK_ESCAPE_SURFACES);
        return selected;
    }

    /**
     * The administrator's on-file acceptance of the identity risk of one
     * unclassified OEM system package, or {@code null} when none was ever
     * recorded. The caller re-checks {@link SystemAppRiskAcceptance#matches}
     * against the currently observed signer and version before treating the
     * package as manageable; this store only persists what was accepted, it does
     * not judge whether it is still valid.
     */
    public static SystemAppRiskAcceptance getSystemRiskAcceptance(Context context, String packageName) {
        SharedPreferences preferences = prefs(context);
        String signerKey = KEY_SYSTEM_RISK_SIGNER_PREFIX + packageName;
        if (!preferences.contains(signerKey)) {
            return null;
        }
        return new SystemAppRiskAcceptance(
                packageName,
                preferences.getString(signerKey, ""),
                preferences.getString(KEY_SYSTEM_RISK_VERSION_PREFIX + packageName, ""),
                preferences.getString(KEY_SYSTEM_RISK_PRIOR_STATE_PREFIX + packageName, ""),
                preferences.getString(KEY_SYSTEM_RISK_FIRMWARE_PREFIX + packageName, ""),
                preferences.getLong(KEY_SYSTEM_RISK_AT_PREFIX + packageName, 0L)
        );
    }

    /**
     * Records an administrator's explicit acceptance of one unclassified OEM
     * package's identity risk. Recording an acceptance never adds the package to
     * {@link #setAllowedPackages}; the caller still has to opt the
     * package in separately, which keeps this a pure audit record rather than a
     * privilege grant on its own.
     */
    public static synchronized void recordSystemRiskAcceptance(
            Context context, SystemAppRiskAcceptance acceptance) {
        String packageName = acceptance.packageName();
        prefs(context).edit()
                .putString(KEY_SYSTEM_RISK_SIGNER_PREFIX + packageName, acceptance.signerDigest())
                .putString(KEY_SYSTEM_RISK_VERSION_PREFIX + packageName, acceptance.version())
                .putString(KEY_SYSTEM_RISK_PRIOR_STATE_PREFIX + packageName, acceptance.priorState())
                .putString(KEY_SYSTEM_RISK_FIRMWARE_PREFIX + packageName, acceptance.firmwareBuild())
                .putLong(KEY_SYSTEM_RISK_AT_PREFIX + packageName, acceptance.acceptedAtMillis())
                .commit();
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

    public static synchronized void setManagementCertificatePins(
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

    /** Saves both parts of the selection together. Returns false on disk failure. */
    public static boolean setAllowedPackages(
            Context context,
            Set<String> packages,
            Set<String> managedPackages,
            Set<String> adminSelectedSystem
    ) {
        return setAllowedPackages(prefs(context), packages, managedPackages, adminSelectedSystem);
    }

    static synchronized boolean setAllowedPackages(
            SharedPreferences preferences, Set<String> packages, Set<String> managedPackages,
            Set<String> adminSelectedSystem
    ) {
        ProtectionMode mode = currentMode(preferences);
        SharedPreferences.Editor editor = preferences.edit()
                .putStringSet(allowedKey(mode), new HashSet<>(packages))
                .putStringSet(KEY_MANAGED_PACKAGES, new HashSet<>(managedPackages))
                .putStringSet(KEY_ADMIN_SELECTED_SYSTEM, guardedSystemSelection(adminSelectedSystem))
                .putBoolean(configuredKey(mode), true)
                .remove(KEY_ALLOWED)
                .remove(KEY_ALLOWLIST_CONFIGURED);
        return DurablePreferences.commit(preferences, editor, allowedKey(mode), KEY_MANAGED_PACKAGES,
                KEY_ADMIN_SELECTED_SYSTEM, configuredKey(mode), KEY_ALLOWED, KEY_ALLOWLIST_CONFIGURED);
    }

    public static synchronized Set<String> getManagedPackages(Context context) {
        return new HashSet<>(prefs(context).getStringSet(KEY_MANAGED_PACKAGES, Collections.emptySet()));
    }

    public static void addManagedPackage(Context context, String packageName) {
        rememberManagedPackage(context, packageName, null);
    }

    public static synchronized void rememberManagedPackage(
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

    /**
     * Remembers a display label <em>without</em> joining the managed-package set.
     *
     * <p>The inventory screen lists system packages too, and a system package that
     * Device Guard has hidden disappears from bulk {@code PackageManager} queries,
     * so its label has to survive somewhere for the row to stay readable. It must
     * not become a {@link #getManagedPackages} member to get that: the policy
     * engine puts every managed package under the allow/block rules, which in
     * "allow only what I select" mode would hide every system package an operator
     * had merely scrolled past. Membership stays the deliberate, separately
     * guarded {@link #setAllowedPackages} decision.
     */
    public static synchronized void rememberPackageLabel(Context context, String packageName, String label) {
        String sanitizedLabel = AppLabelSanitizer.sanitize(label);
        if (sanitizedLabel == null || sanitizedLabel.isBlank()) {
            return;
        }
        prefs(context).edit().putString(KEY_LABEL_PREFIX + packageName, sanitizedLabel).apply();
    }

    public static String getRememberedLabel(Context context, String packageName) {
        return AppLabelSanitizer.sanitize(
                prefs(context).getString(KEY_LABEL_PREFIX + packageName, packageName));
    }

    /** Whether the method currently in force has a saved selection of its own. */
    public static synchronized boolean isAllowlistConfigured(Context context) {
        SharedPreferences preferences = prefs(context);
        ProtectionMode mode = currentMode(preferences);
        return preferences.getBoolean(usesLegacySelection(preferences, mode)
                ? KEY_ALLOWLIST_CONFIGURED : configuredKey(mode), false);
    }

    public static synchronized ProtectionMode getProtectionMode(Context context) {
        return currentMode(prefs(context));
    }

    /**
     * Records the blocking method. Non-destructive: the selection saved under the
     * method being left stays exactly where it is, and the one saved under the
     * method being entered comes back untouched. Returns false on disk failure.
     */
    public static boolean setProtectionMode(Context context, ProtectionMode mode) {
        return setProtectionMode(prefs(context), mode);
    }

    static synchronized boolean setProtectionMode(SharedPreferences preferences, ProtectionMode mode) {
        ProtectionMode previous = currentMode(preferences);
        SharedPreferences.Editor editor = preferences.edit()
                .putString(KEY_MODE, mode.name())
                .remove(KEY_ALLOWED)
                .remove(KEY_ALLOWLIST_CONFIGURED);
        // Bind a legacy selection to its original method in the same write.
        if (usesLegacySelection(preferences, previous)) {
            editor.putStringSet(allowedKey(previous),
                    preferences.getStringSet(KEY_ALLOWED, Collections.emptySet()));
            editor.putBoolean(configuredKey(previous),
                    preferences.getBoolean(KEY_ALLOWLIST_CONFIGURED, false));
        }
        return DurablePreferences.commit(preferences, editor, KEY_MODE, KEY_ALLOWED,
                KEY_ALLOWLIST_CONFIGURED, allowedKey(previous), configuredKey(previous));
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

    public static Runnable watchPolicyState(Context context, Runnable listener) {
        SharedPreferences preferences = prefs(context);
        SharedPreferences.OnSharedPreferenceChangeListener attached = (ignored, key) -> {
            if (KEY_POLICY_STATE.equals(key)) {
                listener.run();
            }
        };
        preferences.registerOnSharedPreferenceChangeListener(attached);
        return () -> preferences.unregisterOnSharedPreferenceChangeListener(attached);
    }

    public static String getPolicyError(Context context) {
        return prefs(context).getString(KEY_POLICY_ERROR, "");
    }

    public static synchronized void markApplyStarted(Context context) {
        prefs(context).edit()
                .putBoolean(KEY_ENABLED, true)
                .putString(KEY_POLICY_STATE, PolicyState.APPLYING.name())
                .remove(KEY_POLICY_ERROR)
                .commit();
    }

    public static synchronized void markApplySucceeded(Context context) {
        prefs(context).edit()
                .putBoolean(KEY_ENABLED, true)
                .putString(KEY_POLICY_STATE, PolicyState.ACTIVE.name())
                .putLong(KEY_POLICY_VERIFIED_AT, System.currentTimeMillis())
                .remove(KEY_POLICY_ERROR)
                .commit();
    }

    /**
     * When protection was last read back as applied, or 0 when it never has been.
     *
     * <p>Written only here, on the one path that has verified the policy rather
     * than merely requested it. A device that reports {@code ACTIVE} with a zero
     * here has a stored state from before this record existed, which the health
     * report treats as unproven rather than as healthy.
     */
    public static long getPolicyVerifiedAt(Context context) {
        return prefs(context).getLong(KEY_POLICY_VERIFIED_AT, 0L);
    }

    public static void markApplyFailed(Context context, String error) {
        markApplyFailed(context, error, true);
    }

    static synchronized void markApplyFailed(Context context, String error, boolean protectionEnabled) {
        prefs(context).edit()
                .putBoolean(KEY_ENABLED, protectionEnabled)
                .putString(KEY_POLICY_STATE, PolicyState.FAILED.name())
                .putString(KEY_POLICY_ERROR, error)
                .commit();
    }

    public static synchronized void markPauseStarted(Context context) {
        prefs(context).edit()
                .putBoolean(KEY_ENABLED, false)
                .putString(KEY_POLICY_STATE, PolicyState.APPLYING.name())
                .remove(KEY_POLICY_ERROR)
                .commit();
    }

    public static synchronized void markPauseSucceeded(Context context) {
        prefs(context).edit()
                .putBoolean(KEY_ENABLED, false)
                .putString(KEY_POLICY_STATE, PolicyState.INACTIVE.name())
                .remove(KEY_POLICY_ERROR)
                .commit();
    }

    public static synchronized void markPauseFailed(Context context, String error) {
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
