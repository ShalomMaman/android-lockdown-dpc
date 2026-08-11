package com.example.lockdowndpc.policy;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.Collections;
import java.util.HashSet;
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

    private AllowedAppsStore() {}

    public static Set<String> getAllowedPackages(Context context) {
        Set<String> stored = prefs(context).getStringSet(KEY_ALLOWED, Collections.emptySet());
        HashSet<String> result = new HashSet<>(stored);
        result.add(context.getPackageName());
        result.add("com.tailscale.ipn");
        return result;
    }

    public static void setAllowedPackages(
            Context context,
            Set<String> packages,
            Set<String> managedPackages
    ) {
        prefs(context).edit()
                .putStringSet(KEY_ALLOWED, new HashSet<>(packages))
                .putStringSet(KEY_MANAGED_PACKAGES, new HashSet<>(managedPackages))
                .putBoolean(KEY_ALLOWLIST_CONFIGURED, true)
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
        if (label != null && !label.isBlank()) {
            editor.putString(KEY_LABEL_PREFIX + packageName, label);
        }
        editor.apply();
    }

    public static String getRememberedLabel(Context context, String packageName) {
        return prefs(context).getString(KEY_LABEL_PREFIX + packageName, packageName);
    }

    public static boolean isAllowlistConfigured(Context context) {
        return prefs(context).getBoolean(KEY_ALLOWLIST_CONFIGURED, false);
    }

    public static ProtectionMode getProtectionMode(Context context) {
        String stored = prefs(context).getString(KEY_MODE, ProtectionMode.BLOCK_SELECTED.name());
        try {
            return ProtectionMode.valueOf(stored);
        } catch (IllegalArgumentException ignored) {
            return ProtectionMode.BLOCK_SELECTED;
        }
    }

    public static void setProtectionMode(Context context, ProtectionMode mode) {
        ProtectionMode current = getProtectionMode(context);
        SharedPreferences.Editor editor = prefs(context).edit().putString(KEY_MODE, mode.name());
        if (current != mode) {
            editor.remove(KEY_ALLOWED).putBoolean(KEY_ALLOWLIST_CONFIGURED, false);
        }
        editor.apply();
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
