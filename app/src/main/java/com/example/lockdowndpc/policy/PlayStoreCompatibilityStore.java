package com.example.lockdowndpc.policy;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * The administrator's stored decision about Google Play Store compatibility.
 *
 * <p>One boolean, in its own preference file, defaulting to off. The default is
 * the security-relevant part: a device that never touches this screen — and an
 * existing pilot upgraded into this build — keeps hiding every application
 * store exactly as before.
 *
 * <p>The file is separate from {@code lockdown_policy} and {@code system_policy}
 * for the same reason {@link SystemPolicyStore} is separate: rolling this
 * feature back must not disturb managed filtering or the system policy choices.
 * Writes use {@code commit()} because a boot reconciliation reads them before
 * the process is guaranteed to survive.
 *
 * <p>Nothing infers this flag. It is written only where an authenticated
 * administrator confirmed the consequence dialog, never from an allowlist entry
 * or an installed package.
 */
public final class PlayStoreCompatibilityStore {

    private static final String PREFS = "play_store_compatibility";
    private static final String KEY_ENABLED = "compatibility_enabled";
    private static final String KEY_CHANGED_AT = "changed_at";
    private static final String KEY_SCHEMA_VERSION = "schema_version";

    /** Bumped only for a change that needs migration code, so 1 means "as designed". */
    private static final int SCHEMA_VERSION = 1;

    private PlayStoreCompatibilityStore() {}

    /** Whether the administrator has opted in. Strict mode is the default. */
    public static boolean isEnabled(Context context) {
        return prefs(context).getBoolean(KEY_ENABLED, false);
    }

    /**
     * Records the decision and drops the stale verification of every control the
     * mode pins on.
     *
     * <p>The invalidation lives here rather than in the caller so that no future
     * entry point can change the base policy while the console keeps rendering
     * yesterday's {@code APPLIED} for a control whose requested value has just
     * moved. The caller still owns authentication and confirmation.
     */
    public static synchronized void setEnabled(Context context, boolean enabled) {
        prefs(context).edit()
                .putBoolean(KEY_ENABLED, enabled)
                .putLong(KEY_CHANGED_AT, System.currentTimeMillis())
                .putInt(KEY_SCHEMA_VERSION, SCHEMA_VERSION)
                .commit();
        for (SystemPolicyControl control : PlayStoreCompatibility.REQUIRED_INSTALL_CONTROLS) {
            SystemPolicyStore.invalidateVerification(context, control);
        }
    }

    /** When the decision was last changed, or 0 when it never has been. */
    public static long changedAt(Context context) {
        return prefs(context).getLong(KEY_CHANGED_AT, 0L);
    }

    private static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }
}
