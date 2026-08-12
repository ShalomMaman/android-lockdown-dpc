package com.example.lockdowndpc.kiosk;

import android.content.Context;
import android.content.SharedPreferences;

import com.example.lockdowndpc.kiosk.KioskStateMachine.KioskState;

/**
 * Persistent kiosk configuration and state.
 *
 * <p>Kept in its own preference file so a kiosk rollback never disturbs the
 * managed-filtering state in {@code lockdown_policy}. Writes use
 * {@code commit()} because reboot restoration reads this before the process is
 * guaranteed to survive, exactly like {@code AllowedAppsStore}.
 */
public final class KioskConfigStore {

    private static final String PREFS = "kiosk_policy";
    private static final String KEY_MODE = "kiosk_mode";
    private static final String KEY_STATE = "kiosk_state";
    private static final String KEY_TARGET_PACKAGE = "kiosk_target_package";
    private static final String KEY_SITE_URL = "kiosk_site_url";
    private static final String KEY_HOME_REGISTERED = "kiosk_home_registered";
    private static final String KEY_FAULT_REASON = "kiosk_fault_reason";
    private static final String KEY_ESCAPE_SURFACES_HIDDEN = "kiosk_escape_surfaces_hidden";

    private KioskConfigStore() {}

    public record Settings(KioskState state, KioskConfig config, String faultReason) {}

    public static Settings read(Context context) {
        SharedPreferences prefs = prefs(context);
        KioskMode mode = KioskMode.fromStoredName(prefs.getString(KEY_MODE, null));
        KioskState state = KioskState.fromStoredName(prefs.getString(KEY_STATE, null));
        if (mode == KioskMode.OFF) {
            // A mode that failed to load must never present as a locked device.
            state = KioskState.OFF;
        }
        KioskConfig config = new KioskConfig(
                mode,
                prefs.getString(KEY_TARGET_PACKAGE, ""),
                prefs.getString(KEY_SITE_URL, "")
        );
        return new Settings(state, config, prefs.getString(KEY_FAULT_REASON, ""));
    }

    public static KioskConfig readConfig(Context context) {
        return read(context).config();
    }

    public static KioskState readState(Context context) {
        return read(context).state();
    }

    public static boolean isActive(Context context) {
        return readState(context) == KioskState.ACTIVE;
    }

    /** Stores a validated configuration. The caller owns authorization. */
    public static void writeConfig(Context context, KioskConfig config, String normalizedSiteUrl) {
        prefs(context).edit()
                .putString(KEY_MODE, config.mode().name())
                .putString(KEY_TARGET_PACKAGE, config.targetPackage())
                .putString(KEY_SITE_URL, normalizedSiteUrl == null ? "" : normalizedSiteUrl)
                .commit();
    }

    public static void writeState(Context context, KioskState state, String faultReason) {
        prefs(context).edit()
                .putString(KEY_STATE, state.name())
                .putString(KEY_FAULT_REASON, faultReason == null ? "" : faultReason)
                .commit();
    }

    public static void clear(Context context) {
        prefs(context).edit()
                .putString(KEY_MODE, KioskMode.OFF.name())
                .putString(KEY_STATE, KioskState.OFF.name())
                .remove(KEY_TARGET_PACKAGE)
                .remove(KEY_SITE_URL)
                .remove(KEY_FAULT_REASON)
                .commit();
    }

    /**
     * Whether a kiosk HOME preference is currently installed. Tracked so exit can
     * revoke exactly what kiosk added instead of clearing every persistent
     * preferred activity unconditionally.
     */
    public static boolean isHomeRegistered(Context context) {
        return prefs(context).getBoolean(KEY_HOME_REGISTERED, false);
    }

    public static void setHomeRegistered(Context context, boolean registered) {
        prefs(context).edit().putBoolean(KEY_HOME_REGISTERED, registered).commit();
    }

    /**
     * Whether the last package-policy pass hid the kiosk escape surfaces.
     *
     * <p>The policy engine uses this to stay exactly as it was before 0.5 on
     * devices that never enabled kiosk, while still getting one reconciliation
     * pass that restores those packages after kiosk is switched off.
     */
    public static boolean wasEscapeSurfaceHidingApplied(Context context) {
        return prefs(context).getBoolean(KEY_ESCAPE_SURFACES_HIDDEN, false);
    }

    public static void setEscapeSurfaceHidingApplied(Context context, boolean applied) {
        prefs(context).edit().putBoolean(KEY_ESCAPE_SURFACES_HIDDEN, applied).commit();
    }

    private static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }
}
