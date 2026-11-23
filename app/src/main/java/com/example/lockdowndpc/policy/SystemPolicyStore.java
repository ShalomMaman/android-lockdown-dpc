package com.example.lockdowndpc.policy;

import android.content.Context;
import android.content.SharedPreferences;

import com.example.lockdowndpc.security.DurablePreferences;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Persistent system policy choices, the profile they are interpreted against,
 * and the last verified result.
 *
 * <p>Kept in its own preference file, like {@code KioskConfigStore}, so a
 * rollback of this feature cannot disturb the managed-filtering state in
 * {@code lockdown_policy}. Writes use {@code commit()} because a boot
 * reconciliation reads them before the process is guaranteed to survive.
 *
 * <h2>Why an absent choice is not "off"</h2>
 *
 * <p>Only controls an administrator has actually touched are stored. Everything
 * else resolves through {@link SystemPolicyControl#defaultRequested} against the
 * pinned profile. An upgraded 0.5.1 pilot therefore arrives here with an empty
 * file and still enforces precisely what it enforced before the upgrade, while
 * developer options and ADB stay available because the pilot default says so.
 */
public final class SystemPolicyStore {

    private static final String PREFS = "system_policy";
    private static final String KEY_SCHEMA_VERSION = "schema_version";
    private static final String KEY_PROFILE = "provisioned_profile";
    private static final String KEY_CHOICE_PREFIX = "choice:";
    private static final String KEY_OUTCOME_PREFIX = "outcome:";
    private static final String KEY_DETAIL_PREFIX = "detail:";
    private static final String KEY_VERIFIED_AT = "verified_at";

    /** Bumped only for a change that needs migration code, so 1 means "as designed". */
    private static final int SCHEMA_VERSION = 1;

    private SystemPolicyStore() {}

    /**
     * The profile this installation is treated as, pinned on first run.
     *
     * <p>Pinning matters because the pin is the record that this device was ever
     * a pilot. {@link SystemPolicyProfile#safest} then refuses to promote it, so
     * a device that has been relying on ADB recovery cannot be hardened by
     * anything short of an administrator saying so on the console.
     */
    public static synchronized SystemPolicyProfile effectiveProfile(Context context) {
        SharedPreferences preferences = prefs(context);
        SystemPolicyProfile detected =
                SystemPolicyProfile.detect(context.getPackageName());
        String stored = preferences.getString(KEY_PROFILE, null);
        if (stored == null) {
            preferences.edit()
                    .putString(KEY_PROFILE, detected.name())
                    .putInt(KEY_SCHEMA_VERSION, SCHEMA_VERSION)
                    .commit();
            return detected;
        }
        SystemPolicyProfile pinned;
        try {
            pinned = SystemPolicyProfile.valueOf(stored);
        } catch (IllegalArgumentException ignored) {
            // An unreadable record is not evidence of production provisioning.
            pinned = SystemPolicyProfile.PILOT;
        }
        return SystemPolicyProfile.safest(pinned, detected);
    }

    /** Only the controls an administrator has explicitly set. */
    public static synchronized Map<SystemPolicyControl, Boolean> explicitChoices(Context context) {
        SharedPreferences preferences = prefs(context);
        LinkedHashMap<SystemPolicyControl, Boolean> choices = new LinkedHashMap<>();
        for (SystemPolicyControl control : SystemPolicyControl.values()) {
            String key = KEY_CHOICE_PREFIX + control.storageKey();
            if (preferences.contains(key)) {
                choices.put(control, preferences.getBoolean(key, false));
            }
        }
        return choices;
    }

    /**
     * The base policy this device is configured for: the administrator's stored
     * choices, raised by compatibility and containment requirements.
     *
     * <p>This is the single seam every consumer of the base policy reads —
     * {@code LockdownPolicyController}, the maintenance coordinator that has to
     * restore it, and the console rows. {@link #explicitChoices} stays the raw
     * record of what was toggled; a caller that used it as "the base policy"
     * would restore a device to a policy weaker than the one it is running.
     */
    public static Map<SystemPolicyControl, Boolean> baseChoices(Context context) {
        return baseChoices(context, HomeFilterController.isEnabled(context));
    }

    /**
     * The same, for a home filter state a policy pass has already settled —
     * including a pending teardown the pass holds, which must look enabled.
     */
    public static Map<SystemPolicyControl, Boolean> baseChoices(Context context, boolean homeFilterEnabled) {
        Map<SystemPolicyControl, Boolean> choices = explicitChoices(context);
        if (ManagementModeStore.hasUnreadableRemoteIntent(context)) {
            // An unreadable marker cannot authorize keeping the ADB recovery path open.
            choices.put(SystemPolicyControl.DEVELOPER_OPTIONS_AND_ADB, true);
        }
        var compatibleChoices = PlayStoreCompatibility.baseChoices(
                PlayStoreCompatibilityStore.isEnabled(context), choices);
        return HomeFilterPolicy.choicesFor(compatibleChoices, homeFilterEnabled);
    }

    /** What a control resolves to right now: the base choice, or the profile default. */
    public static boolean isRequested(Context context, SystemPolicyControl control) {
        return SystemPolicyEnforcer.requestedFor(
                control,
                effectiveProfile(context),
                baseChoices(context)
        );
    }

    public static synchronized boolean hasExplicitChoice(Context context, SystemPolicyControl control) {
        return prefs(context).contains(KEY_CHOICE_PREFIX + control.storageKey());
    }

    /**
     * Records an administrator's decision. The caller owns authentication and
     * confirmation. Returns false on disk failure.
     */
    static boolean setRequested(
            Context context,
            SystemPolicyControl control,
            boolean requested
    ) {
        return setRequested(prefs(context), control, requested);
    }

    static synchronized boolean setRequested(
            SharedPreferences preferences, SystemPolicyControl control, boolean requested
    ) {
        String choice = KEY_CHOICE_PREFIX + control.storageKey();
        String outcome = KEY_OUTCOME_PREFIX + control.storageKey();
        String detail = KEY_DETAIL_PREFIX + control.storageKey();
        SharedPreferences.Editor editor = preferences.edit()
                .putBoolean(choice, requested)
                .putInt(KEY_SCHEMA_VERSION, SCHEMA_VERSION)
                .remove(outcome)
                .remove(detail);
        return DurablePreferences.commit(preferences, editor, choice, KEY_SCHEMA_VERSION, outcome, detail);
    }

    static synchronized boolean projectControls(Context context, Map<String, Boolean> choices) {
        SharedPreferences prefs = prefs(context);
        SharedPreferences.Editor edit = prefs.edit().putInt(KEY_SCHEMA_VERSION, SCHEMA_VERSION);
        ArrayList<String> keys = new ArrayList<>();
        keys.add(KEY_SCHEMA_VERSION);
        if (!prefs.contains(KEY_PROFILE)) {
            edit.putString(KEY_PROFILE, SystemPolicyProfile.detect(context.getPackageName()).name());
            keys.add(KEY_PROFILE);
        }
        for (SystemPolicyControl control : SystemPolicyControl.values()) {
            String id = control.storageKey();
            String key = KEY_CHOICE_PREFIX + id;
            keys.add(key);
            if (choices.containsKey(id)) {
                edit.putBoolean(key, choices.get(id));
            } else {
                edit.remove(key);
            }
        }
        return DurablePreferences.commit(prefs, edit, keys.toArray(new String[0]));
    }

    /**
     * Stores the verified outcome of a pass so the console can render evidence
     * rather than intent, including after a process restart.
     */
    public static synchronized void saveReport(Context context, SystemPolicyReport report) {
        SharedPreferences.Editor editor = prefs(context).edit();
        for (SystemPolicyControlStatus status : report.statuses()) {
            editor.putString(
                    KEY_OUTCOME_PREFIX + status.control().storageKey(),
                    status.outcome().name()
            );
            editor.putString(
                    KEY_DETAIL_PREFIX + status.control().storageKey(),
                    status.detail()
            );
        }
        editor.putLong(KEY_VERIFIED_AT, System.currentTimeMillis()).commit();
    }

    /** The remote pass counts its evidence as stored only when the write is durable. */
    static synchronized boolean saveReportDurably(Context context, SystemPolicyReport report) {
        SharedPreferences prefs = prefs(context);
        SharedPreferences.Editor editor = prefs.edit().putLong(KEY_VERIFIED_AT, System.currentTimeMillis());
        ArrayList<String> keys = new ArrayList<>();
        keys.add(KEY_VERIFIED_AT);
        for (SystemPolicyControlStatus status : report.statuses()) {
            String outcome = KEY_OUTCOME_PREFIX + status.control().storageKey();
            String detail = KEY_DETAIL_PREFIX + status.control().storageKey();
            editor.putString(outcome, status.outcome().name()).putString(detail, status.detail());
            keys.add(outcome);
            keys.add(detail);
        }
        return DurablePreferences.commit(prefs, editor, keys.toArray(new String[0]));
    }

    /**
     * The last verified outcome for one control.
     *
     * <p>{@link SystemPolicyOutcome#REQUESTED} — never verified — is what a
     * control reports when it has been switched on but no apply pass has
     * confirmed it yet, and {@link SystemPolicyOutcome#NOT_REQUESTED} likewise
     * for one switched off. Neither is ever shown as enforcement.
     */
    public static SystemPolicyOutcome lastOutcome(Context context, SystemPolicyControl control) {
        String stored = prefs(context).getString(KEY_OUTCOME_PREFIX + control.storageKey(), null);
        if (stored == null) {
            return isRequested(context, control)
                    ? SystemPolicyOutcome.REQUESTED
                    : SystemPolicyOutcome.NOT_REQUESTED;
        }
        try {
            return SystemPolicyOutcome.valueOf(stored);
        } catch (IllegalArgumentException ignored) {
            return SystemPolicyOutcome.FAILED;
        }
    }

    public static String lastDetail(Context context, SystemPolicyControl control) {
        return prefs(context).getString(KEY_DETAIL_PREFIX + control.storageKey(), "");
    }

    /**
     * Marks every stored outcome stale after a change that has not been applied.
     *
     * <p>Without this, switching a control off would leave yesterday's
     * {@code APPLIED} on screen and the console would keep asserting an
     * enforcement that is no longer even requested.
     */
    static synchronized boolean invalidateVerification(
            Context context, Collection<SystemPolicyControl> controls
    ) {
        SharedPreferences preferences = prefs(context);
        SharedPreferences.Editor editor = preferences.edit();
        ArrayList<String> keys = new ArrayList<>();
        for (SystemPolicyControl control : controls) {
            String outcome = KEY_OUTCOME_PREFIX + control.storageKey();
            String detail = KEY_DETAIL_PREFIX + control.storageKey();
            editor.remove(outcome).remove(detail);
            keys.add(outcome);
            keys.add(detail);
        }
        return DurablePreferences.commit(preferences, editor, keys.toArray(new String[0]));
    }

    /** When the last verification ran, or 0 when none has. */
    public static long lastVerifiedAt(Context context) {
        return prefs(context).getLong(KEY_VERIFIED_AT, 0L);
    }

    private static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }
}
