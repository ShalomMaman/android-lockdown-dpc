package com.example.lockdowndpc.policy;

import android.content.Context;
import android.content.SharedPreferences;

import java.time.DateTimeException;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Set;

/**
 * Android storage for night and work hours.
 *
 * <p>The administrator's configuration (the shared schedule JSON and the
 * allowlist) and the schedule's own enforcement record (which packages it
 * suspended) live in separate preference files, so rolling back a failed
 * configuration write can never rewrite the enforcement record. Every write is
 * a synchronous {@code commit()}; the rules are in {@link SchedulePersistence}.
 */
public final class ScheduleStore {
    private static final String PREFS = "schedule";
    private static final String STATE_PREFS = "schedule_state";
    private static final String KEY_JSON = "schedule_json";
    private static final String KEY_ALLOWLIST = "allowlist";
    private static final String KEY_OWNED = "suspended_by_schedule";

    private ScheduleStore() {}

    /** What a policy pass enforces; an unreadable record is the fail-closed night window. */
    public static ScheduleSettings read(Context context) {
        return SchedulePersistence.read(backing(context), deviceZone());
    }

    /** @return whether the settings were persisted */
    static boolean write(Context context, ScheduleSettings settings) {
        return SchedulePersistence.write(backing(context), settings);
    }

    /** Packages the schedule suspended. A wrong-typed record throws. */
    static Set<String> readOwned(Context context) {
        return SchedulePersistence.decodeOwned(state(context).getString(KEY_OWNED, null));
    }

    static boolean saveOwned(Context context, Set<String> owned) {
        SharedPreferences.Editor editor = state(context).edit();
        if (owned.isEmpty()) {
            editor.remove(KEY_OWNED);
        } else {
            editor.putString(KEY_OWNED, SchedulePersistence.encodeOwned(owned));
        }
        return editor.commit();
    }

    /** The device's zone, for the fail-closed window when the stored zone is unreadable. */
    static ZoneId deviceZone() {
        try {
            return ZoneId.systemDefault();
        } catch (DateTimeException exception) {
            return ZoneOffset.UTC;
        }
    }

    private static SchedulePersistence.Backing backing(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        return new SchedulePersistence.Backing() {
            @Override
            public String[] snapshot() {
                // getString throws ClassCastException for a wrong-typed value,
                // which SchedulePersistence reads as unreadable.
                return new String[]{prefs.getString(KEY_JSON, null), prefs.getString(KEY_ALLOWLIST, null)};
            }

            @Override
            public boolean commit(String json, String allowlist) {
                return edit(prefs, json, allowlist).commit();
            }

            @Override
            public void restore(String[] snapshot) {
                edit(prefs, snapshot[0], snapshot[1]).commit();
            }
        };
    }

    private static SharedPreferences.Editor edit(SharedPreferences prefs, String json, String allowlist) {
        SharedPreferences.Editor editor = prefs.edit();
        if (json == null) {
            editor.remove(KEY_JSON);
        } else {
            editor.putString(KEY_JSON, json);
        }
        if (allowlist == null) {
            editor.remove(KEY_ALLOWLIST);
        } else {
            editor.putString(KEY_ALLOWLIST, allowlist);
        }
        return editor;
    }

    private static SharedPreferences state(Context context) {
        return context.getSharedPreferences(STATE_PREFS, Context.MODE_PRIVATE);
    }
}
