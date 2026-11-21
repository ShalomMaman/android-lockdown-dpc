package com.example.lockdowndpc.policy;

import android.content.Context;
import android.content.SharedPreferences;

import java.io.File;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Set;
import java.util.function.BooleanSupplier;

/**
 * Android storage for night and work hours.
 *
 * <p>The administrator's configuration (the shared schedule JSON and the
 * allowlist) and the schedule's own enforcement record (which packages it
 * suspended) live in separate preference files, so rolling back a failed
 * configuration write can never rewrite the enforcement record. Every write to
 * either is a synchronous {@code commit()} rolled back on failure; the rules
 * are in {@link SchedulePersistence}. The catch-up hint lives in a third file
 * of its own and is written best effort, so it can never make a failed write
 * to the other two durable.
 */
public final class ScheduleStore {
    private static final String PREFS = "schedule";
    private static final String STATE_PREFS = "schedule_state";
    private static final String CATCH_UP_PREFS = "schedule_catch_up";
    private static final String KEY_JSON = "schedule_json";
    private static final String KEY_ALLOWLIST = "allowlist";
    private static final String KEY_FORMAT = "format";
    private static final String KEY_OWNED = "suspended_by_schedule";
    private static final String KEY_RECONCILED_AT = "reconciled_at";

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
        SharedPreferences prefs = state(context);
        return SchedulePersistence.saveOwned(new SchedulePersistence.OwnedBacking() {
            @Override
            public String snapshot() {
                return prefs.getString(KEY_OWNED, null);
            }

            @Override
            public boolean commit(String value) {
                SharedPreferences.Editor editor = prefs.edit();
                if (value == null) {
                    editor.remove(KEY_OWNED);
                } else {
                    editor.putString(KEY_OWNED, value);
                }
                return editor.commit();
            }
        }, owned);
    }

    /**
     * When the schedule step of a policy pass last ran, as a hint for the
     * catch-up check only ({@link ScheduleCatchUp}); never a statement about
     * which window is in force. {@code null} when unknown or unreadable.
     */
    static Instant lastReconciled(Context context) {
        try {
            SharedPreferences prefs = catchUp(context);
            return prefs.contains(KEY_RECONCILED_AT)
                    ? Instant.ofEpochMilli(prefs.getLong(KEY_RECONCILED_AT, 0L))
                    : null;
        } catch (RuntimeException exception) {
            return null;
        }
    }

    /** Records the instant the pass evaluated the schedule at; best effort. */
    static void markReconciled(Context context, Instant at) {
        try {
            catchUp(context).edit().putLong(KEY_RECONCILED_AT, at.toEpochMilli()).apply();
        } catch (RuntimeException ignored) {
            // A missing hint only makes the next catch-up check run a pass.
        }
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
        Context app = context.getApplicationContext() == null ? context : context.getApplicationContext();
        SharedPreferences prefs = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        File file = new File(app.getApplicationInfo().dataDir, "shared_prefs/" + PREFS + ".xml");
        BooleanSupplier fileExists = BuiltInBlockExemptionsStore.fileOrBackupExists(file);
        return new SchedulePersistence.Backing() {
            @Override
            public String[] snapshot() {
                // getString throws ClassCastException for a wrong-typed value,
                // which SchedulePersistence reads as unreadable.
                return new String[]{
                        prefs.getString(KEY_JSON, null),
                        prefs.getString(KEY_ALLOWLIST, null),
                        prefs.getString(KEY_FORMAT, null)};
            }

            @Override
            public boolean fileExists() {
                return fileExists.getAsBoolean();
            }

            @Override
            public boolean commit(String json, String allowlist) {
                return edit(prefs, json, allowlist, SchedulePersistence.FORMAT).commit();
            }

            @Override
            public void restore(String[] snapshot, boolean fileExisted) {
                edit(prefs, snapshot[0], snapshot[1], snapshot[2]).commit();
                if (!fileExisted && snapshot[0] == null && snapshot[1] == null && snapshot[2] == null) {
                    // Delete the file itself, not through deleteSharedPreferences,
                    // so the cached preference instance stays the only one.
                    file.delete();
                    new File(file.getPath() + ".bak").delete();
                }
            }
        };
    }

    private static SharedPreferences.Editor edit(
            SharedPreferences prefs, String json, String allowlist, String format) {
        SharedPreferences.Editor editor = prefs.edit();
        put(editor, KEY_JSON, json);
        put(editor, KEY_ALLOWLIST, allowlist);
        put(editor, KEY_FORMAT, format);
        return editor;
    }

    private static void put(SharedPreferences.Editor editor, String key, String value) {
        if (value == null) {
            editor.remove(key);
        } else {
            editor.putString(key, value);
        }
    }

    private static SharedPreferences state(Context context) {
        return context.getSharedPreferences(STATE_PREFS, Context.MODE_PRIVATE);
    }

    private static SharedPreferences catchUp(Context context) {
        return context.getSharedPreferences(CATCH_UP_PREFS, Context.MODE_PRIVATE);
    }
}
