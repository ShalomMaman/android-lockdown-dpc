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
 * are in {@link SchedulePersistence}, including the markers that tell a damaged
 * file from an empty one. The catch-up hint lives in a third file of its own
 * and is written best effort, so it can never make a failed write to the other
 * two durable.
 */
public final class ScheduleStore {
    private static final String PREFS = "schedule";
    private static final String STATE_PREFS = "schedule_state";
    private static final String CATCH_UP_PREFS = "schedule_catch_up";
    private static final String KEY_JSON = "schedule_json";
    private static final String KEY_ALLOWLIST = "allowlist";
    private static final String KEY_FORMAT = "format";
    private static final String KEY_STATE = "state";
    private static final String KEY_OWNED = "suspended_by_schedule";
    private static final String KEY_OWNED_FORMAT = "format";
    private static final String KEY_VERIFIED_AT = "verified_at";
    private static final String KEY_FAILED_ATTEMPTS = "failed_attempts";
    private static final String KEY_RETRY_AT = "retry_at";

    private ScheduleStore() {}

    /** What a policy pass enforces; an unreadable record is the fail-closed default schedule. */
    public static ScheduleSettings read(Context context) {
        return SchedulePersistence.read(backing(context), deviceZone());
    }

    /** @return whether the settings were persisted */
    static boolean write(Context context, ScheduleSettings settings) {
        return SchedulePersistence.write(backing(context), settings);
    }

    /**
     * Packages the schedule suspended.
     *
     * @throws IllegalStateException when the record is unreadable, including a
     *         damaged file Android loaded as empty; ownership is then unknown
     */
    static Set<String> readOwned(Context context) {
        return SchedulePersistence.readOwned(ownedBacking(context));
    }

    static boolean saveOwned(Context context, Set<String> owned) {
        return SchedulePersistence.saveOwned(ownedBacking(context), owned);
    }

    /**
     * The catch-up hint ({@link ScheduleCatchUp}); never a statement about
     * which window is in force. {@link ScheduleCatchUp.State#UNKNOWN} when
     * absent or unreadable, which asks for a pass.
     */
    static ScheduleCatchUp.State catchUpState(Context context) {
        try {
            SharedPreferences prefs = catchUp(context);
            Instant verified = prefs.contains(KEY_VERIFIED_AT)
                    ? Instant.ofEpochMilli(prefs.getLong(KEY_VERIFIED_AT, 0L))
                    : null;
            Instant retryAt = prefs.contains(KEY_RETRY_AT)
                    ? Instant.ofEpochMilli(prefs.getLong(KEY_RETRY_AT, 0L))
                    : null;
            return new ScheduleCatchUp.State(verified, prefs.getInt(KEY_FAILED_ATTEMPTS, 0), retryAt);
        } catch (RuntimeException exception) {
            return ScheduleCatchUp.State.UNKNOWN;
        }
    }

    /** Records the catch-up hint; best effort. */
    static void saveCatchUpState(Context context, ScheduleCatchUp.State state) {
        try {
            SharedPreferences.Editor editor = catchUp(context).edit();
            if (state.lastVerified() == null) {
                editor.remove(KEY_VERIFIED_AT);
            } else {
                editor.putLong(KEY_VERIFIED_AT, state.lastVerified().toEpochMilli());
            }
            editor.putInt(KEY_FAILED_ATTEMPTS, state.failedAttempts());
            if (state.retryAt() == null) {
                editor.remove(KEY_RETRY_AT);
            } else {
                editor.putLong(KEY_RETRY_AT, state.retryAt().toEpochMilli());
            }
            editor.apply();
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
                        prefs.getString(KEY_FORMAT, null),
                        prefs.getString(KEY_STATE, null)};
            }

            @Override
            public boolean fileExists() {
                return fileExists.getAsBoolean();
            }

            @Override
            public boolean commit(String json, String allowlist) {
                return edit(prefs, json, allowlist, SchedulePersistence.FORMAT,
                        json == null ? SchedulePersistence.STATE_OFF : SchedulePersistence.STATE_SCHEDULE).commit();
            }

            @Override
            public void restore(String[] snapshot, boolean fileExisted) {
                edit(prefs, snapshot[0], snapshot[1], snapshot[2], snapshot[3]).commit();
                if (!fileExisted && allNull(snapshot)) {
                    deleteFile(file);
                }
            }
        };
    }

    private static SchedulePersistence.OwnedBacking ownedBacking(Context context) {
        Context app = context.getApplicationContext() == null ? context : context.getApplicationContext();
        SharedPreferences prefs = app.getSharedPreferences(STATE_PREFS, Context.MODE_PRIVATE);
        File file = new File(app.getApplicationInfo().dataDir, "shared_prefs/" + STATE_PREFS + ".xml");
        BooleanSupplier fileExists = BuiltInBlockExemptionsStore.fileOrBackupExists(file);
        return new SchedulePersistence.OwnedBacking() {
            @Override
            public String[] snapshot() {
                // getString throws ClassCastException for a wrong-typed value,
                // which SchedulePersistence reads as unreadable.
                return new String[]{prefs.getString(KEY_OWNED, null), prefs.getString(KEY_OWNED_FORMAT, null)};
            }

            @Override
            public boolean fileExists() {
                return fileExists.getAsBoolean();
            }

            @Override
            public boolean commit(String packages) {
                SharedPreferences.Editor editor = prefs.edit();
                editor.putString(KEY_OWNED, packages);
                editor.putString(KEY_OWNED_FORMAT, SchedulePersistence.FORMAT);
                return editor.commit();
            }

            @Override
            public void markUnknown(String packages) {
                prefs.edit().putString(KEY_OWNED, packages).remove(KEY_OWNED_FORMAT).commit();
            }
        };
    }

    private static boolean allNull(String[] values) {
        for (String value : values) {
            if (value != null) {
                return false;
            }
        }
        return true;
    }

    /**
     * Deletes the file itself, not through deleteSharedPreferences, so the
     * cached preference instance stays the only one.
     */
    private static void deleteFile(File file) {
        file.delete();
        new File(file.getPath() + ".bak").delete();
    }

    private static SharedPreferences.Editor edit(
            SharedPreferences prefs, String json, String allowlist, String format, String state) {
        SharedPreferences.Editor editor = prefs.edit();
        put(editor, KEY_JSON, json);
        put(editor, KEY_ALLOWLIST, allowlist);
        put(editor, KEY_FORMAT, format);
        put(editor, KEY_STATE, state);
        return editor;
    }

    private static void put(SharedPreferences.Editor editor, String key, String value) {
        if (value == null) {
            editor.remove(key);
        } else {
            editor.putString(key, value);
        }
    }

    private static SharedPreferences catchUp(Context context) {
        return context.getSharedPreferences(CATCH_UP_PREFS, Context.MODE_PRIVATE);
    }
}
