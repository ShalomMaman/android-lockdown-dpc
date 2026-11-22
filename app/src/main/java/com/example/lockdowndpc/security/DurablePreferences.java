package com.example.lockdowndpc.security;

import android.content.SharedPreferences;

import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

/** Synchronous preference writes that undo Android's in-memory change on disk failure. */
public final class DurablePreferences {
    private DurablePreferences() {}

    /** The caller serializes access to this store and names every edited key. */
    public static boolean commit(
            SharedPreferences prefs, SharedPreferences.Editor update, String... keys
    ) {
        Map<String, ?> before = prefs.getAll();
        return commit(update, () -> {
            SharedPreferences.Editor rollback = prefs.edit();
            for (String key : keys) {
                restore(rollback, key, before.get(key));
            }
            return rollback;
        });
    }

    /** For a store that already has a typed snapshot of its previous state. */
    public static boolean commit(
            SharedPreferences.Editor update, Supplier<SharedPreferences.Editor> rollback
    ) {
        try {
            if (update.commit()) {
                return true;
            }
        } catch (RuntimeException failedWrite) {
            // A throwing editor may already have changed the in-memory map.
        }
        // Even if disk is still unwritable, this puts the old values back in memory.
        rollback.get().commit();
        return false;
    }

    @SuppressWarnings("unchecked") // SharedPreferences stores only sets of strings.
    private static void restore(SharedPreferences.Editor editor, String key, Object value) {
        if (value == null) {
            editor.remove(key);
        } else if (value instanceof String text) {
            editor.putString(key, text);
        } else if (value instanceof Set<?> set) {
            editor.putStringSet(key, (Set<String>) set);
        } else if (value instanceof Boolean flag) {
            editor.putBoolean(key, flag);
        } else if (value instanceof Integer number) {
            editor.putInt(key, number);
        } else if (value instanceof Long number) {
            editor.putLong(key, number);
        } else if (value instanceof Float number) {
            editor.putFloat(key, number);
        }
    }
}
