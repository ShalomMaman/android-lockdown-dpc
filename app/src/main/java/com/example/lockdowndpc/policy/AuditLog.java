package com.example.lockdowndpc.policy;

import android.content.Context;
import android.content.SharedPreferences;

import com.example.lockdowndpc.R;
import com.example.lockdowndpc.security.DurablePreferences;

import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public final class AuditLog {
    private static final String PREFS = "admin_audit";
    private static final String KEY_ENTRIES = "entries";
    private static final String KEY_HAS_CODES = "entries_have_codes";
    private static final int MAX_ENTRIES = 50;

    private AuditLog() {}

    /**
     * @deprecated Kept for one release. Use {@link #append(Context, AuditEvent, String)}.
     */
    @Deprecated
    public static void append(Context context, String text) {
        append(context, AuditEvent.GENERIC, text);
    }

    public static synchronized void append(Context context, AuditEvent event, String text) {
        edit(preferences(context), event, text).apply();
    }

    /**
     * Appends and persists before returning. For entries that must be on disk
     * together with the change they record.
     *
     * @return whether the entry was persisted
     */
    public static synchronized boolean appendCommitted(Context context, AuditEvent event, String text) {
        return edit(preferences(context), event, text).commit();
    }

    /** Writes all rows of one transition together, so the caller can retry the whole transition. */
    static boolean appendBatchCommitted(Context context, AuditEvent event, List<String> lines) {
        return appendBatchCommitted(preferences(context), event, lines);
    }

    static synchronized boolean appendBatchCommitted(SharedPreferences prefs, AuditEvent event, List<String> lines) {
        return DurablePreferences.commit(prefs, edit(prefs, event, lines), KEY_ENTRIES, KEY_HAS_CODES);
    }

    static SharedPreferences.Editor edit(SharedPreferences prefs, AuditEvent event, String text) {
        return edit(prefs, event, List.of(text));
    }

    private static SharedPreferences.Editor edit(SharedPreferences prefs, AuditEvent event, List<String> lines) {
        ArrayList<String> entries = new ArrayList<>(rawEntries(prefs));
        // Old text could begin with a code and a pipe. Migrate using the
        // preference marker, and write the marker and all rows in one edit.
        if (!prefs.getBoolean(KEY_HAS_CODES, false)) {
            entries.replaceAll(line -> {
                Entry entry = parse(line, false);
                return entry == null ? line : entry.encode();
            });
        }
        for (String line : lines) {
            entries.add(new Entry(System.currentTimeMillis(), event.code(), line).encode());
        }
        int first = Math.max(0, entries.size() - MAX_ENTRIES);
        return prefs.edit()
                .putString(KEY_ENTRIES, String.join("\n", entries.subList(first, entries.size())))
                .putBoolean(KEY_HAS_CODES, true);
    }

    public static synchronized String formatted(Context context) {
        SharedPreferences prefs = preferences(context);
        List<String> entries = rawEntries(prefs);
        if (entries.isEmpty()) {
            return context.getString(R.string.audit_empty);
        }
        return format(entries, prefs.getBoolean(KEY_HAS_CODES, false),
                DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT));
    }

    static String format(List<String> entries, boolean hasCodes, DateFormat formatter) {
        StringBuilder result = new StringBuilder();
        for (int index = entries.size() - 1; index >= 0; index--) {
            Entry entry = parse(entries.get(index), hasCodes);
            if (entry != null) {
                result.append(formatter.format(new Date(entry.atMillis())))
                        .append(" — ")
                        .append(entry.text())
                        .append('\n');
            }
        }
        return result.toString().trim();
    }

    /** An exportable audit record. */
    public record CodeEntry(long atMillis, String code) {}

    /** Returns the retained timestamps and codes, oldest first. */
    public static synchronized List<CodeEntry> codes(Context context) {
        return readCodes(preferences(context));
    }

    static List<CodeEntry> readCodes(SharedPreferences prefs) {
        boolean hasCodes = prefs.getBoolean(KEY_HAS_CODES, false);
        List<CodeEntry> result = new ArrayList<>();
        for (String line : rawEntries(prefs)) {
            Entry entry = parse(line, hasCodes);
            if (entry != null) {
                result.add(new CodeEntry(entry.atMillis(), entry.code()));
            }
        }
        return List.copyOf(result);
    }

    record Entry(long atMillis, String code, String text) {
        String encode() {
            return atMillis + "|" + code + "|" + text.replace('\n', ' ');
        }
    }

    static Entry parse(String line, boolean hasCodes) {
        int separator = line.indexOf('|');
        if (separator <= 0) {
            return null;
        }
        try {
            long atMillis = Long.parseLong(line.substring(0, separator));
            if (!hasCodes) {
                return new Entry(atMillis, AuditEvent.LEGACY_CODE, line.substring(separator + 1));
            }
            int textSeparator = line.indexOf('|', separator + 1);
            if (textSeparator < 0) {
                return null;
            }
            String code = line.substring(separator + 1, textSeparator);
            return AuditEvent.knownCodes().contains(code)
                    ? new Entry(atMillis, code, line.substring(textSeparator + 1))
                    : null;
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private static SharedPreferences preferences(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private static List<String> rawEntries(SharedPreferences prefs) {
        String stored = prefs.getString(KEY_ENTRIES, "");
        if (stored == null || stored.isEmpty()) {
            return List.of();
        }
        return List.of(stored.split("\n"));
    }
}
