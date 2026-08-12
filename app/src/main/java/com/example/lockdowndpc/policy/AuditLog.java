package com.example.lockdowndpc.policy;

import android.content.Context;
import android.content.SharedPreferences;

import com.example.lockdowndpc.R;

import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public final class AuditLog {
    private static final String PREFS = "admin_audit";
    private static final String KEY_ENTRIES = "entries";
    private static final int MAX_ENTRIES = 50;

    private AuditLog() {}

    public static synchronized void append(Context context, String event) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        ArrayList<String> entries = new ArrayList<>(rawEntries(prefs));
        entries.add(System.currentTimeMillis() + "|" + event.replace('\n', ' '));
        int first = Math.max(0, entries.size() - MAX_ENTRIES);
        prefs.edit().putString(KEY_ENTRIES, String.join("\n", entries.subList(first, entries.size()))).apply();
    }

    public static synchronized String formatted(Context context) {
        List<String> entries = rawEntries(context.getSharedPreferences(PREFS, Context.MODE_PRIVATE));
        if (entries.isEmpty()) {
            return context.getString(R.string.audit_empty);
        }
        DateFormat formatter = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT);
        StringBuilder result = new StringBuilder();
        for (int index = entries.size() - 1; index >= 0; index--) {
            String entry = entries.get(index);
            int separator = entry.indexOf('|');
            if (separator <= 0) {
                continue;
            }
            try {
                long timestamp = Long.parseLong(entry.substring(0, separator));
                result.append(formatter.format(new Date(timestamp)))
                        .append(" — ")
                        .append(entry.substring(separator + 1))
                        .append('\n');
            } catch (NumberFormatException ignored) {
                // Ignore a corrupted historic entry.
            }
        }
        return result.toString().trim();
    }

    private static List<String> rawEntries(SharedPreferences prefs) {
        String stored = prefs.getString(KEY_ENTRIES, "");
        if (stored == null || stored.isEmpty()) {
            return List.of();
        }
        return List.of(stored.split("\n"));
    }
}
