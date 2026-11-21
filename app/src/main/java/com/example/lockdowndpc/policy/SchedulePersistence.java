package com.example.lockdowndpc.policy;

import java.time.ZoneId;
import java.util.Set;

/**
 * Read and write rules for the stored schedule, independent of Android.
 *
 * <p>Android's {@code SharedPreferences.commit()} updates the in-memory map
 * before it writes to disk, so a failed commit would still be visible to every
 * later reader in the process. After a failed commit the previous raw values
 * are therefore written back exactly (never a re-serialised parse, so an
 * unreadable record stays unreadable), and the write is reported as failed.
 *
 * <p>Reading never returns "no schedule" for something that is stored but does
 * not parse: see {@link ScheduleSettings#failClosed}.
 */
final class SchedulePersistence {

    /**
     * The format marker every write stores next to the values. A preference
     * file that exists, or once existed, but carries no marker is a damaged
     * record: Android loads an unparseable preference file as an empty map, and
     * that must never read as "no schedule". Only a device whose file was never
     * written reads as {@link ScheduleSettings#OFF}.
     */
    static final String FORMAT = "1";

    /** The raw preference values. */
    interface Backing {
        /**
         * The stored values exactly as found: {@code [json, allowlist, format]},
         * each {@code null} when absent. May throw when a value has the wrong type.
         */
        String[] snapshot();

        /**
         * Whether the preference file exists on disk in any form, its backup
         * included. May throw; a failed check counts as "exists".
         */
        boolean fileExists();

        /**
         * Writes both values ({@code null} removes a value) and the
         * {@link #FORMAT} marker. Android semantics: memory is updated even
         * when this returns {@code false}.
         */
        boolean commit(String json, String allowlist);

        /**
         * Writes a {@link #snapshot} back exactly; memory is restored whatever
         * the disk does. When the file did not exist before and nothing was
         * stored, the file is removed again, so a failed first save leaves a
         * fresh device as it was rather than with an empty, marker-less file.
         */
        void restore(String[] snapshot, boolean fileExisted);
    }

    /** The raw value of the schedule's ownership record. */
    interface OwnedBacking {
        /** The stored value exactly as found, or {@code null}. May throw for a wrong type. */
        String snapshot();

        /** Writes the value ({@code null} removes it); Android semantics as {@link Backing#commit}. */
        boolean commit(String value);
    }

    private SchedulePersistence() {}

    /** What a policy pass enforces. */
    static ScheduleSettings read(Backing backing, ZoneId fallbackZone) {
        String[] raw;
        try {
            raw = backing.snapshot();
        } catch (RuntimeException exception) {
            return ScheduleSettings.failClosed(fallbackZone);
        }
        if (raw == null || raw.length != 3) {
            return ScheduleSettings.failClosed(fallbackZone);
        }
        if (raw[2] == null) {
            if (raw[0] == null && raw[1] == null && !fileExists(backing)) {
                return ScheduleSettings.OFF;
            }
            // A file without the marker: damaged, emptied on load, or values
            // without the write that carries them.
            return ScheduleSettings.failClosed(fallbackZone);
        }
        if (!FORMAT.equals(raw[2])) {
            return ScheduleSettings.failClosed(fallbackZone);
        }
        return ScheduleSettings.fromStored(raw[0], raw[1], fallbackZone);
    }

    /**
     * Persists {@code settings} and reports whether the disk write succeeded.
     * {@link ScheduleSettings#OFF} removes the values and keeps the marker. The
     * fail-closed stand-in is never written: it describes a corrupt record, not
     * a choice.
     */
    static boolean write(Backing backing, ScheduleSettings settings) {
        if (settings == null || settings.unreadable()) {
            throw new IllegalArgumentException("Only a readable schedule can be stored");
        }
        String json = settings.schedule() == null ? null : SchedulePolicy.toJson(settings.schedule());
        String allowlist = settings.schedule() == null ? null : ScheduleSettings.encodeAllowlist(settings.allowlist());
        String[] previous;
        try {
            previous = backing.snapshot();
        } catch (RuntimeException exception) {
            previous = null;
        }
        boolean existed = fileExists(backing);
        if (backing.commit(json, allowlist)) {
            return true;
        }
        if (previous != null && previous.length == 3) {
            backing.restore(previous, existed);
        } else {
            // The previous record was unreadable as values; dropping the new
            // values from memory would read as "off", so a stored value that
            // can never parse, without a marker, is left instead and the pass
            // stays fail-closed.
            backing.restore(new String[]{"", null, null}, true);
        }
        return false;
    }

    /**
     * Persists the ownership record. A failed commit writes the previous raw
     * value back, so memory never holds a record the disk does not.
     */
    static boolean saveOwned(OwnedBacking backing, Set<String> owned) {
        String previous;
        boolean previousReadable;
        try {
            previous = backing.snapshot();
            previousReadable = true;
        } catch (RuntimeException exception) {
            previous = null;
            previousReadable = false;
        }
        if (backing.commit(owned.isEmpty() ? null : encodeOwned(owned))) {
            return true;
        }
        if (previousReadable) {
            backing.commit(previous);
        }
        // A wrong-typed previous value cannot be written back as it was. The
        // new value stays in memory: the schedule suspends only after a
        // successful save, so it may over-report what it holds, never under-report.
        return false;
    }

    private static boolean fileExists(Backing backing) {
        try {
            return backing.fileExists();
        } catch (RuntimeException exception) {
            return true;
        }
    }

    /** Decodes a stored set of owned packages; malformed entries are dropped. */
    static Set<String> decodeOwned(String stored) {
        java.util.TreeSet<String> packages = new java.util.TreeSet<>();
        if (stored == null || stored.isEmpty()) {
            return packages;
        }
        for (String packageName : stored.split(",", -1)) {
            if (ScheduleSettings.isPackageName(packageName)) {
                packages.add(packageName);
            }
        }
        return packages;
    }

    static String encodeOwned(Set<String> owned) {
        return String.join(",", new java.util.TreeSet<>(owned));
    }
}
