package com.example.lockdowndpc.policy;

import java.time.ZoneId;
import java.util.Set;
import java.util.TreeSet;

/**
 * Read and write rules for the stored schedule and the schedule's ownership
 * record, independent of Android.
 *
 * <p>Android's {@code SharedPreferences.commit()} updates the in-memory map
 * before it writes to disk, so a failed commit would still be visible to every
 * later reader in the process. After a failed commit the previous raw values
 * are therefore written back exactly (never a re-serialised parse, so an
 * unreadable record stays unreadable), and the write is reported as failed.
 *
 * <p>Both records carry a format marker, and the settings record also states
 * explicitly whether it is a schedule or "off". Android loads an unparseable
 * preference file as an empty map, so a file that exists, or once existed, but
 * carries no marker is damaged, and a marker without a stated content is
 * damaged too. Neither ever reads as "off" or as "nothing owned". Only a device
 * whose file was never written reads as empty.
 */
final class SchedulePersistence {

    /** The format marker every write stores next to the values. */
    static final String FORMAT = "1";

    /** The settings record holds a schedule. */
    static final String STATE_SCHEDULE = "schedule";

    /** The settings record is an explicit "off": no schedule, no allowlist. */
    static final String STATE_OFF = "off";

    /** The raw preference values of the settings record. */
    interface Backing {
        /**
         * The stored values exactly as found: {@code [json, allowlist, format,
         * state]}, each {@code null} when absent. May throw when a value has the
         * wrong type.
         */
        String[] snapshot();

        /**
         * Whether the preference file exists on disk in any form, its backup
         * included. May throw; a failed check counts as "exists".
         */
        boolean fileExists();

        /**
         * Writes both values ({@code null} removes a value), the {@link #FORMAT}
         * marker and the state: {@link #STATE_OFF} when {@code json} is
         * {@code null}, otherwise {@link #STATE_SCHEDULE}. Android semantics:
         * memory is updated even when this returns {@code false}.
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

    /** The raw preference values of the ownership record. */
    interface OwnedBacking {
        /**
         * The stored values exactly as found: {@code [packages, format]}, each
         * {@code null} when absent. May throw for a wrong type.
         */
        String[] snapshot();

        /** As {@link Backing#fileExists}. */
        boolean fileExists();

        /**
         * Writes the packages (possibly empty, never removed) and the
         * {@link #FORMAT} marker; Android semantics as {@link Backing#commit}.
         */
        boolean commit(String packages);

        /** As {@link Backing#restore}. */
        void restore(String[] snapshot, boolean fileExisted);
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
        if (raw == null || raw.length != 4) {
            return ScheduleSettings.failClosed(fallbackZone);
        }
        String json = raw[0];
        String allowlist = raw[1];
        String format = raw[2];
        String state = raw[3];
        if (format == null) {
            if (json == null && allowlist == null && state == null && !fileExists(backing)) {
                return ScheduleSettings.OFF;
            }
            // A file without the marker: damaged, emptied on load, or values
            // without the write that carries them.
            return ScheduleSettings.failClosed(fallbackZone);
        }
        if (!FORMAT.equals(format)) {
            return ScheduleSettings.failClosed(fallbackZone);
        }
        if (STATE_OFF.equals(state) && json == null && allowlist == null) {
            return ScheduleSettings.OFF;
        }
        if (STATE_SCHEDULE.equals(state) && json != null) {
            return ScheduleSettings.fromStored(json, allowlist, fallbackZone);
        }
        // A marker without a stated content, or a state its values contradict.
        return ScheduleSettings.failClosed(fallbackZone);
    }

    /**
     * Persists {@code settings} and reports whether the disk write succeeded.
     * {@link ScheduleSettings#OFF} is written as an explicit "off" record. The
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
        if (previous != null && previous.length == 4) {
            backing.restore(previous, existed);
        } else {
            // The previous record was unreadable as values; dropping the new
            // values from memory would read as "off", so a stored value that
            // can never parse, without a marker, is left instead and the pass
            // stays fail-closed.
            backing.restore(new String[]{"", null, null, null}, true);
        }
        return false;
    }

    /**
     * Packages the schedule suspended, as recorded.
     *
     * @throws IllegalStateException when the record is unreadable: a wrong
     *         type, a missing or unknown marker on a file that exists, or any
     *         malformed entry. Ownership is then unknown, never "none".
     */
    static Set<String> readOwned(OwnedBacking backing) {
        String[] raw;
        try {
            raw = backing.snapshot();
        } catch (RuntimeException exception) {
            throw new IllegalStateException("ownership-unreadable", exception);
        }
        if (raw == null || raw.length != 2) {
            throw new IllegalStateException("ownership-unreadable");
        }
        if (raw[1] == null) {
            if (raw[0] == null && !fileExists(backing)) {
                return new TreeSet<>();
            }
            throw new IllegalStateException("ownership-unmarked");
        }
        if (!FORMAT.equals(raw[1]) || raw[0] == null) {
            throw new IllegalStateException("ownership-unreadable");
        }
        return decodeOwned(raw[0]);
    }

    /**
     * Persists the ownership record. A failed commit writes the previous raw
     * values back, so memory never holds a record the disk does not.
     */
    static boolean saveOwned(OwnedBacking backing, Set<String> owned) {
        String[] previous;
        try {
            previous = backing.snapshot();
        } catch (RuntimeException exception) {
            previous = null;
        }
        boolean existed = fileExists(backing);
        if (backing.commit(encodeOwned(owned))) {
            return true;
        }
        if (previous != null && previous.length == 2) {
            backing.restore(previous, existed);
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

    private static boolean fileExists(OwnedBacking backing) {
        try {
            return backing.fileExists();
        } catch (RuntimeException exception) {
            return true;
        }
    }

    /** Decodes a stored set of owned packages; any malformed entry fails the whole record. */
    static Set<String> decodeOwned(String stored) {
        TreeSet<String> packages = new TreeSet<>();
        if (stored.isEmpty()) {
            return packages;
        }
        for (String packageName : stored.split(",", -1)) {
            if (!ScheduleSettings.isPackageName(packageName) || !packages.add(packageName)) {
                throw new IllegalStateException("ownership-malformed");
            }
        }
        return packages;
    }

    static String encodeOwned(Set<String> owned) {
        return String.join(",", new TreeSet<>(owned));
    }
}
