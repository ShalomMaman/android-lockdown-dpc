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

    /** The raw preference values. */
    interface Backing {
        /**
         * The stored values exactly as found: {@code [json, allowlist]}, each
         * {@code null} when absent. May throw when a value has the wrong type.
         */
        String[] snapshot();

        /**
         * Writes both values; {@code null} removes a value. Android semantics:
         * memory is updated even when this returns {@code false}.
         */
        boolean commit(String json, String allowlist);

        /** Writes a {@link #snapshot} back exactly; memory is restored whatever the disk does. */
        void restore(String[] snapshot);
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
        if (raw == null || raw.length != 2) {
            return ScheduleSettings.failClosed(fallbackZone);
        }
        return ScheduleSettings.fromStored(raw[0], raw[1], fallbackZone);
    }

    /**
     * Persists {@code settings} and reports whether the disk write succeeded.
     * {@link ScheduleSettings#OFF} removes the record. The fail-closed stand-in
     * is never written: it describes a corrupt record, not a choice.
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
        if (backing.commit(json, allowlist)) {
            return true;
        }
        if (previous != null && previous.length == 2) {
            backing.restore(previous);
        } else {
            // The previous record was unreadable as values; dropping the new
            // values from memory would read as "off", so a stored marker that
            // can never parse is left instead and the pass stays fail-closed.
            backing.restore(new String[]{"", null});
        }
        return false;
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
