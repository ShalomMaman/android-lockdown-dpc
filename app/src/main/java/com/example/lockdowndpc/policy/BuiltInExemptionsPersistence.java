package com.example.lockdowndpc.policy;

/**
 * Write rule for the stored exemptions, independent of Android.
 *
 * <p>Android's {@code SharedPreferences.commit()} updates the in-memory map
 * before it writes to disk, so a failed commit is still visible to every later
 * reader in the process, and any later commit to the same file can make it
 * durable. Therefore:
 * <ul>
 *   <li>the exemptions have a preference file of their own, written only here;</li>
 *   <li>after a failed commit the previous <em>raw</em> stored values are
 *       written back exactly — never a re-serialised parse and never with a
 *       marker added, so an unreadable record stays unreadable — restoring the
 *       in-memory map whatever the disk does;</li>
 *   <li>and an in-process latch makes every pass see no exemptions at all
 *       until a later commit succeeds. The next edit still starts from the
 *       stored record ({@link #record}).</li>
 * </ul>
 *
 * <p>Every reader gets its answer from {@link Backing#read}, which parses with
 * {@link BuiltInBlockExemptions#parseRecord} — the one parser.
 */
final class BuiltInExemptionsPersistence {

    /** The raw preference file. */
    interface Backing {
        /** The record, parsed by {@link BuiltInBlockExemptions#parseRecord}. */
        BuiltInBlockExemptions.Record read();

        /** Android semantics: memory is updated even when this returns {@code false}. */
        boolean commit(BuiltInBlockExemptions.Settings settings);

        /** The raw stored values, exactly as found, for a rollback. */
        Object snapshot();

        /** Writes {@code snapshot} back exactly; memory is restored whatever the disk does. */
        void restore(Object snapshot);
    }

    private final Backing backing;
    private volatile boolean untrusted;

    BuiltInExemptionsPersistence(Backing backing) {
        this.backing = backing;
    }

    /** The stored record as it is; an unreadable or failing read is unreadable. */
    BuiltInBlockExemptions.Record record() {
        try {
            BuiltInBlockExemptions.Record record = backing.read();
            return record == null ? BuiltInBlockExemptions.Record.UNREADABLE : record;
        } catch (RuntimeException exception) {
            return BuiltInBlockExemptions.Record.UNREADABLE;
        }
    }

    /** What a policy pass enforces: none while untrusted or unreadable. */
    BuiltInBlockExemptions.Settings read() {
        return untrusted ? BuiltInBlockExemptions.Settings.NONE : record().enforced();
    }

    /** @return whether {@code settings} was persisted; {@code false} changes nothing visible */
    synchronized boolean write(BuiltInBlockExemptions.Settings settings) {
        Object previous = backing.snapshot();
        if (backing.commit(settings)) {
            untrusted = false;
            return true;
        }
        untrusted = true;
        backing.restore(previous);
        return false;
    }

    boolean untrusted() {
        return untrusted;
    }
}
