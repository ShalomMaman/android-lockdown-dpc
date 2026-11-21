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
 *   <li>after a failed commit the previous values are written back, which
 *       restores the in-memory map whatever the disk does;</li>
 *   <li>and an in-process latch makes every pass see no exemptions at all
 *       until a later commit succeeds, so it hides everything the exemptions
 *       would have shown. The next edit still starts from the last durable
 *       decision ({@link #readForEdit}).</li>
 * </ul>
 */
final class BuiltInExemptionsPersistence {

    /** The raw preference file. */
    interface Backing {
        BuiltInBlockExemptions.Settings read();

        /** Android semantics: memory is updated even when this returns {@code false}. */
        boolean commit(BuiltInBlockExemptions.Settings settings);
    }

    private final Backing backing;
    private volatile boolean untrusted;

    BuiltInExemptionsPersistence(Backing backing) {
        this.backing = backing;
    }

    /** The stored decision, or none while untrusted or unreadable. */
    BuiltInBlockExemptions.Settings read() {
        if (untrusted) {
            return BuiltInBlockExemptions.Settings.NONE;
        }
        try {
            return backing.read();
        } catch (RuntimeException exception) {
            return BuiltInBlockExemptions.Settings.NONE;
        }
    }

    /**
     * The baseline for the next edit: the last durable decision, whatever the
     * latch says. After a failed write the previous values were written back,
     * so this is the decision as it stood before that write. Editing from it
     * means a retry never drops earlier approvals.
     */
    BuiltInBlockExemptions.Settings readForEdit() {
        try {
            return backing.read();
        } catch (RuntimeException exception) {
            return BuiltInBlockExemptions.Settings.NONE;
        }
    }

    /** @return whether {@code settings} was persisted; {@code false} changes nothing visible */
    synchronized boolean write(BuiltInBlockExemptions.Settings settings) {
        BuiltInBlockExemptions.Settings previous;
        try {
            previous = backing.read();
        } catch (RuntimeException exception) {
            previous = BuiltInBlockExemptions.Settings.NONE;
        }
        if (backing.commit(settings)) {
            untrusted = false;
            return true;
        }
        untrusted = true;
        // Restores the in-memory map; whether the disk accepts it does not
        // matter while the latch hides every exemption.
        backing.commit(previous);
        return false;
    }

    boolean untrusted() {
        return untrusted;
    }
}
