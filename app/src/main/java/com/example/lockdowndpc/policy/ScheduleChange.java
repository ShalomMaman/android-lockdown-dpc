package com.example.lockdowndpc.policy;

/**
 * The write boundary for night and work hours, independent of Android.
 *
 * <p>A tightening (turning a window on, wider hours, more days, a smaller
 * allowlist) is saved at once without an administrator session: it can only
 * restrict the device further. A loosening needs a live administrator session,
 * checked here at the moment of the write rather than when a screen opened, and
 * every saved change is audited. A record that is currently unreadable is
 * compared as the fail-closed default schedule it is enforced as, and any
 * readable replacement that is not looser than that may repair it.
 *
 * <p>An enforcing schedule is saved only while the device clock is locked
 * ({@link ScheduleClock}): on Android 8.0/8.1 that means Android confirmed
 * automatic date and time is required. Otherwise nothing is written.
 */
public final class ScheduleChange {

    public enum Status {
        /** Nothing to write. */
        UNCHANGED,
        /** Saved and audited. */
        SAVED,
        /** A loosening without a live administrator session; nothing written. */
        SESSION_REQUIRED,
        /** The store did not persist it; the previous record stays in force. */
        NOT_SAVED,
        /** An enforcing schedule while the device clock is not locked; nothing written. */
        CLOCK_UNLOCKED
    }

    public record Outcome(Status status, SchedulePolicy.Change change) {}

    /** The store, the session and the audit log. */
    public interface Gateway {
        ScheduleSettings current();

        /** Re-read at the write boundary. */
        boolean sessionUnlocked();

        /**
         * Locks the device clock where that is needed and reports whether it
         * is locked; asked only before an enforcing schedule is written.
         */
        boolean clockLocked();

        /** @return whether the settings were persisted */
        boolean commit(ScheduleSettings settings);

        void audit(String line);
    }

    private ScheduleChange() {}

    public static Outcome apply(ScheduleSettings next, Gateway gateway) {
        if (next == null || next.unreadable()) {
            throw new IllegalArgumentException("Only a readable schedule can be saved");
        }
        ScheduleSettings before = gateway.current();
        SchedulePolicy.Change change = ScheduleSettings.classify(before, next);
        if (change == SchedulePolicy.Change.UNCHANGED && !before.unreadable() && before.equals(next)) {
            return new Outcome(Status.UNCHANGED, change);
        }
        if (change == SchedulePolicy.Change.LOOSEN && !gateway.sessionUnlocked()) {
            return new Outcome(Status.SESSION_REQUIRED, change);
        }
        if (next.enforcing() && !gateway.clockLocked()) {
            return new Outcome(Status.CLOCK_UNLOCKED, change);
        }
        if (!gateway.commit(next)) {
            return new Outcome(Status.NOT_SAVED, change);
        }
        String verb = switch (change) {
            case LOOSEN -> "loosened";
            case TIGHTEN -> "tightened";
            case UNCHANGED -> before.unreadable() ? "repaired" : "rewritten";
        };
        gateway.audit("schedule:" + verb + " " + next.auditSummary()
                + (before.unreadable() ? " (was unreadable)" : ""));
        return new Outcome(Status.SAVED, change);
    }
}
