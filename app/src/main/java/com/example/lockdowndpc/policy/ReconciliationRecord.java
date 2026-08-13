package com.example.lockdowndpc.policy;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * How the last complete reconciliation pass ended.
 *
 * <p>Reconciliation is what keeps a managed device honest between administrator
 * visits: it re-applies and re-verifies the policy after a reboot, an update or
 * a package install. Until this record existed, its result lived only in
 * {@code Log} and in the operator-facing audit prose, so nothing the device
 * could read afterwards knew whether the last unattended pass had actually
 * succeeded — and the health report had to describe every device, however
 * healthy, as unverified.
 *
 * <p>The trigger is a short machine token such as {@code
 * android.intent.action.BOOT_COMPLETED}. The detail is free text from a failure
 * path, kept for the local report and never exported.
 */
public final class ReconciliationRecord {

    private static final String PREFS = "policy_reconciliation";
    private static final String KEY_OUTCOME = "outcome";
    private static final String KEY_AT = "at_millis";
    private static final String KEY_TRIGGER = "trigger";
    private static final String KEY_DETAIL = "detail";

    private ReconciliationRecord() {}

    /** The vocabulary the health assessor reads. */
    public enum Outcome {
        /** No pass has completed since this record existed. */
        NEVER_RUN,
        /** The pass applied the policy and read every part of it back. */
        VERIFIED,
        /** The pass ran and the device disagreed with what was asked for. */
        FAILED,
        /** The pass threw. Distinguished from a failure: nothing is known. */
        CRASHED
    }

    /** One completed pass, or a {@link Outcome#NEVER_RUN} record when there is none. */
    public record Snapshot(Outcome outcome, long atMillis, String trigger, String detail) {
        public Snapshot {
            outcome = outcome == null ? Outcome.NEVER_RUN : outcome;
            atMillis = Math.max(0L, atMillis);
            trigger = trigger == null ? "" : trigger;
            detail = detail == null ? "" : detail;
        }
    }

    public static synchronized void record(
            Context context,
            Outcome outcome,
            String trigger,
            String detail
    ) {
        prefs(context).edit()
                .putString(KEY_OUTCOME, outcome.name())
                .putLong(KEY_AT, System.currentTimeMillis())
                .putString(KEY_TRIGGER, trigger == null ? "" : trigger)
                // Truncated rather than stored whole: a failure summary is a
                // list of restriction keys, and anything longer is a sign
                // something unexpected was interpolated into it.
                .putString(KEY_DETAIL, detail == null ? "" : trim(detail))
                .commit();
    }

    /**
     * The stored record.
     *
     * <p>An unreadable or unrecognised value reads as {@link Outcome#CRASHED}
     * rather than as a pass: a record we cannot parse is not evidence that a
     * device is healthy.
     */
    public static Snapshot read(Context context) {
        SharedPreferences preferences = prefs(context);
        String stored = preferences.getString(KEY_OUTCOME, null);
        if (stored == null) {
            return new Snapshot(Outcome.NEVER_RUN, 0L, "", "");
        }
        Outcome outcome;
        try {
            outcome = Outcome.valueOf(stored);
        } catch (IllegalArgumentException ignored) {
            outcome = Outcome.CRASHED;
        }
        return new Snapshot(
                outcome,
                preferences.getLong(KEY_AT, 0L),
                preferences.getString(KEY_TRIGGER, ""),
                preferences.getString(KEY_DETAIL, ""));
    }

    private static String trim(String detail) {
        return detail.length() <= 200 ? detail : detail.substring(0, 200);
    }

    private static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }
}
