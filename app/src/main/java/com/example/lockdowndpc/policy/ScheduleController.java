package com.example.lockdowndpc.policy;

import android.content.Context;

import com.example.lockdowndpc.security.AdminSession;

import java.util.function.UnaryOperator;

/**
 * Saves night and work hours changes and enforces them at once.
 *
 * <p>Everything runs on the single policy thread, so a change can never
 * interleave with a reconciliation pass that is reading the schedule. The
 * session rule lives in {@link ScheduleChange}: tightening is saved without a
 * session, loosening only while {@link AdminSession#isUnlocked()} is true at the
 * write itself. A saved change is followed by a full policy pass when protection
 * is active; while protection is paused nothing is enforced, so no pass runs.
 */
public final class ScheduleController {

    /**
     * @param outcome what the write boundary decided
     * @param pass    the policy pass that enforced the change, or {@code null}
     *                when nothing was saved or protection is paused
     */
    public record Result(ScheduleChange.Outcome outcome, LockdownPolicyController.PolicyResult pass) {}

    private ScheduleController() {}

    /** The console's single switch: both windows on, or both off. */
    public static Result setEnabled(Context context, boolean enabled) {
        return update(context, current -> current.withWindowsEnabled(enabled, ScheduleStore.deviceZone()));
    }

    /** Applies {@code change} to the stored settings, read on the policy thread. */
    public static Result update(Context context, UnaryOperator<ScheduleSettings> change) {
        Context app = context.getApplicationContext();
        return PolicyReconciliationCoordinator.callOnPolicyThread(() -> {
            ScheduleSettings next = change.apply(ScheduleStore.read(app));
            ScheduleChange.Outcome outcome = ScheduleChange.apply(next, new ScheduleChange.Gateway() {
                @Override
                public ScheduleSettings current() {
                    return ScheduleStore.read(app);
                }

                @Override
                public boolean sessionUnlocked() {
                    return AdminSession.isUnlocked();
                }

                @Override
                public boolean commit(ScheduleSettings settings) {
                    return ScheduleStore.write(app, settings);
                }

                @Override
                public void audit(String line) {
                    AuditLog.append(app, AuditEvent.SCHEDULE_CHANGED, line);
                }
            });
            if (outcome.status() != ScheduleChange.Status.SAVED) {
                return new Result(outcome, null);
            }
            AdminSession.extend();
            LockdownPolicyController.PolicyResult pass = AllowedAppsStore.isProtectionEnabled(app)
                    ? LockdownPolicyController.apply(app)
                    : null;
            return new Result(outcome, pass);
        });
    }
}
