package com.example.lockdowndpc.maintenance;

import android.app.admin.DevicePolicyManager;
import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.content.ComponentName;
import android.content.Context;
import android.os.Build;
import android.util.Log;

import com.example.lockdowndpc.R;
import com.example.lockdowndpc.admin.LockdownAdminReceiver;
import com.example.lockdowndpc.kiosk.BidiText;
import com.example.lockdowndpc.maintenance.MaintenanceCoordinator.MaintenanceOutcome;
import com.example.lockdowndpc.maintenance.MaintenanceStateMachine.CloseReason;
import com.example.lockdowndpc.maintenance.MaintenanceStateMachine.OpenRequest;
import com.example.lockdowndpc.policy.AuditLog;
import com.example.lockdowndpc.policy.SystemPolicyDeviceGateway;
import com.example.lockdowndpc.policy.SystemPolicyStore;

/**
 * What closes a maintenance window when nobody is looking.
 *
 * <h2>Why this class exists</h2>
 *
 * <p>A window that is only enforced while its screen is composed is not a timed
 * exception; it is an open door with a label on it. A technician opens a
 * four-hour break-glass window, presses back, the screen locks and the process
 * is killed — and without something outside the UI, {@code
 * DISALLOW_DEBUGGING_FEATURES} stays cleared indefinitely, because the code that
 * would have noticed the deadline is gone.
 *
 * <p>So expiry is armed on the {@link JobScheduler} the moment a window is
 * written, a safety-net pass runs periodically in case the exact job is dropped,
 * and {@code PolicyRefreshReceiver} calls {@link #refresh} on every boot and
 * package replacement. All four paths converge on the same
 * {@link MaintenanceCoordinator#refresh} call, so the rules stay in one tested
 * place and this class only decides <em>when</em> to ask.
 *
 * <h2>Write-ahead, so a crash cannot lose the record</h2>
 *
 * <p>{@link #open} marks a restore as owed <em>before</em> the first
 * {@code DevicePolicyManager} call, not after the window is persisted. The
 * dangerous gap is between relaxing a restriction and recording that it was
 * relaxed: a process kill in that window would otherwise leave a device with
 * debugging enabled and nothing on disk saying so. Marking the intent first
 * costs, at worst, one redundant re-apply of the base policy; skipping it costs
 * a device that stays open forever.
 */
public final class MaintenanceGuard {

    private static final String TAG = "MaintenanceGuard";

    /** Fires once, at the deadline of the window that is currently open. */
    private static final int EXPIRY_JOB_ID = 0x4D41494e;

    /**
     * Fires regularly whether or not a window is open.
     *
     * <p>The exact job is the primary mechanism; this is the belt to its braces.
     * An OEM that drops a pending job, an aggressive battery saver, or a job lost
     * to an upgrade would otherwise leave the deadline unobserved, so a
     * fifteen-minute sweep re-reads the clocks and closes anything that has
     * lapsed. Fifteen minutes is the platform's own minimum period.
     */
    private static final int SWEEP_JOB_ID = 0x4D41494f;

    private static final long SWEEP_PERIOD_MILLIS = 15L * 60L * 1_000L;

    private MaintenanceGuard() {}

    /**
     * Re-checks the stored window and closes it if it is no longer legitimate.
     *
     * <p>Safe to call from anywhere that is not the main thread: on a device with
     * nothing open it reads one preference file and returns.
     *
     * @return the outcome, or {@code null} when this build is not the Device
     *         Owner and therefore cannot relax or restore anything
     */
    public static synchronized MaintenanceOutcome refresh(Context context) {
        Context appContext = context.getApplicationContext();
        MaintenanceCoordinator coordinator = coordinatorFor(appContext);
        if (coordinator == null) {
            return null;
        }
        MaintenanceWindow stored = MaintenanceStore.readWindow(appContext);
        MaintenanceOutcome outcome;
        if (stored == null && MaintenanceStore.restorePending(appContext)) {
            // Either the record was unusable, or an earlier restore was never
            // proved, or a crash happened between relaxing the device and
            // recording it. All three mean the same thing: something may still
            // be relaxed, so re-apply the base policy and read it back.
            outcome = coordinator.restore(null, CloseReason.UNREADABLE_RECORD);
        } else {
            outcome = coordinator.refresh(stored);
        }
        return record(appContext, outcome);
    }

    /**
     * Opens a window, marking the intent to relax before anything is sent.
     *
     * @param current the window already open, or {@code null}
     */
    public static synchronized MaintenanceOutcome open(
            Context context,
            MaintenanceCoordinator coordinator,
            MaintenanceWindow current,
            OpenRequest request
    ) {
        Context appContext = context.getApplicationContext();
        MaintenanceStore.markRestorePending(appContext);
        MaintenanceOutcome outcome = coordinator.open(current, request);
        if (outcome.status() == MaintenanceCoordinator.MaintenanceStatus.REFUSED
                && !outcome.windowMustBeStored()) {
            // A refusal is decided before anything reaches the device, so there
            // is nothing owed and the flag would only cause a pointless re-apply.
            MaintenanceStore.clearRestorePending(appContext);
        }
        return record(appContext, outcome);
    }

    /** Ends the window by hand and reads the restore back. */
    public static synchronized MaintenanceOutcome cancel(
            Context context,
            MaintenanceCoordinator coordinator,
            MaintenanceWindow current
    ) {
        return record(context.getApplicationContext(), coordinator.cancel(current));
    }

    /**
     * Persists an outcome, publishes its evidence, audits it and re-arms the
     * timers.
     *
     * <p>Every path that touches a window goes through here, including the
     * console's, so the storage rule, the evidence rule and the audit rule cannot
     * drift between the screen and the background.
     */
    public static synchronized MaintenanceOutcome record(
            Context context,
            MaintenanceOutcome outcome
    ) {
        Context appContext = context.getApplicationContext();
        MaintenanceStore.apply(appContext, outcome);
        // The console's system policy rows read SystemPolicyStore. Without this,
        // a control that maintenance has just cleared on the device would keep
        // rendering yesterday's verified "applied", which is exactly the kind of
        // stale claim the read-back rule exists to prevent.
        if (!outcome.report().statuses().isEmpty()) {
            SystemPolicyStore.saveReport(appContext, outcome.report());
        }
        auditFrom(appContext, outcome);
        arm(appContext, outcome.windowOpen() ? outcome.window() : null);
        return outcome;
    }

    /**
     * Arms the deadline for {@code window}, or stands the timers down when there
     * is nothing open and nothing owed.
     */
    public static void arm(Context context, MaintenanceWindow window) {
        Context appContext = context.getApplicationContext();
        JobScheduler scheduler = appContext.getSystemService(JobScheduler.class);
        if (scheduler == null) {
            Log.e(TAG, "No JobScheduler: a maintenance window cannot be closed automatically");
            return;
        }
        ComponentName component = new ComponentName(appContext, MaintenanceGuardJobService.class);
        boolean somethingOwed = window != null || MaintenanceStore.restorePending(appContext);

        try {
            scheduler.cancel(EXPIRY_JOB_ID);
            if (window != null) {
                long remaining = Math.max(
                        0L, window.remainingMillis(MaintenanceStore.deviceClock()
                                .elapsedSinceBootMillis()));
                JobInfo.Builder expiry = new JobInfo.Builder(EXPIRY_JOB_ID, component)
                        .setMinimumLatency(remaining)
                        // A short window rather than "as late as the platform
                        // likes": the deadline is the point of the feature.
                        .setOverrideDeadline(remaining + SWEEP_PERIOD_MILLIS);
                scheduler.schedule(expiry.build());
            }

            if (somethingOwed) {
                if (scheduler.getPendingJob(SWEEP_JOB_ID) == null) {
                    JobInfo.Builder sweep = new JobInfo.Builder(SWEEP_JOB_ID, component)
                            .setPeriodic(SWEEP_PERIOD_MILLIS)
                            // Survives a reboot so a window opened before a
                            // restart is still swept afterwards, alongside the
                            // boot pass PolicyRefreshReceiver runs.
                            .setPersisted(true);
                    scheduler.schedule(sweep.build());
                }
            } else {
                scheduler.cancel(SWEEP_JOB_ID);
            }
        } catch (RuntimeException exception) {
            // Scheduling is the safety net, not the rule. Losing it must not take
            // the console down with it, but it must be visible.
            Log.e(TAG, "Could not arm the maintenance timers", exception);
        }
    }

    /**
     * The coordinator for this device, or {@code null} when this build is not the
     * Device Owner and therefore cannot relax or restore anything.
     */
    public static MaintenanceCoordinator coordinatorFor(Context context) {
        DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
        if (dpm == null || !dpm.isDeviceOwnerApp(context.getPackageName())) {
            return null;
        }
        return new MaintenanceCoordinator(
                Build.VERSION.SDK_INT,
                SystemPolicyStore.effectiveProfile(context),
                SystemPolicyStore.explicitChoices(context),
                new SystemPolicyDeviceGateway(dpm, LockdownAdminReceiver.componentName(context)),
                MaintenanceStore.deviceClock());
    }

    /**
     * The audit line for an outcome that changed something.
     *
     * <p>A liveness pass that changed nothing is not an administrator action, and
     * logging one every fifteen minutes would push real events out of a
     * fifty-entry log.
     */
    private static void auditFrom(Context context, MaintenanceOutcome outcome) {
        int template;
        switch (outcome.phase()) {
            case OPEN:
                if (outcome.status() == MaintenanceCoordinator.MaintenanceStatus.APPLIED) {
                    template = R.string.maint_audit_opened;
                } else if (outcome.restoreVerified()
                        || outcome.status() == MaintenanceCoordinator.MaintenanceStatus.REFUSED) {
                    template = R.string.maint_audit_open_failed;
                } else {
                    template = R.string.maint_audit_restore_failed;
                }
                break;
            case RESTORE:
                template = outcome.restoreVerified()
                        ? R.string.maint_audit_closed
                        : R.string.maint_audit_restore_failed;
                break;
            default:
                return;
        }
        if (outcome.closeReason() != null) {
            AuditLog.append(
                    context,
                    context.getString(MaintenanceLabels.closeAudit(outcome.closeReason())));
        }
        // The summary is Latin machine tokens; isolating it stops them dragging
        // their punctuation to the wrong side of a Hebrew audit line.
        AuditLog.append(
                context,
                context.getString(template, BidiText.bidiIsolated(outcome.auditSummary())));
    }
}
