package com.example.lockdowndpc.policy;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.app.job.JobInfo;
import android.app.job.JobScheduler;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Log;

import com.example.lockdowndpc.receivers.PolicyRefreshReceiver;

import java.time.Duration;
import java.time.Instant;

/**
 * The boundary alarm for night and work hours: a wall-clock alarm at the next
 * window start or end, re-armed by every policy pass and cancelled by a pause,
 * with a catch-up check behind it.
 *
 * <p>Which API, and why. On Android 12 (API 31) and newer, both
 * {@code setExactAndAllowWhileIdle} and {@code setAlarmClock} require the exact
 * alarm permission; {@code setAlarmClock} is not a way around it, and Device
 * Owner status grants no exemption. The app declares
 * {@code SCHEDULE_EXACT_ALARM}, which Android 12 and 13 grant by default and
 * Android 14 and newer deny by default to a fresh install, leaving it to an
 * administrator in Settings (Alarms and reminders). {@code USE_EXACT_ALARM} is
 * deliberately not declared: it is reserved for alarm clock and calendar apps.
 * So:
 * Every boundary arms two alarms, and the first to fire runs the pass, which
 * re-arms both:
 * <ul>
 *   <li>the primary: {@code setExactAndAllowWhileIdle} when exact alarms are
 *       permitted (always below API 31, otherwise when
 *       {@link AlarmManager#canScheduleExactAlarms()} is true), which fires on
 *       time even in Doze; otherwise {@code setWindow}, which needs no
 *       permission and fires shortly after the boundary while the device is
 *       awake but waits in Doze;</li>
 *   <li>the fallback, always: {@code setAndAllowWhileIdle}, which needs no
 *       permission and fires in Doze, but inexactly. Android drops exact
 *       alarms without any broadcast when the permission is revoked, so the
 *       fallback is never cancelled for an exact primary: after a revocation
 *       it is what is left. Plain {@code set} is not used: it waits in Doze.</li>
 * </ul>
 *
 * <p><b>Accepted limit.</b> Without exact alarm access Android decides when an
 * inexact alarm fires: it may be minutes, or in deep Doze up to about an hour,
 * after the boundary, and OEM battery managers may delay it further. The
 * console states the exact-alarm state and points the administrator to Alarms
 * and reminders; it promises no bound. Cheap checks narrow the gap while a
 * schedule is enforcing: the screen turning on or the device being unlocked
 * (registered by the device admin service while the process runs), a periodic
 * {@link ScheduleSweepJobService} job every fifteen minutes (JobScheduler's
 * minimum; Doze defers it to maintenance windows), and a one-off retry job
 * with backoff after a pass that was not verified. Each asks for a full pass
 * only when {@link ScheduleCatchUp#due} says so. A permission revoked between
 * the check and the call falls back to {@code setWindow} instead of crashing
 * the pass. {@code RTC_WAKEUP} follows the wall clock, and a clock or timezone
 * change also triggers a full pass that re-arms it.
 */
public final class ScheduleAlarm {

    /** The broadcast the boundary alarm sends to {@link PolicyRefreshReceiver}. */
    public static final String ACTION_BOUNDARY = "com.example.lockdowndpc.action.SCHEDULE_BOUNDARY";

    static final long INEXACT_WINDOW_MILLIS = 10L * 60L * 1_000L;
    private static final String TAG = "ScheduleAlarm";
    private static final int REQUEST_CODE = 0x5343;
    private static final int IDLE_REQUEST_CODE = 0x5344;
    static final int SWEEP_JOB_ID = 0x53434857;
    static final int RETRY_JOB_ID = 0x53435259;
    private static final long SWEEP_PERIOD_MILLIS = 15L * 60L * 1_000L;

    private ScheduleAlarm() {}

    /**
     * Arms the boundary and the periodic sweep; throws when Android offers no
     * alarm service or refuses the sweep job (after arming the alarms).
     */
    static void arm(Context context, Instant at) {
        AlarmManager alarms = context.getSystemService(AlarmManager.class);
        if (alarms == null) {
            throw new IllegalStateException("alarm-manager-unavailable");
        }
        long trigger = at.toEpochMilli();
        // The fallback first, so it is armed whatever happens to the primary.
        alarms.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, trigger, operation(context, IDLE_REQUEST_CODE));
        boolean exact = false;
        if (exactPermitted(alarms)) {
            try {
                alarms.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, trigger, operation(context, REQUEST_CODE));
                exact = true;
            } catch (SecurityException revoked) {
                // Revoked since the check: the inexact primary below.
            }
        }
        if (!exact) {
            alarms.setWindow(AlarmManager.RTC_WAKEUP, trigger, INEXACT_WINDOW_MILLIS,
                    operation(context, REQUEST_CODE));
        }
        armSweep(context);
    }

    /** Cancels an armed boundary, the sweep and a pending retry; a device that never armed one is left untouched. */
    static void cancel(Context context) {
        AlarmManager alarms = context.getSystemService(AlarmManager.class);
        cancelAlarm(context, alarms, REQUEST_CODE);
        cancelAlarm(context, alarms, IDLE_REQUEST_CODE);
        JobScheduler scheduler = context.getSystemService(JobScheduler.class);
        if (scheduler != null) {
            scheduler.cancel(SWEEP_JOB_ID);
            scheduler.cancel(RETRY_JOB_ID);
        }
    }

    /**
     * Schedules the one-off retry of a pass that was not verified, replacing a
     * pending one. It runs {@link #catchUp} like the sweep, which respects the
     * stored backoff. Throws when Android refuses the job.
     */
    static void scheduleRetry(Context context, Duration delay) {
        JobScheduler scheduler = context.getSystemService(JobScheduler.class);
        if (scheduler == null) {
            throw new IllegalStateException("schedule-retry-unavailable");
        }
        JobInfo retry = new JobInfo.Builder(RETRY_JOB_ID,
                new ComponentName(context, ScheduleSweepJobService.class))
                .setMinimumLatency(delay.toMillis())
                .setPersisted(true)
                .build();
        if (scheduler.schedule(retry) != JobScheduler.RESULT_SUCCESS) {
            throw new IllegalStateException("schedule-retry-refused");
        }
    }

    /** Cancels a pending retry after a verified pass. */
    static void cancelRetry(Context context) {
        JobScheduler scheduler = context.getSystemService(JobScheduler.class);
        if (scheduler != null) {
            scheduler.cancel(RETRY_JOB_ID);
        }
    }

    /**
     * The catch-up check behind the boundary alarm, for the screen and unlock
     * broadcasts and the sweep and retry jobs. Run it on the policy thread: it
     * reads the stored schedule and queues a full pass only when the last pass
     * did not verify or a boundary passed since the last verified one, and no
     * retry backoff is pending.
     *
     * @param completion runs when a queued pass ends; never when nothing was queued
     * @return whether a pass was queued
     */
    public static boolean catchUp(Context context, String trigger, Runnable completion) {
        Context app = context.getApplicationContext();
        try {
            if (AllowedAppsStore.isProtectionEnabled(app)
                    && ScheduleCatchUp.due(ScheduleStore.read(app), ScheduleStore.catchUpState(app), Instant.now())) {
                PolicyReconciliationCoordinator.reconcileAsync(app, "schedule-catch-up:" + trigger, completion);
                return true;
            }
        } catch (RuntimeException exception) {
            // The next trigger, the alarm or the sweep checks again.
            Log.e(TAG, "Schedule catch-up check failed", exception);
        }
        return false;
    }

    private static void armSweep(Context context) {
        JobScheduler scheduler = context.getSystemService(JobScheduler.class);
        if (scheduler == null) {
            throw new IllegalStateException("schedule-sweep-unavailable");
        }
        if (scheduler.getPendingJob(SWEEP_JOB_ID) != null) {
            return;
        }
        JobInfo sweep = new JobInfo.Builder(SWEEP_JOB_ID,
                new ComponentName(context, ScheduleSweepJobService.class))
                .setPeriodic(SWEEP_PERIOD_MILLIS)
                // Survives a reboot alongside the boot pass.
                .setPersisted(true)
                .build();
        // schedule() reports a refusal as RESULT_FAILURE rather than throwing.
        if (scheduler.schedule(sweep) != JobScheduler.RESULT_SUCCESS) {
            throw new IllegalStateException("schedule-sweep-refused");
        }
    }

    private static void cancelAlarm(Context context, AlarmManager alarms, int requestCode) {
        PendingIntent existing = PendingIntent.getBroadcast(context, requestCode, intent(context),
                PendingIntent.FLAG_NO_CREATE | PendingIntent.FLAG_IMMUTABLE);
        if (alarms != null && existing != null) {
            alarms.cancel(existing);
            existing.cancel();
        }
    }

    /** Whether boundaries are exact on this device right now; the console may show it. */
    public static boolean exactPermitted(Context context) {
        AlarmManager alarms = context.getSystemService(AlarmManager.class);
        return alarms != null && exactPermitted(alarms);
    }

    private static boolean exactPermitted(AlarmManager alarms) {
        return Build.VERSION.SDK_INT < Build.VERSION_CODES.S || alarms.canScheduleExactAlarms();
    }

    private static PendingIntent operation(Context context, int requestCode) {
        return PendingIntent.getBroadcast(context, requestCode, intent(context),
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
    }

    private static Intent intent(Context context) {
        return new Intent(context, PolicyRefreshReceiver.class).setAction(ACTION_BOUNDARY);
    }
}
