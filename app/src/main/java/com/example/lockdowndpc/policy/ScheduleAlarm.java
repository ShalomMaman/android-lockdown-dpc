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
 * <ul>
 *   <li>when exact alarms are permitted (always below API 31, otherwise when
 *       {@link AlarmManager#canScheduleExactAlarms()} is true) the boundary uses
 *       {@code setExactAndAllowWhileIdle}, which fires on time even in Doze;</li>
 *   <li>otherwise it arms two alarms for the same boundary, and the first to
 *       fire runs the pass, which re-arms both: {@code setWindow} with a
 *       {@link #INEXACT_WINDOW_MILLIS} window, which needs no permission and
 *       fires within ten minutes of the boundary while the device is awake but
 *       waits in Doze; and {@code setAndAllowWhileIdle}, which also needs no
 *       permission and does fire in Doze, but inexactly: Android may deliver a
 *       one-time inexact alarm up to an hour after its time, and while idle it
 *       allows only a limited number of such alarms per app (one boundary
 *       spends one). Plain {@code set} is not used: it waits in Doze too.</li>
 * </ul>
 * Two cheap checks back the alarm up while a schedule is enforcing, because an
 * OEM may drop alarms: the screen turning on or the device being unlocked
 * (registered by the device admin service while the process runs), and a
 * periodic {@link ScheduleSweepJobService} job every fifteen minutes (JobScheduler's
 * minimum; Doze defers it to maintenance windows). Each asks for a full pass
 * only when {@link ScheduleCatchUp#due} finds a boundary passed since the last
 * pass. A permission revoked between the check and the call falls back to the
 * inexact alarms instead of crashing the pass. {@code RTC_WAKEUP} follows the
 * wall clock, and a clock or timezone change also triggers a full pass that
 * re-arms it.
 */
public final class ScheduleAlarm {

    /** The broadcast the boundary alarm sends to {@link PolicyRefreshReceiver}. */
    public static final String ACTION_BOUNDARY = "com.example.lockdowndpc.action.SCHEDULE_BOUNDARY";

    static final long INEXACT_WINDOW_MILLIS = 10L * 60L * 1_000L;
    private static final String TAG = "ScheduleAlarm";
    private static final int REQUEST_CODE = 0x5343;
    private static final int IDLE_REQUEST_CODE = 0x5344;
    private static final int SWEEP_JOB_ID = 0x53434857;
    private static final long SWEEP_PERIOD_MILLIS = 15L * 60L * 1_000L;

    private ScheduleAlarm() {}

    /**
     * Arms the boundary and the periodic sweep; throws when Android offers no
     * alarm service or refuses the sweep job (after arming the alarm).
     */
    static void arm(Context context, Instant at) {
        AlarmManager alarms = context.getSystemService(AlarmManager.class);
        if (alarms == null) {
            throw new IllegalStateException("alarm-manager-unavailable");
        }
        long trigger = at.toEpochMilli();
        boolean exact = false;
        if (exactPermitted(alarms)) {
            try {
                alarms.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, trigger, operation(context, REQUEST_CODE));
                exact = true;
            } catch (SecurityException revoked) {
                // Revoked since the check: fall through to the inexact alarms.
            }
        }
        if (exact) {
            cancelAlarm(context, alarms, IDLE_REQUEST_CODE);
        } else {
            alarms.setWindow(AlarmManager.RTC_WAKEUP, trigger, INEXACT_WINDOW_MILLIS,
                    operation(context, REQUEST_CODE));
            alarms.setAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, trigger, operation(context, IDLE_REQUEST_CODE));
        }
        armSweep(context);
    }

    /** Cancels an armed boundary and the sweep; a device that never armed one is left untouched. */
    static void cancel(Context context) {
        AlarmManager alarms = context.getSystemService(AlarmManager.class);
        cancelAlarm(context, alarms, REQUEST_CODE);
        cancelAlarm(context, alarms, IDLE_REQUEST_CODE);
        JobScheduler scheduler = context.getSystemService(JobScheduler.class);
        if (scheduler != null) {
            scheduler.cancel(SWEEP_JOB_ID);
        }
    }

    /**
     * The catch-up check behind the boundary alarm, for the screen and unlock
     * broadcasts and the sweep job. Run it on the policy thread: it reads the
     * stored schedule and queues a full pass only when a boundary was missed.
     *
     * @param completion runs when a queued pass ends; never when nothing was queued
     * @return whether a pass was queued
     */
    public static boolean catchUp(Context context, String trigger, Runnable completion) {
        Context app = context.getApplicationContext();
        try {
            if (AllowedAppsStore.isProtectionEnabled(app)
                    && ScheduleCatchUp.due(ScheduleStore.read(app), ScheduleStore.lastReconciled(app), Instant.now())) {
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
