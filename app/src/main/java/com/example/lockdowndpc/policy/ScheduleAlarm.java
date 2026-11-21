package com.example.lockdowndpc.policy;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

import com.example.lockdowndpc.receivers.PolicyRefreshReceiver;

import java.time.Instant;

/**
 * The boundary alarm for night and work hours: one wall-clock alarm at the next
 * window start or end, re-armed by every policy pass and cancelled by a pause.
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
 *   <li>otherwise it uses {@code setWindow} with a {@link #INEXACT_WINDOW_MILLIS}
 *       window, which needs no permission and fires within ten minutes of the
 *       boundary while the device is awake. In Doze it waits for the next
 *       maintenance window or the moment the screen turns on, which is when the
 *       user could first notice the difference. Plain {@code set} is not used:
 *       Android may defer it by up to three quarters of the time to the trigger,
 *       which is hours here.</li>
 * </ul>
 * A permission revoked between the check and the call falls back to the window
 * instead of crashing the pass. {@code RTC_WAKEUP} follows the wall clock, and a
 * clock or timezone change also triggers a full pass that re-arms it.
 */
public final class ScheduleAlarm {

    /** The broadcast the boundary alarm sends to {@link PolicyRefreshReceiver}. */
    public static final String ACTION_BOUNDARY = "com.example.lockdowndpc.action.SCHEDULE_BOUNDARY";

    static final long INEXACT_WINDOW_MILLIS = 10L * 60L * 1_000L;
    private static final int REQUEST_CODE = 0x5343;

    private ScheduleAlarm() {}

    /** Arms the boundary; throws when Android offers no alarm service. */
    static void arm(Context context, Instant at) {
        AlarmManager alarms = context.getSystemService(AlarmManager.class);
        if (alarms == null) {
            throw new IllegalStateException("alarm-manager-unavailable");
        }
        PendingIntent operation = operation(context);
        long trigger = at.toEpochMilli();
        if (exactPermitted(alarms)) {
            try {
                alarms.setExactAndAllowWhileIdle(AlarmManager.RTC_WAKEUP, trigger, operation);
                return;
            } catch (SecurityException revoked) {
                // Revoked since the check: fall through to the inexact window.
            }
        }
        alarms.setWindow(AlarmManager.RTC_WAKEUP, trigger, INEXACT_WINDOW_MILLIS, operation);
    }

    /** Cancels an armed boundary; a device that never armed one is left untouched. */
    static void cancel(Context context) {
        AlarmManager alarms = context.getSystemService(AlarmManager.class);
        PendingIntent existing = PendingIntent.getBroadcast(context, REQUEST_CODE, intent(context),
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

    private static PendingIntent operation(Context context) {
        return PendingIntent.getBroadcast(context, REQUEST_CODE, intent(context),
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
    }

    private static Intent intent(Context context) {
        return new Intent(context, PolicyRefreshReceiver.class).setAction(ACTION_BOUNDARY);
    }
}
