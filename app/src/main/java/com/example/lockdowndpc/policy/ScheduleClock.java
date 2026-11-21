package com.example.lockdowndpc.policy;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.os.Build;
import android.provider.Settings;

import com.example.lockdowndpc.admin.LockdownAdminReceiver;

/**
 * The device clock night and work hours depend on.
 *
 * <p>Every window is computed from the wall clock, so a user who can set the
 * clock could end a window early. From Android 9 the date and time control
 * ({@code DISALLOW_CONFIG_DATE_TIME}, see {@link SystemPolicyControl}) closes
 * that. Android 8.0 and 8.1 have no such restriction; there the only lock is
 * {@link DevicePolicyManager#setAutoTimeRequired}, which keeps automatic date
 * and time on and out of the user's reach. On those releases the schedule may
 * be turned on only once Android confirms both, and every pass with an
 * enforcing schedule requires it again and reports {@link #UNLOCKED_ERROR}
 * while it is not confirmed.
 */
public final class ScheduleClock {

    /** Error token a pass reports on Android 8.0/8.1 while the clock is not locked. */
    public static final String UNLOCKED_ERROR = "schedule-clock-unlocked";

    /** The first release with the date and time restriction (Android 9). */
    static final int RESTRICTION_SDK = Build.VERSION_CODES.P;

    /** Android, as seen by this class. Any call may throw. */
    interface Gate {
        /** Asks Android to require automatic date and time. */
        void require();

        /** Whether Android reports automatic date and time as required. */
        boolean required();

        /** Whether automatic date and time is on. */
        boolean automatic();
    }

    private ScheduleClock() {}

    /**
     * Locks the clock where only the device owner can, and reports whether it
     * is locked. Always {@code true} from Android 9, without any call.
     */
    static boolean lock(int sdk, Gate gate) {
        if (sdk >= RESTRICTION_SDK) {
            return true;
        }
        try {
            gate.require();
        } catch (RuntimeException exception) {
            // Read back below: a refusal reads as "not required".
        }
        return locked(sdk, gate);
    }

    /** Whether the clock is locked, by read-back only; nothing is written. */
    static boolean locked(int sdk, Gate gate) {
        if (sdk >= RESTRICTION_SDK) {
            return true;
        }
        try {
            return gate.required() && gate.automatic();
        } catch (RuntimeException exception) {
            return false;
        }
    }

    /** {@link #lock} on this device; run it on the policy thread. */
    public static boolean lock(Context context, DevicePolicyManager dpm, ComponentName admin) {
        return lock(Build.VERSION.SDK_INT, gate(context, dpm, admin));
    }

    /** {@link #locked} on this device, for the console; nothing is written. */
    public static boolean locked(Context context) {
        if (Build.VERSION.SDK_INT >= RESTRICTION_SDK) {
            return true;
        }
        DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
        return dpm != null && locked(Build.VERSION.SDK_INT,
                gate(context, dpm, LockdownAdminReceiver.componentName(context)));
    }

    private static Gate gate(Context context, DevicePolicyManager dpm, ComponentName admin) {
        return new Gate() {
            @Override
            @SuppressWarnings("deprecation")
            public void require() {
                dpm.setAutoTimeRequired(admin, true);
            }

            @Override
            @SuppressWarnings("deprecation")
            public boolean required() {
                return dpm.getAutoTimeRequired();
            }

            @Override
            public boolean automatic() {
                return Settings.Global.getInt(context.getContentResolver(), Settings.Global.AUTO_TIME, 0) == 1;
            }
        };
    }
}
