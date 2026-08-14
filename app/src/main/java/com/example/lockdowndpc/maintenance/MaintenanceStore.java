package com.example.lockdowndpc.maintenance;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.SystemClock;

import com.example.lockdowndpc.maintenance.MaintenanceCoordinator.MaintenanceOutcome;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * The one Android-aware class in this package: it persists the open window and
 * reads the device clocks. Nothing decides anything here.
 *
 * <p>The split is the same one {@code SystemPolicyStore} makes. Every rule about
 * expiry, reboot, authorisation and restore lives in
 * {@link MaintenanceStateMachine}, {@link MaintenancePlan} and
 * {@link MaintenanceCoordinator}, which hold no Android type and are proved on
 * the JVM. What is left here is reading and writing a preference file, which is
 * exactly the part a unit test could only pretend to exercise.
 *
 * <h2>Failing closed on a record it cannot trust</h2>
 *
 * <p>A stored window is a claim that this device may currently have restrictions
 * relaxed. If any part of that claim is unreadable — a missing field, a
 * capability key this build does not know, a value that will not parse — the
 * store does not guess. It drops the record and leaves
 * {@link #restorePending(Context)} set, so the next pass restores and verifies
 * the base policy instead of assuming a device that was never opened.
 *
 * <p>{@link #restorePending(Context)} is set the moment a window is written and
 * cleared only when a restore has been read back. A process killed mid-window,
 * a crash, or a preference file that survives an unexpected upgrade therefore
 * all end with the base policy re-asserted rather than with a device quietly
 * left open.
 */
public final class MaintenanceStore {

    private static final String PREFS = "maintenance";
    private static final String KEY_SCHEMA_VERSION = "schema_version";
    private static final String KEY_CAPABILITIES = "capabilities";
    private static final String KEY_DURATION = "duration_millis";
    private static final String KEY_OPENED_WALL = "opened_wall_clock";
    private static final String KEY_OPENED_ELAPSED = "opened_elapsed";
    private static final String KEY_LAST_WALL = "last_seen_wall_clock";
    private static final String KEY_LAST_ELAPSED = "last_seen_elapsed";
    private static final String KEY_RESTORE_PENDING = "restore_pending";

    /** Bumped only for a change that needs migration code, so 1 means "as designed". */
    private static final int SCHEMA_VERSION = 1;

    private MaintenanceStore() {}

    /**
     * The device clocks.
     *
     * <p>{@code SystemClock.elapsedRealtime()} is the monotonic reading:
     * milliseconds since boot including deep sleep, reset by a restart and not
     * settable by anyone. {@code System.currentTimeMillis()} is the calendar
     * clock an OEM time sync or a user can move.
     */
    public static MaintenanceClock deviceClock() {
        return new MaintenanceClock() {
            @Override
            public long wallClockMillis() {
                return System.currentTimeMillis();
            }

            @Override
            public long elapsedSinceBootMillis() {
                return SystemClock.elapsedRealtime();
            }
        };
    }

    /**
     * The stored window, or {@code null} when there is none — including when the
     * record exists but cannot be trusted.
     */
    public static synchronized MaintenanceWindow readWindow(Context context) {
        SharedPreferences preferences = prefs(context);
        String capabilityKeys = preferences.getString(KEY_CAPABILITIES, null);
        if (capabilityKeys == null || capabilityKeys.isEmpty()) {
            return null;
        }
        try {
            Set<MaintenanceCapability> capabilities = new LinkedHashSet<>();
            for (String key : capabilityKeys.split(",")) {
                MaintenanceCapability capability = MaintenanceCapability.fromStorageKey(key.trim());
                if (capability == null) {
                    return discard(context);
                }
                capabilities.add(capability);
            }
            return new MaintenanceWindow(
                    capabilities,
                    preferences.getLong(KEY_DURATION, 0L),
                    preferences.getLong(KEY_OPENED_WALL, 0L),
                    preferences.getLong(KEY_OPENED_ELAPSED, -1L),
                    preferences.getLong(KEY_LAST_WALL, 0L),
                    preferences.getLong(KEY_LAST_ELAPSED, -1L));
        } catch (RuntimeException ignored) {
            // A rejected duration, a value stored under the wrong type, an empty
            // capability list: none of them is evidence of a legitimate window.
            return discard(context);
        }
    }

    /** Whether a restore still has to be verified before this device is trusted again. */
    public static boolean restorePending(Context context) {
        return prefs(context).getBoolean(KEY_RESTORE_PENDING, false);
    }

    /**
     * Records the intent to relax, before anything is sent to the device.
     *
     * <p>The dangerous gap is between clearing a restriction and recording that
     * it was cleared: a process kill in between would otherwise leave a device
     * with debugging enabled and nothing on disk saying so, and the next pass
     * would find no window, no pending flag and nothing to restore. Writing the
     * flag first costs, at worst, one redundant re-apply of the base policy.
     *
     * <p>{@code commit()} rather than {@code apply()} on purpose: the point is
     * that the record reaches disk before the first {@code DevicePolicyManager}
     * call, and an asynchronous write is exactly the race being closed.
     */
    public static synchronized boolean markRestorePending(Context context) {
        // The return value is the whole point. SharedPreferences.commit()
        // reports false when the values did not reach storage, and a caller that
        // ignores that would relax a device on the strength of a record that
        // does not exist. The caller must refuse to open when this is false.
        return prefs(context).edit().putBoolean(KEY_RESTORE_PENDING, true).commit();
    }

    /**
     * Withdraws the intent when nothing was sent after all.
     *
     * <p>Only legitimate for a request the state machine refused before any
     * device call — never as a way to forget a relaxation that did happen.
     */
    public static synchronized boolean clearRestorePending(Context context) {
        return prefs(context).edit().putBoolean(KEY_RESTORE_PENDING, false).commit();
    }

    /**
     * Persists exactly what an outcome hands back.
     *
     * <p>The storage rule in one place so no caller can get it wrong: a window is
     * stored whenever the outcome carries one — an open window, or a window whose
     * restore could not be verified — and the pending flag survives until a
     * restore has actually been read back.
     *
     * @return whether every write reached storage. A caller that has just relaxed
     *         a device and gets {@code false} is holding a device whose state no
     *         later pass can reconstruct, and must close the window rather than
     *         report it as open.
     */
    public static synchronized boolean apply(Context context, MaintenanceOutcome outcome) {
        boolean durable;
        if (outcome.windowMustBeStored()) {
            durable = saveWindow(context, outcome.window());
        } else {
            durable = clearWindow(context);
        }
        if (outcome.restoreVerified()) {
            durable &= prefs(context).edit().putBoolean(KEY_RESTORE_PENDING, false).commit();
        }
        return durable;
    }

    /**
     * Writes the window and marks a restore as owed.
     *
     * @return whether the record actually reached storage
     */
    public static synchronized boolean saveWindow(Context context, MaintenanceWindow window) {
        return prefs(context).edit()
                .putInt(KEY_SCHEMA_VERSION, SCHEMA_VERSION)
                .putString(KEY_CAPABILITIES, window.capabilitySummary())
                .putLong(KEY_DURATION, window.durationMillis())
                .putLong(KEY_OPENED_WALL, window.openedAtWallClock())
                .putLong(KEY_OPENED_ELAPSED, window.openedAtElapsed())
                .putLong(KEY_LAST_WALL, window.lastSeenWallClock())
                .putLong(KEY_LAST_ELAPSED, window.lastSeenElapsed())
                .putBoolean(KEY_RESTORE_PENDING, true)
                .commit();
    }

    /**
     * Removes the window. The pending flag is deliberately untouched.
     *
     * @return whether the removal actually reached storage
     */
    public static synchronized boolean clearWindow(Context context) {
        return prefs(context).edit()
                .remove(KEY_CAPABILITIES)
                .remove(KEY_DURATION)
                .remove(KEY_OPENED_WALL)
                .remove(KEY_OPENED_ELAPSED)
                .remove(KEY_LAST_WALL)
                .remove(KEY_LAST_ELAPSED)
                .commit();
    }

    private static MaintenanceWindow discard(Context context) {
        prefs(context).edit().putBoolean(KEY_RESTORE_PENDING, true).commit();
        clearWindow(context);
        return null;
    }

    private static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }
}
