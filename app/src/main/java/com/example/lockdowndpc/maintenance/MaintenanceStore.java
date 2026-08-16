package com.example.lockdowndpc.maintenance;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.SystemClock;

import com.example.lockdowndpc.maintenance.MaintenanceCoordinator.MaintenanceOutcome;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

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
    private static final String KEY_PROCESS_SESSION = "process_session";

    /** Version 2 makes every maintenance authorization process-bound. */
    private static final int SCHEMA_VERSION = 2;
    private static final String PROCESS_SESSION = UUID.randomUUID().toString();

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
        if (!belongsToCurrentProcess(
                preferences.getInt(KEY_SCHEMA_VERSION, 0),
                preferences.getString(KEY_PROCESS_SESSION, null),
                PROCESS_SESSION)) {
            // A process death is a fail-closed maintenance boundary. It also
            // defeats resurrection of a stale on-disk authorization if clearing
            // the old window previously reported an I/O failure.
            return discard(context);
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

    /**
     * The stored window, but only when the state machine would still honour it.
     *
     * <p>The full liveness evaluation, not a bare expiry check. An expiry-only
     * test reads a pre-reboot window as live — after a restart the monotonic
     * clock is near zero, comfortably below the old deadline — so a caller that
     * checked the deadline alone would treat a dead window's relaxations as
     * current. Closing a lapsed window stays {@link MaintenanceGuard}'s job,
     * because that has to be read back and audited; this only answers whether a
     * window is one the guard would still honour.
     */
    public static MaintenanceWindow liveWindow(Context context) {
        MaintenanceWindow window = readWindow(context);
        if (window == null) {
            return null;
        }
        MaintenanceStateMachine.Evaluation evaluation =
                MaintenanceStateMachine.evaluate(window, deviceClock());
        return evaluation.open() ? evaluation.window() : null;
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
     * <p>The storage rule in one place so no caller can get it wrong: only a
     * verified-open authorization is stored as a window. A failed close may
     * still carry the old window as audit evidence, but storing it would let the
     * next refresh mistake failed cancellation for a live authorization. In that
     * case the window is removed while the pending flag survives, so the next
     * pass can only retry the base-policy restore.
     *
     * @return whether every write reached storage. A caller that has just relaxed
     *         a device and gets {@code false} is holding a device whose state no
     *         later pass can reconstruct, and must close the window rather than
     *         report it as open.
     */
    public static synchronized boolean apply(Context context, MaintenanceOutcome outcome) {
        boolean durable;
        MaintenanceWindow authorizedWindow = outcome.windowForPersistence();
        if (authorizedWindow != null) {
            durable = saveWindow(context, authorizedWindow);
        } else {
            durable = clearWindow(context);
        }
        if (outcome.restoreProven()) {
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
                .putString(KEY_PROCESS_SESSION, PROCESS_SESSION)
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
                .remove(KEY_PROCESS_SESSION)
                .commit();
    }

    static boolean belongsToCurrentProcess(
            int schemaVersion,
            String storedSession,
            String currentSession
    ) {
        return schemaVersion == SCHEMA_VERSION
                && storedSession != null
                && storedSession.equals(currentSession);
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
