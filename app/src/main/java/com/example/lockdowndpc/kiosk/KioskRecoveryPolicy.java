package com.example.lockdowndpc.kiosk;

/**
 * The two decisions that make local authenticated recovery reachable from inside
 * a kiosk, kept pure so they are proved on the JVM rather than on a device that
 * has to be re-provisioned after every wrong answer.
 *
 * <p>0.5.0 pinned lock task to {@code LOCK_TASK_FEATURE_NONE} and, in single-app
 * mode, handed the screen to the pinned package. A target that traps Back — a
 * full-screen player, an exam client, a signage app — then left
 * {@link KioskHostActivity} unreachable, and with it the administrator corner
 * gesture the console documents. The documented recovery path did not exist and
 * re-provisioning became the first resort.
 *
 * <p>The fix is the supported Device Owner shape: the DPC is the persistent HOME
 * host, so the HOME key is allowed to come back to it. That is not an escape.
 * HOME resolves to {@link KioskHostActivity}, which is inside the lock task
 * allowlist; lock task refuses to launch any activity outside the allowlist, so
 * even a vendor launcher that won the preference race cannot be reached. What
 * HOME buys is an opportunity to authenticate — the administrator PIN remains
 * the only authority that leaves or changes kiosk.
 */
public final class KioskRecoveryPolicy {

    private KioskRecoveryPolicy() {}

    /** What the kiosk host draws for one render pass. */
    public enum HostSurface {
        /** The safe error state: no target, no site, no fallback. */
        ERROR,
        /** The contained WebView of a single-site kiosk. */
        SITE,
        /** Start the pinned single-app target. */
        LAUNCH_TARGET,
        /**
         * The contained kiosk home of a single-app kiosk: reached by HOME, or by
         * a target that closed itself. It offers a way back into the target and
         * hosts the administrator corner gesture, and nothing else.
         */
        RECOVERY_HOME,
    }

    /**
     * Whether the HOME key may be enabled while kiosk holds.
     *
     * <p>Only for single-app, and only once the kiosk HOME preference is actually
     * installed. Single-site needs nothing: the host <em>is</em> the foreground
     * activity, so the gesture is always on screen. Requiring
     * {@code homeRegistered} is the safety interlock — enabling HOME while no
     * launcher of ours is registered is exactly the configuration the platform
     * rejects, and the one where HOME could land somewhere we did not choose.
     */
    public static boolean allowHomeKey(KioskMode mode, boolean homeRegistered) {
        return mode == KioskMode.SINGLE_APP && homeRegistered;
    }

    /**
     * What the host renders, given the stored mode and whether this host instance
     * has already started its target.
     *
     * <p>{@code targetLaunched} is what stops the host from bouncing the operator
     * straight back into the pinned app: the first pass launches the target, and
     * every later resume — the HOME key, or the target finishing — lands on
     * {@link HostSurface#RECOVERY_HOME}. Because nothing relaunches on its own,
     * there is no relaunch loop to rate-limit either.
     */
    public static HostSurface surfaceFor(KioskMode mode, boolean configValid, boolean targetLaunched) {
        if (!configValid || mode == null) {
            return HostSurface.ERROR;
        }
        return switch (mode) {
            case SINGLE_SITE -> HostSurface.SITE;
            case SINGLE_APP -> targetLaunched ? HostSurface.RECOVERY_HOME : HostSurface.LAUNCH_TARGET;
            default -> HostSurface.ERROR;
        };
    }
}
