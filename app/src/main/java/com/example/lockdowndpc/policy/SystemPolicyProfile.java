package com.example.lockdowndpc.policy;

/**
 * Which deployment an installation belongs to, which is what decides whether a
 * control that removes the pilot break-glass path may default to on.
 *
 * <p>0.5.1 pilot devices are reachable over ADB on purpose: the signed
 * self-update drill has not been completed on hardware yet, so debugging is
 * still the documented recovery path. Turning {@code DISALLOW_DEBUGGING_FEATURES}
 * on by default during an update would remove that path from a device that is
 * relying on it, with no administrator action and no way back short of
 * re-provisioning. The profile is the seam that prevents it.
 *
 * <p>The identity is not invented here. {@code gradle/production-identity.gradle}
 * already fixes a distinct production application ID, applied only by an explicit
 * {@code production.init.gradle.kts} build; ordinary pilot builds keep the
 * {@code com.example.lockdowndpc} identity from {@code app/build.gradle.kts}. So
 * the running application ID <em>is</em> the profile, and it is one Android
 * refuses to change underneath a device: an in-place update must carry the same
 * application ID, so a provisioned pilot cannot become a production install. A
 * production device is a separate provisioning of a separately signed package.
 *
 * <p>Everything unrecognised is {@link #PILOT}. A renamed, forked or
 * white-labelled build therefore keeps the safe default rather than silently
 * inheriting production hardening it was never validated for.
 */
public enum SystemPolicyProfile {

    /** Pilot and every unrecognised build. Debugging stays available by default. */
    PILOT,

    /** The separately provisioned production identity. Hardened by default. */
    PRODUCTION;

    /**
     * The application ID {@code gradle/production-identity.gradle} assigns to a
     * production build.
     *
     * <p>This is deliberately a literal rather than a {@code BuildConfig} field:
     * adding one would mean editing the Gradle files, which this change does not
     * own. See the integration request in {@code docs/production-roadmap.md} — if
     * the production application ID is ever changed, this constant has to move
     * with it, and the safe failure mode if it is forgotten is that a production
     * device is treated as a pilot.
     */
    public static final String PRODUCTION_APPLICATION_ID = "il.co.shalommaman.deviceguard";

    /** The profile implied by a running application ID. Unknown means pilot. */
    public static SystemPolicyProfile detect(String applicationId) {
        return PRODUCTION_APPLICATION_ID.equals(applicationId) ? PRODUCTION : PILOT;
    }

    /**
     * Reconciles the profile recorded on first run with the one detected now,
     * always in favour of the weaker default.
     *
     * <p>A device only becomes {@link #PRODUCTION} when both agree. Any
     * disagreement — a restored backup, a stored value from a different build, a
     * value that failed to parse — resolves to {@link #PILOT}, so the worst case
     * of a confused record is that an administrator has to switch debugging off
     * by hand, never that a device loses its recovery path unannounced.
     */
    public static SystemPolicyProfile safest(SystemPolicyProfile stored, SystemPolicyProfile detected) {
        return stored == PRODUCTION && detected == PRODUCTION ? PRODUCTION : PILOT;
    }
}
