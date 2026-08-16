package com.example.lockdowndpc.policy;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The explicit, administrator-controlled exception that lets applications which
 * require the Google Play Store package keep working, without giving up the
 * installation controls.
 *
 * <h2>Why the exception exists</h2>
 *
 * <p>Some Play-distributed applications refuse to start while
 * {@code com.android.vending} is hidden, even though Google Play services and
 * the active WebView provider are untouched. That was reproduced on a physical
 * Android 13 Device Owner pilot: with protection verified the application showed
 * its own "Check that Google Play is enabled" error, and it started only after an
 * authenticated, bounded maintenance window made the Store package available
 * again. The dependency is on the Store <em>package</em>, not on Play services.
 *
 * <h2>What the exception is, and what it is not</h2>
 *
 * <ul>
 *   <li><b>Explicit.</b> The only input that turns it on is an administrator's
 *       stored decision. Nothing here reads the allowlist, so allowing an
 *       application can never enable the Store as a side effect.</li>
 *   <li><b>Narrow.</b> {@link #keepsAvailable} answers for exactly one package.
 *       Every other store in {@link LockdownPackages#ALWAYS_BLOCKED} stays
 *       blocked, and the Play Store itself stays in that set: this is an
 *       exception applied at the policy pass, not a hole in the catalogue. It is
 *       therefore still ineligible as a kiosk target and still refused by
 *       {@code AllowedAppsStore.setAdminSelectedSystemPackages}.</li>
 *   <li><b>Priced.</b> Making the Store available raises the base policy floor:
 *       {@link #REQUIRED_INSTALL_CONTROLS} are requested regardless of what the
 *       administrator chose for them, and they are read back like every other
 *       control.</li>
 *   <li><b>Fail-closed.</b> If that install lock is not confirmed by the device,
 *       {@link #evaluate} reports {@link State#INSTALL_LOCK_UNVERIFIED}: the
 *       Store stays hidden and the pass carries an error, so protection is never
 *       reported as active over an unverified install lock. A maintenance window
 *       that opens one of those controls without opening application-store
 *       access withholds the Store for its duration instead — see
 *       {@link State#WITHHELD_DURING_MAINTENANCE}.</li>
 * </ul>
 *
 * <h2>The boundary this class does not cross</h2>
 *
 * <p>Android's Device Owner APIs can hide or suspend a whole package; they
 * cannot portably hide one launcher entry while leaving the package usable by
 * other applications. So on an ordinary launcher an available Play Store may
 * remain visible and openable — installation is what is blocked and verified,
 * not the Store's user interface. Kiosk containment is different and stronger:
 * the lock-task allowlist and the managed HOME component decide what is
 * reachable, and the Store is in neither, so it stays off the exposed surface
 * while remaining available to the applications that depend on it. The console
 * says this in as many words rather than claiming the Store is hidden.
 *
 * <p>Like {@link SystemPolicyControl}, this class holds no Android type and no
 * resource identifier, so every rule above is an ordinary JVM test.
 */
public final class PlayStoreCompatibility {

    /** The one package this exception may ever apply to. */
    public static final String PLAY_STORE_PACKAGE = "com.android.vending";

    /**
     * The controls that must be enforced while the Store package is available.
     *
     * <p>{@code DISALLOW_INSTALL_APPS} through
     * {@link SystemPolicyControl#APP_STORES_AND_INSTALLERS}, and both
     * unknown-source restrictions through
     * {@link SystemPolicyControl#UNKNOWN_SOURCE_INSTALLS}. Both are critical, so
     * a device that refuses either already faults protection on its own; this
     * class additionally refuses to make the Store available.
     */
    public static final List<SystemPolicyControl> REQUIRED_INSTALL_CONTROLS = List.of(
            SystemPolicyControl.APP_STORES_AND_INSTALLERS,
            SystemPolicyControl.UNKNOWN_SOURCE_INSTALLS);

    /**
     * The one control whose authorised relaxation may leave the Store available.
     *
     * <p>{@code MaintenanceCapability.APP_STORE_ACCESS} is the only capability
     * that relaxes it, which makes this the exact seam between "an administrator
     * authorised working with an application store" and "an administrator
     * authorised a local APK install". The second must never buy the first.
     */
    public static final SystemPolicyControl STORE_INSTALL_CONTROL =
            SystemPolicyControl.APP_STORES_AND_INSTALLERS;

    /** The error a pass records when the mode is on but its price was not paid. */
    public static final String INSTALL_LOCK_UNVERIFIED_ERROR =
            "play-compatibility-install-lock-unverified";

    private PlayStoreCompatibility() {}

    /** What the compatibility exception resolves to for one policy pass. */
    public enum State {

        /** The default. App stores are hidden, exactly as before this feature. */
        STRICT(false),

        /** Requested, and the install lock was read back as in force. */
        ACTIVE(true),

        /**
         * Requested, and a live maintenance window has deliberately opened
         * <em>application-store installation</em> — the capability that owns
         * store visibility for its duration.
         *
         * <p>Not a failure: that window is authenticated, bounded, audited and
         * restored, and it makes the stores visible itself. Reported separately
         * so the console never shows a relaxed device as a locked one.
         */
        RELAXED_BY_MAINTENANCE(true),

        /**
         * Requested, but a live maintenance window has opened one of the other
         * controls this mode pins on — today, unknown sources through
         * {@code LOCAL_APK_INSTALL} — without opening application-store access.
         *
         * <p>The Store is withheld for the duration. The mode's contract is that
         * the Store is available only while <em>every</em> installation control
         * it pins on is actually enforced, and a window that opens unknown
         * sources has, by definition, stopped enforcing one of them. The
         * administrator authorised a local APK install; that authorisation does
         * not extend to leaving an application store available beside it.
         *
         * <p>This is not a fault. Nothing failed: the device is stricter than
         * the compatibility mode would like, on the strength of an authorisation
         * the administrator actually gave. Faulting protection here would turn
         * an authorised service action into a red console.
         */
        WITHHELD_DURING_MAINTENANCE(false),

        /**
         * Requested, but the device did not confirm the install lock. The Store
         * stays hidden and the pass is reported as unverified.
         */
        INSTALL_LOCK_UNVERIFIED(false);

        private final boolean playStoreAvailable;

        State(boolean playStoreAvailable) {
            this.playStoreAvailable = playStoreAvailable;
        }

        /** Whether this pass may leave {@link #PLAY_STORE_PACKAGE} unhidden. */
        public boolean keepsPlayStoreAvailable() {
            return playStoreAvailable;
        }

        /** Whether this state must be added to the pass's error list. */
        public boolean faultsProtection() {
            return this == INSTALL_LOCK_UNVERIFIED;
        }
    }

    /**
     * The administrator's stored choices, raised by the compatibility floor.
     *
     * <p>When the mode is off this is the stored map unchanged, so a device that
     * never enables it behaves exactly as it did before. When it is on, the
     * required controls are written in as explicit requests, which is what makes
     * every later stage — the enforcer, a maintenance plan, a maintenance
     * restore and the console rows — agree on one base policy instead of each
     * re-deriving it.
     */
    public static Map<SystemPolicyControl, Boolean> baseChoices(
            boolean enabled,
            Map<SystemPolicyControl, Boolean> storedChoices
    ) {
        LinkedHashMap<SystemPolicyControl, Boolean> choices = new LinkedHashMap<>();
        if (storedChoices != null) {
            for (SystemPolicyControl control : SystemPolicyControl.values()) {
                Boolean value = storedChoices.get(control);
                if (value != null) {
                    choices.put(control, value);
                }
            }
        }
        if (enabled) {
            for (SystemPolicyControl control : REQUIRED_INSTALL_CONTROLS) {
                choices.put(control, true);
            }
        }
        return Collections.unmodifiableMap(choices);
    }

    /**
     * Whether the mode pins this control on, so the console can show the switch
     * as locked instead of letting an administrator turn off a restriction the
     * next pass would put straight back.
     */
    public static boolean locksControl(SystemPolicyControl control, boolean enabled) {
        // An immutable List refuses contains(null) with an exception, and this is
        // a public entry point the console calls once per rendered row.
        return enabled && control != null && REQUIRED_INSTALL_CONTROLS.contains(control);
    }

    /**
     * Whether the policy pass must leave {@code packageName} available.
     *
     * <p>Exactly one package, and only when the caller has already resolved a
     * state that keeps it available. This never turns into "allow the stores".
     */
    public static boolean keepsAvailable(String packageName, boolean playStoreAvailable) {
        return playStoreAvailable && PLAY_STORE_PACKAGE.equals(packageName);
    }

    /**
     * Whether opening a window with these declared relaxations must withhold the
     * Store — the precondition an open has to satisfy <em>before</em> it relaxes
     * anything.
     *
     * <h2>Why this does not ask whether compatibility is enabled</h2>
     *
     * <p>It deliberately takes no preference. The compatibility flag is an
     * <em>intent</em>; whether {@link #PLAY_STORE_PACKAGE} is actually visible is
     * <em>device state</em>, and the two disagree for as long as an administrator
     * has changed the switch without applying. That gap was a reachable bypass:
     * enable and apply so the Store is visible, save the switch back to off
     * without applying, then open a window that clears the unknown-source
     * restrictions. A precondition that consulted the preference skipped itself,
     * the base policy no longer pinned the installation lock, and an already
     * visible Store stayed usable with no application-store authorisation
     * anywhere in the transaction.
     *
     * <p>So the question is asked of the window alone: does it relax an
     * installation control this exception is priced at, without carrying the
     * application-store authorisation that owns store visibility? If it does, the
     * Store is hidden and read back first, whatever any preference says. On a
     * device that is already strict the Store is already hidden and the extra
     * write is a verified no-op, which is the cheapest possible way to be sure.
     *
     * <p>Decided from the window's declared set rather than from the plan's
     * effective set for the same reason. The effective set depends on what the
     * base policy happens to be enforcing at that moment; the declared set is
     * what the administrator authorised. A precondition that asks "what will
     * actually be relaxed" can be argued out of running by a base policy that has
     * drifted, and this one must not be.
     *
     * <p>{@link State#WITHHELD_DURING_MAINTENANCE} is the state the compatibility
     * mode reports once such a window is open. The two are separate because they
     * answer different questions at different times, and only one of them may
     * depend on the preference: this one gates the open and must not, that one
     * describes a device running the exception and must.
     */
    public static boolean requiresPlayStoreWithheld(
            Set<SystemPolicyControl> windowRelaxableControls
    ) {
        if (windowRelaxableControls == null) {
            return false;
        }
        if (windowRelaxableControls.contains(STORE_INSTALL_CONTROL)) {
            // Application-store access is authorised, so the window owns store
            // visibility and unhides the stores itself — after the restrictions.
            return false;
        }
        for (SystemPolicyControl control : REQUIRED_INSTALL_CONTROLS) {
            if (windowRelaxableControls.contains(control)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Resolves the state from a pass that has just run.
     *
     * @param enabled              the administrator's stored decision
     * @param relaxedByMaintenance controls a live window has legitimately relaxed
     * @param report               the read-back evidence of this pass
     */
    public static State evaluate(
            boolean enabled,
            Set<SystemPolicyControl> relaxedByMaintenance,
            SystemPolicyReport report
    ) {
        LinkedHashMap<SystemPolicyControl, SystemPolicyOutcome> outcomes = new LinkedHashMap<>();
        if (report != null) {
            for (SystemPolicyControlStatus status : report.statuses()) {
                outcomes.put(status.control(), status.outcome());
            }
        }
        return evaluateOutcomes(enabled, relaxedByMaintenance, outcomes);
    }

    /**
     * The same rule against outcomes read from storage, for the console.
     *
     * <p>A control with no recorded outcome is not treated as enforced: an
     * absent verdict is the absence of evidence, which is the whole reason the
     * console renders verified outcomes rather than saved switches.
     *
     * <h2>Which authorisation buys store availability</h2>
     *
     * <p>Only {@link #STORE_INSTALL_CONTROL}. A maintenance window excuses a
     * control from the verification requirement — there is nothing to read back
     * once an authorised window has deliberately turned it off — but excusing a
     * control is not the same as authorising the Store, and the two must not be
     * collapsed. {@code APP_STORE_ACCESS} is the capability an administrator
     * opens to work with an application store, and it is the one that relaxes
     * {@link #STORE_INSTALL_CONTROL}. A window that only opens unknown sources
     * ({@code LOCAL_APK_INSTALL}) carries no such authorisation, so it withholds
     * the Store instead of granting it — fail-closed, and without faulting,
     * because nothing failed.
     */
    public static State evaluateOutcomes(
            boolean enabled,
            Set<SystemPolicyControl> relaxedByMaintenance,
            Map<SystemPolicyControl, SystemPolicyOutcome> verifiedOutcomes
    ) {
        if (!enabled) {
            return State.STRICT;
        }
        boolean storeAccessOpened = false;
        boolean otherLockOpened = false;
        for (SystemPolicyControl control : REQUIRED_INSTALL_CONTROLS) {
            if (relaxedByMaintenance != null && relaxedByMaintenance.contains(control)) {
                if (control == STORE_INSTALL_CONTROL) {
                    storeAccessOpened = true;
                } else {
                    otherLockOpened = true;
                }
                continue;
            }
            SystemPolicyOutcome outcome =
                    verifiedOutcomes == null ? null : verifiedOutcomes.get(control);
            if (outcome != SystemPolicyOutcome.APPLIED) {
                return State.INSTALL_LOCK_UNVERIFIED;
            }
        }
        if (storeAccessOpened) {
            return State.RELAXED_BY_MAINTENANCE;
        }
        return otherLockOpened ? State.WITHHELD_DURING_MAINTENANCE : State.ACTIVE;
    }
}
