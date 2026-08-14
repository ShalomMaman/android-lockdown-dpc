package com.example.lockdowndpc.policy;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Sends the requested system policy controls and reports what the platform
 * actually did.
 *
 * <p>Every pass reads the restriction back after writing it. A control is
 * reported as applied only when {@code DevicePolicyManager} says it is in force,
 * which is why a saved switch can never stand in for enforcement anywhere in the
 * console or in the reconciliation result.
 *
 * <p>The class holds no Android types on purpose: it takes an SDK level, a
 * profile, the administrator's stored choices and a
 * {@link SystemPolicyGateway}. That makes apply, withdraw, verification
 * failure, unsupported releases and fault propagation provable as ordinary JVM
 * tests.
 */
public final class SystemPolicyEnforcer {

    private SystemPolicyEnforcer() {}

    /**
     * Whether a control is on, given the administrator's stored choices.
     *
     * <p>An absent choice is not "off": it is "no choice yet", which resolves to
     * the profile default. That is what keeps an upgraded pilot enforcing exactly
     * what 0.5.1 enforced instead of silently releasing every restriction the
     * first time this code runs.
     */
    public static boolean requestedFor(
            SystemPolicyControl control,
            SystemPolicyProfile profile,
            Map<SystemPolicyControl, Boolean> explicitChoices
    ) {
        Boolean choice = explicitChoices == null ? null : explicitChoices.get(control);
        return choice != null ? choice : control.defaultRequested(profile);
    }

    /** Applies every control and verifies each one against the platform. */
    public static SystemPolicyReport enforce(
            int sdkInt,
            SystemPolicyProfile profile,
            Map<SystemPolicyControl, Boolean> explicitChoices,
            SystemPolicyGateway gateway
    ) {
        List<SystemPolicyControlStatus> statuses = new ArrayList<>();
        for (SystemPolicyControl control : SystemPolicyControl.values()) {
            boolean requested = requestedFor(control, profile, explicitChoices);
            statuses.add(applyOne(control, sdkInt, requested, gateway));
        }
        return new SystemPolicyReport(statuses);
    }

    /**
     * Withdraws every control, for {@code pause}.
     *
     * <p>Driven from the control catalogue rather than from a hand-kept list, so
     * a control added later cannot be left behind on a paused device — which
     * would leave a restriction in force that no screen admits to.
     */
    public static SystemPolicyReport release(int sdkInt, SystemPolicyGateway gateway) {
        List<SystemPolicyControlStatus> statuses = new ArrayList<>();
        for (SystemPolicyControl control : SystemPolicyControl.values()) {
            statuses.add(applyOne(control, sdkInt, false, gateway));
        }
        return new SystemPolicyReport(statuses);
    }

    private static SystemPolicyControlStatus applyOne(
            SystemPolicyControl control,
            int sdkInt,
            boolean requested,
            SystemPolicyGateway gateway
    ) {
        if (!control.supportedOn(sdkInt)) {
            return new SystemPolicyControlStatus(
                    control,
                    false,
                    requested,
                    SystemPolicyOutcome.UNSUPPORTED,
                    "needs-sdk-" + control.minSdk()
            );
        }

        List<SystemPolicyControl.Restriction> applicable = control.supportedRestrictions(sdkInt);
        List<String> problems = new ArrayList<>();

        for (SystemPolicyControl.Restriction restriction : applicable) {
            try {
                if (requested) {
                    gateway.addRestriction(restriction.key());
                } else {
                    gateway.clearRestriction(restriction.key());
                }
            } catch (RuntimeException exception) {
                problems.add(restriction.key() + "/" + exception.getClass().getSimpleName());
            }
        }

        boolean unreadable = false;
        boolean allInForce = true;
        boolean allWithdrawn = true;
        for (SystemPolicyControl.Restriction restriction : applicable) {
            try {
                boolean inForce = gateway.isRestrictionInForce(restriction.key());
                allInForce &= inForce;
                allWithdrawn &= !inForce;
            } catch (RuntimeException exception) {
                unreadable = true;
                problems.add(restriction.key() + "/unreadable");
            }
        }

        // A control made of several restrictions is only honoured when all of its
        // supported parts agree. Half of DISALLOW_INSTALL_UNKNOWN_SOURCES and its
        // global counterpart is not "unknown sources blocked".
        SystemPolicyOutcome.VerifiedState state;
        if (unreadable) {
            state = SystemPolicyOutcome.VerifiedState.UNREADABLE;
        } else if (requested) {
            state = allInForce
                    ? SystemPolicyOutcome.VerifiedState.ON
                    : SystemPolicyOutcome.VerifiedState.OFF;
        } else {
            state = allWithdrawn
                    ? SystemPolicyOutcome.VerifiedState.OFF
                    : SystemPolicyOutcome.VerifiedState.ON;
        }

        SystemPolicyOutcome outcome = SystemPolicyOutcome.verify(true, requested, state);
        if (outcome == SystemPolicyOutcome.FAILED && problems.isEmpty()) {
            problems.add(requested ? "not-in-force" : "not-withdrawn");
        }
        // A control the release only partly implements is reported even when it
        // succeeded, so an operator is never shown an unqualified "applied" for
        // something this Android cannot fully do.
        for (SystemPolicyControl.Restriction missing : control.unsupportedRestrictions(sdkInt)) {
            problems.add("unavailable-" + missing.key());
        }

        return new SystemPolicyControlStatus(
                control,
                true,
                requested,
                outcome,
                String.join(",", problems)
        );
    }
}
