package com.example.lockdowndpc.policy;

/**
 * The narrow slice of {@code DevicePolicyManager} the system policy controls use.
 *
 * <p>It exists so the decisions — what to send, what counts as verified, what
 * faults protection — are provable on the JVM instead of only on a provisioned
 * device that has to be re-enrolled after every wrong answer. The production
 * implementation, {@link SystemPolicyDeviceGateway}, is a thin adapter over
 * {@code DevicePolicyManager#addUserRestriction},
 * {@code #clearUserRestriction} and {@code #getUserRestrictions}; no other
 * mechanism is used.
 *
 * <p>Every method may throw. A device owner call can fail for reasons the
 * console cannot anticipate, and {@link SystemPolicyEnforcer} treats a throw as
 * an absence of evidence rather than as a result.
 */
public interface SystemPolicyGateway {

    /** Requests one restriction. */
    void addRestriction(String key);

    /** Withdraws one restriction. */
    void clearRestriction(String key);

    /** Reads the restriction back from the platform. This is the only source of truth. */
    boolean isRestrictionInForce(String key);
}
