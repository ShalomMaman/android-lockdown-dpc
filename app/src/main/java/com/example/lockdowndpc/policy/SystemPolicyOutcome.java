package com.example.lockdowndpc.policy;

/**
 * What actually happened to one system policy control on this device.
 *
 * <p>The distinction between {@link #REQUESTED} and {@link #APPLIED} is the whole
 * point of this type. A saved switch is an intent; only a read-back of
 * {@code DevicePolicyManager#getUserRestrictions} is evidence. A console that
 * renders the switch as the state tells an operator a device is hardened when the
 * platform may have refused the request outright.
 */
public enum SystemPolicyOutcome {

    /** The running Android release has no such restriction. Nothing was sent. */
    UNSUPPORTED,

    /** The administrator has this control off, and the platform confirms it is off. */
    NOT_REQUESTED,

    /**
     * The administrator has this control on, but no verification has been made
     * since. This is the state of a saved switch before an apply pass, and it is
     * never presented as protection.
     */
    REQUESTED,

    /** The administrator asked for it and the platform reports it in force. */
    APPLIED,

    /** The platform's state disagrees with what was asked for, or is unreadable. */
    FAILED;

    /** What the platform reported when the restriction was read back. */
    public enum VerifiedState {
        /** The restriction is in force. */
        ON,
        /** The restriction is not in force. */
        OFF,
        /** The platform could not be asked; treated as no evidence at all. */
        UNREADABLE
    }

    /**
     * Resolves the outcome from the running SDK's support, the administrator's
     * intent, and the state the platform actually reported.
     *
     * <p>{@link VerifiedState#UNREADABLE} is never optimistic. An unreadable
     * restriction is a failure whichever way the intent points, because the one
     * thing that would justify reporting a state is missing.
     */
    public static SystemPolicyOutcome verify(
            boolean supported,
            boolean requested,
            VerifiedState state
    ) {
        if (!supported) {
            return UNSUPPORTED;
        }
        if (state == null || state == VerifiedState.UNREADABLE) {
            return FAILED;
        }
        if (requested) {
            return state == VerifiedState.ON ? APPLIED : FAILED;
        }
        return state == VerifiedState.OFF ? NOT_REQUESTED : FAILED;
    }
}
