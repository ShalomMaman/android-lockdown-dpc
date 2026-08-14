package com.example.lockdowndpc.policy;

/**
 * What one control asked for and what the platform actually reported.
 *
 * @param control   the control this describes
 * @param supported whether the running release implements any of its restrictions
 * @param requested whether the administrator has it on
 * @param outcome   the verified result
 * @param detail    a short machine-readable reason, empty when there is nothing
 *                  to explain; never holds anything an operator must not see
 */
public record SystemPolicyControlStatus(
        SystemPolicyControl control,
        boolean supported,
        boolean requested,
        SystemPolicyOutcome outcome,
        String detail
) {

    public SystemPolicyControlStatus {
        if (control == null) {
            throw new IllegalArgumentException("A status needs a control");
        }
        if (outcome == null) {
            throw new IllegalArgumentException("A status needs an outcome");
        }
        detail = detail == null ? "" : detail;
    }

    /**
     * Whether this status must stop protection from claiming to be active.
     *
     * <p>Only a <em>requested</em> critical control that failed. Two exclusions
     * are deliberate:
     *
     * <ul>
     *   <li>{@link SystemPolicyOutcome#UNSUPPORTED} never faults. A device
     *       running an older Android is not a broken device, and faulting would
     *       leave an operator with no way to bring it back. It is reported
     *       instead, so nobody reads a blank row as enforcement.</li>
     *   <li>A failure to <em>withdraw</em> a control does not fault. The device
     *       is then stricter than asked, not weaker, and faulting there would
     *       strand an administrator who is trying to open a capability back
     *       up — including the one who is trying to restore ADB access.</li>
     * </ul>
     */
    public boolean faultsProtection() {
        return control.critical() && requested && outcome == SystemPolicyOutcome.FAILED;
    }

    /** Any disagreement between intent and platform state, faulting or not. */
    public boolean failed() {
        return outcome == SystemPolicyOutcome.FAILED;
    }

    /** A stable, non-sensitive summary for the audit log and the error list. */
    public String summary() {
        String base = control.storageKey() + ":" + outcome.name().toLowerCase(java.util.Locale.ROOT);
        return detail.isEmpty() ? base : base + ":" + detail;
    }
}
