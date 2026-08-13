package com.example.lockdowndpc.policy;

import java.util.List;

/**
 * The verified result of one system policy pass, over every control.
 *
 * <p>This is what the console renders and what {@link LockdownPolicyController}
 * consults, so that neither ever infers enforcement from a stored switch.
 */
public record SystemPolicyReport(List<SystemPolicyControlStatus> statuses) {

    public SystemPolicyReport {
        statuses = List.copyOf(statuses);
    }

    public static SystemPolicyReport empty() {
        return new SystemPolicyReport(List.of());
    }

    /** The status of one control, or {@code null} when the report predates it. */
    public SystemPolicyControlStatus statusOf(SystemPolicyControl control) {
        return statuses.stream()
                .filter(status -> status.control() == control)
                .findFirst()
                .orElse(null);
    }

    /**
     * Failures that must stop protection from being reported as active.
     *
     * <p>{@link LockdownPolicyController} adds these to its error list, which is
     * what drives {@code AllowedAppsStore.markApplyFailed} and therefore the
     * {@code FAILED} protection state the console shows as a fault.
     */
    public List<SystemPolicyControlStatus> faults() {
        return statuses.stream().filter(SystemPolicyControlStatus::faultsProtection).toList();
    }

    /** Every disagreement, including the advisory ones that do not fault. */
    public List<SystemPolicyControlStatus> failures() {
        return statuses.stream().filter(SystemPolicyControlStatus::failed).toList();
    }

    /** Failures that are recorded and shown but deliberately do not fault protection. */
    public List<SystemPolicyControlStatus> nonFaultingFailures() {
        return statuses.stream()
                .filter(status -> status.failed() && !status.faultsProtection())
                .toList();
    }

    /** Controls the administrator asked for that this Android release cannot honour. */
    public List<SystemPolicyControlStatus> unsupportedButRequested() {
        return statuses.stream()
                .filter(status -> status.requested()
                        && status.outcome() == SystemPolicyOutcome.UNSUPPORTED)
                .toList();
    }

    /** Whether this pass leaves protection unable to claim it is active. */
    public boolean faulted() {
        return !faults().isEmpty();
    }
}
