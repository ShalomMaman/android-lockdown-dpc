package com.example.lockdowndpc.maintenance;

import com.example.lockdowndpc.maintenance.MaintenanceStateMachine.CloseReason;
import com.example.lockdowndpc.maintenance.MaintenanceStateMachine.Evaluation;
import com.example.lockdowndpc.maintenance.MaintenanceStateMachine.OpenDecision;
import com.example.lockdowndpc.maintenance.MaintenanceStateMachine.OpenRequest;
import com.example.lockdowndpc.policy.SystemPolicyControl;
import com.example.lockdowndpc.policy.SystemPolicyControlStatus;
import com.example.lockdowndpc.policy.SystemPolicyEnforcer;
import com.example.lockdowndpc.policy.SystemPolicyGateway;
import com.example.lockdowndpc.policy.SystemPolicyOutcome;
import com.example.lockdowndpc.policy.SystemPolicyProfile;
import com.example.lockdowndpc.policy.SystemPolicyReport;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Turns a maintenance decision into a verified device state.
 *
 * <p>It owns no clock, no storage and no Android type: it is given an SDK level,
 * a profile, the administrator's stored choices, a {@link SystemPolicyGateway}
 * and a {@link MaintenanceClock}, and it drives the same
 * {@link SystemPolicyEnforcer} every other policy pass uses. That is deliberate.
 * Maintenance must obey the engine's central rule — nothing is reported as being
 * in force until it has been read back — and the cheapest way to guarantee that
 * is to have no second code path that could forget.
 *
 * <h2>What "failed" means here, and why it is never quiet</h2>
 *
 * <p>Two failures matter, and they are not symmetrical.
 *
 * <ul>
 *   <li><b>Opening failed.</b> The device is stricter than the technician asked
 *       for. Nothing is less safe, but the window would be a lie, so the
 *       coordinator restores the base policy immediately and reports
 *       {@link MaintenanceStatus#FAILED}. Only if that restore <em>also</em>
 *       fails does it hand back the old window as failure evidence; durable
 *       storage removes the authorization and keeps a restore-debt bit.</li>
 *   <li><b>Closing failed.</b> The device may still be relaxed — this is the
 *       dangerous direction. The outcome is {@link MaintenanceStatus#FAILED},
 *       {@link MaintenanceOutcome#restoreVerified()} is false, and the window is
 *       returned as failure evidence while durable storage keeps only the
 *       restore debt and retries. A close is never reported as done because the
 *       calls were made; only because the restrictions read back as restored.
 *       The failed window is never persisted as a live authorization.</li>
 * </ul>
 */
public final class MaintenanceCoordinator {

    /** The verified result of one maintenance operation. */
    public enum MaintenanceStatus {
        /** Refused before anything was sent to the device. */
        REFUSED,
        /** Nothing needed changing; no policy call was made. */
        UNCHANGED,
        /** Requested, sent, and read back exactly as asked. */
        APPLIED,
        /** The platform's state disagrees with what was asked for. */
        FAILED
    }

    /** Which half of the feature produced an outcome. */
    public enum Phase {
        /** An attempt to open a window. */
        OPEN,
        /** A liveness check that changed nothing. */
        REFRESH,
        /** An attempt to put the base policy back. */
        RESTORE
    }

    /**
     * What happened, in the vocabulary the console and the audit log both use.
     *
     * @param phase       which operation this describes
     * @param status      the verified result
     * @param window      the live window or transient failure evidence;
     *                    {@link #windowForPersistence()} is the only value
     *                    durable storage may treat as authorization
     * @param closeReason why a window closed, {@code null} otherwise
     * @param restoreProven explicit readback evidence that the base policy is restored
     * @param plan        the plan that was applied, {@code null} when refused
     * @param report      the per-control evidence, never {@code null}
     * @param failures    non-sensitive summaries of every disagreement
     * @param reason      a stable, non-sensitive token naming the decision
     */
    public record MaintenanceOutcome(
            Phase phase,
            MaintenanceStatus status,
            MaintenanceWindow window,
            CloseReason closeReason,
            boolean restoreProven,
            MaintenancePlan plan,
            SystemPolicyReport report,
            List<String> failures,
            String reason
    ) {

        public MaintenanceOutcome {
            failures = failures == null ? List.of() : List.copyOf(failures);
            report = report == null ? SystemPolicyReport.empty() : report;
            if (restoreProven && (closeReason == null || window != null)) {
                throw new IllegalArgumentException(
                        "Restore proof requires a closed outcome with no live window");
            }
            if (restoreProven
                    && !((phase == Phase.RESTORE && status == MaintenanceStatus.APPLIED)
                    || (phase == Phase.OPEN && status == MaintenanceStatus.FAILED))) {
                throw new IllegalArgumentException(
                        "Restore proof does not match the maintenance phase and status");
            }
        }

        public boolean failed() {
            return status == MaintenanceStatus.FAILED;
        }

        /**
         * Whether a maintenance window is in force after this operation.
         *
         * <p>A window that is returned <em>with</em> a {@link CloseReason} is not
         * open: it is a record of relaxations the device may still be carrying,
         * kept so the next pass can try again.
         */
        public boolean windowOpen() {
            return window != null && closeReason == null;
        }

        /** Whether the outcome carries window evidence for callers and audit. */
        public boolean windowMustBeStored() {
            return window != null;
        }

        /**
         * The only window durable storage may treat as an authorization.
         *
         * <p>A failed close deliberately carries its old window for audit and
         * operator evidence, but persisting that shape would let a later refresh
         * reinterpret the failed close as a still-authorized live window. The
         * separate restore-pending bit is the durable record of that unsafe
         * state, so a failed close persists no authorization at all.
         */
        public MaintenanceWindow windowForPersistence() {
            return windowOpen() ? window : null;
        }

        /** Whether a close was attempted but the base policy is still unproved. */
        public boolean restoreOwed() {
            return closeReason != null && !restoreProven();
        }

        /**
         * Whether the base policy is proven to be back in force.
         *
         * <p>Only meaningful for {@link Phase#RESTORE}; false everywhere else,
         * because no other phase has read the base policy back.
         */
        public boolean restoreVerified() {
            return phase == Phase.RESTORE && status == MaintenanceStatus.APPLIED;
        }

        /**
         * A stable, non-sensitive audit line.
         *
         * <p>Capability keys, control keys and a duration in milliseconds. No
         * PIN, no recovery code, no kiosk URL, nothing an operator must not see
         * in a log that is read on the device.
         */
        public String auditSummary() {
            StringBuilder summary = new StringBuilder("maintenance:")
                    .append(phase.name().toLowerCase(java.util.Locale.ROOT))
                    .append(':')
                    .append(status.name().toLowerCase(java.util.Locale.ROOT))
                    .append(':')
                    .append(reason == null ? "" : reason);
            if (closeReason != null) {
                summary.append(";close=").append(closeReason.token());
            }
            if (window != null) {
                summary.append(";capabilities=").append(window.capabilitySummary());
                summary.append(";duration-ms=").append(window.durationMillis());
            }
            if (plan != null && plan.relaxesAnything()) {
                summary.append(";relaxed=").append(plan.relaxedSummary());
            }
            if (!failures.isEmpty()) {
                summary.append(";failures=").append(String.join("|", failures));
            }
            return summary.toString();
        }
    }

    private final int sdkInt;
    private final SystemPolicyProfile profile;
    private final Map<SystemPolicyControl, Boolean> baseChoices;
    private final SystemPolicyGateway gateway;
    private final MaintenanceCapabilityGateway capabilityGateway;
    private final MaintenanceClock clock;

    /**
     * @param sdkInt      the running {@code Build.VERSION.SDK_INT}
     * @param profile     the profile the stored choices are resolved against
     * @param baseChoices the administrator's stored choices, without maintenance
     * @param gateway     the device policy seam
     * @param capabilityGateway non-restriction capability effects, including
     *                          verified application-store visibility
     * @param clock       the two clock readings a window is judged by
     */
    public MaintenanceCoordinator(
            int sdkInt,
            SystemPolicyProfile profile,
            Map<SystemPolicyControl, Boolean> baseChoices,
            SystemPolicyGateway gateway,
            MaintenanceCapabilityGateway capabilityGateway,
            MaintenanceClock clock
    ) {
        if (profile == null) {
            throw new IllegalArgumentException("A maintenance coordinator needs a profile");
        }
        if (gateway == null) {
            throw new IllegalArgumentException("A maintenance coordinator needs a policy gateway");
        }
        if (capabilityGateway == null) {
            throw new IllegalArgumentException("A maintenance coordinator needs a capability gateway");
        }
        if (clock == null) {
            throw new IllegalArgumentException("A maintenance coordinator needs a clock");
        }
        this.sdkInt = sdkInt;
        this.profile = profile;
        this.baseChoices = baseChoices == null ? Map.of() : Map.copyOf(baseChoices);
        this.gateway = gateway;
        this.capabilityGateway = capabilityGateway;
        this.clock = clock;
    }

    /**
     * Opens a window: authorise, apply, read back.
     *
     * @param current the window already open, or {@code null}
     * @param request what the administrator asked for
     */
    public MaintenanceOutcome open(MaintenanceWindow current, OpenRequest request) {
        OpenDecision decision = MaintenanceStateMachine.open(current, request, clock);
        if (!decision.allowed()) {
            // Nothing was sent to the device, so `current` is returned untouched:
            // a refusal must not become a way to forget an open window.
            return new MaintenanceOutcome(
                    Phase.OPEN,
                    MaintenanceStatus.REFUSED,
                    current,
                    null,
                    false,
                    null,
                    SystemPolicyReport.empty(),
                    List.of(),
                    decision.reason());
        }

        MaintenanceWindow window = decision.window();
        MaintenancePlan plan = MaintenancePlan.forWindow(profile, baseChoices, window);
        SystemPolicyReport report =
                SystemPolicyEnforcer.enforce(sdkInt, profile, plan.effectiveChoices(), gateway);
        List<String> failures = new ArrayList<>(openFailures(report, plan));
        failures.addAll(capabilityGateway.open(window));

        if (failures.isEmpty()) {
            return new MaintenanceOutcome(
                    Phase.OPEN,
                    MaintenanceStatus.APPLIED,
                    window,
                    null,
                    false,
                    plan,
                    report,
                    List.of(),
                    "opened");
        }

        // A half-open window is the one state nobody can act on, so the device is
        // put back before the failure is reported.
        MaintenanceOutcome restored = restore(window, CloseReason.OPEN_FAILED);
        List<String> combined = new ArrayList<>(failures);
        combined.addAll(restored.failures());
        boolean restoreVerified = restored.restoreVerified();
        return new MaintenanceOutcome(
                Phase.OPEN,
                MaintenanceStatus.FAILED,
                // Keep the window as failure evidence when the device may still
                // be relaxed. windowForPersistence() strips this closed window;
                // the durable restore-pending bit is what drives the retry.
                restoreVerified ? null : window,
                CloseReason.OPEN_FAILED,
                restoreVerified,
                plan,
                report,
                combined,
                restoreVerified ? "open-failed-policy-restored" : "open-failed-restore-failed");
    }

    /**
     * Re-checks an open window and closes it when it is no longer legitimate.
     *
     * <p>This is the call a boot receiver, a console screen or a periodic pass
     * makes. While the window is still valid it touches no device policy at all
     * and simply hands back a heartbeated window for the caller to store.
     */
    public MaintenanceOutcome refresh(MaintenanceWindow current) {
        Evaluation evaluation = MaintenanceStateMachine.evaluate(current, clock);
        if (evaluation.open()) {
            return new MaintenanceOutcome(
                    Phase.REFRESH,
                    MaintenanceStatus.UNCHANGED,
                    evaluation.window(),
                    null,
                    false,
                    null,
                    SystemPolicyReport.empty(),
                    List.of(),
                    evaluation.reason());
        }
        if (!evaluation.needsRestore()) {
            return new MaintenanceOutcome(
                    Phase.REFRESH,
                    MaintenanceStatus.UNCHANGED,
                    null,
                    null,
                    false,
                    null,
                    SystemPolicyReport.empty(),
                    List.of(),
                    evaluation.reason());
        }
        return restore(evaluation.window(), evaluation.closeReason());
    }

    /** An administrator ending the window by hand. */
    public MaintenanceOutcome cancel(MaintenanceWindow current) {
        Evaluation evaluation = MaintenanceStateMachine.cancel(current);
        if (!evaluation.needsRestore()) {
            return new MaintenanceOutcome(
                    Phase.REFRESH,
                    MaintenanceStatus.UNCHANGED,
                    null,
                    null,
                    false,
                    null,
                    SystemPolicyReport.empty(),
                    List.of(),
                    evaluation.reason());
        }
        return restore(evaluation.window(), evaluation.closeReason());
    }

    /**
     * Puts the base policy back and reads it back.
     *
     * <p>Expiry, reboot, a suspicious clock, a cancel, a failed open and an
     * unreadable record all land here, and all produce the same device state.
     * Only {@code closeReason} — and therefore the audit line — differs.
     *
     * @param window      the window being undone, or {@code null} when the record
     *                    was unreadable and there is nothing left to describe
     * @param closeReason why the window is being closed
     */
    public MaintenanceOutcome restore(MaintenanceWindow window, CloseReason closeReason) {
        MaintenancePlan plan = MaintenancePlan.restore(profile, baseChoices);
        List<String> failures = new ArrayList<>(capabilityGateway.restore());
        SystemPolicyReport report =
                SystemPolicyEnforcer.enforce(sdkInt, profile, plan.effectiveChoices(), gateway);
        failures.addAll(summaries(report.failures()));
        boolean verified = failures.isEmpty();
        return new MaintenanceOutcome(
                Phase.RESTORE,
                verified ? MaintenanceStatus.APPLIED : MaintenanceStatus.FAILED,
                // A restore that could not be proved keeps the old window only
                // as failure evidence. Durable storage removes its authorization
                // shape and retains restore-pending, so the caller retries without
                // any later refresh being able to reopen it.
                verified ? null : window,
                closeReason,
                verified,
                plan,
                report,
                failures,
                verified ? "restore-verified" : "restore-failed");
    }

    /**
     * Everything that stops an open window from being honest.
     *
     * <p>Two different things are checked, because the enforcer's own idea of a
     * fault is the wrong one here. A restriction that will not come off does not
     * fault ordinary protection — the device is stricter than asked — but during
     * maintenance it means the capability the technician was promised is simply
     * not available, so it counts.
     */
    private List<String> openFailures(SystemPolicyReport report, MaintenancePlan plan) {
        List<String> failures = new ArrayList<>(summaries(report.failures()));
        for (SystemPolicyControl control : plan.relaxed()) {
            SystemPolicyControlStatus status = report.statusOf(control);
            if (status == null) {
                failures.add("maintenance-unreported:" + control.storageKey());
                continue;
            }
            // UNSUPPORTED is not a failure to relax: a restriction this release
            // does not implement was never in force in the first place.
            if (status.outcome() != SystemPolicyOutcome.NOT_REQUESTED
                    && status.outcome() != SystemPolicyOutcome.UNSUPPORTED) {
                String summary = "maintenance-not-relaxed:" + status.summary();
                if (!failures.contains(summary)) {
                    failures.add(summary);
                }
            }
        }
        return Collections.unmodifiableList(failures);
    }

    private static List<String> summaries(List<SystemPolicyControlStatus> statuses) {
        List<String> summaries = new ArrayList<>();
        for (SystemPolicyControlStatus status : statuses) {
            summaries.add(status.summary());
        }
        return Collections.unmodifiableList(summaries);
    }
}
