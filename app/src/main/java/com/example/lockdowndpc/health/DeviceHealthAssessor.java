package com.example.lockdowndpc.health;

import com.example.lockdowndpc.health.DeviceHealthSnapshot.Kiosk;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.KioskPresence;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.ManagementIdentity;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Ownership;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Platform;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Policy;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.PolicyVerification;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Reconciliation;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.SystemControls;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.UpdateState;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Updates;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Answers one question about one device: is it actually healthy?
 *
 * <p>A pure function from {@link DeviceHealthSnapshot} to a status and an ordered
 * list of findings. It holds no state, reads nothing, and takes the current time
 * as an argument, so every rule below is provable as an ordinary JVM test.
 *
 * <p>The rule the whole class exists to enforce is the same one
 * {@code SystemPolicyOutcome} enforces one control at a time: <b>nothing
 * unproven is reported as healthy.</b> A device whose policy was requested but
 * never read back is {@link DeviceHealthStatus#UNVERIFIED}, not
 * {@link DeviceHealthStatus#HEALTHY}, and so is a device whose last proof is old
 * enough that it is no longer evidence about now. That is deliberately stricter
 * than a "no known problems" report, which is what a fleet console usually shows
 * and what makes an unenrolled or half-applied device look fine from a distance.
 *
 * <p>{@link DeviceHealthStatus#UNVERIFIED} outranks
 * {@link DeviceHealthStatus#DEGRADED} for the same reason: a known small problem
 * is a smaller thing than an unknown state, because the unknown state could be
 * any problem at all.
 */
public final class DeviceHealthAssessor {

    /**
     * How long a verified policy pass stays evidence about the present.
     *
     * <p>Reconciliation runs on boot and on package changes, so a device that has
     * produced nothing for a week is not a quiet device; it is a device whose
     * last proof no longer describes it.
     */
    public static final long POLICY_PROOF_VALID_FOR_MILLIS = 7L * 24L * 60L * 60L * 1000L;

    /** How long an update check stays current before it is worth reporting. */
    public static final long UPDATE_CHECK_VALID_FOR_MILLIS = 7L * 24L * 60L * 60L * 1000L;

    private DeviceHealthAssessor() {}

    /** The single answer an administrator asked for. */
    public enum DeviceHealthStatus {
        /** Every finding is a recorded fact; nothing is unproven or wrong. */
        HEALTHY(0),
        /** Something is worth attention but the device's state is known. */
        DEGRADED(1),
        /** Something about this device is not proven. Never reported as healthy. */
        UNVERIFIED(2),
        /** Something the administrator asked for is not in force. */
        FAILED(3);

        private final int rank;

        DeviceHealthStatus(int rank) {
            this.rank = rank;
        }

        public int rank() {
            return rank;
        }

        /** The worse of two statuses; the report always shows the worse one. */
        public static DeviceHealthStatus worst(DeviceHealthStatus left, DeviceHealthStatus right) {
            if (left == null) {
                return right == null ? UNVERIFIED : right;
            }
            if (right == null) {
                return left;
            }
            return left.rank >= right.rank ? left : right;
        }
    }

    /** What one finding does to the overall status. */
    public enum Severity {
        /** A recorded fact. Reported so the report is complete, not as a problem. */
        INFO(DeviceHealthStatus.HEALTHY),
        /** A real problem whose extent is known. */
        ADVISORY(DeviceHealthStatus.DEGRADED),
        /** Something this device cannot prove about itself. */
        UNVERIFIED(DeviceHealthStatus.UNVERIFIED),
        /** Something requested is not in force. */
        CRITICAL(DeviceHealthStatus.FAILED);

        private final DeviceHealthStatus status;

        Severity(DeviceHealthStatus status) {
            this.status = status;
        }

        public DeviceHealthStatus status() {
            return status;
        }
    }

    /**
     * Every conclusion this assessor can reach, with the stable machine code that
     * identifies it outside this process.
     *
     * <p>The code is the contract: it is what an export carries and what an
     * operator's own tooling can match on, so it must survive a rename of the
     * constant. The operator-facing sentence for each finding lives in
     * {@code res/values/device_health_strings.xml} under
     * {@code health_finding_<constant name, lower case>} and is resolved by
     * {@link DeviceHealthReport#messageRes}; keeping the resource identifiers out
     * of this class is what lets the rules stay ordinary JVM-testable code, in the
     * same split as {@code SystemPolicyControl} and {@code SystemPolicyLabels}.
     */
    public enum Finding {
        SNAPSHOT_UNAVAILABLE("device.state-unreadable"),

        DEVICE_OWNER_MISSING("policy.device-owner-missing"),
        DEVICE_OWNER_UNKNOWN("policy.device-owner-unknown"),
        POLICY_VERIFICATION_FAILED("policy.verification-failed"),
        POLICY_VERIFICATION_UNKNOWN("policy.verification-unknown"),
        POLICY_NEVER_VERIFIED("policy.never-verified"),
        POLICY_NOT_REQUESTED("policy.not-requested"),
        POLICY_VERIFICATION_STALE("policy.verification-stale"),
        POLICY_VERIFIED("policy.verified"),

        SYSTEM_CONTROL_FAULTED("system-control.faulted"),
        SYSTEM_CONTROL_ADVISORY_FAILED("system-control.advisory-failed"),
        SYSTEM_CONTROL_UNSUPPORTED("system-control.unsupported"),

        MANAGEMENT_IDENTITY_REJECTED("management.identity-rejected"),
        MANAGEMENT_IDENTITY_UNPROVEN("management.identity-unproven"),
        MANAGEMENT_IDENTITY_MISSING("management.identity-missing"),
        MANAGEMENT_IDENTITY_VERIFIED("management.identity-verified"),
        MANAGEMENT_NOT_CONFIGURED("management.not-configured"),

        RECONCILIATION_CRASHED("reconciliation.crashed"),
        RECONCILIATION_FAILED("reconciliation.failed"),
        RECONCILIATION_UNKNOWN("reconciliation.unknown"),
        RECONCILIATION_NEVER_RUN("reconciliation.never-run"),
        RECONCILIATION_VERIFIED("reconciliation.verified"),

        KIOSK_FAULTED("kiosk.faulted"),
        KIOSK_TARGET_UNRESOLVED("kiosk.target-unresolved"),
        KIOSK_STATE_UNKNOWN("kiosk.state-unknown"),
        KIOSK_ARMED_NOT_ACTIVE("kiosk.armed-not-active"),
        KIOSK_ACTIVE("kiosk.active"),
        KIOSK_OFF("kiosk.off"),

        UPDATE_CHANNEL_DISABLED("update.channel-disabled"),
        UPDATE_STATE_UNKNOWN("update.state-unknown"),
        UPDATE_NEVER_CHECKED("update.never-checked"),
        UPDATE_FAILED("update.failed"),
        UPDATE_CHECK_STALE("update.check-stale"),
        UPDATE_PENDING("update.pending"),
        UPDATE_IN_PROGRESS("update.in-progress"),
        UPDATE_CURRENT("update.current"),

        PLATFORM_NOT_READABLE("platform.not-readable");

        private final String code;

        Finding(String code) {
            this.code = code;
        }

        /** Stable outside this process; safe to export and to match on. */
        public String code() {
            return code;
        }

        /** The resource key both locales must define for this finding. */
        public String resourceKey() {
            return "health_finding_" + name().toLowerCase(java.util.Locale.ROOT);
        }
    }

    /** One conclusion, with the weight it carries. */
    public record DeviceHealthFinding(Severity severity, Finding finding) {
        public DeviceHealthFinding {
            if (severity == null || finding == null) {
                throw new IllegalArgumentException("a finding needs a severity and a subject");
            }
        }

        public String code() {
            return finding.code();
        }
    }

    /** The complete answer: one status, and the ordered evidence behind it. */
    public record Assessment(DeviceHealthStatus status, List<DeviceHealthFinding> findings) {
        public Assessment {
            status = status == null ? DeviceHealthStatus.UNVERIFIED : status;
            findings = DeviceHealthSnapshot.copyOf(findings);
        }

        public boolean has(Finding finding) {
            return findings.stream().anyMatch(entry -> entry.finding() == finding);
        }

        public List<Finding> findingsOf(Severity severity) {
            return findings.stream()
                    .filter(entry -> entry.severity() == severity)
                    .map(DeviceHealthFinding::finding)
                    .toList();
        }

        /** The findings in the order the report shows them. */
        public List<Finding> codesInOrder() {
            return findings.stream().map(DeviceHealthFinding::finding).toList();
        }
    }

    /**
     * Assesses one device.
     *
     * <p>Findings are produced in domain order — policy, system controls,
     * management identity, reconciliation, kiosk, updates, platform — and then
     * stably re-ordered by severity, so the worst thing about a device is always
     * the first line of its report while equally severe findings keep the order an
     * administrator reads them in.
     *
     * <p>Each domain contributes exactly one finding, chosen by precedence within
     * that domain, except the system controls, whose three outcomes are
     * independent facts about different controls. One finding per domain is what
     * keeps the report an answer instead of a log: an unenrolled device says
     * "Device Guard is not the Device Owner", not that plus six consequences of it.
     *
     * @param nowMillis the current wall clock, passed in so staleness is testable
     */
    public static Assessment assess(DeviceHealthSnapshot snapshot, long nowMillis) {
        if (snapshot == null) {
            return new Assessment(
                    DeviceHealthStatus.UNVERIFIED,
                    List.of(new DeviceHealthFinding(
                            Severity.UNVERIFIED, Finding.SNAPSHOT_UNAVAILABLE))
            );
        }

        List<DeviceHealthFinding> findings = new ArrayList<>();
        assessPolicy(snapshot.policy(), nowMillis, findings);
        assessSystemControls(snapshot.policy().systemControls(), findings);
        assessManagement(snapshot.managementIdentities(), findings);
        assessReconciliation(snapshot.reconciliation(), findings);
        assessKiosk(snapshot.kiosk(), findings);
        assessUpdates(snapshot.updates(), nowMillis, findings);
        assessPlatform(snapshot.platform(), findings);

        if (findings.isEmpty()) {
            // Unreachable through the branches above, which all end in a fallback.
            // Kept because the safe answer to "this device produced no evidence" is
            // never "healthy".
            findings.add(new DeviceHealthFinding(
                    Severity.UNVERIFIED, Finding.SNAPSHOT_UNAVAILABLE));
        }

        findings.sort(Comparator.comparingInt(
                (DeviceHealthFinding entry) -> entry.severity().status().rank()).reversed());

        DeviceHealthStatus status = DeviceHealthStatus.HEALTHY;
        for (DeviceHealthFinding finding : findings) {
            status = DeviceHealthStatus.worst(status, finding.severity().status());
        }
        return new Assessment(status, findings);
    }

    private static void assessPolicy(
            Policy policy,
            long nowMillis,
            List<DeviceHealthFinding> findings
    ) {
        if (policy.ownership() == Ownership.NOT_DEVICE_OWNER) {
            // Nothing else about policy can be true on a device that is not
            // provisioned, so this replaces the consequences rather than joining
            // them.
            findings.add(critical(Finding.DEVICE_OWNER_MISSING));
            return;
        }
        if (policy.ownership() == Ownership.UNKNOWN) {
            // Not the same claim as "not the owner". Sending an operator to
            // re-provision a device whose ownership merely could not be read is
            // the more expensive of the two mistakes.
            findings.add(unverified(Finding.DEVICE_OWNER_UNKNOWN));
            return;
        }

        boolean contradictory = policy.verification() == PolicyVerification.VERIFIED
                && !policy.verificationErrors().isEmpty();
        if (policy.verification() == PolicyVerification.FAILED || contradictory) {
            // A stored "verified" that still carries errors is not evidence of
            // anything; the stricter of the two readings wins.
            findings.add(critical(Finding.POLICY_VERIFICATION_FAILED));
            return;
        }
        switch (policy.verification()) {
            case UNKNOWN -> findings.add(unverified(Finding.POLICY_VERIFICATION_UNKNOWN));
            case REQUESTED_NOT_VERIFIED ->
                    findings.add(unverified(Finding.POLICY_NEVER_VERIFIED));
            case NOT_REQUESTED -> findings.add(advisory(Finding.POLICY_NOT_REQUESTED));
            case VERIFIED -> {
                if (policy.lastVerifiedAtMillis() <= 0L) {
                    // "Verified" with no timestamp is a claim without evidence.
                    findings.add(unverified(Finding.POLICY_NEVER_VERIFIED));
                } else if (isStale(policy.lastVerifiedAtMillis(), nowMillis,
                        POLICY_PROOF_VALID_FOR_MILLIS)) {
                    findings.add(unverified(Finding.POLICY_VERIFICATION_STALE));
                } else {
                    findings.add(info(Finding.POLICY_VERIFIED));
                }
            }
            default -> findings.add(unverified(Finding.POLICY_VERIFICATION_UNKNOWN));
        }
    }

    private static void assessSystemControls(
            SystemControls controls,
            List<DeviceHealthFinding> findings
    ) {
        if (controls.faulted() > 0) {
            findings.add(critical(Finding.SYSTEM_CONTROL_FAULTED));
        }
        if (controls.advisoryFailures() > 0) {
            findings.add(advisory(Finding.SYSTEM_CONTROL_ADVISORY_FAILED));
        }
        if (controls.unsupportedRequested() > 0) {
            // An older Android is not a broken device. Reported so nobody reads a
            // blank row as enforcement, but it does not degrade the device.
            findings.add(info(Finding.SYSTEM_CONTROL_UNSUPPORTED));
        }
    }

    private static void assessManagement(
            List<ManagementIdentity> identities,
            List<DeviceHealthFinding> findings
    ) {
        if (identities.isEmpty()) {
            findings.add(info(Finding.MANAGEMENT_NOT_CONFIGURED));
            return;
        }
        boolean rejected = false;
        boolean unproven = false;
        boolean missing = false;
        for (ManagementIdentity identity : identities) {
            switch (identity.verdict()) {
                case PINNED_MISMATCH, UNKNOWN_SIGNER -> rejected = true;
                case UNPINNED -> unproven = true;
                case NOT_INSTALLED -> missing = true;
                default -> { }
            }
        }
        if (rejected) {
            findings.add(critical(Finding.MANAGEMENT_IDENTITY_REJECTED));
        } else if (unproven) {
            // Trust resting on a package name alone. This is the pilot's
            // documented proof gap, and it is why a pilot device is honestly
            // reported as unverified rather than healthy.
            findings.add(unverified(Finding.MANAGEMENT_IDENTITY_UNPROVEN));
        } else if (missing) {
            findings.add(advisory(Finding.MANAGEMENT_IDENTITY_MISSING));
        } else {
            findings.add(info(Finding.MANAGEMENT_IDENTITY_VERIFIED));
        }
    }

    private static void assessReconciliation(
            Reconciliation reconciliation,
            List<DeviceHealthFinding> findings
    ) {
        switch (reconciliation.outcome()) {
            case CRASHED -> findings.add(critical(Finding.RECONCILIATION_CRASHED));
            case FAILED -> findings.add(critical(Finding.RECONCILIATION_FAILED));
            case NEVER_RUN -> findings.add(unverified(Finding.RECONCILIATION_NEVER_RUN));
            case VERIFIED -> {
                if (reconciliation.atMillis() <= 0L) {
                    findings.add(unverified(Finding.RECONCILIATION_UNKNOWN));
                } else {
                    findings.add(info(Finding.RECONCILIATION_VERIFIED));
                }
            }
            default -> findings.add(unverified(Finding.RECONCILIATION_UNKNOWN));
        }
    }

    private static void assessKiosk(Kiosk kiosk, List<DeviceHealthFinding> findings) {
        if (kiosk.state() == KioskPresence.FAULT) {
            findings.add(critical(Finding.KIOSK_FAULTED));
            return;
        }
        if (kiosk.state() == KioskPresence.UNKNOWN) {
            findings.add(unverified(Finding.KIOSK_STATE_UNKNOWN));
            return;
        }
        boolean configured = kiosk.state() == KioskPresence.ARMED
                || kiosk.state() == KioskPresence.ACTIVE;
        if (configured && !kiosk.targetResolved()) {
            // A kiosk pointing at something this device no longer has is a fault
            // waiting for the next activation, and the console is the only place
            // it can be seen before it happens.
            findings.add(critical(Finding.KIOSK_TARGET_UNRESOLVED));
            return;
        }
        switch (kiosk.state()) {
            case ACTIVE -> findings.add(info(Finding.KIOSK_ACTIVE));
            case ARMED -> findings.add(advisory(Finding.KIOSK_ARMED_NOT_ACTIVE));
            default -> findings.add(info(Finding.KIOSK_OFF));
        }
    }

    private static void assessUpdates(
            Updates updates,
            long nowMillis,
            List<DeviceHealthFinding> findings
    ) {
        if (!updates.channelEnabled() || updates.state() == UpdateState.NOT_CONFIGURED) {
            // A device with no update channel cannot be given a fix, which is a
            // known limitation rather than an unknown state.
            findings.add(advisory(Finding.UPDATE_CHANNEL_DISABLED));
            return;
        }
        switch (updates.state()) {
            case UNKNOWN -> findings.add(unverified(Finding.UPDATE_STATE_UNKNOWN));
            case NEVER_CHECKED -> findings.add(unverified(Finding.UPDATE_NEVER_CHECKED));
            case FAILED -> findings.add(advisory(Finding.UPDATE_FAILED));
            case IN_PROGRESS -> findings.add(info(Finding.UPDATE_IN_PROGRESS));
            case UPDATE_PENDING -> findings.add(advisory(Finding.UPDATE_PENDING));
            case UP_TO_DATE -> {
                if (updates.lastCheckedAtMillis() <= 0L) {
                    findings.add(unverified(Finding.UPDATE_NEVER_CHECKED));
                } else if (isStale(updates.lastCheckedAtMillis(), nowMillis,
                        UPDATE_CHECK_VALID_FOR_MILLIS)) {
                    findings.add(advisory(Finding.UPDATE_CHECK_STALE));
                } else {
                    findings.add(info(Finding.UPDATE_CURRENT));
                }
            }
            default -> findings.add(unverified(Finding.UPDATE_STATE_UNKNOWN));
        }
    }

    private static void assessPlatform(Platform platform, List<DeviceHealthFinding> findings) {
        if (!platform.readable()) {
            findings.add(advisory(Finding.PLATFORM_NOT_READABLE));
        }
    }

    /**
     * Whether a recorded proof is older than it is allowed to be.
     *
     * <p>A timestamp in the future is treated as current rather than as stale: the
     * clock can be wrong, and a wrong clock must not be able to turn a working
     * device into a reported fault. It cannot hide a fault either, because every
     * other finding is read from state rather than from time.
     */
    private static boolean isStale(long recordedAtMillis, long nowMillis, long validForMillis) {
        return nowMillis - recordedAtMillis > validForMillis;
    }

    private static DeviceHealthFinding critical(Finding finding) {
        return new DeviceHealthFinding(Severity.CRITICAL, finding);
    }

    private static DeviceHealthFinding unverified(Finding finding) {
        return new DeviceHealthFinding(Severity.UNVERIFIED, finding);
    }

    private static DeviceHealthFinding advisory(Finding finding) {
        return new DeviceHealthFinding(Severity.ADVISORY, finding);
    }

    private static DeviceHealthFinding info(Finding finding) {
        return new DeviceHealthFinding(Severity.INFO, finding);
    }
}
