package com.example.lockdowndpc.health;

import com.example.lockdowndpc.R;
import com.example.lockdowndpc.health.DeviceHealthAssessor.Assessment;
import com.example.lockdowndpc.health.DeviceHealthAssessor.DeviceHealthFinding;
import com.example.lockdowndpc.health.DeviceHealthAssessor.DeviceHealthStatus;
import com.example.lockdowndpc.health.DeviceHealthAssessor.Finding;
import com.example.lockdowndpc.health.DeviceHealthAssessor.Severity;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.AuditEvent;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.IdentityVerdict;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Kiosk;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.KioskPresence;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.KioskProfile;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.ManagementIdentity;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Ownership;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Platform;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Policy;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.PolicyVerification;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Reconciliation;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.ReconciliationOutcome;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.UpdateState;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Updates;

/**
 * Renders a device health assessment, locally.
 *
 * <p>Two renderings, for two different readers:
 *
 * <ul>
 *   <li>{@link #local} is the report an administrator reads on the device. It is
 *       built entirely from string resources, so it is a first-class Hebrew
 *       screen rather than an English dump, and it may name what the local
 *       screens already name.</li>
 *   <li>{@link #export} is the stable, machine-readable line format an
 *       administrator can hand to someone else. It is ASCII, deterministic, and
 *       redacted: it runs {@link DeviceHealthRedaction#redact} over every snapshot
 *       it is given, so there is no call path that exports an unredacted one.</li>
 * </ul>
 *
 * <p><b>There is no network code in this class, in this package, or behind it.</b>
 * The export is a string. Producing it is an operator action, taken on the device
 * by an authenticated administrator; Device Guard never generates, schedules,
 * uploads or transmits a health report on its own, and there is no endpoint for
 * it to transmit one to. That is the whole point of doing fleet health this way:
 * the fleet answer is assembled by whoever collects the exports, not by the
 * device phoning somewhere.
 *
 * <p>The class takes its string lookup as an interface rather than a
 * {@code Context}, which keeps the export path free of Android and lets the
 * redaction tests exercise it directly.
 */
public final class DeviceHealthReport {

    /** Version tag of the export format. Bump it when a reader would break. */
    public static final String EXPORT_FORMAT = "device-guard-health/1";

    private static final String NEW_LINE = "\n";

    private DeviceHealthReport() {}

    /** Resolves one string resource. On a device this is {@code Context::getString}. */
    @FunctionalInterface
    public interface Strings {
        String get(int resourceId, Object... formatArgs);
    }

    /** Formats an epoch-millis instant for a human reader, in the current locale. */
    @FunctionalInterface
    public interface Timestamps {
        String format(long atMillis);
    }

    /**
     * The report an administrator reads on the device.
     *
     * @param generatedAtMillis when this rendering was produced
     */
    public static String local(
            DeviceHealthSnapshot snapshot,
            Assessment assessment,
            long generatedAtMillis,
            Strings strings,
            Timestamps timestamps
    ) {
        DeviceHealthSnapshot device =
                snapshot == null ? DeviceHealthSnapshot.unreadable() : snapshot;
        Assessment result = assessment == null
                ? DeviceHealthAssessor.assess(device, generatedAtMillis)
                : assessment;

        StringBuilder report = new StringBuilder();
        report.append(strings.get(R.string.health_title)).append(NEW_LINE);
        report.append(strings.get(
                R.string.health_generated_at, timestamps.format(generatedAtMillis)))
                .append(NEW_LINE);
        report.append(strings.get(R.string.health_local_only)).append(NEW_LINE);
        report.append(NEW_LINE);

        report.append(strings.get(R.string.health_status_headline,
                        strings.get(statusRes(result.status())),
                        strings.get(statusBodyRes(result.status()))))
                .append(NEW_LINE);
        report.append(NEW_LINE);

        report.append(strings.get(R.string.health_section_findings)).append(NEW_LINE);
        for (DeviceHealthFinding finding : result.findings()) {
            report.append(strings.get(
                            R.string.health_finding_line,
                            strings.get(severityRes(finding.severity())),
                            strings.get(messageRes(finding.finding()))))
                    .append(NEW_LINE);
        }
        report.append(NEW_LINE);

        appendPolicy(report, device.policy(), strings, timestamps);
        appendKiosk(report, device.kiosk(), strings);
        appendUpdates(report, device.updates(), strings, timestamps);
        appendManagement(report, device, strings);
        appendReconciliation(report, device.reconciliation(), strings, timestamps);
        appendPlatform(report, device.platform(), strings);

        return report.toString().strip();
    }

    private static void appendPolicy(
            StringBuilder report,
            Policy policy,
            Strings strings,
            Timestamps timestamps
    ) {
        report.append(strings.get(R.string.health_section_policy)).append(NEW_LINE);
        line(report, strings, R.string.health_field_device_owner,
                strings.get(ownershipRes(policy.ownership())));
        line(report, strings, R.string.health_field_verification,
                strings.get(verificationRes(policy.verification())));
        line(report, strings, R.string.health_field_last_verified,
                policy.lastVerifiedAtMillis() <= 0L
                        ? strings.get(R.string.health_value_never)
                        : timestamps.format(policy.lastVerifiedAtMillis()));
        line(report, strings, R.string.health_field_blocked,
                String.valueOf(policy.packages().blocked()));
        line(report, strings, R.string.health_field_allowed,
                String.valueOf(policy.packages().allowed()));
        line(report, strings, R.string.health_field_system_controls,
                strings.get(
                        R.string.health_value_system_controls,
                        policy.systemControls().requested(),
                        policy.systemControls().applied(),
                        policy.systemControls().faulted(),
                        policy.systemControls().advisoryFailures(),
                        policy.systemControls().unsupportedRequested()));
        report.append(NEW_LINE);
    }

    private static void appendKiosk(StringBuilder report, Kiosk kiosk, Strings strings) {
        report.append(strings.get(R.string.health_section_kiosk)).append(NEW_LINE);
        line(report, strings, R.string.health_field_kiosk_state,
                strings.get(kioskStateRes(kiosk.state())));
        line(report, strings, R.string.health_field_kiosk_profile,
                strings.get(kioskProfileRes(kiosk.profile())));
        if (kiosk.profile() == KioskProfile.SINGLE_APP) {
            line(report, strings, R.string.health_field_kiosk_target,
                    valueOrUnknown(kiosk.targetPackage(), strings));
        }
        if (kiosk.profile() == KioskProfile.SINGLE_SITE) {
            // The origin, never the URL. The path and query of a kiosk target can
            // carry a one-time code, and this line is the one an administrator is
            // most likely to paste into a ticket.
            line(report, strings, R.string.health_field_kiosk_origin,
                    valueOrUnknown(DeviceHealthRedaction.originOf(kiosk.siteUrl()), strings));
        }
        report.append(NEW_LINE);
    }

    private static void appendUpdates(
            StringBuilder report,
            Updates updates,
            Strings strings,
            Timestamps timestamps
    ) {
        report.append(strings.get(R.string.health_section_updates)).append(NEW_LINE);
        line(report, strings, R.string.health_field_update_channel,
                strings.get(updates.channelEnabled()
                        ? R.string.health_value_enabled : R.string.health_value_disabled));
        line(report, strings, R.string.health_field_update_state,
                strings.get(updateStateRes(updates.state())));
        line(report, strings, R.string.health_field_last_check,
                updates.lastCheckedAtMillis() <= 0L
                        ? strings.get(R.string.health_value_never)
                        : timestamps.format(updates.lastCheckedAtMillis()));
        line(report, strings, R.string.health_field_installed_version,
                valueOrUnknown(updates.installedVersion(), strings));
        report.append(NEW_LINE);
    }

    private static void appendManagement(
            StringBuilder report,
            DeviceHealthSnapshot device,
            Strings strings
    ) {
        report.append(strings.get(R.string.health_section_management)).append(NEW_LINE);
        if (device.managementIdentities().isEmpty()) {
            report.append(strings.get(R.string.health_value_none)).append(NEW_LINE);
        }
        for (ManagementIdentity identity : device.managementIdentities()) {
            report.append(strings.get(
                            R.string.health_line,
                            valueOrUnknown(identity.packageName(), strings),
                            strings.get(identityRes(identity.verdict()))))
                    .append(NEW_LINE);
        }
        report.append(NEW_LINE);
    }

    private static void appendReconciliation(
            StringBuilder report,
            Reconciliation reconciliation,
            Strings strings,
            Timestamps timestamps
    ) {
        report.append(strings.get(R.string.health_section_reconciliation)).append(NEW_LINE);
        line(report, strings, R.string.health_field_reconciliation,
                strings.get(reconciliationRes(reconciliation.outcome())));
        line(report, strings, R.string.health_field_reconciliation_at,
                reconciliation.atMillis() <= 0L
                        ? strings.get(R.string.health_value_never)
                        : timestamps.format(reconciliation.atMillis()));
        report.append(NEW_LINE);
    }

    private static void appendPlatform(
            StringBuilder report,
            Platform platform,
            Strings strings
    ) {
        report.append(strings.get(R.string.health_section_platform)).append(NEW_LINE);
        line(report, strings, R.string.health_field_android_release,
                valueOrUnknown(platform.androidRelease(), strings));
        line(report, strings, R.string.health_field_build_fingerprint,
                valueOrUnknown(platform.buildFingerprint(), strings));
        line(report, strings, R.string.health_field_app_version,
                valueOrUnknown(platform.applicationVersion(), strings));
        report.append(NEW_LINE);
    }

    private static void line(StringBuilder report, Strings strings, int labelRes, String value) {
        report.append(strings.get(R.string.health_line, strings.get(labelRes), value))
                .append(NEW_LINE);
    }

    private static String valueOrUnknown(String value, Strings strings) {
        return value == null || value.isBlank()
                ? strings.get(R.string.health_value_unknown)
                : value;
    }

    /**
     * The redacted, machine-readable export.
     *
     * <p>Redaction is applied here rather than expected of the caller, and the
     * assessment is taken from the redacted snapshot, so the exported status is
     * exactly the status the redacted facts support. Redaction never changes the
     * assessment — no rule reads a field it removes — so this is the same answer
     * the local screen shows, not a milder one.
     *
     * <p>The format is one {@code key=value} line per fact, ASCII only, in a fixed
     * order, so a diff between two exports of the same device is readable and a
     * script can parse it without a library. It is written when an administrator
     * asks for it and at no other time.
     */
    public static String export(DeviceHealthSnapshot snapshot, long generatedAtMillis) {
        DeviceHealthSnapshot device = DeviceHealthRedaction.redact(snapshot);
        Assessment assessment = DeviceHealthAssessor.assess(device, generatedAtMillis);

        StringBuilder out = new StringBuilder();
        out.append(EXPORT_FORMAT).append(NEW_LINE);
        out.append("# operator-initiated local export; Device Guard transmits nothing on its own")
                .append(NEW_LINE);
        entry(out, "generated-at", generatedAtMillis);
        entry(out, "status", assessment.status().name());
        for (DeviceHealthFinding finding : assessment.findings()) {
            entry(out, "finding", finding.severity().name() + " " + finding.code());
        }

        Policy policy = device.policy();
        entry(out, "policy.verification", policy.verification().name());
        entry(out, "policy.ownership", policy.ownership().name());
        entry(out, "policy.last-verified-at", policy.lastVerifiedAtMillis());
        for (String error : policy.verificationErrors()) {
            entry(out, "policy.error", error);
        }
        entry(out, "policy.packages.blocked", policy.packages().blocked());
        entry(out, "policy.packages.allowed", policy.packages().allowed());
        entry(out, "policy.system-controls.requested", policy.systemControls().requested());
        entry(out, "policy.system-controls.applied", policy.systemControls().applied());
        entry(out, "policy.system-controls.faulted", policy.systemControls().faulted());
        entry(out, "policy.system-controls.advisory-failures",
                policy.systemControls().advisoryFailures());
        entry(out, "policy.system-controls.unsupported-requested",
                policy.systemControls().unsupportedRequested());

        Kiosk kiosk = device.kiosk();
        entry(out, "kiosk.state", kiosk.state().name());
        entry(out, "kiosk.profile", kiosk.profile().name());
        entry(out, "kiosk.target", kiosk.targetPackage());
        entry(out, "kiosk.origin", kiosk.siteUrl());
        entry(out, "kiosk.target-resolved", kiosk.targetResolved());

        Updates updates = device.updates();
        entry(out, "updates.channel-enabled", updates.channelEnabled());
        entry(out, "updates.state", updates.state().name());
        entry(out, "updates.last-checked-at", updates.lastCheckedAtMillis());
        entry(out, "updates.installed-version", updates.installedVersion());
        entry(out, "updates.installed-version-code", updates.installedVersionCode());

        for (ManagementIdentity identity : device.managementIdentities()) {
            entry(out, "management.identity",
                    identity.packageName() + " " + identity.verdict().name());
        }

        Reconciliation reconciliation = device.reconciliation();
        entry(out, "reconciliation.outcome", reconciliation.outcome().name());
        entry(out, "reconciliation.at", reconciliation.atMillis());
        entry(out, "reconciliation.trigger", reconciliation.trigger());

        Platform platform = device.platform();
        entry(out, "platform.android-release", platform.androidRelease());
        entry(out, "platform.sdk-int", platform.sdkInt());
        entry(out, "platform.build-fingerprint", platform.buildFingerprint());
        entry(out, "platform.app-version", platform.applicationVersion());
        entry(out, "platform.app-version-code", platform.applicationVersionCode());

        for (AuditEvent event : device.audit()) {
            entry(out, "audit", event.atMillis() + " " + event.eventCode());
        }

        return out.toString().strip();
    }

    private static void entry(StringBuilder out, String key, String value) {
        // A value is already redacted by the time it reaches here; the newline
        // guard exists because a single stray line break would let one field
        // impersonate another in the exported format.
        out.append(key).append('=')
                .append(value == null ? "" : value.replace('\n', ' ').replace('\r', ' '))
                .append(NEW_LINE);
    }

    private static void entry(StringBuilder out, String key, long value) {
        entry(out, key, String.valueOf(value));
    }

    private static void entry(StringBuilder out, String key, int value) {
        entry(out, key, String.valueOf(value));
    }

    private static void entry(StringBuilder out, String key, boolean value) {
        entry(out, key, String.valueOf(value));
    }

    /**
     * The operator-facing sentence for one finding.
     *
     * <p>Exhaustive on purpose: a finding added to {@link Finding} without a
     * sentence will not compile, and
     * {@code DeviceHealthStringsParityTest} catches the other half of that
     * mistake — a branch pointing at a key one of the two locales never defined.
     */
    public static int messageRes(Finding finding) {
        return switch (finding) {
            case SNAPSHOT_UNAVAILABLE -> R.string.health_finding_snapshot_unavailable;
            case DEVICE_OWNER_MISSING -> R.string.health_finding_device_owner_missing;
            case DEVICE_OWNER_UNKNOWN -> R.string.health_finding_device_owner_unknown;
            case POLICY_VERIFICATION_FAILED -> R.string.health_finding_policy_verification_failed;
            case POLICY_VERIFICATION_UNKNOWN -> R.string.health_finding_policy_verification_unknown;
            case POLICY_NEVER_VERIFIED -> R.string.health_finding_policy_never_verified;
            case POLICY_NOT_REQUESTED -> R.string.health_finding_policy_not_requested;
            case POLICY_VERIFICATION_STALE -> R.string.health_finding_policy_verification_stale;
            case POLICY_VERIFIED -> R.string.health_finding_policy_verified;
            case SYSTEM_CONTROL_FAULTED -> R.string.health_finding_system_control_faulted;
            case SYSTEM_CONTROL_ADVISORY_FAILED ->
                    R.string.health_finding_system_control_advisory_failed;
            case SYSTEM_CONTROL_UNSUPPORTED -> R.string.health_finding_system_control_unsupported;
            case MANAGEMENT_IDENTITY_REJECTED ->
                    R.string.health_finding_management_identity_rejected;
            case MANAGEMENT_IDENTITY_UNPROVEN ->
                    R.string.health_finding_management_identity_unproven;
            case MANAGEMENT_IDENTITY_MISSING -> R.string.health_finding_management_identity_missing;
            case MANAGEMENT_IDENTITY_VERIFIED ->
                    R.string.health_finding_management_identity_verified;
            case MANAGEMENT_NOT_CONFIGURED -> R.string.health_finding_management_not_configured;
            case RECONCILIATION_CRASHED -> R.string.health_finding_reconciliation_crashed;
            case RECONCILIATION_FAILED -> R.string.health_finding_reconciliation_failed;
            case RECONCILIATION_UNKNOWN -> R.string.health_finding_reconciliation_unknown;
            case RECONCILIATION_NEVER_RUN -> R.string.health_finding_reconciliation_never_run;
            case RECONCILIATION_VERIFIED -> R.string.health_finding_reconciliation_verified;
            case KIOSK_FAULTED -> R.string.health_finding_kiosk_faulted;
            case KIOSK_TARGET_UNRESOLVED -> R.string.health_finding_kiosk_target_unresolved;
            case KIOSK_STATE_UNKNOWN -> R.string.health_finding_kiosk_state_unknown;
            case KIOSK_ARMED_NOT_ACTIVE -> R.string.health_finding_kiosk_armed_not_active;
            case KIOSK_ACTIVE -> R.string.health_finding_kiosk_active;
            case KIOSK_OFF -> R.string.health_finding_kiosk_off;
            case UPDATE_CHANNEL_DISABLED -> R.string.health_finding_update_channel_disabled;
            case UPDATE_STATE_UNKNOWN -> R.string.health_finding_update_state_unknown;
            case UPDATE_NEVER_CHECKED -> R.string.health_finding_update_never_checked;
            case UPDATE_FAILED -> R.string.health_finding_update_failed;
            case UPDATE_CHECK_STALE -> R.string.health_finding_update_check_stale;
            case UPDATE_PENDING -> R.string.health_finding_update_pending;
            case UPDATE_IN_PROGRESS -> R.string.health_finding_update_in_progress;
            case UPDATE_CURRENT -> R.string.health_finding_update_current;
            case PLATFORM_NOT_READABLE -> R.string.health_finding_platform_not_readable;
        };
    }

    public static int statusRes(DeviceHealthStatus status) {
        return switch (status) {
            case HEALTHY -> R.string.health_status_healthy;
            case DEGRADED -> R.string.health_status_degraded;
            case UNVERIFIED -> R.string.health_status_unverified;
            case FAILED -> R.string.health_status_failed;
        };
    }

    public static int statusBodyRes(DeviceHealthStatus status) {
        return switch (status) {
            case HEALTHY -> R.string.health_status_healthy_body;
            case DEGRADED -> R.string.health_status_degraded_body;
            case UNVERIFIED -> R.string.health_status_unverified_body;
            case FAILED -> R.string.health_status_failed_body;
        };
    }

    public static int severityRes(Severity severity) {
        return switch (severity) {
            case INFO -> R.string.health_severity_info;
            case ADVISORY -> R.string.health_severity_advisory;
            case UNVERIFIED -> R.string.health_severity_unverified;
            case CRITICAL -> R.string.health_severity_critical;
        };
    }

    public static int ownershipRes(Ownership ownership) {
        return switch (ownership) {
            case DEVICE_OWNER -> R.string.health_ownership_device_owner;
            case NOT_DEVICE_OWNER -> R.string.health_ownership_not_device_owner;
            case UNKNOWN -> R.string.health_ownership_unknown;
        };
    }

    public static int verificationRes(PolicyVerification verification) {
        return switch (verification) {
            case NOT_REQUESTED -> R.string.health_policy_verification_not_requested;
            case REQUESTED_NOT_VERIFIED -> R.string.health_policy_verification_requested_not_verified;
            case VERIFIED -> R.string.health_policy_verification_verified;
            case FAILED -> R.string.health_policy_verification_failed;
            case UNKNOWN -> R.string.health_policy_verification_unknown;
        };
    }

    public static int kioskStateRes(KioskPresence state) {
        return switch (state) {
            case OFF -> R.string.health_kiosk_state_off;
            case ARMED -> R.string.health_kiosk_state_armed;
            case ACTIVE -> R.string.health_kiosk_state_active;
            case FAULT -> R.string.health_kiosk_state_fault;
            case UNKNOWN -> R.string.health_kiosk_state_unknown;
        };
    }

    public static int kioskProfileRes(KioskProfile profile) {
        return switch (profile) {
            case NONE -> R.string.health_kiosk_profile_none;
            case SINGLE_APP -> R.string.health_kiosk_profile_single_app;
            case SINGLE_SITE -> R.string.health_kiosk_profile_single_site;
        };
    }

    public static int updateStateRes(UpdateState state) {
        return switch (state) {
            case NOT_CONFIGURED -> R.string.health_update_state_not_configured;
            case NEVER_CHECKED -> R.string.health_update_state_never_checked;
            case UP_TO_DATE -> R.string.health_update_state_up_to_date;
            case UPDATE_PENDING -> R.string.health_update_state_update_pending;
            case IN_PROGRESS -> R.string.health_update_state_in_progress;
            case FAILED -> R.string.health_update_state_failed;
            case UNKNOWN -> R.string.health_update_state_unknown;
        };
    }

    public static int identityRes(IdentityVerdict verdict) {
        return switch (verdict) {
            case PINNED_MATCH -> R.string.health_identity_pinned_match;
            case PINNED_MISMATCH -> R.string.health_identity_pinned_mismatch;
            case UNPINNED -> R.string.health_identity_unpinned;
            case UNKNOWN_SIGNER -> R.string.health_identity_unknown_signer;
            case NOT_INSTALLED -> R.string.health_identity_not_installed;
        };
    }

    public static int reconciliationRes(ReconciliationOutcome outcome) {
        return switch (outcome) {
            case NEVER_RUN -> R.string.health_reconciliation_never_run;
            case VERIFIED -> R.string.health_reconciliation_verified;
            case FAILED -> R.string.health_reconciliation_failed;
            case CRASHED -> R.string.health_reconciliation_crashed;
            case UNKNOWN -> R.string.health_reconciliation_unknown;
        };
    }
}
