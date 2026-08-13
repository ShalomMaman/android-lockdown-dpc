package com.example.lockdowndpc.health;

import java.util.ArrayList;
import java.util.List;

/**
 * Everything the device health report is allowed to reason about, as plain data.
 *
 * <p>This type reads nothing. It is populated by a thin Android adapter that
 * already holds the answers — {@code AllowedAppsStore}, {@code SystemPolicyStore},
 * {@code KioskConfigStore}, {@code UpdateStateStore}, {@code LockdownPackages} —
 * so that every rule in {@link DeviceHealthAssessor} and every rule in
 * {@link DeviceHealthRedaction} is an ordinary JVM test rather than an
 * instrumentation run. The health package therefore holds no Android type at all.
 *
 * <p>The vocabulary is deliberately verification-honest and mirrors
 * {@code SystemPolicyOutcome}: a field says what was <em>observed</em>, never what
 * was <em>intended</em>. There is an {@code UNKNOWN} constant in every enum
 * because "the adapter could not read this" is a real device state, and the one
 * thing it must never collapse into is the healthy one.
 *
 * <p>Nothing here leaves the device on its own. The snapshot exists to be
 * rendered locally by {@link DeviceHealthReport}; the export is written only when
 * an administrator asks for it, and only after {@link DeviceHealthRedaction} has
 * reduced it.
 */
public record DeviceHealthSnapshot(
        Policy policy,
        Kiosk kiosk,
        Updates updates,
        List<ManagementIdentity> managementIdentities,
        Reconciliation reconciliation,
        Platform platform,
        List<AuditEvent> audit
) {

    public DeviceHealthSnapshot {
        policy = policy == null ? Policy.unknown() : policy;
        kiosk = kiosk == null ? Kiosk.unknown() : kiosk;
        updates = updates == null ? Updates.unknown() : updates;
        managementIdentities = copyOf(managementIdentities);
        reconciliation = reconciliation == null ? Reconciliation.unknown() : reconciliation;
        platform = platform == null ? Platform.unreadable() : platform;
        audit = copyOf(audit);
    }

    /**
     * A device whose state could not be read at all.
     *
     * <p>Assessed as {@code UNVERIFIED}, never as healthy. An adapter that throws
     * has to be able to produce something, and the something must not be a clean
     * bill of health.
     */
    public static DeviceHealthSnapshot unreadable() {
        return new DeviceHealthSnapshot(
                Policy.unknown(),
                Kiosk.unknown(),
                Updates.unknown(),
                List.of(),
                Reconciliation.unknown(),
                Platform.unreadable(),
                List.of()
        );
    }

    /** What the last policy pass proved, in the same vocabulary the console uses. */
    public enum PolicyVerification {
        /** Protection is deliberately off. Nothing is being enforced. */
        NOT_REQUESTED,
        /** Protection is on, but nothing has been read back since it changed. */
        REQUESTED_NOT_VERIFIED,
        /** The last pass wrote every control and read every one of them back. */
        VERIFIED,
        /** The platform's state disagreed with what was asked for. */
        FAILED,
        /** The stored state could not be read. Never treated as either extreme. */
        UNKNOWN
    }

    /**
     * Whether Device Guard is the Device Owner of this device.
     *
     * <p>Three states rather than a boolean, because "the platform could not be
     * asked" is not the same claim as "Device Guard is not the owner". The first
     * is an unproven device; the second is an unmanaged one, and reporting the
     * first as the second sends an operator to re-provision a device that may be
     * fine.
     */
    public enum Ownership {
        DEVICE_OWNER,
        NOT_DEVICE_OWNER,
        UNKNOWN
    }

    /**
     * The policy half of the report.
     *
     * @param verification        what the last pass proved
     * @param ownership           whether Device Guard is still the Device Owner
     * @param lastVerifiedAtMillis epoch millis of the last verified pass, 0 for never
     * @param verificationErrors  the machine-readable errors of the last pass
     * @param packages            how many packages the pass blocked and allowed
     * @param systemControls      the aggregate of the system policy report
     */
    public record Policy(
            PolicyVerification verification,
            Ownership ownership,
            long lastVerifiedAtMillis,
            List<String> verificationErrors,
            PackageCensus packages,
            SystemControls systemControls
    ) {
        public Policy {
            verification = verification == null ? PolicyVerification.UNKNOWN : verification;
            ownership = ownership == null ? Ownership.UNKNOWN : ownership;
            lastVerifiedAtMillis = Math.max(0L, lastVerifiedAtMillis);
            verificationErrors = copyOf(verificationErrors);
            packages = packages == null ? PackageCensus.none() : packages;
            systemControls = systemControls == null ? SystemControls.none() : systemControls;
        }

        public static Policy unknown() {
            return new Policy(
                    PolicyVerification.UNKNOWN,
                    Ownership.UNKNOWN,
                    0L,
                    List.of(),
                    PackageCensus.none(),
                    SystemControls.none()
            );
        }
    }

    /**
     * How many packages the policy governs, and — for the local report only —
     * which ones.
     *
     * <p>The counts and the names are separate fields on purpose. An administrator
     * standing in front of the device may see the names; they are already on the
     * inventory screen. An export may not, because a list of every application on
     * a device profiles the person holding it. {@link DeviceHealthRedaction} drops
     * the names and keeps the counts, which is the fleet-relevant part.
     */
    public record PackageCensus(
            int blocked,
            int allowed,
            List<String> blockedPackages,
            List<String> allowedPackages
    ) {
        public PackageCensus {
            blocked = Math.max(0, blocked);
            allowed = Math.max(0, allowed);
            blockedPackages = copyOf(blockedPackages);
            allowedPackages = copyOf(allowedPackages);
        }

        /** Counts derived from the names, for a caller that holds both. */
        public static PackageCensus of(List<String> blocked, List<String> allowed) {
            List<String> blockedNames = copyOf(blocked);
            List<String> allowedNames = copyOf(allowed);
            return new PackageCensus(
                    blockedNames.size(), allowedNames.size(), blockedNames, allowedNames);
        }

        /** Counts only, for a caller that never held the names. */
        public static PackageCensus counted(int blocked, int allowed) {
            return new PackageCensus(blocked, allowed, List.of(), List.of());
        }

        public static PackageCensus none() {
            return counted(0, 0);
        }
    }

    /**
     * The aggregate of one {@code SystemPolicyReport}.
     *
     * @param requested            controls the administrator has on
     * @param applied              controls the platform confirmed in force
     * @param faulted              requested critical controls that failed
     * @param advisoryFailures     failures that are recorded but do not fault
     * @param unsupportedRequested controls this Android release cannot honour
     */
    public record SystemControls(
            int requested,
            int applied,
            int faulted,
            int advisoryFailures,
            int unsupportedRequested
    ) {
        public SystemControls {
            requested = Math.max(0, requested);
            applied = Math.max(0, applied);
            faulted = Math.max(0, faulted);
            advisoryFailures = Math.max(0, advisoryFailures);
            unsupportedRequested = Math.max(0, unsupportedRequested);
        }

        public static SystemControls none() {
            return new SystemControls(0, 0, 0, 0, 0);
        }
    }

    /** The persisted kiosk state, in the vocabulary of {@code KioskStateMachine}. */
    public enum KioskPresence {
        OFF,
        ARMED,
        ACTIVE,
        FAULT,
        UNKNOWN
    }

    /** Which kiosk profile is configured, if any. */
    public enum KioskProfile {
        NONE,
        SINGLE_APP,
        SINGLE_SITE
    }

    /**
     * @param targetResolved whether the configured target still resolves on this
     *                       device; an armed kiosk pointing at an uninstalled
     *                       application is a fault waiting for the next activation
     * @param siteUrl        the configured single-site URL as stored. The export
     *                       never carries more than its origin.
     */
    public record Kiosk(
            KioskPresence state,
            KioskProfile profile,
            String targetPackage,
            String siteUrl,
            boolean targetResolved
    ) {
        public Kiosk {
            state = state == null ? KioskPresence.UNKNOWN : state;
            profile = profile == null ? KioskProfile.NONE : profile;
            targetPackage = targetPackage == null ? "" : targetPackage;
            siteUrl = siteUrl == null ? "" : siteUrl;
        }

        public static Kiosk off() {
            return new Kiosk(KioskPresence.OFF, KioskProfile.NONE, "", "", true);
        }

        public static Kiosk unknown() {
            return new Kiosk(KioskPresence.UNKNOWN, KioskProfile.NONE, "", "", false);
        }
    }

    /**
     * The update channel as the device last observed it.
     *
     * <p>Mapped by the adapter from {@code UpdatePhase} rather than reused from
     * it, so this package stays free of the Kotlin update module and the report
     * keeps its own stable vocabulary if the phases are ever renamed.
     */
    public enum UpdateState {
        NOT_CONFIGURED,
        NEVER_CHECKED,
        UP_TO_DATE,
        UPDATE_PENDING,
        IN_PROGRESS,
        FAILED,
        UNKNOWN
    }

    /**
     * @param lastResultDetail the operator-facing message of the last result. It
     *                         is free text of unknown provenance, so the export
     *                         never carries it.
     */
    public record Updates(
            boolean channelEnabled,
            UpdateState state,
            long lastCheckedAtMillis,
            String lastResultDetail,
            String installedVersion,
            long installedVersionCode
    ) {
        public Updates {
            state = state == null ? UpdateState.UNKNOWN : state;
            lastCheckedAtMillis = Math.max(0L, lastCheckedAtMillis);
            lastResultDetail = lastResultDetail == null ? "" : lastResultDetail;
            installedVersion = installedVersion == null ? "" : installedVersion;
        }

        public static Updates unknown() {
            return new Updates(false, UpdateState.UNKNOWN, 0L, "", "", -1L);
        }
    }

    /**
     * What comparing an installed management signer against its record proved.
     *
     * <p>{@link #UNPINNED} is the honest name for the pilot's documented gap:
     * trust resting on a package name alone. It is a verdict, not a pass, and
     * {@link DeviceHealthAssessor} refuses to call such a device healthy.
     */
    public enum IdentityVerdict {
        PINNED_MATCH,
        PINNED_MISMATCH,
        UNPINNED,
        UNKNOWN_SIGNER,
        NOT_INSTALLED
    }

    public record ManagementIdentity(String packageName, IdentityVerdict verdict) {
        public ManagementIdentity {
            packageName = packageName == null ? "" : packageName;
            verdict = verdict == null ? IdentityVerdict.UNKNOWN_SIGNER : verdict;
        }
    }

    /** How the last complete reconciliation pass ended. */
    public enum ReconciliationOutcome {
        NEVER_RUN,
        VERIFIED,
        FAILED,
        CRASHED,
        UNKNOWN
    }

    /**
     * @param trigger a short machine-readable reason such as {@code boot}
     * @param detail  free text from the failure path; never exported
     */
    public record Reconciliation(
            ReconciliationOutcome outcome,
            long atMillis,
            String trigger,
            String detail
    ) {
        public Reconciliation {
            outcome = outcome == null ? ReconciliationOutcome.UNKNOWN : outcome;
            atMillis = Math.max(0L, atMillis);
            trigger = trigger == null ? "" : trigger;
            detail = detail == null ? "" : detail;
        }

        public static Reconciliation unknown() {
            return new Reconciliation(ReconciliationOutcome.UNKNOWN, 0L, "", "");
        }

        public static Reconciliation neverRun() {
            return new Reconciliation(ReconciliationOutcome.NEVER_RUN, 0L, "", "");
        }
    }

    /** Firmware and application identity — the fleet columns, not user data. */
    public record Platform(
            String androidRelease,
            int sdkInt,
            String buildFingerprint,
            String applicationVersion,
            long applicationVersionCode
    ) {
        public Platform {
            androidRelease = androidRelease == null ? "" : androidRelease;
            buildFingerprint = buildFingerprint == null ? "" : buildFingerprint;
            applicationVersion = applicationVersion == null ? "" : applicationVersion;
            sdkInt = Math.max(0, sdkInt);
        }

        public static Platform unreadable() {
            return new Platform("", 0, "", "", -1L);
        }

        /** Whether enough was read to state what this device actually is. */
        public boolean readable() {
            return !androidRelease.isBlank() && sdkInt > 0 && !buildFingerprint.isBlank();
        }
    }

    /**
     * One administrator action, as a stable event code rather than as prose.
     *
     * <p>{@code AuditLog} stores localized sentences today, which is right for the
     * screen an administrator reads and wrong for anything that leaves the device:
     * a sentence can carry whatever a call site interpolated into it. The export
     * therefore carries codes only, and {@link DeviceHealthRedaction} drops every
     * entry whose code it does not recognise.
     *
     * @param detail free text kept for the local report; never exported
     */
    public record AuditEvent(long atMillis, String eventCode, String detail) {
        public AuditEvent {
            atMillis = Math.max(0L, atMillis);
            eventCode = eventCode == null ? "" : eventCode;
            detail = detail == null ? "" : detail;
        }
    }

    /** Null-tolerant immutable copy; {@code List.copyOf} rejects null elements. */
    static <T> List<T> copyOf(List<T> source) {
        if (source == null || source.isEmpty()) {
            return List.of();
        }
        List<T> copy = new ArrayList<>(source.size());
        for (T element : source) {
            if (element != null) {
                copy.add(element);
            }
        }
        return List.copyOf(copy);
    }
}
