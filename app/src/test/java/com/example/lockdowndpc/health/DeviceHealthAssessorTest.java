package com.example.lockdowndpc.health;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.health.DeviceHealthAssessor.Assessment;
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
import com.example.lockdowndpc.health.DeviceHealthSnapshot.PackageCensus;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Platform;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Policy;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.PolicyVerification;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Reconciliation;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.ReconciliationOutcome;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.SystemControls;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.UpdateState;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Updates;

import org.junit.Test;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Every status this assessor can reach, and the precedence between findings.
 *
 * <p>The case that matters most is
 * {@link #aPolicyThatWasNeverReadBackIsUnverifiedRatherThanHealthy()}: a device
 * that was asked to apply a policy and never confirmed it looks identical, from
 * a switch-shaped console, to one that applied it perfectly. Reporting the first
 * as healthy is the failure this whole class exists to prevent, and it is the
 * same rule {@code SystemPolicyOutcome} applies one control at a time.
 */
public final class DeviceHealthAssessorTest {

    private static final long NOW = 1_700_000_000_000L;
    private static final long HOUR = 60L * 60L * 1000L;
    private static final long DAY = 24L * HOUR;

    @Test
    public void aFullyProvenDeviceIsHealthy() {
        assertEquals(DeviceHealthStatus.HEALTHY, assess(proven()).status());
    }

    @Test
    public void aPolicyThatWasNeverReadBackIsUnverifiedRatherThanHealthy() {
        DeviceHealthSnapshot snapshot = withPolicy(proven(), policy(
                PolicyVerification.REQUESTED_NOT_VERIFIED, Ownership.DEVICE_OWNER, NOW - HOUR, List.of()));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.UNVERIFIED, assessment.status());
        assertTrue(assessment.has(Finding.POLICY_NEVER_VERIFIED));
    }

    @Test
    public void verifiedWithNoTimestampIsAClaimWithoutEvidence() {
        DeviceHealthSnapshot snapshot = withPolicy(proven(), policy(
                PolicyVerification.VERIFIED, Ownership.DEVICE_OWNER, 0L, List.of()));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.UNVERIFIED, assessment.status());
        assertTrue(assessment.has(Finding.POLICY_NEVER_VERIFIED));
    }

    @Test
    public void aProofOlderThanItsValidityIsNoLongerEvidence() {
        DeviceHealthSnapshot snapshot = withPolicy(proven(), policy(
                PolicyVerification.VERIFIED, Ownership.DEVICE_OWNER, NOW - 8L * DAY, List.of()));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.UNVERIFIED, assessment.status());
        assertTrue(assessment.has(Finding.POLICY_VERIFICATION_STALE));
    }

    @Test
    public void aClockThatRanBackwardsDoesNotManufactureAFault() {
        // A wrong clock must not be able to turn a working device into a report
        // of a problem it does not have; every other finding is read from state.
        DeviceHealthSnapshot snapshot = withPolicy(proven(), policy(
                PolicyVerification.VERIFIED, Ownership.DEVICE_OWNER, NOW + 10L * DAY, List.of()));

        assertEquals(DeviceHealthStatus.HEALTHY, assess(snapshot).status());
    }

    @Test
    public void aPolicyThePlatformDisagreedWithIsFaulted() {
        DeviceHealthSnapshot snapshot = withPolicy(proven(), policy(
                PolicyVerification.FAILED, Ownership.DEVICE_OWNER, NOW - HOUR,
                List.of("package-policy-state-mismatch")));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.FAILED, assessment.status());
        assertTrue(assessment.has(Finding.POLICY_VERIFICATION_FAILED));
    }

    @Test
    public void verifiedWhileStillCarryingErrorsIsReadAsFaulted() {
        // The two halves of the stored state contradict each other. The stricter
        // reading wins, because the optimistic one is the one that hides a fault.
        DeviceHealthSnapshot snapshot = withPolicy(proven(), policy(
                PolicyVerification.VERIFIED, Ownership.DEVICE_OWNER, NOW - HOUR, List.of("link-filter-target-unverified")));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.FAILED, assessment.status());
        assertTrue(assessment.has(Finding.POLICY_VERIFICATION_FAILED));
        assertFalse(assessment.has(Finding.POLICY_VERIFIED));
    }

    @Test
    public void anUnreadablePolicyStateIsUnverified() {
        DeviceHealthSnapshot snapshot = withPolicy(proven(), policy(
                PolicyVerification.UNKNOWN, Ownership.DEVICE_OWNER, 0L, List.of()));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.UNVERIFIED, assessment.status());
        assertTrue(assessment.has(Finding.POLICY_VERIFICATION_UNKNOWN));
    }

    @Test
    public void protectionDeliberatelyOffIsDegradedRatherThanHealthy() {
        DeviceHealthSnapshot snapshot = withPolicy(proven(), policy(
                PolicyVerification.NOT_REQUESTED, Ownership.DEVICE_OWNER, 0L, List.of()));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.DEGRADED, assessment.status());
        assertTrue(assessment.has(Finding.POLICY_NOT_REQUESTED));
    }

    @Test
    public void aDeviceWithNoOwnershipReportsThatAndNotItsConsequences() {
        DeviceHealthSnapshot snapshot = withPolicy(proven(), policy(
                PolicyVerification.REQUESTED_NOT_VERIFIED, Ownership.NOT_DEVICE_OWNER, 0L,
                List.of("device-owner-required")));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.FAILED, assessment.status());
        assertTrue(assessment.has(Finding.DEVICE_OWNER_MISSING));
        assertFalse(assessment.has(Finding.POLICY_NEVER_VERIFIED));
        assertFalse(assessment.has(Finding.POLICY_VERIFICATION_FAILED));
    }

    @Test
    public void ownershipThatCouldNotBeReadIsUnverifiedRatherThanUnmanaged() {
        // "Could not ask the platform" is not "Device Guard was removed". Sending
        // an operator to re-provision a device that is fine is the more expensive
        // of the two mistakes, and the report has no business guessing.
        DeviceHealthSnapshot snapshot = withPolicy(proven(), policy(
                PolicyVerification.UNKNOWN, Ownership.UNKNOWN, 0L, List.of()));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.UNVERIFIED, assessment.status());
        assertTrue(assessment.has(Finding.DEVICE_OWNER_UNKNOWN));
        assertFalse(assessment.has(Finding.DEVICE_OWNER_MISSING));
        assertFalse(assessment.has(Finding.POLICY_VERIFICATION_UNKNOWN));
    }

    @Test
    public void aFaultedSystemControlFaultsTheDevice() {
        DeviceHealthSnapshot snapshot = withSystemControls(proven(),
                new SystemControls(16, 15, 1, 0, 0));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.FAILED, assessment.status());
        assertTrue(assessment.has(Finding.SYSTEM_CONTROL_FAULTED));
    }

    @Test
    public void anAdvisorySystemControlRefusalDegradesWithoutFaulting() {
        DeviceHealthSnapshot snapshot = withSystemControls(proven(),
                new SystemControls(16, 15, 0, 1, 0));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.DEGRADED, assessment.status());
        assertTrue(assessment.has(Finding.SYSTEM_CONTROL_ADVISORY_FAILED));
    }

    @Test
    public void anOlderAndroidIsReportedButIsNotABrokenDevice() {
        DeviceHealthSnapshot snapshot = withSystemControls(proven(),
                new SystemControls(16, 14, 0, 0, 2));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.HEALTHY, assessment.status());
        assertTrue(assessment.has(Finding.SYSTEM_CONTROL_UNSUPPORTED));
    }

    @Test
    public void managementTrustedByPackageNameAloneIsNeverHealthy() {
        // The pilot's documented proof gap. It is a verdict, not a pass.
        DeviceHealthSnapshot snapshot = withIdentities(proven(),
                List.of(new ManagementIdentity("com.tailscale.ipn", IdentityVerdict.UNPINNED)));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.UNVERIFIED, assessment.status());
        assertTrue(assessment.has(Finding.MANAGEMENT_IDENTITY_UNPROVEN));
    }

    @Test
    public void aRejectedManagementSignerFaultsTheDevice() {
        DeviceHealthSnapshot snapshot = withIdentities(proven(), List.of(
                new ManagementIdentity("com.tailscale.ipn", IdentityVerdict.PINNED_MISMATCH),
                new ManagementIdentity("com.example.other", IdentityVerdict.UNPINNED)));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.FAILED, assessment.status());
        assertTrue(assessment.has(Finding.MANAGEMENT_IDENTITY_REJECTED));
        assertFalse(assessment.has(Finding.MANAGEMENT_IDENTITY_UNPROVEN));
    }

    @Test
    public void anUnreadableManagementSignerIsAlsoARejection() {
        DeviceHealthSnapshot snapshot = withIdentities(proven(),
                List.of(new ManagementIdentity("com.tailscale.ipn", IdentityVerdict.UNKNOWN_SIGNER)));

        assertTrue(assess(snapshot).has(Finding.MANAGEMENT_IDENTITY_REJECTED));
    }

    @Test
    public void aMissingManagementApplicationDegrades() {
        DeviceHealthSnapshot snapshot = withIdentities(proven(),
                List.of(new ManagementIdentity("com.tailscale.ipn", IdentityVerdict.NOT_INSTALLED)));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.DEGRADED, assessment.status());
        assertTrue(assessment.has(Finding.MANAGEMENT_IDENTITY_MISSING));
    }

    @Test
    public void aDeviceWithNoManagementApplicationIsRecordedNotDowngraded() {
        DeviceHealthSnapshot snapshot = withIdentities(proven(), List.of());

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.HEALTHY, assessment.status());
        assertTrue(assessment.has(Finding.MANAGEMENT_NOT_CONFIGURED));
    }

    @Test
    public void aCrashedReconciliationFaultsTheDevice() {
        DeviceHealthSnapshot snapshot = withReconciliation(proven(),
                new Reconciliation(ReconciliationOutcome.CRASHED, NOW - HOUR, "boot", "NullPointerException"));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.FAILED, assessment.status());
        assertTrue(assessment.has(Finding.RECONCILIATION_CRASHED));
    }

    @Test
    public void aFailedReconciliationFaultsTheDevice() {
        DeviceHealthSnapshot snapshot = withReconciliation(proven(),
                new Reconciliation(ReconciliationOutcome.FAILED, NOW - HOUR, "package-changed", ""));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.FAILED, assessment.status());
        assertTrue(assessment.has(Finding.RECONCILIATION_FAILED));
    }

    @Test
    public void aReconciliationThatNeverRanIsUnverified() {
        DeviceHealthSnapshot snapshot = withReconciliation(proven(), Reconciliation.neverRun());

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.UNVERIFIED, assessment.status());
        assertTrue(assessment.has(Finding.RECONCILIATION_NEVER_RUN));
    }

    @Test
    public void aVerifiedReconciliationWithNoTimeIsUnverified() {
        DeviceHealthSnapshot snapshot = withReconciliation(proven(),
                new Reconciliation(ReconciliationOutcome.VERIFIED, 0L, "boot", ""));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.UNVERIFIED, assessment.status());
        assertTrue(assessment.has(Finding.RECONCILIATION_UNKNOWN));
    }

    @Test
    public void anUnreadableReconciliationResultIsUnverified() {
        DeviceHealthSnapshot snapshot = withReconciliation(proven(), Reconciliation.unknown());

        assertEquals(DeviceHealthStatus.UNVERIFIED, assess(snapshot).status());
    }

    @Test
    public void aFaultedKioskFaultsTheDevice() {
        DeviceHealthSnapshot snapshot = withKiosk(proven(), new Kiosk(
                KioskPresence.FAULT, KioskProfile.SINGLE_APP, "com.example.app", "", true));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.FAILED, assessment.status());
        assertTrue(assessment.has(Finding.KIOSK_FAULTED));
    }

    @Test
    public void aKioskPointingAtSomethingThisDeviceLacksFaultsBeforeItIsActivated() {
        DeviceHealthSnapshot snapshot = withKiosk(proven(), new Kiosk(
                KioskPresence.ARMED, KioskProfile.SINGLE_APP, "com.example.app", "", false));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.FAILED, assessment.status());
        assertTrue(assessment.has(Finding.KIOSK_TARGET_UNRESOLVED));
        assertFalse(assessment.has(Finding.KIOSK_ARMED_NOT_ACTIVE));
    }

    @Test
    public void anUnreadableKioskStateIsUnverified() {
        DeviceHealthSnapshot snapshot = withKiosk(proven(), Kiosk.unknown());

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.UNVERIFIED, assessment.status());
        assertTrue(assessment.has(Finding.KIOSK_STATE_UNKNOWN));
    }

    @Test
    public void aConfiguredButUnlockedKioskDegrades() {
        DeviceHealthSnapshot snapshot = withKiosk(proven(), new Kiosk(
                KioskPresence.ARMED, KioskProfile.SINGLE_SITE, "", "https://portal.school.example/", true));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.DEGRADED, assessment.status());
        assertTrue(assessment.has(Finding.KIOSK_ARMED_NOT_ACTIVE));
    }

    @Test
    public void aLockedKioskIsARecordedFact() {
        DeviceHealthSnapshot snapshot = withKiosk(proven(), new Kiosk(
                KioskPresence.ACTIVE, KioskProfile.SINGLE_SITE, "", "https://portal.school.example/", true));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.HEALTHY, assessment.status());
        assertTrue(assessment.has(Finding.KIOSK_ACTIVE));
    }

    @Test
    public void aDeviceWithNoUpdateChannelCannotBeSentAFixAndSaysSo() {
        DeviceHealthSnapshot snapshot = withUpdates(proven(),
                new Updates(false, UpdateState.NOT_CONFIGURED, 0L, "", "0.5.1", 51L));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.DEGRADED, assessment.status());
        assertTrue(assessment.has(Finding.UPDATE_CHANNEL_DISABLED));
    }

    @Test
    public void aConfiguredChannelThatWasNeverCheckedIsUnverified() {
        DeviceHealthSnapshot snapshot = withUpdates(proven(),
                new Updates(true, UpdateState.NEVER_CHECKED, 0L, "", "0.5.1", 51L));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.UNVERIFIED, assessment.status());
        assertTrue(assessment.has(Finding.UPDATE_NEVER_CHECKED));
    }

    @Test
    public void upToDateWithNoRecordedCheckIsNotEvidenceEither() {
        DeviceHealthSnapshot snapshot = withUpdates(proven(),
                new Updates(true, UpdateState.UP_TO_DATE, 0L, "", "0.5.1", 51L));

        assertTrue(assess(snapshot).has(Finding.UPDATE_NEVER_CHECKED));
    }

    @Test
    public void anOldUpdateCheckDegrades() {
        DeviceHealthSnapshot snapshot = withUpdates(proven(),
                new Updates(true, UpdateState.UP_TO_DATE, NOW - 8L * DAY, "", "0.5.1", 51L));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.DEGRADED, assessment.status());
        assertTrue(assessment.has(Finding.UPDATE_CHECK_STALE));
    }

    @Test
    public void aFailedUpdateDegradesButDoesNotFaultProtection() {
        DeviceHealthSnapshot snapshot = withUpdates(proven(),
                new Updates(true, UpdateState.FAILED, NOW - HOUR, "signature mismatch", "0.5.1", 51L));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.DEGRADED, assessment.status());
        assertTrue(assessment.has(Finding.UPDATE_FAILED));
    }

    @Test
    public void aWaitingUpdateDegrades() {
        DeviceHealthSnapshot snapshot = withUpdates(proven(),
                new Updates(true, UpdateState.UPDATE_PENDING, NOW - HOUR, "", "0.5.1", 51L));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.DEGRADED, assessment.status());
        assertTrue(assessment.has(Finding.UPDATE_PENDING));
    }

    @Test
    public void aRunningUpdateIsARecordedFact() {
        DeviceHealthSnapshot snapshot = withUpdates(proven(),
                new Updates(true, UpdateState.IN_PROGRESS, NOW - HOUR, "", "0.5.1", 51L));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.HEALTHY, assessment.status());
        assertTrue(assessment.has(Finding.UPDATE_IN_PROGRESS));
    }

    @Test
    public void anUnreadableUpdateStateIsUnverified() {
        DeviceHealthSnapshot snapshot = withUpdates(proven(),
                new Updates(true, UpdateState.UNKNOWN, NOW - HOUR, "", "0.5.1", 51L));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.UNVERIFIED, assessment.status());
        assertTrue(assessment.has(Finding.UPDATE_STATE_UNKNOWN));
    }

    @Test
    public void aDeviceThatCannotSayWhatFirmwareItRunsDegrades() {
        DeviceHealthSnapshot snapshot = withPlatform(proven(), Platform.unreadable());

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.DEGRADED, assessment.status());
        assertTrue(assessment.has(Finding.PLATFORM_NOT_READABLE));
    }

    @Test
    public void aSnapshotThatCouldNotBeBuiltIsUnverified() {
        Assessment assessment = DeviceHealthAssessor.assess(null, NOW);

        assertEquals(DeviceHealthStatus.UNVERIFIED, assessment.status());
        assertEquals(List.of(Finding.SNAPSHOT_UNAVAILABLE), assessment.codesInOrder());
    }

    @Test
    public void aSnapshotOfAnUnreadableDeviceIsUnverified() {
        assertEquals(
                DeviceHealthStatus.UNVERIFIED,
                assess(DeviceHealthSnapshot.unreadable()).status());
    }

    @Test
    public void anUnprovenStateOutranksAKnownSmallProblem() {
        // A known small problem is smaller than an unknown state, because the
        // unknown state could be any problem at all.
        DeviceHealthSnapshot snapshot = withKiosk(
                withUpdates(proven(),
                        new Updates(true, UpdateState.UP_TO_DATE, NOW - 8L * DAY, "", "0.5.1", 51L)),
                Kiosk.unknown());

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.UNVERIFIED, assessment.status());
        assertTrue(assessment.has(Finding.UPDATE_CHECK_STALE));
        assertTrue(assessment.has(Finding.KIOSK_STATE_UNKNOWN));
    }

    @Test
    public void aFaultOutranksAnUnprovenState() {
        DeviceHealthSnapshot snapshot = withSystemControls(
                withPolicy(proven(), policy(
                        PolicyVerification.REQUESTED_NOT_VERIFIED, Ownership.DEVICE_OWNER, 0L, List.of())),
                new SystemControls(16, 15, 1, 0, 0));

        Assessment assessment = assess(snapshot);

        assertEquals(DeviceHealthStatus.FAILED, assessment.status());
        assertTrue(assessment.has(Finding.POLICY_NEVER_VERIFIED));
        assertTrue(assessment.has(Finding.SYSTEM_CONTROL_FAULTED));
    }

    @Test
    public void theWorstThingAboutADeviceIsItsFirstLine() {
        DeviceHealthSnapshot snapshot = withKiosk(proven(), new Kiosk(
                KioskPresence.FAULT, KioskProfile.SINGLE_APP, "com.example.app", "", true));

        Assessment assessment = assess(snapshot);

        assertEquals(Finding.KIOSK_FAULTED, assessment.codesInOrder().get(0));
        assertEquals(Severity.CRITICAL, assessment.findings().get(0).severity());
    }

    @Test
    public void equallySevereFindingsKeepTheOrderAnAdministratorReadsThemIn() {
        // Stable within a severity band: policy, system controls, management,
        // reconciliation, kiosk, updates, platform.
        Assessment assessment = assess(proven());

        assertEquals(
                List.of(
                        Finding.POLICY_VERIFIED,
                        Finding.MANAGEMENT_IDENTITY_VERIFIED,
                        Finding.RECONCILIATION_VERIFIED,
                        Finding.KIOSK_OFF,
                        Finding.UPDATE_CURRENT),
                assessment.codesInOrder());
    }

    @Test
    public void everyFindingCarriesADistinctStableCode() {
        Set<String> codes = new HashSet<>();
        List<String> duplicates = new ArrayList<>();
        for (Finding finding : Finding.values()) {
            assertFalse(finding + " has a blank code", finding.code().isBlank());
            if (!codes.add(finding.code())) {
                duplicates.add(finding.code());
            }
        }
        assertEquals("finding codes must be unique", List.of(), duplicates);
    }

    @Test
    public void everySeverityMapsOntoTheStatusItProduces() {
        assertEquals(DeviceHealthStatus.HEALTHY, Severity.INFO.status());
        assertEquals(DeviceHealthStatus.DEGRADED, Severity.ADVISORY.status());
        assertEquals(DeviceHealthStatus.UNVERIFIED, Severity.UNVERIFIED.status());
        assertEquals(DeviceHealthStatus.FAILED, Severity.CRITICAL.status());
    }

    @Test
    public void theWorseOfTwoStatusesIsAlwaysTheReportedOne() {
        assertEquals(
                DeviceHealthStatus.FAILED,
                DeviceHealthStatus.worst(DeviceHealthStatus.FAILED, DeviceHealthStatus.UNVERIFIED));
        assertEquals(
                DeviceHealthStatus.UNVERIFIED,
                DeviceHealthStatus.worst(DeviceHealthStatus.DEGRADED, DeviceHealthStatus.UNVERIFIED));
        assertEquals(
                DeviceHealthStatus.DEGRADED,
                DeviceHealthStatus.worst(DeviceHealthStatus.HEALTHY, DeviceHealthStatus.DEGRADED));
        // A missing half is not an argument for the healthier reading.
        assertEquals(
                DeviceHealthStatus.UNVERIFIED,
                DeviceHealthStatus.worst(null, null));
    }

    @Test
    public void anAuditTailDoesNotChangeTheAnswer() {
        // The audit is carried for the report, not consulted by the rules; a
        // device is not healthier because it logged more.
        DeviceHealthSnapshot withAudit = new DeviceHealthSnapshot(
                proven().policy(),
                proven().kiosk(),
                proven().updates(),
                proven().managementIdentities(),
                proven().reconciliation(),
                proven().platform(),
                List.of(new AuditEvent(NOW - HOUR, "policy.apply", "by an administrator")),
                DeviceHealthSnapshot.Maintenance.closed()
        );

        assertEquals(assess(proven()).status(), assess(withAudit).status());
    }

    private static Assessment assess(DeviceHealthSnapshot snapshot) {
        return DeviceHealthAssessor.assess(snapshot, NOW);
    }

    /** A device on which every question this report asks has a proven answer. */
    private static DeviceHealthSnapshot proven() {
        return new DeviceHealthSnapshot(
                policy(PolicyVerification.VERIFIED, Ownership.DEVICE_OWNER, NOW - HOUR, List.of()),
                Kiosk.off(),
                new Updates(true, UpdateState.UP_TO_DATE, NOW - HOUR, "", "0.5.1", 51L),
                List.of(new ManagementIdentity("com.tailscale.ipn", IdentityVerdict.PINNED_MATCH)),
                new Reconciliation(ReconciliationOutcome.VERIFIED, NOW - HOUR, "boot", ""),
                new Platform("14", 34, "brand/product:14/UP1A/9999:user/release-keys", "0.5.1", 51L),
                List.of(),
                DeviceHealthSnapshot.Maintenance.closed()
        );
    }

    private static Policy policy(
            PolicyVerification verification,
            Ownership ownership,
            long lastVerifiedAtMillis,
            List<String> errors
    ) {
        return new Policy(
                verification,
                ownership,
                lastVerifiedAtMillis,
                errors,
                PackageCensus.counted(3, 20),
                new SystemControls(16, 16, 0, 0, 0));
    }

    private static DeviceHealthSnapshot withPolicy(DeviceHealthSnapshot base, Policy policy) {
        return new DeviceHealthSnapshot(
                policy, base.kiosk(), base.updates(), base.managementIdentities(),
                base.reconciliation(), base.platform(), base.audit(),
                DeviceHealthSnapshot.Maintenance.closed()
        );
    }

    private static DeviceHealthSnapshot withSystemControls(
            DeviceHealthSnapshot base,
            SystemControls controls
    ) {
        Policy policy = base.policy();
        return withPolicy(base, new Policy(
                policy.verification(),
                policy.ownership(),
                policy.lastVerifiedAtMillis(),
                policy.verificationErrors(),
                policy.packages(),
                controls));
    }

    private static DeviceHealthSnapshot withKiosk(DeviceHealthSnapshot base, Kiosk kiosk) {
        return new DeviceHealthSnapshot(
                base.policy(), kiosk, base.updates(), base.managementIdentities(),
                base.reconciliation(), base.platform(), base.audit(),
                DeviceHealthSnapshot.Maintenance.closed()
        );
    }

    private static DeviceHealthSnapshot withUpdates(DeviceHealthSnapshot base, Updates updates) {
        return new DeviceHealthSnapshot(
                base.policy(), base.kiosk(), updates, base.managementIdentities(),
                base.reconciliation(), base.platform(), base.audit(),
                DeviceHealthSnapshot.Maintenance.closed()
        );
    }

    private static DeviceHealthSnapshot withIdentities(
            DeviceHealthSnapshot base,
            List<ManagementIdentity> identities
    ) {
        return new DeviceHealthSnapshot(
                base.policy(), base.kiosk(), base.updates(), identities,
                base.reconciliation(), base.platform(), base.audit(),
                DeviceHealthSnapshot.Maintenance.closed()
        );
    }

    private static DeviceHealthSnapshot withReconciliation(
            DeviceHealthSnapshot base,
            Reconciliation reconciliation
    ) {
        return new DeviceHealthSnapshot(
                base.policy(), base.kiosk(), base.updates(), base.managementIdentities(),
                reconciliation, base.platform(), base.audit(),
                DeviceHealthSnapshot.Maintenance.closed()
        );
    }

    private static DeviceHealthSnapshot withPlatform(DeviceHealthSnapshot base, Platform platform) {
        return new DeviceHealthSnapshot(
                base.policy(), base.kiosk(), base.updates(), base.managementIdentities(),
                base.reconciliation(), platform, base.audit(),
                DeviceHealthSnapshot.Maintenance.closed()
        );
    }
}
