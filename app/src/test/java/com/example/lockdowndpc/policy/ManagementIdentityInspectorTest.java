package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Signer inspection for the management identity console.
 *
 * <p>The cases that matter are the ones a device cannot be asked twice about
 * without re-provisioning it: a management package that is not installed, a
 * platform that reports no signer at all, an application signed by several
 * certificates of which one is approved, and a digest pasted in whichever shape
 * the vendor published it in. Each of those decides whether a package keeps
 * management privilege, so each is proved here rather than on hardware.
 *
 * <p>Nothing in this suite touches Android. The device is reached through
 * {@link ManagementIdentityInspector.SignerSource}, exactly as the system policy
 * controls reach {@code DevicePolicyManager} through
 * {@link SystemPolicyGateway}.
 */
public final class ManagementIdentityInspectorTest {

    private static final String TRANSPORT = "com.example.transport";
    private static final String DIGEST_A = repeated('a');
    private static final String DIGEST_B = repeated('b');
    private static final String DIGEST_C = repeated('c');

    @Test
    public void anAbsentPackageIsReportedAsAbsentAndTrustsNothing() {
        FakeSigners device = new FakeSigners();

        ManagementIdentityStatus status = ManagementIdentityInspector.inspect(
                record(DIGEST_A), device);

        assertFalse(status.installed());
        assertEquals(Set.of(), status.observedCertificateSha256());
        assertFalse(status.trustedOnThisDevice());
        assertFalse(status.canPinInstalledSigner());
    }

    @Test
    public void anAbsentPackageWithNoApprovedCertificateIsStillOnlyNameTrust() {
        // The verdict for an unpinned record never depends on the device, so it
        // has to keep saying UNPINNED even when there is nothing installed. The
        // console distinguishes "absent" from "unproven" itself.
        FakeSigners device = new FakeSigners();

        ManagementIdentityStatus status = ManagementIdentityInspector.inspect(record(), device);

        assertEquals(LockdownPackages.SignerVerdict.UNPINNED, status.verdict());
        assertFalse(status.trustedOnThisDevice());
    }

    @Test
    public void aPlatformThatReportsNoSignerIsRefusedRatherThanAssumedGood() {
        FakeSigners device = new FakeSigners().install(TRANSPORT);

        ManagementIdentityStatus status = ManagementIdentityInspector.inspect(
                record(DIGEST_A), device);

        assertTrue(status.installed());
        assertEquals(LockdownPackages.SignerVerdict.UNKNOWN_SIGNER, status.verdict());
        assertTrue(status.refused());
        assertFalse(status.trustedOnThisDevice());
        assertFalse(status.canPinInstalledSigner());
    }

    @Test
    public void anUnreadableSignerIsAnAbsenceOfEvidenceNotAPass() {
        FakeSigners device = new FakeSigners().install(TRANSPORT, DIGEST_A).failSignerRead();

        ManagementIdentityStatus status = ManagementIdentityInspector.inspect(
                record(DIGEST_A), device);

        assertEquals(Set.of(), status.observedCertificateSha256());
        assertEquals(LockdownPackages.SignerVerdict.UNKNOWN_SIGNER, status.verdict());
        assertTrue(status.refused());
    }

    @Test
    public void anUnreadablePresenceCheckIsTreatedAsPresentSoTheSignerStillDecides() {
        // Reporting "not installed" for a package we could not ask about would
        // turn a refusal into a reassuring blank row. The signer is still read,
        // and a signer that matches is evidence the presence check is not.
        FakeSigners device = new FakeSigners().install(TRANSPORT, DIGEST_A).failPresenceCheck();

        ManagementIdentityStatus status = ManagementIdentityInspector.inspect(
                record(DIGEST_A), device);

        assertTrue(status.installed());
        assertEquals(LockdownPackages.SignerVerdict.MATCH, status.verdict());
    }

    @Test
    public void aDeviceThatAnswersNothingIsRefusedRatherThanReportedAbsent() {
        FakeSigners device = new FakeSigners()
                .install(TRANSPORT, DIGEST_A)
                .failPresenceCheck()
                .failSignerRead();

        ManagementIdentityStatus status = ManagementIdentityInspector.inspect(
                record(DIGEST_A), device);

        assertTrue(status.installed());
        assertEquals(LockdownPackages.SignerVerdict.UNKNOWN_SIGNER, status.verdict());
        assertTrue(status.refused());
    }

    @Test
    public void oneMatchingSignerOutOfSeveralProvesIdentity() {
        FakeSigners device = new FakeSigners().install(TRANSPORT, DIGEST_B, DIGEST_A, DIGEST_C);

        ManagementIdentityStatus status = ManagementIdentityInspector.inspect(
                record(DIGEST_A), device);

        assertEquals(LockdownPackages.SignerVerdict.MATCH, status.verdict());
        assertTrue(status.identityProven());
        assertTrue(status.trustedOnThisDevice());
        assertEquals(Set.of(DIGEST_A, DIGEST_B, DIGEST_C), status.observedCertificateSha256());
    }

    @Test
    public void severalSignersAndNoApprovedOneAmongThemIsRefused() {
        FakeSigners device = new FakeSigners().install(TRANSPORT, DIGEST_B, DIGEST_C);

        ManagementIdentityStatus status = ManagementIdentityInspector.inspect(
                record(DIGEST_A), device);

        assertEquals(LockdownPackages.SignerVerdict.MISMATCH, status.verdict());
        assertFalse(status.identityProven());
        assertTrue(status.refused());
    }

    @Test
    public void colonSeparatedAndUpperCaseFormsAreTheSameCertificate() {
        // Vendors publish digests colon-separated and in upper case; an operator
        // pastes whichever shape they were given, and the device reports its own.
        FakeSigners device = new FakeSigners().install(TRANSPORT, colonUpperCase(DIGEST_A));

        ManagementIdentityStatus status = ManagementIdentityInspector.inspect(
                record(colonUpperCase(DIGEST_A)), device);

        assertEquals(LockdownPackages.SignerVerdict.MATCH, status.verdict());
        assertEquals(Set.of(DIGEST_A), status.observedCertificateSha256());
        assertEquals(Set.of(DIGEST_A), status.pinnedCertificateSha256());
    }

    @Test
    public void spacedFormIsTheSameCertificate() {
        FakeSigners device = new FakeSigners().install(TRANSPORT, DIGEST_A);

        ManagementIdentityStatus status = ManagementIdentityInspector.inspect(
                record(spaced(DIGEST_A)), device);

        assertEquals(LockdownPackages.SignerVerdict.MATCH, status.verdict());
    }

    @Test
    public void anEmptyApprovedSetIsTrustedButNotProven() {
        // The shipped default. It is deliberately not a failure, and it is
        // deliberately not a pass either: the console has to be able to say both.
        FakeSigners device = new FakeSigners().install(TRANSPORT, DIGEST_A);

        ManagementIdentityStatus status = ManagementIdentityInspector.inspect(record(), device);

        assertEquals(LockdownPackages.SignerVerdict.UNPINNED, status.verdict());
        assertFalse(status.identityProven());
        assertTrue(status.trustedOnThisDevice());
        assertFalse(status.refused());
        assertFalse(status.hasPinnedCertificate());
    }

    @Test
    public void pinningTheInstalledSignerIsOfferedOnlyWhileSomethingWouldChange() {
        FakeSigners device = new FakeSigners().install(TRANSPORT, DIGEST_A, DIGEST_B);

        ManagementIdentityStatus unpinned =
                ManagementIdentityInspector.inspect(record(), device);
        assertTrue(unpinned.canPinInstalledSigner());
        assertEquals(Set.of(DIGEST_A, DIGEST_B), unpinned.unpinnedObservedDigests());

        ManagementIdentityStatus partly =
                ManagementIdentityInspector.inspect(record(DIGEST_A), device);
        assertEquals(Set.of(DIGEST_B), partly.unpinnedObservedDigests());

        ManagementIdentityStatus complete =
                ManagementIdentityInspector.inspect(record(DIGEST_A, DIGEST_B), device);
        assertFalse(complete.canPinInstalledSigner());
        assertEquals(Set.of(), complete.unpinnedObservedDigests());
    }

    @Test
    public void everyConfiguredManagementPackageIsInspected() {
        FakeSigners device = new FakeSigners();

        List<ManagementIdentityStatus> statuses =
                ManagementIdentityInspector.inspect(Map.of(), device);

        assertEquals(
                new ArrayList<>(LockdownPackages.managementPackageNames()),
                statuses.stream().map(ManagementIdentityStatus::packageName).toList());
    }

    @Test
    public void configurationTightensARecordAndCannotIntroduceOne() {
        String management = LockdownPackages.MANAGEMENT_DEFAULTS.get(0).packageName();
        FakeSigners device = new FakeSigners().install(management, DIGEST_A);
        Map<String, Set<String>> configured = new LinkedHashMap<>();
        configured.put(management, Set.of(colonUpperCase(DIGEST_A)));
        configured.put("com.impostor.transport", Set.of(DIGEST_B));

        List<ManagementIdentityStatus> statuses =
                ManagementIdentityInspector.inspect(configured, device);

        assertEquals(
                new ArrayList<>(LockdownPackages.managementPackageNames()),
                statuses.stream().map(ManagementIdentityStatus::packageName).toList());
        assertEquals(LockdownPackages.SignerVerdict.MATCH, statuses.get(0).verdict());
    }

    @Test
    public void onlyAWellFormedDigestMayBeStored() {
        assertTrue(ManagementIdentityInspector.isPinnableDigest(DIGEST_A));
        assertTrue(ManagementIdentityInspector.isPinnableDigest(colonUpperCase(DIGEST_A)));
        assertTrue(ManagementIdentityInspector.isPinnableDigest(spaced(DIGEST_A)));
        assertTrue(ManagementIdentityInspector.isPinnableDigest("  " + DIGEST_A + "  "));

        assertFalse(ManagementIdentityInspector.isPinnableDigest(""));
        assertFalse(ManagementIdentityInspector.isPinnableDigest(null));
        assertFalse(ManagementIdentityInspector.isPinnableDigest(DIGEST_A.substring(1)));
        assertFalse(ManagementIdentityInspector.isPinnableDigest(DIGEST_A + "a"));
        assertFalse(ManagementIdentityInspector.isPinnableDigest(repeated('z')));
        assertFalse(ManagementIdentityInspector.isPinnableDigest(DIGEST_A.substring(1) + "g"));
    }

    @Test
    public void addingAPinNormalizesAndKeepsWhatWasAlreadyApproved() {
        Set<String> pins = ManagementIdentityInspector.pinsAfterAdding(
                Set.of(DIGEST_A), List.of(colonUpperCase(DIGEST_B), DIGEST_A));

        assertEquals(Set.of(DIGEST_A, DIGEST_B), pins);
    }

    @Test
    public void aMalformedDigestIsRefusedInsteadOfStored() {
        // A mistyped pin fails closed on the device and hides the management
        // transport, so it may not reach the store by any path.
        assertThrows(
                IllegalArgumentException.class,
                () -> ManagementIdentityInspector.pinsAfterAdding(Set.of(), List.of("deadbeef")));
    }

    @Test
    public void removingAPinAcceptsWhicheverShapeTheOperatorIsLookingAt() {
        Set<String> pins = ManagementIdentityInspector.pinsAfterRemoving(
                Set.of(DIGEST_A, DIGEST_B), colonUpperCase(DIGEST_A));

        assertEquals(Set.of(DIGEST_B), pins);
    }

    @Test
    public void removingTheLastPinLeavesNameOnlyTrustRatherThanARefusal() {
        FakeSigners device = new FakeSigners().install(TRANSPORT, DIGEST_C);
        Set<String> pins = ManagementIdentityInspector.pinsAfterRemoving(Set.of(DIGEST_A), DIGEST_A);

        ManagementIdentityStatus status = ManagementIdentityInspector.inspect(
                new LockdownPackages.ManagementPackage(TRANSPORT, pins), device);

        assertEquals(LockdownPackages.SignerVerdict.UNPINNED, status.verdict());
        assertTrue(status.trustedOnThisDevice());
    }

    private static LockdownPackages.ManagementPackage record(String... approvedDigests) {
        return new LockdownPackages.ManagementPackage(TRANSPORT, Set.of(approvedDigests));
    }

    /** A 64-character digest made of one hex character. */
    private static String repeated(char character) {
        return String.valueOf(character).repeat(ManagementIdentityInspector.DIGEST_LENGTH);
    }

    /** The shape a vendor usually publishes: colon-separated, upper case. */
    private static String colonUpperCase(String digest) {
        StringBuilder result = new StringBuilder();
        for (int index = 0; index < digest.length(); index += 2) {
            if (index > 0) {
                result.append(':');
            }
            result.append(digest, index, index + 2);
        }
        return result.toString().toUpperCase(Locale.ROOT);
    }

    /** The shape a console or a spreadsheet usually produces. */
    private static String spaced(String digest) {
        StringBuilder result = new StringBuilder();
        for (int index = 0; index < digest.length(); index += 2) {
            if (index > 0) {
                result.append(' ');
            }
            result.append(digest, index, index + 2);
        }
        return result.toString();
    }

    /** The device, as this screen is allowed to see it. */
    private static final class FakeSigners implements ManagementIdentityInspector.SignerSource {

        private final Map<String, Set<String>> signers = new LinkedHashMap<>();
        private boolean signerReadThrows;
        private boolean presenceCheckThrows;

        FakeSigners install(String packageName, String... digests) {
            signers.put(packageName, new LinkedHashSet<>(List.of(digests)));
            return this;
        }

        FakeSigners failSignerRead() {
            signerReadThrows = true;
            return this;
        }

        FakeSigners failPresenceCheck() {
            presenceCheckThrows = true;
            return this;
        }

        @Override
        public boolean isInstalled(String packageName) {
            if (presenceCheckThrows) {
                throw new IllegalStateException("package manager unavailable");
            }
            return signers.containsKey(packageName);
        }

        @Override
        public Set<String> signingCertificateSha256(String packageName) {
            if (signerReadThrows) {
                throw new IllegalStateException("signature read failed");
            }
            return signers.getOrDefault(packageName, Set.of());
        }
    }
}
