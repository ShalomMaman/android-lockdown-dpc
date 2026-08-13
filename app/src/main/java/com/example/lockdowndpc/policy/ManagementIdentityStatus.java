package com.example.lockdowndpc.policy;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * What is known about one management package's identity on this device.
 *
 * <p>This is evidence, not a decision. It records three separate things and
 * never collapses them into a single reassuring boolean:
 *
 * <ol>
 *   <li>whether the package is present at all,</li>
 *   <li>the signing certificates the platform actually reported, and</li>
 *   <li>the certificates an administrator approved.</li>
 * </ol>
 *
 * <p>{@link #verdict()} is the same {@link LockdownPackages.SignerVerdict} the
 * apply pass computes from those inputs, so the console cannot show an identity
 * status the policy engine would contradict. In particular
 * {@link LockdownPackages.SignerVerdict#UNPINNED} is <em>trusted but not
 * proven</em>: {@link #identityProven()} is false for it while
 * {@link #trustedOnThisDevice()} is true, which is exactly the proof gap this
 * screen exists to close.
 *
 * <p>Free of every Android type so the inspection and the presentation logic
 * above it are provable as ordinary JVM tests.
 */
public record ManagementIdentityStatus(
        String packageName,
        boolean installed,
        Set<String> observedCertificateSha256,
        Set<String> pinnedCertificateSha256,
        LockdownPackages.SignerVerdict verdict
) {

    public ManagementIdentityStatus {
        if (packageName == null || packageName.isEmpty()) {
            throw new IllegalArgumentException("A management identity status needs a package name");
        }
        if (verdict == null) {
            throw new IllegalArgumentException("A management identity status needs a verdict");
        }
        observedCertificateSha256 = normalizedCopy(observedCertificateSha256);
        pinnedCertificateSha256 = normalizedCopy(pinnedCertificateSha256);
    }

    /** True only for {@code MATCH}: an approved certificate was matched, not assumed. */
    public boolean identityProven() {
        return verdict == LockdownPackages.SignerVerdict.MATCH;
    }

    /**
     * Whether the apply pass would grant this package the management exemption
     * on this device. An absent package is granted nothing, which is why
     * {@link #installed()} is part of the answer.
     */
    public boolean trustedOnThisDevice() {
        return installed && LockdownPackages.grantsManagementTrust(verdict);
    }

    /**
     * Whether management privilege is being withheld from an installed package.
     * The apply pass hides such a package rather than exempting it and reports
     * the whole pass as unverified.
     */
    public boolean refused() {
        return installed && !LockdownPackages.grantsManagementTrust(verdict);
    }

    public boolean hasPinnedCertificate() {
        return !pinnedCertificateSha256.isEmpty();
    }

    /** The observed signers that are not approved yet — what pinning would add. */
    public Set<String> unpinnedObservedDigests() {
        LinkedHashSet<String> missing = new LinkedHashSet<>(observedCertificateSha256);
        missing.removeAll(pinnedCertificateSha256);
        return Collections.unmodifiableSet(missing);
    }

    /**
     * Whether "pin the signer installed now" has anything to write. False for an
     * absent package, for a device that reported no readable signer, and once
     * every observed signer is already approved.
     */
    public boolean canPinInstalledSigner() {
        return installed && !unpinnedObservedDigests().isEmpty();
    }

    private static Set<String> normalizedCopy(Set<String> digests) {
        LinkedHashSet<String> normalized = new LinkedHashSet<>();
        if (digests != null) {
            for (String digest : digests) {
                String value = LockdownPackages.normalizeDigest(digest);
                if (!value.isEmpty()) {
                    normalized.add(value);
                }
            }
        }
        return Collections.unmodifiableSet(normalized);
    }
}
