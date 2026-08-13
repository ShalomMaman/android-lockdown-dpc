package com.example.lockdowndpc.policy;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Reads the installed signer of every management package and states, per
 * package, whether management identity is proven.
 *
 * <p>The device is reached through {@link SignerSource} for the same reason
 * {@link SystemPolicyEnforcer} reaches {@code DevicePolicyManager} through
 * {@link SystemPolicyGateway}: the interesting decisions — an absent package, a
 * platform that reports no signer, several signers of which one matches, a
 * digest pasted in a different case or with colons — are worth proving on the
 * JVM rather than only on a provisioned device that has to be re-enrolled after
 * every wrong answer. The production implementation is a thin
 * {@code PackageManager} adapter in {@code ui/ManagementIdentityActivity.kt}.
 *
 * <p>The verdict is not recomputed here in a second dialect: it comes from
 * {@link LockdownPackages#verifySigner}, the same call
 * {@link LockdownPolicyController} makes while applying policy, so this screen
 * cannot report an identity the apply pass would contradict.
 *
 * <p>This class only reports. It never writes a pin, never grants trust, and
 * cannot introduce a management package: {@link LockdownPackages#managementPackages}
 * merges configuration into the built-in records and drops anything else, so a
 * pin for an unlisted package name is inert.
 */
public final class ManagementIdentityInspector {

    private ManagementIdentityInspector() {}

    /** A SHA-256 digest is 64 hexadecimal characters once separators are removed. */
    public static final int DIGEST_LENGTH = 64;

    /**
     * The narrow slice of {@code PackageManager} this screen needs.
     *
     * <p>Both methods may throw. A read of another package can fail for reasons
     * the console cannot anticipate, and a throw is treated as an absence of
     * evidence, never as a pass — see {@link #inspect(LockdownPackages.ManagementPackage, SignerSource)}.
     */
    public interface SignerSource {

        /** Whether the package is present on this device. */
        boolean isInstalled(String packageName);

        /**
         * Lower-case hex SHA-256 digests of every signing certificate the
         * platform reports for the package, or an empty set when it reports
         * none. Digests are normalized again on the way in, so an
         * implementation may return whichever form is convenient.
         */
        Set<String> signingCertificateSha256(String packageName);
    }

    /**
     * Inspects every configured management package.
     *
     * @param configuredPins administrator-configured pins, as
     *                       {@link AllowedAppsStore#getManagementCertificatePins}
     *                       returns them
     */
    public static List<ManagementIdentityStatus> inspect(
            Map<String, Set<String>> configuredPins,
            SignerSource source
    ) {
        List<ManagementIdentityStatus> statuses = new ArrayList<>();
        for (LockdownPackages.ManagementPackage record
                : LockdownPackages.managementPackages(configuredPins)) {
            statuses.add(inspect(record, source));
        }
        return Collections.unmodifiableList(statuses);
    }

    /**
     * Inspects one record.
     *
     * <p>A throw while reading the signer becomes "no digest observed", which a
     * pinned record reports as {@code UNKNOWN_SIGNER} — refused — rather than as
     * a pass. A throw while asking whether the package is present is treated as
     * "present, identity unreadable" for the same fail-closed reason: an
     * unreadable presence check must not be able to turn a refusal into a quiet
     * "not installed on this device".
     */
    public static ManagementIdentityStatus inspect(
            LockdownPackages.ManagementPackage record,
            SignerSource source
    ) {
        boolean installed;
        try {
            installed = source.isInstalled(record.packageName());
        } catch (RuntimeException exception) {
            installed = true;
        }
        Set<String> observed = installed ? observedDigests(source, record.packageName()) : Set.of();
        return new ManagementIdentityStatus(
                record.packageName(),
                installed,
                observed,
                record.approvedCertificateSha256(),
                LockdownPackages.verifySigner(record, observed)
        );
    }

    /**
     * Whether a digest an operator supplied may be stored as an approved
     * certificate: exactly {@link #DIGEST_LENGTH} hexadecimal characters once
     * {@link LockdownPackages#normalizeDigest} has removed colons and spaces and
     * lower-cased it.
     *
     * <p>This is the single acceptance rule. The console classifies <em>why</em>
     * a paste was rejected for the operator, but it decides <em>whether</em> to
     * accept it here, so no screen can widen what reaches the store.
     */
    public static boolean isPinnableDigest(String raw) {
        String normalized = LockdownPackages.normalizeDigest(raw);
        if (normalized.length() != DIGEST_LENGTH) {
            return false;
        }
        for (int index = 0; index < normalized.length(); index++) {
            if (!isHex(normalized.charAt(index))) {
                return false;
            }
        }
        return true;
    }

    /**
     * The pin set to store after approving {@code digests}.
     *
     * <p>Rejects anything that is not a well-formed digest instead of storing it:
     * a mistyped pin fails closed on the device and hides the management
     * transport, so it may not reach the store by any path.
     */
    public static Set<String> pinsAfterAdding(Set<String> current, Collection<String> digests) {
        LinkedHashSet<String> pins = normalizedCopy(current);
        for (String digest : digests) {
            if (!isPinnableDigest(digest)) {
                throw new IllegalArgumentException("Not a SHA-256 certificate digest");
            }
            pins.add(LockdownPackages.normalizeDigest(digest));
        }
        return Collections.unmodifiableSet(pins);
    }

    /** The pin set to store after withdrawing one approved certificate. */
    public static Set<String> pinsAfterRemoving(Set<String> current, String digest) {
        LinkedHashSet<String> pins = normalizedCopy(current);
        pins.remove(LockdownPackages.normalizeDigest(digest));
        return Collections.unmodifiableSet(pins);
    }

    private static Set<String> observedDigests(SignerSource source, String packageName) {
        try {
            Set<String> digests = source.signingCertificateSha256(packageName);
            return digests == null ? Set.of() : digests;
        } catch (RuntimeException exception) {
            // Absence of evidence. A pinned record turns this into UNKNOWN_SIGNER.
            return Set.of();
        }
    }

    private static LinkedHashSet<String> normalizedCopy(Set<String> digests) {
        LinkedHashSet<String> normalized = new LinkedHashSet<>();
        if (digests != null) {
            for (String digest : digests) {
                String value = LockdownPackages.normalizeDigest(digest);
                if (!value.isEmpty()) {
                    normalized.add(value);
                }
            }
        }
        return normalized;
    }

    private static boolean isHex(char character) {
        return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'f');
    }
}
