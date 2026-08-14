package com.example.lockdowndpc.policy;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Which administrator-selected system packages the policy engine may still act
 * on, given what is installed right now.
 *
 * <h2>Why a stored selection is not an authorisation</h2>
 *
 * <p>An administrator opting a system package into management is not a
 * preference; it is an acceptance of a specific, recorded risk about a specific
 * binary — {@code docs/production-roadmap.md} requires the package name, signer
 * digest, version, prior state and firmware build to be recorded before the
 * choice is accepted. The reason is that {@code ESSENTIAL_SYSTEM} cannot be an
 * exhaustive list of what an OEM build needs, so the safety of managing an
 * unclassified component rests entirely on the administrator having looked at
 * <em>that</em> component.
 *
 * <p>An OEM update replaces the binary. It can change the signer, the version, or
 * both, while the package name — the only thing the stored selection holds —
 * stays identical. Acting on the old acceptance then means hiding a component
 * nobody reviewed, on a device nobody is holding, during an automatic
 * reconciliation pass. That is precisely the failure the acceptance record exists
 * to prevent, and it is why re-checking belongs here, in the engine, rather than
 * only on the screen that first asked.
 *
 * <h2>Failing closed means leaving the component alone</h2>
 *
 * <p>When the identity has drifted, the package is dropped from the managed set.
 * It is deliberately <em>not</em> turned into a policy fault: an OEM update is a
 * normal event, and faulting protection on every firmware update would strand a
 * fleet for a condition an administrator can resolve in the console. The drop is
 * reported so the console and the audit log can say the acceptance needs
 * renewing.
 *
 * <p>Pure logic with an injected view of the device, so every branch is an
 * ordinary JVM test.
 */
public final class SystemAppSelection {

    private SystemAppSelection() {}

    /** The installed identity of one package, as the engine observes it now. */
    public record InstalledIdentity(String signerDigest, String version) {
        public InstalledIdentity {
            signerDigest = signerDigest == null ? "" : signerDigest;
            version = version == null ? "" : version;
        }

        /** Nothing could be read. Never treated as a match. */
        public static InstalledIdentity unreadable() {
            return new InstalledIdentity("", "");
        }
    }

    /**
     * The result of re-checking every opted-in system package.
     *
     * @param managed  packages whose recorded acceptance still describes what is
     *                 installed, and which the policy engine may therefore act on
     * @param revoked  packages dropped because their identity has drifted or their
     *                 acceptance cannot be found
     */
    public record Revalidation(Set<String> managed, Set<String> revoked) {
        public Revalidation {
            managed = managed == null ? Set.of() : Collections.unmodifiableSet(
                    new LinkedHashSet<>(managed));
            revoked = revoked == null ? Set.of() : Collections.unmodifiableSet(
                    new LinkedHashSet<>(revoked));
        }

        public boolean anyRevoked() {
            return !revoked.isEmpty();
        }

        /** A stable, non-sensitive summary for the audit log. */
        public String revokedSummary() {
            return String.join(",", revoked);
        }
    }

    /**
     * Re-checks the stored selection against the installed identities.
     *
     * @param selected    the packages an administrator opted in, as stored
     * @param acceptances the recorded acceptance per package; a missing entry
     *                    means the selection predates the acceptance record and
     *                    cannot be honoured
     * @param installed   the identity observed for each package now; a missing
     *                    entry means the package could not be read, which is not
     *                    evidence that it is unchanged
     */
    public static Revalidation revalidate(
            Set<String> selected,
            Map<String, SystemAppRiskAcceptance> acceptances,
            Map<String, InstalledIdentity> installed
    ) {
        LinkedHashSet<String> managed = new LinkedHashSet<>();
        LinkedHashSet<String> revoked = new LinkedHashSet<>();
        if (selected == null) {
            return new Revalidation(managed, revoked);
        }
        for (String packageName : selected) {
            if (packageName == null || packageName.isEmpty()) {
                continue;
            }
            SystemAppRiskAcceptance acceptance =
                    acceptances == null ? null : acceptances.get(packageName);
            if (acceptance == null) {
                revoked.add(packageName);
                continue;
            }
            InstalledIdentity identity =
                    installed == null ? null : installed.get(packageName);
            if (identity == null) {
                // The package may be absent, or unreadable. Either way there is
                // nothing to manage and nothing proven, so it is not managed.
                revoked.add(packageName);
                continue;
            }
            if (acceptance.matches(identity.signerDigest(), identity.version())) {
                managed.add(packageName);
            } else {
                revoked.add(packageName);
            }
        }
        return new Revalidation(managed, revoked);
    }
}
