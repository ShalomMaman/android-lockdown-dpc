package com.example.lockdowndpc.policy;

/**
 * An administrator's explicit acceptance of the identity risk of one
 * unclassified OEM system package, as required by
 * {@code docs/production-roadmap.md#system-application-safety-model}: "Before
 * accepting an advanced system-package choice, Device Guard should record the
 * package name, signer digest, version, enabled/hidden state and the firmware
 * build."
 *
 * <p>{@code priorState} and {@code firmwareBuild} are audit context recorded
 * at acceptance time; only the signer digest and version are drift signals
 * that {@link #matches} re-checks. A package can be re-signed or replaced by
 * an OEM update without its enabled/hidden state or the firmware build
 * string changing, so those two fields alone would miss the identity change
 * this record exists to catch.
 */
public record SystemAppRiskAcceptance(
        String packageName,
        String signerDigest,
        String version,
        String priorState,
        String firmwareBuild,
        long acceptedAtMillis
) {
    public SystemAppRiskAcceptance {
        if (packageName == null || packageName.isEmpty()) {
            throw new IllegalArgumentException("packageName is required");
        }
        signerDigest = LockdownPackages.normalizeDigest(signerDigest);
        version = version == null ? "" : version;
        priorState = priorState == null ? "" : priorState;
        firmwareBuild = firmwareBuild == null ? "" : firmwareBuild;
    }

    /**
     * Whether the identity this acceptance was recorded for still matches what is
     * observed now. An empty accepted signer digest never matches: a signer that
     * could not be read at acceptance time is not a proven identity, so it cannot
     * be reconfirmed by observing another unreadable signer later.
     */
    public boolean matches(String observedSignerDigest, String observedVersion) {
        String normalizedObserved = LockdownPackages.normalizeDigest(observedSignerDigest);
        if (signerDigest.isEmpty() || normalizedObserved.isEmpty()) {
            return false;
        }
        return signerDigest.equals(normalizedObserved)
                && version.equals(observedVersion == null ? "" : observedVersion);
    }
}
