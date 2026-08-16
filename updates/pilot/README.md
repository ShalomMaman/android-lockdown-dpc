# Pilot update channel

This directory is the stable metadata endpoint for the existing Device Guard pilot installation.

`channel.json` is the non-secret machine-readable trust record shared by the
Gradle release gate and protected publication workflow. It pins the package,
stable manifest URL, APK certificate, metadata-key fingerprint, and public-key
file. Keeping those values in one reviewed record prevents release scripts and
CI from drifting apart.

Build the pilot channel with the repository-native fail-closed command documented
in [`docs/secure-updates.md`](../../docs/secure-updates.md). A normal
`assembleRelease` intentionally does not embed this channel.

`latest.json` currently advertises **0.5.2 (`versionCode 12`)**. Build 11 was an
unpublished hardware pilot; build 12 is deliberately newer so that enrolled
test devices can receive the compact-inventory fix through this channel. The
signed transition from both published 0.5.1 and hardware build 11 passed the
offline rehearsal in [`docs/update-drill.md`](../../docs/update-drill.md).

- `latest.json` is a compact ECDSA-signed update envelope.
- `public-key.pub` is the non-secret PEM-encoded P-256 metadata verification key.
- Approved public-key DER SHA-256: `c83816c000a61a600d90b8d4dab4a63aa27585292d605938ba8104b6559955cc`.
- APK artifacts are immutable assets on GitHub Releases and are verified again by size, SHA-256, package identity, version, and Android signing certificate before installation.

Use the protected workflow in
[`docs/pilot-release-automation.md`](../../docs/pilot-release-automation.md) for
normal publication. It publishes the immutable APK before merging a generated,
verified `latest.json`. Never commit the corresponding private key or its
passphrase. This channel is a prerelease compatibility path for the existing
test device, not the production customer channel.
