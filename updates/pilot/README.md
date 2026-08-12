# Pilot update channel

This directory is the stable metadata endpoint for the existing Device Guard pilot installation.

Build Pilot 0.5.1 with the repository-native fail-closed command documented in
[`docs/secure-updates.md`](../../docs/secure-updates.md). A normal
`assembleRelease` intentionally does not embed this channel.

- `latest.json` is a compact ECDSA-signed update envelope.
- `public-key.pub` is the non-secret PEM-encoded P-256 metadata verification key.
- Approved public-key DER SHA-256: `c83816c000a61a600d90b8d4dab4a63aa27585292d605938ba8104b6559955cc`.
- APK artifacts are immutable assets on GitHub Releases and are verified again by size, SHA-256, package identity, version, and Android signing certificate before installation.

Publish the immutable APK before replacing `latest.json`. Never commit the corresponding private key or its passphrase. This channel is a prerelease compatibility path for the existing test device, not the production customer channel.
