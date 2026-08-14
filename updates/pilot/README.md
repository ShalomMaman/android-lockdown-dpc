# Pilot update channel

This directory is the stable metadata endpoint for the existing Device Guard pilot installation.

Build the pilot channel with the repository-native fail-closed command documented
in [`docs/secure-updates.md`](../../docs/secure-updates.md). A normal
`assembleRelease` intentionally does not embed this channel.

`latest.json` currently advertises **0.5.1 (`versionCode 10`)**, which is the last
release whose APK was actually published and signed. The source tree has moved on
to 0.5.2 (`versionCode 11`). Publishing 0.5.2 to this channel requires the offline
metadata signing key and an immutable published APK asset, neither of which exists
in this repository; until that happens a device on this channel correctly sees no
newer version rather than a broken one. Rehearse the transition with
[`docs/update-drill.md`](../../docs/update-drill.md) before publishing.

- `latest.json` is a compact ECDSA-signed update envelope.
- `public-key.pub` is the non-secret PEM-encoded P-256 metadata verification key.
- Approved public-key DER SHA-256: `c83816c000a61a600d90b8d4dab4a63aa27585292d605938ba8104b6559955cc`.
- APK artifacts are immutable assets on GitHub Releases and are verified again by size, SHA-256, package identity, version, and Android signing certificate before installation.

Publish the immutable APK before replacing `latest.json`. Never commit the corresponding private key or its passphrase. This channel is a prerelease compatibility path for the existing test device, not the production customer channel.
