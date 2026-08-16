# Signed update publisher

The normal pilot publication path is the protected workflow described in
[`../docs/pilot-release-automation.md`](../docs/pilot-release-automation.md).
The tools in this directory remain independently runnable, and the workflow
composes the same fail-closed commands rather than replacing their checks.

`plan_pilot_release.py` verifies the committed channel configuration, public
P-256 key, current signed envelope, candidate APK identity and exact signer. It
requires a strictly higher `versionCode` and emits only validated, line-safe
release names and workflow outputs. It never reads private key material.

`publish_update.py` creates the compact, signed JSON envelope consumed by the Device Guard updater. It reads package and version metadata from the APK with `aapt2`, calculates SHA-256 and size by streaming the file, and asks OpenSSL to sign only the canonical payload with `SHA256withECDSA`.

The tool requires Python 3, OpenSSL, Android SDK Build Tools (`aapt2` and `apksigner`), and a working Java runtime for `apksigner`. Set `JAVA_HOME` when Java is not available system-wide.

The EC private key must live outside the repository. The tool never copies it into the envelope, prints it, or passes its contents on the command line. Do not generate or store production keys in this directory.

Example using an existing external key:

```bash
./tools/publish_update.py \
  --apk /secure/releases/device-guard.apk \
  --apk-url https://updates.example.test/device-guard.apk \
  --expected-package com.example.lockdowndpc \
  --expected-signer-sha256 25507e47f49cbacc8cad66ee4967b2bae3f22bbd26fbb4587e9326626669014b \
  --private-key /secure/offline/device-guard-update-ec.pem \
  --expected-metadata-key-sha256 APPROVED_PUBLIC_KEY_DER_SHA256 \
  --output /secure/releases/update-envelope.json
```

For an encrypted EC key, put the passphrase in an environment variable and pass only its name:

```bash
# Inject DEVICE_GUARD_UPDATE_KEY_PASSWORD through the operator's secret manager first.
./tools/publish_update.py \
  ... \
  --key-passphrase-env DEVICE_GUARD_UPDATE_KEY_PASSWORD
```

The tool never reads or prints the variable value; it gives OpenSSL the `env:` reference. Without `--key-passphrase-env`, OpenSSL receives an explicit empty passphrase, so an encrypted key fails immediately instead of waiting for an unavailable TTY prompt.

Safety defaults:

- only clean HTTPS APK URLs are accepted;
- APK identity is extracted rather than supplied by the operator;
- the extracted application ID must equal `--expected-package`;
- `apksigner` must report exactly one signing-certificate digest, equal to `--expected-signer-sha256`;
- the public key derived from the metadata private key must match the approved
  `--expected-metadata-key-sha256` used by the production build;
- APKs over the client's 100 MiB limit are rejected;
- envelopes expire after 30 days by default and cannot exceed 90 days;
- existing output is not replaced unless `--force` is explicit;
- output is written atomically and can never target the APK or private key.

The payload is canonical compact JSON with sorted keys. `payload` and its DER ECDSA `signature` are URL-safe Base64 without padding, matching `UpdateEnvelopeVerifier`.

## Locale parity

`check_locale_parity.py` compares `values/strings.xml` against `values-iw/strings.xml`
and fails on a missing key, a mismatched format placeholder, a missing plural
category, an English value left in the Hebrew file, or a Hebrew value in the
English default. It reads `strings.xml` and nothing else, so a feature that
ships its own resource file carries its own parity test on the JVM instead —
see `SystemPolicyLocaleParityTest`, `MaintenanceStringsParityTest`,
`SystemAppInventoryStringsParityTest`, `ManagementIdentityStringsParityTest` and
`DeviceHealthStringsParityTest`.

## Self-update drill

`update_drill.py` rehearses and records the offline half of a real signed
self-update. It proves that the installed and candidate APKs form a legal
in-place update pair — identical application ID, identical signing certificate,
strictly higher `versionCode` — and that the published envelope satisfies the
same rules the device applies in `UpdateEnvelopeVerifier` and
`SecureUpdateManager`: ECDSA P-256 over the canonical payload, the approved
metadata public-key fingerprint, APK hash and size, package identity, exact
version binding, an HTTPS-only URL, and the replay floor.

It refuses a downgrade, a replayed older envelope, a signer change, and an
envelope whose metadata does not match the APK it points at. The result is a
machine-readable drill record plus a PASS/FAIL summary that lists which checks
ran and which could not be performed here — a check that was skipped is never
reported as passed, and a run with skipped checks is `INCOMPLETE` rather than
`PASS`.

The on-device half of the drill cannot be automated from this repository and is
documented in [`../docs/update-drill.md`](../docs/update-drill.md). ADB must
remain the working recovery path until that half has been completed on hardware.

## Device Owner provisioning payload

`provisioning_payload.py` builds and validates the QR/NFC provisioning payload
for a Device Owner enrolment: the administrator component, the download
location, the package checksum, and the optional network and locale extras. It
refuses a non-HTTPS download location, a malformed component name and an invalid
checksum, and it never takes a Wi-Fi password on the command line — only the
name of an environment variable to read, exactly as `publish_update.py` does for
the key passphrase. The operator runbook is
[`../docs/provisioning.md`](../docs/provisioning.md).
