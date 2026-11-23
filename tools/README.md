# Signed update publisher

The normal pilot publication path is the protected workflow described in
[`../docs/pilot-release-automation.md`](../docs/pilot-release-automation.md).
The tools in this directory remain independently runnable, and the workflow
composes the same fail-closed commands rather than replacing their checks.

`plan_pilot_release.py` verifies the committed channel configuration, public
P-256 key, current signed envelope, candidate APK identity and exact signer. It
requires a strictly higher `versionCode` and emits only validated, line-safe
release names and workflow outputs. It never reads private key material.

`publish_update.py` creates the compact, signed JSON envelope consumed by the Maakeh updater. It reads package and version metadata from the APK with `aapt2`, calculates SHA-256 and size by streaming the file, and asks OpenSSL to sign only the canonical payload with `SHA256withECDSA`.

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

## Offline fleet administration

Run `python3 tools/fleet_admin.py --help` or add `--help` after a subcommand.
Pass base64url values in the `--option=value` form (for example
`--device-id=<id>`, `--nonce=<nonce>`): a value may start with `-`, which a
separate argument would turn into an option.
Use an external P-256 PEM and pass only the environment variable name via
`--key-passphrase-env` for an encrypted PEM. Keep inventory, enrolment
records, credentials and signed outputs outside the checkout.

- `keyset` signs the supplied public keys and server URL with the fleet root.
  Save the displayed root fingerprint for provisioning and keep the trusted
  root public PEM for use with `policy` and `recovery`.
- `tickets` and `bench-code` accept `--devices`, a JSON array of objects with
  `identityType` (`serial` or `enrollmentSpecificId`), `identity` and
  `firmwareFamily`. Supply one device for `bench-code`. The tool writes
  the credentials to `tickets.txt` or `bench-code.txt`, and saves the
  independent local identity bindings in `inventory.json`. Give the server
  only `server.json`, which contains the fleet, ticket hashes, expiry and
  use limits. The server enforces consumption and the bench attempt limit.
- `verify-enrolment` takes a downloaded `--record`, the local `--inventory`
  and the intended `--fleet-id`. Independently obtain the current Google
  hardware attestation roots (PEM bundle or JSON array of PEMs) and status
  JSON for `--attestation-roots` and `--revocation-list`. Download the
  [Google revocation list](https://android.googleapis.com/attestation/status)
  directly and preserve its local modification time if you copy it. The
  offline tool uses that time to enforce `--revocation-max-age-days` (default
  7, a positive whole number) and tolerates timestamps up to five minutes ahead.
  Refresh older copies from Google. Use the approved application ID and APK
  signing certificate digest. Verification checks the chain signatures,
  attestation challenge and revocation status.
  Expired factory attestation certificates can pass these checks.
- `policy` signs a schema-validated `--body` for the listed `--device-id`
  targets. Supply each downloaded `--enrolment-record` and the same trust
  inputs as `verify-enrolment`. `--allow-untrusted` adds the affected targets
  to the signed audit note. `--previous` accepts the operator's local
  previous envelope for a field comparison, including after key rotation.
  The tool verifies the current key set and checks that the signer is an
  approved policy key before signing.
- Before signing a policy that disables ADB or omits
  `systemControls.developer_options_and_adb`, supply `--drill-evidence`.
  Production devices block ADB by default when this field is omitted.
  The evidence is an unsigned local JSON array with one entry per firmware family.
  Each entry has `firmwareFamily`, `offline` (the JSON record from
  `update_drill.py` with verdict `PASS`), `onDevice` (`PASS`),
  and `onDeviceEvidence` (a reference to the recorded hardware observations
  for steps 0–5). The verified target's family must match a passing entry.
- `recovery --output <new-directory>` writes `recovery-code.txt` and the
  signed verifier `recovery.json` together in a private directory (mode
  `0700`, files `0600`). It refuses an existing directory and prints only
  the path to the code file. Import the code into the operator's vault.
- `reanchor` takes the current binding root fingerprint, the displayed nonce
  and the four latest issued floors. For a same-version resend, supply the
  original issued key set with `--keyset-envelope`. To also resend a policy at
  its floor, add the original issued policy with `--policy-envelope`.
  The tool verifies the key set against the current root and the policy
  against an approved policy key from that key set. Each envelope must match
  the fleet and its floor version. The tool hashes the exact decoded payload
  bytes.
  See the [re-anchor contract](../docs/remote-contract/README.md#console-re-anchor).

The offline enrolment record uses `fleetId`, `deviceId`, `ticketSha256`
(lowercase hex), `challenge` (32 bytes in unpadded base64url),
`attestationChain` (a leaf-first array of unpadded base64url DER certificates),
`facts` (including integer `sdk` and `firmwareFamily`, and
`enrollmentSpecificId` when used for binding), and `transcriptSignature`
(unpadded base64url DER ECDSA). The transcript is the canonical JSON array
`["dg-enrol/1", challenge, ticketSha256, chainSha256, factsSha256]`.
The last two values are lowercase hex SHA-256 digests of the canonical JSON
chain array and facts object. An enrolment ticket hashes the decoded 24 random
bytes. A bench code hashes its 16 ASCII characters. Both use the same
`ticketSha256` field. See [the v1 encoding contract](../docs/remote-contract/README.md).

Provisioning remains local by default. To build remote QR payloads supply
`--remote-server`, `--remote-root`, `--remote-fleet` and the name of the
environment variable that holds the ticket via `--enrolment-ticket-env`.
Repeat `--remote-tls-pin` for up to two pins. The bundle encodes the pins in
one comma-separated string. For a batch, set the path of `tickets.txt` in
the named `--enrolment-tickets-file-env` variable and use a new output
directory. The output files are private and the report maps them to their
ticket lines. The QR images carry the same credentials as the payload files.
