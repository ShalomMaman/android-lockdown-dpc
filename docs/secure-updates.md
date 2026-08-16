# Remote updates without ADB

Device Guard includes a self-update channel for a Device Owner installation. The channel is disabled by default and becomes active only when the build receives both an HTTPS manifest URL and an EC public key for metadata verification.

## Trust boundary

The file host is not trusted by itself. Before installation, the client requires every condition below:

1. The manifest has a valid ECDSA signature from the offline metadata key.
2. The package name matches the installed app and the version code is higher.
3. The APK URL and every redirect use HTTPS.
4. The downloaded size and SHA-256 match the signed manifest.
5. Android can parse the APK, and its package, version, and signing lineage match the authorized values and installed app.
6. Only then does the client open a `PackageInstaller.Session` for that package.

Any failure stops installation without pausing or weakening the protection policy. The app checks once after bootstrap and then daily with `JobScheduler`; it does not keep a network service resident in memory. An authorized administrator can also request an immediate check from the console.

## Build configuration

Ordinary builds are unconditionally channel-disabled and ignore ambient update
properties and environment variables. Build the existing public pilot channel
with one explicit command:

```bash
./gradlew -I gradle/pilot-update.init.gradle.kts --no-daemon --max-workers=2 clean pilotChannelRelease
```

That task validates the committed HTTPS URL and P-256 public key, checks the
approved key and APK-signer fingerprints, runs tests and lint, builds the APK,
and structurally reads its compiled `BuildConfig` from DEX. It fails if package,
version, signer, URL, or key drift, so it cannot silently emit a channel-disabled
pilot APK. No private material is used.

GitHub-hosted runners create their own ephemeral Android debug certificate, so
CI uses the separate `ciPilotChannelRelease` task. That task requires exactly
one valid signer and verifies the complete compiled channel, but it deliberately
does not approve that certificate for distribution. Never publish its APK. The
documented `pilotChannelRelease` command remains the release gate and requires
the exact signer of the already enrolled pilot device.

Production remains a separate explicit build. These values are supported only
by the production init path as Gradle properties or environment variables:

```text
deviceGuardUpdateManifestUrl / DEVICE_GUARD_UPDATE_MANIFEST_URL
deviceGuardUpdatePublicKey / DEVICE_GUARD_UPDATE_PUBLIC_KEY
deviceGuardUpdatePublicKeySha256 / DEVICE_GUARD_UPDATE_PUBLIC_KEY_SHA256
```

The public key is a DER-encoded EC SubjectPublicKeyInfo value represented as Base64 without line breaks. Keep the metadata key separate from the APK-signing key. Generate an encrypted P-256 key pair outside the repository, for example:

```bash
openssl genpkey -algorithm EC \
  -pkeyopt ec_paramgen_curve:P-256 \
  -aes-256-cbc \
  -out /secure/offline/device-guard-update-ec.pem

openssl pkey \
  -in /secure/offline/device-guard-update-ec.pem \
  -pubout -outform DER \
  | openssl base64 -A
```

Store the private key and passphrase in an organizational vault with encrypted backup and access control. The public key is not secret. The production build fails if either update configuration or APK-signing configuration is incomplete.

## Create a release

`tools/publish_update.py` verifies APK identity and signer with the Android SDK tools before creating the signed manifest. It never overwrites an existing output unless `--force` is explicit.

```bash
./tools/publish_update.py \
  --apk /secure/releases/device-guard.apk \
  --apk-url https://HOST/releases/download/v0.4.2/device-guard.apk \
  --expected-package com.example.lockdowndpc \
  --expected-signer-sha256 CERTIFICATE_SHA256 \
  --private-key /secure/offline/device-guard-update-ec.pem \
  --expected-metadata-key-sha256 APPROVED_PUBLIC_KEY_DER_SHA256 \
  --key-passphrase-env DEVICE_GUARD_UPDATE_KEY_PASSWORD \
  --output /secure/releases/latest.json
```

Upload the immutable APK first, then atomically replace the stable `latest.json` consumed by devices. The signed manifest includes issue and expiration times. Clients reject validity periods above 91 days; the publisher defaults to 30 days. Refresh `latest.json` before expiration even when no APK version changes.

After uploading the immutable asset and creating the signed envelope, bind the
exact APK to the intended channel before replacing `updates/pilot/latest.json`:

```bash
python3 tools/verify_pilot_apk.py \
  --apk app/build/outputs/apk/release/app-release.apk \
  --expected-package com.example.lockdowndpc \
  --expected-version-code 12 --expected-version-name 0.5.2 \
  --expected-signer-sha256 25507e47f49cbacc8cad66ee4967b2bae3f22bbd26fbb4587e9326626669014b \
  --expected-manifest-url https://raw.githubusercontent.com/ShalomMaman/android-lockdown-dpc/main/updates/pilot/latest.json \
  --expected-public-key-file updates/pilot/public-key.pub \
  --expected-public-key-sha256 c83816c000a61a600d90b8d4dab4a63aa27585292d605938ba8104b6559955cc \
  --manifest /secure/releases/latest.json \
  --expected-apk-url https://github.com/ShalomMaman/android-lockdown-dpc/releases/download/pilot-v0.5.2/device-guard-pilot-v0.5.2.apk
```

This final gate verifies the manifest ECDSA signature, current validity, immutable
HTTPS asset URL, and exact APK hash, size, identity, version, signer, and embedded
channel. It uses only public material.

Before replacing `latest.json`, rehearse and record the offline half of the
update drill with `tools/update_drill.py`, which additionally proves that the
installed and candidate APKs form a legal in-place update pair and that the
envelope cannot be a downgrade or a replay. The full procedure, including the
on-device half this repository cannot automate, is in
[`update-drill.md`](update-drill.md). ADB must remain the working recovery path
until one real signed self-update from the installed version to a higher version
has completed on hardware.

The device also records the highest authorized version code it has accepted. A compromised file host therefore cannot replay an older signed manifest after the device has observed a newer one.

## Bootstrap and rollback

A device running a version without the updater needs one bootstrap installation through ADB. Routine updates no longer need a computer after that, provided the device has network access and can reach the HTTPS channel.

Android does not allow a normal update to replace an application ID or unrelated APK signer. The pilot remains `com.example.lockdowndpc` with its existing pilot signer. New customer devices must be provisioned with the production identity and key. Ship a corrective release or rollback as a new, higher `versionCode`, never as a downgrade.

On Android 9 and newer, the client accepts certificate rotation only when the new APK contains a platform-verified signing lineage that includes the currently installed signer. Multi-signer packages require an exact signer set and cannot use this rotation path. Rehearse every signer rotation on a test device before customer release: `tools/update_drill.py` deliberately reports any signer change as an unrecoverable in-place-update failure, because it compares digests and cannot see the lineage the platform would accept. A rotation that the drill refuses may still be legitimate — and must then be proven on hardware, following [`update-drill.md`](update-drill.md), rather than assumed.
