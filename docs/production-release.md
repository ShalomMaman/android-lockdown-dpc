# Production identity and signing

The production path is intentionally separate from the existing pilot:

- A normal build keeps the `com.example.lockdowndpc` identity and pilot signer, so it can update the already provisioned Device Owner test device.
- A production build uses the temporary `il.co.shalommaman.deviceguard` identity and requires an external signing key. Keys and secrets never live in this repository.

> Finalize the organization name and application ID before provisioning the first customer device. Changing either after release is a migration, not a normal update.

## Signing material

Store the keystore in an organizational vault with an encrypted backup, outside the project directory. Provide these values through a CI secret store, local environment variables, or an untracked `~/.gradle/gradle.properties` file:

```properties
deviceGuardStoreFile=/absolute/secure/path/device-guard-production.jks
deviceGuardStorePassword=REDACTED
deviceGuardKeyAlias=device-guard-production
deviceGuardKeyPassword=REDACTED
```

Equivalent environment variables are:

```text
DEVICE_GUARD_STORE_FILE
DEVICE_GUARD_STORE_PASSWORD
DEVICE_GUARD_KEY_ALIAS
DEVICE_GUARD_KEY_PASSWORD
DEVICE_GUARD_UPDATE_MANIFEST_URL
DEVICE_GUARD_UPDATE_PUBLIC_KEY
DEVICE_GUARD_UPDATE_PUBLIC_KEY_SHA256
```

The final three values enable the signed update channel. The manifest URL must use HTTPS. The public key is an EC SubjectPublicKeyInfo value encoded as X.509 DER and then Base64. Its matching private key is separate from the APK-signing key and is used only to sign update manifests. The SHA-256 value is the fingerprint of the decoded public-key DER bytes. A production build fails if any value is missing, the key is not valid P-256 EC/X.509, or the approved fingerprint does not match.

## Build

The init script is an explicit switch: without `-I`, Gradle produces a pilot APK; with it, Gradle produces a production APK.

```bash
./gradlew -I gradle/production.init.gradle.kts clean assembleRelease lintRelease test
```

Verify identity and signer before publishing:

```bash
apkanalyzer manifest application-id app/build/outputs/apk/release/app-release.apk
apksigner verify --print-certs app/build/outputs/apk/release/app-release.apk
```

Do not distribute an APK if its application ID is not `il.co.shalommaman.deviceguard`, it uses a debug certificate, or its certificate fingerprint differs from the approved organizational record.

## Provisioning

The source namespace remains `com.example.lockdowndpc` so the pilot's administration component stays stable. Use the fully qualified component name for production provisioning:

```bash
adb shell dpm set-device-owner \
  il.co.shalommaman.deviceguard/com.example.lockdowndpc.admin.LockdownAdminReceiver
```

The same value is required in `android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME` during QR provisioning.

## Recovery caveats before a customer rollout

`0.5.0` keeps the pilot `applicationId` and the debug-compatible release signing config, so an ordinary `assembleRelease` still updates the existing pilot device. Nothing in this repository configures a production secret, and none is required to build.

Before enabling kiosk mode on any device that is not physically at hand:

- Confirm the administrator PIN is known to more than one person and that a current recovery code is stored securely off the device. Without both, the only exit from an active kiosk is re-provisioning, which destroys local data.
- Confirm the responsible administrator has been briefed on the kiosk entry gesture documented in [`docs/kiosk-mode.md`](kiosk-mode.md#administrator-entry-from-inside-kiosk).
- Treat kiosk mode as unproven until it has been exercised on a Device Owner-provisioned handset of the same model and Android build. Lock task behaviour, HOME-preference persistence across reboot, and the completeness of the escape-surface catalogue are all OEM-specific and are **not** verified by the unit tests.
- Verify that a kiosk-off device still reports a verified policy apply on the target hardware, so that the kiosk reconciliation added in 0.5 has not turned ordinary managed filtering into a reported failure.

## No in-place pilot-to-production migration

The production APK is a different application and cannot update `com.example.lockdowndpc`. Device Owner ownership is also bound to the existing administrator component. Moving a pilot device to the production identity requires a planned migration, normally management removal or a factory reset followed by fresh provisioning.

Official references: [application ID and namespace](https://developer.android.com/build/configure-app-module), [app signing and updates](https://developer.android.com/studio/publish/app-signing), and [building a DPC](https://developer.android.com/work/dpc/build-dpc).
