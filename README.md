# Device Guard DPC

[![Android CI](https://github.com/ShalomMaman/android-lockdown-dpc/actions/workflows/android-ci.yml/badge.svg)](https://github.com/ShalomMaman/android-lockdown-dpc/actions/workflows/android-ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Android 8+](https://img.shields.io/badge/Android-8.0%2B-3DDC84.svg?logo=android&logoColor=white)](https://developer.android.com/about/versions/oreo)

Device Guard is an Android device-policy controller for fully managed, Device Owner deployments. It is designed for dedicated devices where an authorized administrator chooses which apps remain available and protects the policy with a local PIN.

The app interface is fully bilingual: English is the default locale and Hebrew is a complete translation, selectable from the authenticated console and mirrored for right-to-left layout. The source code, build documentation, security model, and contribution workflow are maintained in English.

## Features

- Three explicit operating profiles: managed app filtering, single-app kiosk, and single-site kiosk. Kiosk is opt-in — an upgrade or a reboot never turns it on. See [`docs/kiosk-mode.md`](docs/kiosk-mode.md).
- Blocklist and strict allowlist operating modes. Each keeps its own saved app list, so switching between them is reversible and never discards a curated selection.
- Built-in blocking for known browsers, app stores, and social-media apps.
- HTTP/HTTPS link interception while protection is active.
- A 6–12 digit administrator PIN with progressive throttling and lockout.
- A one-time recovery code stored only as a protected verifier.
- Policy pause and resume, including restoration of hidden packages.
- Automatic reconciliation after reboot, app update, or package installation. On Android 8+, a `DeviceAdminService` and dynamic package receiver follow Android's supported DPC lifecycle.
- A persistent package inventory, so administrators can manage packages that are currently hidden.
- Verified policy state (`applying`, `active`, or `failed`) that never reports success after a partial policy application.
- Synchronous verification of restrictions, package visibility, uninstall blocking, WebView availability, and link routing; Android 14+ policy callbacks provide additional asynchronous confirmation.
- Keeps the system WebView provider available while blocking its browser UI when Chrome supplies the WebView engine.
- Keeps the management app and Tailscale available and protected from removal.
- Local administrative audit log, including kiosk configure, activation, refused activation, exit and restore events. It never records PINs, recovery codes, or the path, query or fragment of a kiosk website — a single-site event records the allowed origin only.
- Signed self-update channel with daily checks, ECDSA metadata verification, APK hash/identity/version/signer verification, and silent Device Owner installation.
- English and Hebrew UI with enforced locale parity: every key, plural category and format placeholder is checked in CI and by a standalone script, so a half-translated release fails the build instead of showing English inside a Hebrew screen.

## Requirements

- Android 8.0 or newer (`minSdk 26`).
- JDK 17 and the Android SDK.
- A test device that can be provisioned as Device Owner.

## Build and test

```bash
export JAVA_HOME="/path/to/jdk-17"
export ANDROID_HOME="/path/to/android-sdk"
./gradlew assembleDebug lintDebug test
```

Locale parity can also be checked without an Android SDK:

```bash
python3 tools/check_locale_parity.py
python3 -m unittest discover -s tools -p 'test_*.py'
```

## Development provisioning

`set-device-owner` is intended for a clean test device and normally requires a factory reset. Never run it on a personal device or on a device that contains important data.

```bash
adb install -t app/build/outputs/apk/debug/app-debug.apk
adb shell dpm set-device-owner \
  com.example.lockdowndpc/.admin.LockdownAdminReceiver
```

Open Device Guard, set an administrator PIN, store the recovery code securely, select a policy mode and package list, then activate protection.

## Security and deployment

The fail-closed package-reconciliation design is documented in [`docs/package-reconciliation.md`](docs/package-reconciliation.md). The remote update architecture and release process are documented in [`docs/secure-updates.md`](docs/secure-updates.md). What an independent UI, localization and kiosk-administration review found, what changed, and what remains unproven without hardware are recorded in [`docs/ui-qa-remediation.md`](docs/ui-qa-remediation.md).

- Never commit an APK-signing key, metadata-signing key, administrator PIN, recovery code, or device credential.
- A normal build retains the pilot identity and development signer for compatibility with the existing test device. The explicit production identity and external-signing flow are documented in [`docs/production-release.md`](docs/production-release.md).
- Commercial deployments should use QR or USB provisioning after a factory reset and a documented signed-update process.
- Do not enable `DISALLOW_DEBUGGING_FEATURES` until an independent management path has been tested, or remote recovery may become impossible.
- Recovery reset or firmware flashing can remove any DPC. A serious threat model must also cover boot-chain integrity and physical access.
- **Kiosk mode is unverified on hardware.** Nothing in 0.5.0 has been tested on a Device Owner-provisioned handset or on any OEM build. Before enabling kiosk on a device you cannot easily reach, confirm the administrator PIN is known to more than one person and a current recovery code is stored off the device: without either, the only way out of kiosk is re-provisioning, which destroys local data. The unverified assumptions are enumerated in [`docs/kiosk-mode.md`](docs/kiosk-mode.md#what-is-not-proven-without-a-device).

## Contributing

Contributions are welcome. Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request and report vulnerabilities according to [`SECURITY.md`](SECURITY.md), not through a public issue.

Licensed under the [Apache License 2.0](LICENSE).

## Status

Pilot release: `0.5.0` (`versionCode 9`).

`0.5.0` keeps the pilot `applicationId` and signer, so it updates the already provisioned pilot device in place.

| Area | State |
| --- | --- |
| Managed app filtering (0.4 behaviour) | Unchanged when kiosk is off; covered by the existing JVM tests |
| Administrator PIN, lockout, recovery code | Unchanged; covered by JVM tests |
| English/Hebrew UI and RTL layout | Complete; parity enforced by `LocaleParityTest` and `tools/check_locale_parity.py` |
| Kiosk state machine, URL and origin rules, target eligibility, console refusal handling | Pure logic, covered by JVM tests |
| Kiosk console flow (profile, app picker, site editor, confirmation) | Implemented; **not** exercised on a device or an emulator |
| Lock task, HOME takeover, escape-surface hiding, reboot restoration | **Unverified on hardware.** No Device Owner handset and no OEM build has been tested |
| Production identity and external signing | Documented, unused by this build; no production secrets are configured |

Kiosk mode should be treated as a pilot feature pending Device Owner testing.
