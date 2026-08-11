# Remote update hardening context

- Source root: `/Users/shalommaman/Documents/Codex/2026-08-11/adb`
- Target revision: `482e0235aeaa18afc6921e3996c9345c32049ec5`
- Source collection SHA-256: `394a60a344fd7e9622c484a780daa84555ebf9e4e8c62181eefabbc9c931cc9a`
- Evidence mode: inspected source plus Android platform documentation.

## Evidence inventory

| ID | Evidence | What it establishes |
| --- | --- | --- |
| E001 | Current repository at the target revision | The DPC has no network update client; upgrades currently use ADB. |
| E002 | `app/build.gradle.kts` and `docs/production-release.md` | Pilot and production identities/signing are deliberately separate; update compatibility requires the existing package name and certificate. |
| E003 | Android `PackageInstaller.Session` documentation | A device owner can commit an install without user interaction and receives an asynchronous status callback. |
| E004 | Android dedicated-device cookbook | Fully managed device admins can install private APKs through `PackageInstaller`. |
| E005 | Operator observation on 2026-08-11 | Rebooting the Android 9 device closes ADB TCP, so ADB is not a durable management plane. |

Primary platform references:

- https://developer.android.com/reference/android/content/pm/PackageInstaller.Session
- https://developer.android.com/reference/android/content/pm/PackageInstaller.SessionParams
- https://developer.android.com/work/dpc/dedicated-devices/cookbook

