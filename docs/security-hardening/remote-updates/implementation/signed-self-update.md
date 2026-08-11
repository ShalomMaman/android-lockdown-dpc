# Implementation Plan: Signed self-update

## Selected Design And Constraints

Implement the signed self-update option for minSdk 26 with the Android 9 physical device as the compatibility floor. Remote updates are disabled unless both an HTTPS manifest URL and an ECDSA public key are injected at build time.

## Source Revision And Drift Check

The decision is anchored to revision `482e0235aeaa18afc6921e3996c9345c32049ec5` and source collection SHA-256 `394a60a344fd7e9622c484a780daa84555ebf9e4e8c62181eefabbc9c931cc9a`. No source drift existed when implementation began.

## Affected Components

- Gradle BuildConfig and production initialization
- Android manifest and boot/device-admin service integration
- New `updates` package and install result receiver
- Compose administrator console
- Unit tests, publishing tool, and operator documentation

## Ordered Work Packages

1. Add disabled-by-default build configuration and update state storage.
2. Implement bounded signed-envelope parsing and verification.
3. Implement APK download, digest/size/package/version/signer verification.
4. Commit a self-update-only PackageInstaller session and record its callback.
5. Schedule periodic checks and add an administrator manual-check/status surface.
6. Add offline release tooling and deployment documentation.
7. Validate failure cases, Android 9 installation, policy reconciliation, and rollback.

The implemented reconciliation stores the candidate PackageInstaller session ID
and version code, then re-reads the installed package before reporting success.
Metadata has bounded issued/expiry times and a persisted highest-seen version;
network work has wall-clock deadlines and JobScheduler cancellation.

## Compatibility And Migration

The pilot keeps `com.example.lockdowndpc` and its existing signer. The production identity remains a separate reset/re-provision migration. The envelope schema is versioned; unsupported schemas fail closed. On Android 9+ a signer rotation is accepted only through platform-verified signing history containing the currently installed signer; multi-signer packages still require an exact set match.

## Tactical Protections During Migration

Keep the current ADB procedure and Tailscale available as break-glass access. Do not enable polling in a build without a production endpoint and backed-up offline metadata key.

## Tests And Security Validation

Cover malformed/oversized metadata, invalid signature, wrong package, same/lower version, wrong size/digest, wrong APK signer, non-HTTPS URLs, redirects, interrupted download, non-owner install, and every PackageInstaller terminal status.

## Performance And Resource Benchmarks

Measure no-update check bytes/time, update download bytes/time, peak cache size, and worker memory on Android 9. Acceptance threshold: no resident background service and no unbounded in-memory APK buffering.

## Rollout And Rollback

Bootstrap one device with ADB, manually verify a signed no-update check, then deliver one higher-version self-update. Expand only after the device reports final install success and policy reconciliation. Rollback is a higher-version corrective release; emergency recovery remains ADB.

## Acceptance Criteria

- Unsigned or altered metadata never initiates an APK download.
- An unauthorized APK never reaches PackageInstaller.
- A valid higher same-signer APK installs without user interaction on the Android 9 Device Owner.
- Failed updates do not change protection state.
- Successful replacement rebinds the admin service and reconciles policy.

## Open Decisions

- Production release endpoint.
- Offline metadata-key storage/backup procedure.
