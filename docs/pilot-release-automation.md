# Protected pilot release automation

The `Publish Pilot Release` workflow turns one reviewed release commit on
`main` into a signed, verified pilot release. It replaces the previous sequence
of manual build, upload, envelope signing, verification, and metadata editing.

Publication remains an explicit product decision. Ordinary merges never ship a
new APK. The operator selects the current `main` commit and runs the workflow;
that dispatch is the single release approval.

## Security boundary

The workflow uses the GitHub environment named `pilot-release`. That environment
accepts only protected branches. Its secrets are not repository secrets and are
not available to ordinary CI, pull requests, or builds from unprotected refs.

Six environment secrets are required:

| Secret | Purpose |
| --- | --- |
| `PILOT_SIGNING_KEYSTORE_B64` | Base64 of the existing pilot APK keystore |
| `PILOT_SIGNING_STORE_PASSWORD` | Keystore password |
| `PILOT_SIGNING_KEY_ALIAS` | Alias of the enrolled pilot signing key |
| `PILOT_SIGNING_KEY_PASSWORD` | Private-key password |
| `PILOT_UPDATE_PRIVATE_KEY_B64` | Base64 of the encrypted P-256 metadata private key |
| `PILOT_UPDATE_KEY_PASSWORD` | Metadata-key passphrase |

The two private files are decoded only into the ephemeral GitHub-hosted runner,
mode `0600`, after the trusted-source check. They are deleted by an `always()`
cleanup step. Password values are passed only as masked environment secrets.
The repository contains only the public trust record in
`updates/pilot/channel.json` and `updates/pilot/public-key.pub`.

Do not generate replacement keys for this setup. Existing enrolled devices
accept only the current APK certificate and metadata key. The workflow verifies
both fingerprints before it can create a release.

## One-time setup

An administrator must populate the six environment secrets from the existing
vaulted pilot material. Encode each private file as one Base64 string outside
the repository. Do not paste a key, keystore, password, or encoded private file
into an Issue, Pull Request, workflow input, terminal transcript, or Actions
log.

The environment policy and secret names can be reviewed under:

`Repository settings → Environments → pilot-release`

The environment is intentionally restricted to protected branches. Adding a
required deployment reviewer is supported, but changes the operator experience
from one action (dispatch) to two actions (dispatch and deployment approval).

## Prepare a release commit

1. Change `versionCode` and `versionName` once in `app/build.gradle.kts`.
   `versionCode` must be strictly higher than the signed value in
   `updates/pilot/latest.json`.
2. Update release-facing documentation and complete the normal reviewed Pull
   Request. Merge it to `main` only after Android CI is green.
3. Do not edit `updates/pilot/latest.json`. The protected workflow creates that
   signed file from the exact release APK.

The Gradle release gate reads the version directly from the Android
configuration, so the same version no longer needs to be copied into Gradle
verification tasks or CI commands.

## Publish

Open `Actions → Publish Pilot Release → Run workflow`, select `main`, optionally
enter release notes, and run it. The workflow then:

1. proves it is running the current protected `main` commit;
2. restores the two private files in the ephemeral runner;
3. runs tests, lint, the channel-aware release build, exact signer verification,
   and compiled-channel verification;
4. verifies the current signed envelope and requires a higher `versionCode`;
5. creates and independently verifies the new signed envelope;
6. downloads the current public APK, checks its signed hash and size, and runs
   the offline in-place update drill;
7. creates a draft prerelease containing the APK, envelope, and drill record;
8. opens a generated metadata Pull Request and explicitly runs Android CI on
   that bot-created commit;
9. publishes the immutable GitHub Release;
10. only after the APK is public, merges the verified metadata Pull Request;
11. reads `latest.json` back from public `main` and requires byte-for-byte
    equality with the verified envelope.

The workflow never overwrites a tag, release, asset, output file, or metadata
branch. A release therefore has one identity and one auditable artifact set.

## Failure and recovery

The active update channel is changed only at the end. A build, signing,
verification, drill, draft-release, or metadata-CI failure leaves the existing
`latest.json` unchanged.

If a run stops after creating a draft release, inspect and delete that draft
before retrying the same version. If it stops after publishing the release but
before merging metadata, the release is a safe orphan: inspect the generated
metadata Pull Request and merge it only if its recorded Android CI run passed.
Do not recreate or overwrite the tag.

If a bad build ever reaches a device, Android and the replay floor prevent a
downgrade. Fix it with a new, higher `versionCode` and roll forward.

This automation proves the offline release chain. The separate physical-device
self-update gate in [`update-drill.md`](update-drill.md) still must pass before
ADB is treated as an exceptional recovery path.
