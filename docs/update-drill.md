# Signed self-update drill

The acceptance gate for treating ADB as an exceptional recovery tool rather than
the normal one is a single concrete event: **one real, signed, in-place update
from an installed version to a higher version, completed on the enrolled device,
before ADB is disabled.** Until that has happened on hardware, disabling ADB
removes the only proven way to recover the device.

The drill has two halves.

| Half | What it covers | Automated here | Status |
| --- | --- | --- | --- |
| Offline | The two APKs form a legal in-place update pair, and the published envelope satisfies exactly the rules the client enforces | Yes, `tools/update_drill.py` | Reproducible on any workstation with the release tools |
| On-device | Stage, trigger the app's scheduled check, and verify silent Device Owner installation and retained policy | `tools/device_update_drill.py` for the isolated production channel, with a witness | **Unproven until it is executed on hardware** |

Do not record the gate as met or disable ADB on the strength of the offline half
alone. Keep the evidence for the exact device and firmware used.

## What the offline half proves

`tools/update_drill.py` re-implements the checks that `UpdateEnvelopeVerifier`
and `SecureUpdateManager` perform on the device, so that a bad release is caught
before it reaches a device rather than after:

- the application ID is identical on both sides;
- the candidate `versionCode` is strictly higher than the installed one;
- the APK signing certificate is identical on both sides, and both match the
  approved channel certificate;
- the envelope is a well-formed `payload`/`signature` pair, unpadded URL-safe
  Base64 over UTF-8 JSON, within the 64 KiB client limit;
- the ECDSA P-256 signature verifies over the canonical payload;
- the metadata public key is a P-256 key whose DER SHA-256 equals the approved
  fingerprint compiled into the build;
- the payload names the expected package, exactly the candidate version, the
  candidate APK's SHA-256 and byte size, and a clean HTTPS URL with no
  credentials and no fragment;
- the validity window is currently open, ordered, and no longer than 91 days;
- the payload version is higher than the installed version and at or above the
  replay floor the device has already recorded.

A signer change or an application ID change is reported as an **unrecoverable**
failure. Android will not replace an installed package across either change, so
no envelope, no republish, and no retry repairs it. The only routes out are a
rebuilt candidate with the enrolled identity and signer, or re-provisioning the
device — which needs the recovery path the gate is about to remove.

## Prerequisites

- Python 3 and OpenSSL.
- Android SDK Build Tools (`aapt2`, `apksigner`) when APK files are supplied.
  Each external binary degrades independently: if one is absent, the checks that
  need it are reported `SKIP`, never `PASS`.
- The installed APK, or its exact metadata, and the candidate APK.
- The published envelope and the non-secret metadata public key.
- No network access is used or required.

## Part 1 — offline rehearsal

```bash
python3 tools/update_drill.py \
  --from-apk /secure/releases/device-guard-pilot-v0.5.1.apk \
  --to-apk /secure/releases/device-guard-pilot-v0.6.0.apk \
  --envelope /secure/releases/latest.json \
  --metadata-public-key updates/pilot/public-key.pub \
  --expected-metadata-key-sha256 c83816c000a61a600d90b8d4dab4a63aa27585292d605938ba8104b6559955cc \
  --expected-package com.example.lockdowndpc \
  --expected-signer-sha256 25507e47f49cbacc8cad66ee4967b2bae3f22bbd26fbb4587e9326626669014b \
  --expected-apk-url https://HOST/releases/download/pilot-v0.6.0/device-guard-pilot-v0.6.0.apk \
  --highest-authorized-version-code 10 \
  --record evidence/update-drill-0.6.0.json
```

When the installed APK file is no longer on hand, describe it instead of
supplying it: `--from-package`, `--from-version-code`, `--from-version-name`,
`--from-signer-sha256`. Read those values off the device itself, not off a
build record. Supplying both a file and a declared value is allowed and is
checked for agreement; a contradiction fails the drill.

`--highest-authorized-version-code` is the replay floor the device has already
recorded (`highest_authorized_version` in the app's `secure_updates`
preferences). When it is omitted the tool assumes it equals the installed
`versionCode` and says so in the record.

### Reading the result

| Verdict | Exit code | Meaning |
| --- | --- | --- |
| `PASS` | 0 | Every offline check ran and passed. |
| `INCOMPLETE` | 1 | Nothing failed, but at least one check could not be performed here. The gate is not met. |
| `FAIL` | 2 | At least one check failed. Do not publish. |
| — | 3 | The inputs were rejected before any check ran. |

The human summary lists every check as `PASS`, `FAIL`, or `SKIP` with the reason,
and the `--record` file is the same content as JSON for attaching to the issue.
An existing record is never overwritten unless `--force` is explicit, so a rerun
cannot quietly replace earlier evidence. Without `--record`, the JSON is printed
after the summary instead.
A `SKIP` is never counted as a pass and never upgrades the verdict; an
`INCOMPLETE` run means the environment was missing something, not that the
update is sound.

## Part 2 — scripted production-channel drill

Use a dedicated physical bench device and an isolated, direct HTTPS update
channel reserved for that device. Have a witness and keep ADB available for
recovery. The installed baseline must be a single, hardened production release,
signed with the same APK key and built to trust that channel. If a new baseline
is needed, build it with `gradle/production.init.gradle.kts` at the source
version and provision it before the drill. On the bench device, enable and verify
the factory-reset restriction and the other expected policies. Open the console
to let the app schedule its update job. Keep the old manifest current until
the script asks you to stage the new one.

Use JDK 17, the project Gradle wrapper, Python 3.10+, OpenSSL, Android SDK
Build Tools, and authorized USB ADB. Select the device with `ANDROID_SERIAL`
if more than one is connected. Load these four signing values at runtime from
the secure credential store (for example, macOS Keychain).

- `DEVICE_GUARD_STORE_FILE`
- `DEVICE_GUARD_STORE_PASSWORD`
- `DEVICE_GUARD_KEY_ALIAS`
- `DEVICE_GUARD_KEY_PASSWORD`

Keep the keystore outside the checkout. Supply the existing channel's
`DEVICE_GUARD_UPDATE_MANIFEST_URL`, `DEVICE_GUARD_UPDATE_PUBLIC_KEY` and
`DEVICE_GUARD_UPDATE_PUBLIC_KEY_SHA256` through the environment. Run the script
from the checkout with shell tracing disabled, a new private output directory,
and a version code above the installed version, source version, and any
previously authorized version on this bench channel.

```bash
python3 tools/device_update_drill.py \
  --version-code "$DRILL_VERSION_CODE" --output-dir "$NEW_DRILL_DIR"
```

1. The script uses ADB to read Device Owner and the owner user's effective
   restrictions, then pulls the installed APK to check its identity, channel,
   and signer. Confirm the baseline and isolated test setup when prompted.
2. It builds `candidate.apk` with the production init script and the higher
   version code, then checks the release boundary, matching signer, and
   unchanged channel. At the staging prompt, watch the device. Sign the new
   envelope with the separate metadata key using
   [`tools/publish_update.py`](../tools/publish_update.py) and the instructions in
   [Secure updates](secure-updates.md). Stage the exact candidate at an
   immutable HTTPS URL first, then replace the isolated channel's manifest.
3. The script verifies the served envelope against the candidate, checks that
   the baseline is still installed, and runs
   `adb shell cmd jobscheduler run -f -u OWNER_USER PACKAGE 1146441796`.
   The app downloads, verifies, and installs the update through its normal path.
   Observe the device continuously. Stop if an installation prompt appears.
4. The script compares the installed APK byte-for-byte by digest and size with
   the candidate. Check the console for both update audit entries and verify the
   same policies and end-user behavior as before. Confirm the witness prompt
   only after seeing the full sequence and no request for install approval.
   The script then reads back Device Owner and effective restrictions with ADB.
5. Save the single JSON line from standard output with the hardware case.
   `PASS` exits 0. `FAIL` exits 1 with the stage and a sanitized reason.
   The result covers the scripted checks and the witness observations. Record
   the remaining hardware observations below, including a follow-up check that
   the app reports the candidate as current. Keep ADB enabled when any check fails.

ADB starts the app's scheduled check and reads back device state. Use the
operator session to stage channel artifacts. Leave the installed app, app data,
and policy in place throughout the run. If the periodic check
installs the update during staging and before the controlled trigger, capture
what was observed and repeat the scripted drill with a fresh higher version.
If the device's ADB output cannot be interpreted, record the failed stage and
use the manual procedure below to gather firmware-specific evidence.

### Manual procedure

Use this procedure for the pilot channel or to gather additional observations.
Execute it on the enrolled device with ADB still enabled.

**Step 0 — record the starting state.** Note the installed `versionName` and
`versionCode`, that the app is Device Owner, that the policy screen reports the
active policies as verified, and that ADB is still reachable. A drill that
starts from an unknown state proves nothing.

**Step 1 — build and publish N+1.** Build the candidate with the fail-closed
channel command in [`docs/secure-updates.md`](secure-updates.md), sign the
envelope with `tools/publish_update.py`, and bind the artifact to the channel
with `tools/verify_pilot_apk.py`. Upload the immutable APK asset **first**, then
run Part 1 of this drill, and only then atomically replace `latest.json`.
Replacing the metadata before the asset exists gives every device a valid
envelope pointing at nothing.

**Step 2 — observe the check.** The client checks once after bootstrap and then
daily through `JobScheduler` (24-hour period, 6-hour flex), so the natural
observation window is up to about a day. To rehearse deliberately, use the
console's "Check for a secure update" action, which runs the same code path. Do
not reboot, sideload, or clear app data to force the result; that would rehearse
a different path than the one customers will rely on.

**Step 3 — confirm the installation was silent and policy-driven.** Expect no
installation prompt and no user interaction: the session is created with
`INSTALL_REASON_POLICY` and, from Android 12, `USER_ACTION_NOT_REQUIRED`. If a
prompt appears, or the check reports `automatic-update-requires-device-owner`,
the device is not a Device Owner and the drill has failed at its premise.

**Step 4 — confirm the device came back.** After the process is replaced, check
that:

- the installed `versionName`/`versionCode` are the candidate's;
- the app is still Device Owner and the console is reachable;
- every policy the device is supposed to enforce is shown as verified — the
  policy engine reports a policy as active only after reading it back, so
  "requested" is not "applied";
- kiosk or managed profile behaviour is unchanged for the end user;
- the audit log contains the update entries, `Update <version> verified and sent
  for install` followed by `Update <version> installed successfully`. The second
  entry is also written by the post-replacement reconciliation path, so its
  absence means the install did not complete, not merely that a callback was
  lost.

**Step 5 — confirm the channel is still healthy.** Run the check once more and
expect `Version <candidate> is current`. This proves the device recorded the new
version as its replay floor and will not accept the older envelope again.

**Step 6 — only then consider the ADB question.** The gate is met when Part 1
returned `PASS` and Steps 0–5 were observed on the device and recorded.

## Evidence to capture

Attach to the issue, in this order:

1. the `--record` JSON from Part 1 (verdict, counts, and every check);
2. installed `versionName`/`versionCode` before and after, read from the device;
3. the SHA-256 of the published APK and the published `latest.json`, so the
   artifacts that were actually installed can be identified later;
4. the console state sequence you observed (checking, downloading, installing,
   installed) and the wall-clock time each transition took;
5. the relevant audit entries;
6. a note of anything that could not be observed, stated as unobserved rather
   than assumed.

Never capture a PIN, a recovery code, a kiosk URL path, query or fragment, the
metadata private key, its passphrase, or any keystore material. The audit log is
designed not to contain them; screenshots and terminal transcripts are not, so
review them before attaching.

## If the drill fails

Keep ADB enabled. A failed drill is exactly the situation the recovery path
exists for.

| Failure | Response |
| --- | --- |
| Offline verdict `FAIL` on an envelope check | Fix and republish the envelope. Nothing reached a device. |
| Offline verdict `INCOMPLETE` | Install the missing tool and rerun. Do not proceed on the passing subset. |
| Signer or application ID change | Unrecoverable for an in-place update. Rebuild the candidate with the enrolled identity and signer. If the wrong artifact was already installed, the device must be re-provisioned. |
| Envelope expired before install | Republish with a fresh validity window; the APK does not change. |
| Download or hash failure on the device | The client discards the cached APK and retries on the next scheduled check. Confirm the asset URL is immutable and the host serves the exact bytes that were hashed. |
| Bad release installed successfully | Roll **forward**: ship the correction as a higher `versionCode`. Android does not allow a downgrade, and the device's recorded replay floor will refuse an older envelope even if it is validly signed. |
| Device does not come back with policy verified | Recover over ADB, capture the state, and treat the gate as failed. Do not retry the drill on the same device until the cause is understood. |

## Current status

The offline half is implemented and covered by unit tests
(`tools/test_update_drill.py`), including the downgrade, replay, signer-change,
package-mismatch, corrupted-signature, and skipped-check paths. The tests
generate throwaway EC keys inside a temporary directory; no key material is
stored in this repository.

The on-device half still requires execution on hardware. Record the result
against the tested device model, Android version, and firmware.
