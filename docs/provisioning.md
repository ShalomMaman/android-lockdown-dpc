# Device Owner provisioning

Device Guard only enforces policy when Android has made it the **Device Owner**.
Every restriction, the kiosk profiles and the signed self-update path check
`isDeviceOwnerApp` first and refuse to act otherwise, so provisioning is the
first operation of a deployment and the one that cannot be repaired remotely.

This runbook is the repeatable replacement for the single documented pilot
command. It covers building a verified provisioning payload, the QR flow on the
setup wizard, the ADB fallback, partial failures, proof that ownership actually
took effect, and recovery from a device enrolled with the wrong identity.

> **Rehearsal status.** The payload builder and its refusals are covered by JVM
> unit tests. The QR enrolment flow itself has **not** been rehearsed on any OEM
> hardware family. Ad-hoc ADB pilot enrolments have been performed, but no
> runbook-qualified OEM record has been completed. Treat every device-side step
> below as a procedure to be validated on the first unit of each model, not as
> verified behaviour. Issue #28 stays open until at least one QR enrolment has
> been completed end to end on target hardware.

## When Device Owner can be set at all

Android accepts a device owner only on a device that has **no user accounts and
no other device or profile owner**, which in practice means immediately after a
factory reset and before the setup wizard finishes. There is no supported way to
promote an ordinary installation on a device already in use.

Three consequences shape everything below:

- Enrolment is destructive. Plan it before the device holds any customer data.
- A device that fails halfway must be factory reset again rather than patched.
- The `afw#` Google Play enrolment token does not apply: Device Guard is
  distributed as a self-hosted APK, not through managed Google Play.

Device Guard requires Android 8.0 (API 26) or newer.

## The identity being provisioned

| Build | Application ID | Provisioning component |
| --- | --- | --- |
| Pilot / development | `com.example.lockdowndpc` | `com.example.lockdowndpc/com.example.lockdowndpc.admin.LockdownAdminReceiver` |
| Production | `il.co.shalommaman.deviceguard` | `il.co.shalommaman.deviceguard/com.example.lockdowndpc.admin.LockdownAdminReceiver` |

The source namespace stays `com.example.lockdowndpc` while the production
application ID differs, so the receiver class lives in a **different package
name from the application ID**. The abbreviated `package/.Class` form would
resolve to `il.co.shalommaman.deviceguard.admin.LockdownAdminReceiver`, which
does not exist, and provisioning would fail after the wizard has already wiped
the device. `tools/provisioning_payload.py` refuses the abbreviated form for
this reason. Always write the component in full.

The production identity is still provisional; see
[`docs/production-release.md`](production-release.md). Do not enrol a customer
device before it is fixed, because changing the application ID later is a
migration and a factory reset, not an update.

## Build the provisioning payload

`tools/provisioning_payload.py` produces the JSON object that the setup wizard
reads. It derives nothing from trust: given the release APK it reads the package
with `aapt2`, checks the signing certificate with `apksigner`, and refuses to
write anything if either disagrees with the operator's input.

```bash
python3 tools/provisioning_payload.py \
  --apk /secure/releases/device-guard-pilot-v0.5.4.apk \
  --admin-component il.co.shalommaman.deviceguard/com.example.lockdowndpc.admin.LockdownAdminReceiver \
  --download-location https://updates.example.test/device-guard-pilot-v0.5.4.apk \
  --signer-sha256 25507e47f49cbacc8cad66ee4967b2bae3f22bbd26fbb4587e9326626669014b \
  --locale iw_IL \
  --time-zone Asia/Jerusalem \
  --output /secure/provisioning/device-guard-payload.json
```

The tool prints a JSON summary containing the resolved component, the package
read from the APK, the signature checksum in the web-safe Base64 form Android
requires, the payload size, and the exact offline QR commands. It exits non-zero
with an actionable message on every validation failure and writes no partial
output.

What it refuses:

- a download location that is not clean HTTPS, or that carries credentials or a
  fragment — the wizard fetches it before any policy, VPN or trust store exists
  on the device;
- an empty, single-part or abbreviated administrator component;
- a signer value that is not a 32-byte SHA-256 digest in hexadecimal or Base64;
- an APK whose package differs from the component's package, or whose signing
  certificate differs from `--signer-sha256`;
- a payload above 1800 bytes, which produces a QR symbol that is unreliable to
  scan from a printed sheet;
- an admin-extras key that looks like a credential (`pin`, `password`,
  `recovery`, `token`, …), because a provisioning QR is printed, photographed
  and forwarded.

If the Android SDK build tools are unavailable the tool stops and names the
degraded option rather than emitting an unchecked payload. `--skip-apk-verification`
then produces a payload whose package and signer are **unverified operator
input**; the summary records `"apkVerification": "skipped-by-operator"` and a
warning is printed on stderr. Only use it to prepare a payload away from the
release artifact, and re-run the verified command before enrolling a device.

### Optional provisioning Wi-Fi

The wizard needs network access before the DPC exists. Cabled Ethernet or a
manually joined network is preferred. When the payload must carry the network:

```bash
# Inject DEVICE_GUARD_WIFI_PASSPHRASE through the operator's secret manager first.
python3 tools/provisioning_payload.py \
  ... \
  --wifi-ssid DeviceGuard-Enrolment \
  --wifi-security-type WPA \
  --wifi-password-env DEVICE_GUARD_WIFI_PASSPHRASE
```

The passphrase is never accepted as an argument and never echoed, but it is
necessarily written into the payload, because Android reads it from there. The
tool therefore writes that file with owner-only permissions and reports
`"wifiPasswordEmbedded": true`. **The payload file and any QR image made from it
are credentials.** Store them like a key, hand them out per enrolment session,
and destroy them afterwards. WEP and enterprise EAP networks are refused: WEP is
broken, and EAP needs identity and certificate extras this tool does not model.

The tool also refuses to write inside this repository. A provisioning payload is
never committed.

### Defaults this tool chooses, and why

- `PROVISIONING_LEAVE_ALL_SYSTEM_APPS_ENABLED` defaults to **true**. Letting
  provisioning disable system applications can remove the OEM dialer, settings
  or WebView provider and leave an unusable handset. Device Guard controls
  applications through verified policy instead.
- `PROVISIONING_SKIP_ENCRYPTION` defaults to **false**. Storage encryption stays
  on unless an operator asks for the opposite in writing.
- `PROVISIONING_SKIP_USER_CONSENT` is never emitted. It applies to test-only
  builds, and a silent enrolment is not a property this project claims.
- The signature checksum is the SHA-256 of the **signing certificate**, not of
  the APK file, so one printed QR survives a rebuild of the same version and
  every future release signed with the same key. The download URL still has to
  point at a current APK.

## Turn the payload into a QR code, offline

This project deliberately does **not** implement a QR encoder. A silently
malformed symbol would only be discovered on a wiped device in front of a
customer, and an encoder without a decoder cannot prove itself. Use an
established offline encoder and then read the symbol back.

```bash
# Encode. -8 forces byte mode; the payload file has no trailing newline.
qrencode -8 -l M -s 8 -m 4 \
  -o /secure/provisioning/device-guard-payload.png \
  -r /secure/provisioning/device-guard-payload.json

# Decode the produced image and prove it matches, byte for byte after parsing.
zbarimg --raw --quiet /secure/provisioning/device-guard-payload.png \
  > /secure/provisioning/decoded.json

python3 - <<'PY'
import json, sys
original = json.load(open("/secure/provisioning/device-guard-payload.json"))
decoded = json.load(open("/secure/provisioning/decoded.json"))
sys.exit(0 if original == decoded else "QR does not reproduce the payload")
PY
```

`qrencode` and `zbarimg` are offline tools (`qrencode` / `zbar-tools` on Debian,
`qrencode` / `zbar` in Homebrew). Never paste a provisioning payload into an
online QR generator: it identifies your fleet, and it may contain a Wi-Fi
passphrase.

Print at a size that scans from roughly 15–20 cm with the module edges intact,
and keep the quiet zone (`-m 4`) around the symbol.

## Runbook A — QR enrolment on the setup wizard

1. **Factory reset.** Settings → System → Reset options → Erase all data, or
   the recovery-menu equivalent. Remove any Google account **before** wiping so
   factory reset protection does not lock the device afterwards.
2. **Stop at the welcome screen.** Do not add an account and do not complete the
   wizard. If the wizard was completed, reset again.
3. **Open the enrolment entry point.** Tap the welcome screen six times in the
   same spot. Wording, tap target and the number of taps vary by OEM; some
   builds ask to join Wi-Fi first and then offer the QR scanner.
4. **Connect to a network** if prompted, or rely on the Wi-Fi keys in the
   payload.
5. **Scan the printed QR code.**
6. **Let the wizard download and install the DPC** from the download location
   and verify the signing certificate against the checksum in the payload.
7. **Accept the management consent screen** the platform shows.
8. **Finish the wizard** and confirm the checks in "Prove Device Owner took
   effect".

Record for each device: model, Android build number, serial, payload SHA-256,
APK version code, the operator, and the outcome. Never record the Wi-Fi
passphrase, the administrator PIN or a recovery code.

> **Known gap before the first QR attempt.** Device Guard's manifest declares
> the admin receiver with `DEVICE_ADMIN_ENABLED` and
> `PROFILE_PROVISIONING_COMPLETE`, and `LockdownAdminReceiver` implements
> `onProfileProvisioningComplete`. It declares no activity for
> `android.app.action.GET_PROVISIONING_MODE` or
> `android.app.action.ADMIN_POLICY_COMPLIANCE`, which recent platform versions
> hand to the DPC to finish setup-wizard provisioning. Expect the first QR
> attempt on Android 11 or newer to expose this, and treat the hardware
> rehearsal as the test that decides it. The ADB path in Runbook B does not use
> those intents and is unaffected.

## Runbook B — ADB fallback

Use when there is no camera path, when the OEM wizard has no QR entry point, or
during a rehearsal at a bench.

1. Factory reset and stop at the welcome screen, as above.
2. Complete the minimum wizard steps needed to reach developer options without
   adding an account, then enable USB debugging.
3. Install the exact release APK:

   ```bash
   adb install /secure/releases/device-guard-pilot-v0.5.4.apk
   ```

4. Set the device owner:

   ```bash
   adb shell dpm set-device-owner \
     il.co.shalommaman.deviceguard/com.example.lockdowndpc.admin.LockdownAdminReceiver
   ```

5. Verify as below, then finish the wizard.

`dpm set-device-owner` fails once an account exists on the device — the usual
cause of "Not allowed to set the device owner because there are already several
users on the device". The remedy is another factory reset, not a flag.

ADB remains the pilot's break-glass recovery path and is deliberately still
enabled by the pilot profile. It cannot be withdrawn until the signed
self-update drill in the production roadmap has passed on real hardware.

## Prove Device Owner took effect

Never report an enrolment as successful because the wizard finished. Confirm all
three:

1. **The platform's record**, over ADB while it is still available:

   ```bash
   adb shell dumpsys device_policy | sed -n '1,40p'
   ```

   A provisioned device shows a device owner entry naming the Device Guard
   package and `LockdownAdminReceiver`. On builds that support it,
   `adb shell dpm list-owners` prints the same fact more compactly.

2. **The console.** Open Device Guard. The status surface reads
   `isDeviceOwnerApp` directly, so it shows ownership rather than an assumption.

3. **A verified policy apply.** Apply the intended protection profile and
   confirm the console reports it as applied. Device Guard never reports a
   requested policy as active until it has read the value back from the
   platform, so an "applied" state is evidence and a "failed" state is a real
   OEM refusal to investigate — not a display defect.

An enrolment that satisfies 1 and 2 but not 3 is an OEM policy problem on a
correctly owned device. Record which restriction failed before continuing; that
is exactly the per-model evidence the OEM matrix work needs.

## When provisioning fails halfway

A half-provisioned device is not a running device. Do not hand it over, and do
not try to repair it in place.

| Symptom | Likely cause | Action |
| --- | --- | --- |
| Wizard cannot download the APK | Download location unreachable, HTTP redirect, captive portal | Fix the host and network; re-scan. The URL must be clean HTTPS end to end. |
| "Package checksum does not match" or a signature error | The URL serves an APK signed with a different key, or `--signer-sha256` was wrong | Rebuild the payload with `--apk` so the digest is read from the artifact. |
| Wizard installs the DPC but does not hand over | The mode/compliance intents above are unresolved, or the DPC crashed on the callback | Factory reset. Capture `adb logcat` from the next attempt before resetting if possible. |
| "Already provisioned" / owner already set | The device was not fully wiped | Factory reset. |
| Enrolment ends with no management consent screen | Wizard was already completed once | Factory reset. |
| Device reboots into the wizard repeatedly | Encryption or wizard step interrupted | Factory reset; do not use `--skip-encryption` as a workaround. |

After any failure: factory reset, then start Runbook A from step 1. If the
device became owned before it failed, the Settings reset entry may already be
blocked — see the recovery section below for what remains. Keep the failure in
the enrolment record — the pattern across models is the deliverable
of the OEM matrix, not noise.

## Recovering a device with the wrong component or identity

There is no supported operator-side transfer of Device Owner to a different
application. Device Guard implements no ownership transfer, and Android will not
let an external tool reassign it.

- **Wrong application ID (pilot enrolled where production was intended, or the
  reverse).** These are different applications to Android. There is no in-place
  migration. Factory reset and re-provision with the correct payload.
- **Wrong component string that still provisioned.** Only a component that
  resolves can become the owner, so this normally appears as a failed
  provisioning, handled above.
- **Right identity, wrong policy.** Not a provisioning problem. Fix it in the
  console with an authenticated administrator session.
- **Device Guard is the owner but the device must be released.** Device Guard
  implements no self-removal: there is no ownership transfer, no
  `clearDeviceOwnerApp` and no remote wipe in this codebase. Releasing a device
  is a wipe.
- `adb shell dpm remove-active-admin …` only works for test-only builds. A
  release-signed Device Guard will refuse, by design: an active kiosk that ADB
  could dismantle would not be a kiosk.

**Wiping an already-managed device is harder than wiping a fresh one.** Device
Guard enforces `DISALLOW_FACTORY_RESET` on every profile, pilot included, so
once protection has been applied the Settings reset entry is gone. The remaining
path is the bootloader/recovery wipe for that model, entered with the hardware
key combination. `DISALLOW_SAFE_BOOT` is enforced as well, so Safe Boot is not
an escape either. This is deliberate: a device a student can reset is not a
managed device. Budget for it in the enrolment plan — the recovery-mode
procedure is model-specific and belongs in the per-model record.

Before any wipe, confirm the Google account state. Factory reset protection can
lock a wiped device until the previously signed-in account is re-entered, which
turns a five-minute recovery into a support case.

## What is proven and what is not

Proven by `tools/test_provisioning_payload.py` (JVM-free Python unit tests):
payload structure and key set, digest normalisation across hexadecimal and
Base64, every refusal path, the environment-variable-only handling of the Wi-Fi
passphrase, the restricted file mode when a passphrase is embedded, and the
non-zero exit on validation failure.

Not proven anywhere in this repository: that a printed QR scans on any specific
OEM setup wizard, that the wizard completes the handover to
`LockdownAdminReceiver` on Android 11 or newer, that the download location is
reachable from a device before policy exists, and that a provisioned device then
reports a verified policy apply. Those are hardware acceptance items and they
belong to the physical validation gate in
[`docs/production-roadmap.md`](production-roadmap.md).

Official references: [provisioning a fully managed device](https://developer.android.com/work/dpc/provisioning),
[QR-code provisioning extras](https://developer.android.com/reference/android/app/admin/DevicePolicyManager),
and [building a DPC](https://developer.android.com/work/dpc/build-dpc).
