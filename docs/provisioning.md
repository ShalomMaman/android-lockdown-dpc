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

> **Android 12 (API 31) and later.** Use an APK that includes both setup wizard
> handlers. Device Guard selects fully managed device mode and cancels setup
> if Android supplies an allowed-mode list that excludes it. After Android
> grants Device Owner, the compliance handler shows a progress screen and
> applies Device Guard's baseline policy through the same verified pass the
> console uses, recorded as `provisioning-compliance`. Protection is switched
> on by that pass. The wizard continues only when Android has read the whole
> policy back; an unverified or crashed pass cancels setup, and the failure is
> kept in the policy status and the audit log. A later compliance request
> returns immediately when a verified compliance pass was recorded or when
> setup is complete and the last policy pass was already verified. The
> recorded flag preserves an administrator's later decision to pause protection
> on devices that went through this compliance step. Both
> handlers require `BIND_DEVICE_ADMIN`. After setup, check ownership and policy
> read-back as described below. QR enrolment on physical devices is pending in
> [Group Q](hardware-validation.md#group-q--android-12-qr-enrolment).

## Home filter

1. Use Android 10 (API 29) or later. Complete **Runbook A** to enroll Device
   Guard as Device Owner, set the administrator PIN, and verify the device has
   only the intended user and no work or private profile.
2. Install a current official Tailscale Android build (`com.tailscale.ipn`),
   sign in to the intended tailnet, and verify you can reach the home proxy
   through the intended exit node. Obtain the APK signing certificate's
   SHA-256 digest from a trusted source. Enter it under **Management identity**
   for the default package, or directly in **Home filter network** for the
   selected package. An absent or mismatched pin leaves the VPN untrusted.
   An alternate package must be a trusted Tailscale build that implements the
   same Android managed configuration schema.
3. In **Home filter network**, enter the tailnet ID, the HTTPS coordination
   server URL (prefilled for Tailscale), one stable exit node ID from the
   admin console, and the organization name. Enter the PAC URL for the family
   mitmproxy service. Prefer HTTPS with an already-trusted certificate. If the
   filter needs a user CA, select its single **public** PEM or DER certificate.
   Keep the proxy private key on the server. Select **Enable home filter**.
4. Optionally enter an HTTPS check URL and its expected response. Use an
   endpoint that returns HTTP 200 with the exact configured UTF-8 text only
   when reached through the home filter. Use a TLS certificate Device Guard
   already trusts, and keep the response at or below 1 KiB without redirects.
   The app checks it in the background, with a four-second deadline, and
   does not log the response body.
5. Reboot the device and verify the settings again. Inspect the installed
   Tailscale client and verify it uses the configured exit node. Test the
   canary from mobile data and another Wi-Fi network. Confirm ordinary apps
   lose access when the tunnel goes down. Test direct connections from apps
   that ignore the PAC and verify the home gateway denies unauthorized egress,
   including alternate DNS and IPv6 routes.

Device Guard reads back the VPN signer, per-app uninstall block, always-on VPN
with lockdown and no exemptions, managed configuration, opportunistic
(automatic) Private DNS, recommended PAC URL, selected CA when configured, and
device restrictions. The [Tailscale Android managed configuration schema] and
[Tailscale system policies] specify `ForceEnabled=true`, `Tailnet=required:<ID>`,
`LoginURL`, `ExitNodeID`, `ExitNodesPicker=hide`, `ExitNodeAllowLANAccess=never`, and
`ManagedByOrganizationName`. Android confirms it stored these values. Verify
that the installed client applies them. The Android schema currently has no
published sign-out or account-switching restriction. Check these paths with the
deployed client and keep the administrator PIN available for local recovery.
An older Device Guard profile without routing settings must be disabled and
configured again. A corrupt configuration records an apply failure and leaves
the existing device policy in place pending administrator recovery.

The console displays **Android settings confirmed** after Android read-back.
**Home filter active** also requires a passing configured HTTPS check. A failing
check leaves the filter status inactive and the Android policy in force. The
check measures reachability at the time it runs. It cannot certify enforcement
for every app or network path.

The app allowlist keeps the configured VPN package visible while the home
filter is enabled. Pausing app protection keeps the home-filter restrictions,
including install and uninstall controls, app settings, date and time, work
profile creation and, on Android 15 (API 35) or later, Private Space creation.
Maintenance cannot relax these controls. While all app installation is
restricted, plan Device Guard and Tailscale updates with the administrator.
**Remove certificate** removes the selected CA. **Turn off home filter** clears
the profile's VPN, managed settings, proxy and selected CA, and releases its
restrictions. Other Device Guard policies continue to govern their own
restrictions. The Private DNS mode remains automatic after disable.

Android exposes the effective PAC URL through `ConnectivityManager`. This
read-back cannot distinguish a matching Wi-Fi PAC from the global PAC, so
Device Guard also requires evidence that the global setter ran successfully.
A matching Wi-Fi PAC can also leave removal unconfirmed. Some apps ignore
Android's recommended proxy, and Android may exempt system traffic from VPN
lockdown. Restrict device egress at the family gateway, use a full tunnel,
and verify that split tunneling and direct LAN access cannot provide an
unfiltered path. Omit `DIRECT` from the PAC.

Apps that pin certificates or ignore user CAs cannot have their encrypted
traffic inspected. Apps targeting Android 7 or later ignore user-added CAs by
default unless they opt in. For those apps, the family filter can only allow
or deny their domains when traffic passes through the family gateway and the
domain is identifiable.

See [Android VPN management](https://developer.android.com/work/dpc/network-telephony.html),
[Android CA trust defaults](https://developer.android.com/privacy-and-security/security-config),
and [Tailscale exit nodes](https://tailscale.com/docs/features/exit-nodes).

[Tailscale Android managed configuration schema]: https://github.com/tailscale/tailscale-android/blob/main/android/src/main/res/xml/app_restrictions.xml
[Tailscale system policies]: https://tailscale.com/kb/1315/mdm-keys

### Chrome and approved apps through the home filter

With protection on, every browser, application store and well-known social or
messaging app is hidden. **System policy → Exemptions from the built-in block**
offers two narrow, default-off exceptions. Adding either needs the
administrator PIN session; removing either is accepted without it. Approvals
can only be changed while protection is on ("Resume protection to change
approvals" otherwise); each change is committed, written to the audit log
(before → after) and applied at once by a protected pass. A change that fails to persist is not applied
and the console reports it; until a later save succeeds, every policy pass
treats all exemptions as absent, while the next edit still starts from the
last saved decision; any save in that state, a removal included, needs the
administrator session. A removal made after the administrator session expired is
audited as such.

**Chrome.** Only `com.android.chrome`, only on Android 10 or later, and only
while Chrome is not the system WebView provider; otherwise the exemption is
inert (shown as not available) and Chrome is handled exactly as without it. Its
single current signer must be Google's release certificate. Each protected pass
shows Chrome only when:

- an administrator exempted Chrome;
- the home filter is enabled and protection is active (not paused);
- Chrome's managed configuration was written with
  `setApplicationRestrictions` and read back before Chrome is unhidden.

The configuration makes Chrome fail closed on its own:

- `ProxySettings` (a JSON string, the form Chrome's Android schema uses for
  dictionary policies) set to
  `{"ProxyMode":"pac_script","ProxyPacUrl":"<filter PAC>","ProxyPacMandatory":true}`.
  `ProxyPacMandatory` exists only inside `ProxySettings`
  ([`ProxySettings.yaml`](https://source.chromium.org/chromium/chromium/src/+/main:components/policy/resources/templates/policy_definitions/Miscellaneous/ProxySettings.yaml),
  supported on Android from Chrome 30), so the separate, deprecated
  `ProxyMode`, `ProxyPacUrl`, `ProxyServer`, `ProxyServerMode` and
  `ProxyBypassList` keys are removed rather than written.
- `IncognitoModeAvailability=1`, `DnsOverHttpsMode=off`,
  `DeveloperToolsAvailability=2` (honoured only by Chrome versions that
  support it on Android; older ones ignore it),
  `BrowserSignin=0`.

A pass that does not continue the last verified one — resuming from pause,
the first pass after boot, a pass after a failed or interrupted one, or any
change to the home filter settings since — hides Chrome in its opening step
before protection is marked active, whatever stored state says, and shows it
again only at the end of that same pass once the filter's own reconciliation
confirms the VPN, PAC and CA. Every protected pass starts with one containment step, before any early return
(unreadable home filter settings included): each installed catalogue social app
without a verified exemption is hidden, a browser-backed WebView provider is
suspended by the existing routine, and Chrome, unless it is already allowed, is
hidden; each is read back, and a pass that stops on unreadable settings records
what Android reports before it returns. Chrome's configuration is written only
after Android confirmed that hide. Chrome is shown again only after the home
filter's own reconciliation in the same pass reported no error (so enabling the
filter with a missing VPN app keeps it hidden); a show Android does not confirm
is undone, and links follow that final result. The home filter can be turned off, or its CA
removed, only when no Chrome approval is saved (an unreadable approval record
counts as saved) and, while protection is on, Android reports Chrome hidden,
suspended or not installed right now. `HomeFilterController` checks this live,
before any change; the home filter screen explains a refusal. A teardown that
was requested earlier and is still pending is held the same way on every pass,
including boot: each pass settles once, after containment, which filter
settings it enforces, and a held teardown is "on" to every step — system
policy (its required restrictions stay), packages and the filter's own
reconciliation — while the pass reports why. Maintenance windows (open and
restore) and pausing protection use the same settled state, from one helper
(`HomeFilterController.settledFilter`), so no policy writer treats a held
turn-off as off.
Chrome can be approved only while the filter is on, nothing is pending, and its
CA (if the profile has one) is installed. `DISALLOW_CONFIG_CREDENTIALS`
keeps the CA from being removed in Android Settings for the approval's whole
life: it is set and read back before a Chrome approval is saved (also while
protection is paused; no lock, no save), each pass confirms it before the CA
check that Chrome's release relies on, and it is released only when the
teardown guard would allow a teardown, so a refused hide keeps it. Every save
writes a format marker, and one parser reads the record for every use
(enforcement, kiosk eligibility, the teardown guard, the console and edits): a
file that exists without the marker — zero bytes, damaged, or an older format —
is unreadable, enforces no approval and refuses filter teardown. Pausing first
removes the evidence a later pass would use to continue a verified one, and is
refused if Android does not persist that. If the
stored exemption record cannot be read, no exemption applies, ordinary edits
are refused, and only an explicit "Clear all approvals" replaces it; a failed
save restores the exact stored record. A Chrome that is
disabled in Android is never shown. A home filter save that
fails to persist restores the previous settings in memory and still runs a
pass. Every Android state the console shows is read live when the screen opens
or returns, never from a stored result: a disabled app reads as disabled, an
uninstalled one as not installed, and every saved social approval is listed
(installed or not) so it can still be removed. A refused hide is an error, so the pass is
reported unverified. The console shows, per app, only what Android last
reported for the current decision. While Chrome is shown, `http`/`https`
links route to it; Custom Tabs and Trusted Web Activities that
open in Chrome run inside the Chrome package and follow its managed
configuration. Network enforcement for every app stays the home filter's
always-on VPN in lockdown; Chrome does not re-prove it.

**Approved social and messaging apps.** Only packages in a fixed, reviewed
list (`BuiltInBlockExemptions.EXEMPTABLE_SOCIAL`). Each approval pins the
app's single current signer digest. Every pass (package changes trigger one)
re-reads it with the hidden-package query and shows the app only on an exact
match; a different or unreadable signer keeps it hidden. Such an app can be a
single-app kiosk target only while its exemption verifies. Application stores
and browsers can never be approved this way, and a built-in blocked package
cannot be configured as the home filter's VPN.

**Known limits.**

- After a reboot, a Chrome that was shown before it may stay visible until
  the first protected pass runs (Device Guard does no direct-boot work). Its
  managed configuration — the mandatory filter proxy — and the always-on VPN
  lockdown still apply in that window, and the first pass hides it unless it
  continues the last verified pass.
- A failed link-routing step does not hide Chrome or fail the pass: links
  fall back to the blocked page and the failure is logged on every pass and
  audited once, when it starts and again when it recovers.
- Android refuses to hide an active device administrator. Such an app cannot
  be approved, and an approved app that becomes one loses its approval on the
  next pass. A catalogue app whose hide is refused is suspended instead; if
  Android refuses that too, the app stays launchable and every pass reports
  `CONTAINMENT_REFUSED` for it (audited when the set of such apps changes).
  Remove the app's administrator access in Android Settings.

- Web content that another app renders itself (its own WebView or in-app
  browser) does not follow Chrome's policies; it is filtered only at the
  network boundary. Constrain it at the gateway, as above.
- Pausing protection is an administrator action that lifts it: every hidden
  app, Chrome included, becomes visible until protection is resumed.

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

3. **A verified policy apply.** After Android 12+ QR enrolment, check the
   baseline before changing policy in the console. Confirm the status reads
   **Protection is active and verified**. In Device Health, check that
   **Policy verification** reads **Verified against the platform** and that
   **Last reconciliation** shows **Result: Verified** and a **When** timestamp.
   The clipboard export includes the latest trigger. Once protection is on,
   a later pass such as `device-admin-service-started` can replace the
   `provisioning-compliance` record. The result and timestamp describe the
   most recent pass. For other enrolment methods, apply
   the intended protection profile before checking the console. Investigate
   a failed verification before handing over the device. Confirm the
   Settings factory-reset option is unavailable. See
   [the recovery section](#recovering-a-device-with-the-wrong-component-or-identity).
   On production builds, the baseline disables USB debugging. Use the console
   for policy evidence and Settings for the factory-reset check.

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
| Wizard installs the DPC but does not hand over | The APK lacks a provisioning handler, fully managed mode is unavailable, or the compliance callback could not verify the baseline | Check the APK version and capture `adb logcat` where available. If the console opens, record its policy error. Factory reset before retrying; a failed compliance pass may already have blocked the Settings reset entry. |
| Setup finished, then the device must be wiped | Compliance passed, so the baseline, including `DISALLOW_FACTORY_RESET`, is in force | The Settings reset entry is disabled. Use the model's recovery-mode wipe; see the recovery section below. |
| "Already provisioned" / owner already set | The device was not fully wiped | Factory reset. |
| Enrolment ends with no management consent screen | Wizard was already completed once | Factory reset. |
| Device reboots into the wizard repeatedly | Encryption or wizard step interrupted | Factory reset; do not use `--skip-encryption` as a workaround. |

After any failure: factory reset, then start Runbook A from step 1. Once the
compliance step has applied the baseline, the Settings reset entry is
disabled even if setup failed afterwards, and only the recovery-mode wipe
works — see the recovery section below. Keep the failure in
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
non-zero exit on validation failure. `tools/test_manifest_permissions.py` checks
the exported provisioning handlers, their intent filters and their permission.

Not proven anywhere in this repository: that a printed QR scans on any specific
OEM setup wizard, that the wizard completes both provisioning callbacks on
Android 12 or later, that the download location is reachable from a device
before policy exists, and that a provisioned device then reports a verified
policy apply. Those are hardware acceptance items and they
belong to the physical validation gate in
[`docs/production-roadmap.md`](production-roadmap.md).

Official references: [provisioning a fully managed device](https://developer.android.com/work/dpc/provisioning),
[QR-code provisioning extras](https://developer.android.com/reference/android/app/admin/DevicePolicyManager),
and [building a DPC](https://developer.android.com/work/dpc/build-dpc).
