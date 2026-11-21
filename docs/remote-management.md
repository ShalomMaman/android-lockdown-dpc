# Remote management design

**Status: design proposal, revision 2. Nothing in this document is implemented
yet unless a section says "exists today".** It describes how Device Guard can be
managed by a family or organisation administrator across many devices, with no
manual on-device setup and no on-device administrator PIN, in the way a
supervised iOS device is managed by an MDM server.

Revision 2 resolves an independent security review of revision 1. Every
finding and its resolution is listed in
[Appendix A](#appendix-a-review-resolution).

Remote management is an **optional mode**. The local, PIN-protected mode that
ships today stays the default and keeps working without any server, so the
README statement that the project has "no required management cloud" remains
true.

Every Android API named here links to its Android developer reference. Links
and statements marked **(verify)** are written from memory or from platform
behaviour that is not yet proven on hardware, and must be checked against the
current documentation or a device before the implementing PR is merged.

## Contents

1. [Goals and non-goals](#1-goals-and-non-goals)
2. [What exists today](#2-what-exists-today)
3. [Architecture overview](#3-architecture-overview)
4. [Enrolment](#4-enrolment)
5. [Managed-remotely mode](#5-managed-remotely-mode)
6. [Signed documents, approvals and the apply journal](#6-signed-documents-approvals-and-the-apply-journal)
7. [Policy model](#7-policy-model)
8. [Effective state, classification and human approval](#8-effective-state-classification-and-human-approval)
9. [Command contract and full management parity](#9-command-contract-and-full-management-parity)
10. [Install windows, self-update and system OTA](#10-install-windows-self-update-and-system-ota)
11. [Management server and MCP interface](#11-management-server-and-mcp-interface)
12. [Optional pilot: on-device content check through Accessibility](#12-optional-pilot-on-device-content-check-through-accessibility)
13. [Threat model](#13-threat-model)
14. [Phased delivery plan](#14-phased-delivery-plan)
15. [Open questions and blockers](#15-open-questions-and-blockers)
- [Appendix A: Review resolution](#appendix-a-review-resolution)

---

## 1. Goals and non-goals

### Goals

- **Zero-touch-style enrolment.** A wiped device is enrolled from the setup
  wizard by scanning one QR code. It downloads Device Guard, becomes Device
  Owner, applies a verified built-in baseline, registers with the management
  server and receives its policy without anyone opening the Device Guard
  console. Steps that genuinely need the device in hand (for example signing
  in to a VPN client that offers no managed sign-in) are named as such, never
  hidden (7.1, 15).
- **No on-device administrator PIN in remote mode.** All administration arrives
  as signed documents. The on-device console becomes a read-only status screen.
- **Full management parity.** Every action available in the on-device console
  is also available as a signed remote command or policy field and as an MCP
  tool, so an administrator never needs the device in hand (section 9).
- **Neither the server nor an agent can loosen a device on its own.**
  Tightening applies at once. Loosening, and tightening that can cut a
  recovery path, needs a human approval that is produced on an approver device
  which renders the change itself, is bound to the exact signed bytes and to a
  fresh challenge issued by the target device, and is verified by the device
  (sections 6 and 8).
- **Every remote change is read back.** The existing rule that Device Guard
  never reports a requested policy as applied until Android confirms it is kept,
  and the read-back is returned to the server in a signed report.

### Non-goals

- Replacing Android Enterprise or managed Google Play. Device Guard stays a
  self-hosted DPC; the `afw#` token path does not apply (see
  [`provisioning.md`](provisioning.md)).
- Making consumer hardware impossible to reset or reflash. The boundary in the
  README and [`SECURITY.md`](../SECURITY.md) still applies; section 13 states
  exactly what remote management adds.
- Silent enrolment of a device the user has not consented to. The platform
  consent screen stays; `PROVISIONING_SKIP_USER_CONSENT` is still never emitted.
- An "update-only" window for third-party apps through an app store. Android
  offers no such control to a DPC; section 10 says what is offered instead.

---

## 2. What exists today

Remote management is built on parts that already exist and are tested. This
section is the inventory the rest of the design refers to.

| Area | Exists today | Where |
| --- | --- | --- |
| Device Owner check before any policy | `isDeviceOwnerApp` gate in every apply, pause and update path | `policy/LockdownPolicyController.java` (`apply`, `pause`), `updates/SecureUpdateManager.kt` (`performCheck`) |
| Verified policy apply and pause | Every package visibility change and user restriction is read back; partial results are failures | `LockdownPolicyController.apply`, `applyPackagePolicy`, `policy/SystemPolicyEnforcer.java` |
| Single policy thread | All `DevicePolicyManager` writers run on one FIFO executor | `policy/PolicyReconciliationCoordinator.java` (`runOnPolicyThread`, `callOnPolicyThread`) |
| Lifecycle reconciliation | Boot, own-package replacement, `PACKAGE_ADDED`/`PACKAGE_REMOVED` via `DeviceAdminService`, periodic sweep | `receivers/PolicyRefreshReceiver.java`, `admin/LockdownDeviceAdminService.java`, [`package-reconciliation.md`](package-reconciliation.md) |
| App policy | Allowlist (`ALLOW_SELECTED`) or blocklist (`BLOCK_SELECTED`), each with its own stored selection and its own "configured" flag (`isAllowlistConfigured`); a mode switch is non-destructive. Managed packages are hidden only when the current mode's selection is configured. Built-in store/browser catalogue; reviewed system-app selection with risk acceptance | `policy/AllowedAppsStore.java` (`setProtectionMode`, `isAllowlistConfigured`), `policy/LockdownPackages.java`, `policy/SystemAppClassifier.java`, `policy/SystemAppSelection.java` |
| Package decision order | Built-in block (`ALWAYS_BLOCKED`, `KNOWN_BROWSER_AND_SOCIAL`), then the mode's selection, then exceptions in this order: store maintenance, Play compatibility, kiosk escape surfaces, trusted management packages (an unverified management package is forced hidden), WebView provider, essential system packages, kiosk target | `LockdownPolicyController.applyPackagePolicy` |
| Browser blocking | Browsers in `ALWAYS_BLOCKED` and `KNOWN_BROWSER_AND_SOCIAL` are hidden unconditionally (the allowlist branch never unhides them); `http`/`https` `VIEW` intents are routed to `BlockedBrowserActivity` through `addPersistentPreferredActivity`; a browser-backed WebView provider in `ALWAYS_BLOCKED` is suspended unless it is the home-filter VPN | `LockdownPolicyController.applyPackagePolicy`, `configureBlockedBrowser`, `suspendBrowserBackedWebViewIfNeeded` |
| System controls | 16 named controls mapped to `UserManager.DISALLOW_*` restrictions, each `CRITICAL` or `ADVISORY`, with a default of `ENFORCED_SINCE_PILOT`, `PRODUCTION_ONLY` (debugging) or `OPT_IN`. The base policy is the stored choices raised by floors: Play compatibility pins the install controls on, the home filter pins `REQUIRED_CONTROLS` on | `policy/SystemPolicyControl.java`, `policy/SystemPolicyStore.java` (`baseChoices`, `isRequested`), `policy/PlayStoreCompatibility.java` (`baseChoices`), `policy/HomeFilterPolicy.java` (`requireControls`) |
| Google Play compatibility | Opt-in that keeps `com.android.vending` available only while the install lock is read back as on; turning it off removes that floor and the install controls fall back to the stored choices | `policy/PlayStoreCompatibility.java`, [`play-store-compatibility.md`](play-store-compatibility.md) |
| Home filter network | Always-on VPN with lockdown, VPN managed configuration, recommended global PAC proxy, opportunistic Private DNS, optional user CA, HTTPS canary check from Device Guard's own process, and a set of required controls maintenance cannot relax. `restrictionsMatch` requires every required control on while the filter is enabled | `policy/HomeFilterPolicy.java` (`REQUIRED_CONTROLS`, `permitsRelaxing`), `policy/HomeFilterController.java` (`restrictionsMatch`), `policy/HomeFilterProbe.java`, [`provisioning.md`](provisioning.md#home-filter) |
| Home filter setup | Manual: install the VPN client, sign in to it on the device, then configure the filter in the console | [`provisioning.md`](provisioning.md#home-filter), steps 1–3 |
| Management identity pins | Signing-certificate pins decide which management package (default: the VPN client) keeps its exemption | `policy/ManagementIdentityInspector.java`, `LockdownPackages.MANAGEMENT_DEFAULTS` |
| Kiosk | Single-app and single-site Lock Task with an authenticated state machine; `BOOT_RESTORE` is the only unauthenticated path and only into `ACTIVE` | `kiosk/KioskStateMachine.java`, `kiosk/KioskController.java`, [`kiosk-mode.md`](kiosk-mode.md) |
| Timed maintenance | Named capabilities, at most four hours, monotonic-clock expiry, process-bound authorisation, write-ahead "restore owed" marker, expiry job (`setMinimumLatency` with an override deadline 15 minutes later) plus a persisted 15-minute sweep, verified restore of the base policy, audit | `maintenance/` (`MaintenanceCapability`, `MaintenanceStateMachine.MAX_DURATION_MILLIS`, `MaintenanceStore.belongsToCurrentProcess`, `MaintenanceGuard`) |
| Boot path | `PolicyRefreshReceiver` handles `BOOT_COMPLETED` and `MY_PACKAGE_REPLACED` and is **not** direct-boot aware, so nothing runs before the first unlock after a reboot | `AndroidManifest.xml` (`PolicyRefreshReceiver`, `directBootAware="false"`) |
| Local administrator authority | 6–12 digit PIN (PBKDF2-SHA256 210 000 iterations, then HMAC with an Android Keystore key), progressive lockout bound to `Settings.Global.BOOT_COUNT`, 12-digit one-time recovery code **generated on the device** (`rotateRecoveryCode`), three-minute in-memory session. A device with no PIN goes straight to PIN setup with no prior verification (`unlockWith` → `NOT_CONFIGURED` → `PIN_SETUP`); using the recovery code opens a session and forces a new PIN | `security/AdminPinStore.java`, `security/PinLockoutPolicy.java`, `security/AdminSession.java`, `ui/MainActivity.kt` (`savePin`, `unlockWith`) |
| Signed self-update | ECDSA P-256 (`SHA256withECDSA`) envelope `{payload, signature}` in base64url, schema version, package binding, 91-day maximum validity, 5-minute clock-skew allowance, persistent version floor, HTTPS-only redirects, APK hash/size/signer/lineage checks, `PackageInstaller` session with `INSTALL_REASON_POLICY`; the result arrives asynchronously in `UpdateInstallReceiver` | `updates/UpdateEnvelopeVerifier.kt`, `updates/SecureUpdateManager.kt`, `updates/UpdateStateStore.kt` (`highestAuthorizedVersion`), `updates/UpdateScheduler.kt`, [`secure-updates.md`](secure-updates.md) |
| Provisioning payload | Verified QR payload builder: full component name, signer checksum from the APK, refuses admin-extras keys containing `credential`, `passcode`, `passphrase`, `password`, `pin`, `recovery`, `secret` or `token`; 1800-byte limit | `tools/provisioning_payload.py` (`FORBIDDEN_ADMIN_EXTRA_FRAGMENTS`, `parse_admin_extras`), [`provisioning.md`](provisioning.md) |
| Health report | Redacted, allowlisted snapshot of policy, controls, kiosk, maintenance, updates, management identity and platform | `health/DeviceHealthSnapshot.java`, `health/DeviceHealthRedaction.java` |
| Audit log | 50 entries of localized prose with a timestamp, no machine-readable event code | `policy/AuditLog.java` |

### Gaps this design depends on

These are existing gaps. Remote management cannot ship before gaps 1, 3, 6 and
7 are closed.

1. **No `GET_PROVISIONING_MODE` / `ADMIN_POLICY_COMPLIANCE` activities.**
   [`provisioning.md`](provisioning.md) records that the manifest declares
   neither. Setup-wizard (QR) provisioning of a fully managed device on
   Android 12 and newer expects the DPC to handle both, so QR enrolment is
   expected to fail today on current devices.
2. **`AuditLog` stores prose, not event codes** (production roadmap, known gap
   1). A remote audit trail needs stable codes; the health redaction allowlist
   already expects them.
3. **Authorization is tied to an in-memory UI session.** `AdminSession` is a
   static timer. Activities check it, and so do `KioskController` and
   `HomeFilterController`. `LockdownPolicyController.apply`/`pause` and the
   store setters (`SystemPolicyStore.setRequested`: "the caller owns
   authentication") check nothing and rely on their callers. A remote command
   path must not fake a UI session, and every store writer must sit behind one
   authority gate before any remote writer exists (5.3).
4. **Accessibility services and input methods are not restricted.** No code
   calls `setPermittedAccessibilityServices` or `setPermittedInputMethods`.
5. **No hardware key attestation, no `SystemUpdatePolicy`, no automatic-time
   enforcement.** Searches of the source find none of these APIs.
6. **Restore depends on the process and on the first unlock.** Relaxed user
   restrictions persist across a reboot (Android keeps Device Owner
   restrictions), but the only boot hook is `BOOT_COMPLETED`, which arrives
   after the first unlock, and the expiry job can be deferred by Doze. Section
   5.5 closes this before any remote loosening.
7. **The generic admin-extras path would accept an enrolment ticket.** None of
   the forbidden fragments matches `ticket`, so `--admin-extra
   dg.remote.ticket=…` is accepted today. Section 4.1 closes this.

---

## 3. Architecture overview

```text
   approver device (approver app, Keystore key)        agent (MCP client)
   renders the change from the signed bytes itself            |
                 |  approval statements                       | prepare / confirm
                 v                                            v
   +-------------------------------------------------------------+
   |                 management server (minimal)                 |
   |  devices | policies (immutable versions) | commands |       |
   |  approvals | audit log (hash-chained)                       |
   |  online policy-signing key (KMS/HSM)                        |
   |  enforces: loosening requires a valid approval statement    |
   +-------------------------------------------------------------+
                 ^  HTTPS pull (device-signed request)
                 |  signed policies (catch-up chain), commands,
                 |  key set, time; device reports + fresh challenges
                 v
   +-------------------------------------------------------------+
   |  Device Guard (Device Owner)                                |
   |  RemoteSync job -> SignedDocumentVerifier                   |
   |   -> EffectiveState.evaluate -> classify -> approval check  |
   |   -> ApplyJournal (durable) -> RemotePolicyApplier          |
   |   -> AuthorizedPolicyWriter -> existing stores              |
   |   -> LockdownPolicyController.apply on the policy thread    |
   |   -> signed report (redacted health snapshot + read-back)   |
   +-------------------------------------------------------------+
```

Keys and their roles:

| Key | Holder | Signs | Compromise means |
| --- | --- | --- | --- |
| **Fleet root key** (P-256) | Offline, in the administrator's vault | Key-set documents only (which policy and approval keys are valid, their owners, their versions) | Full fleet control; mitigated only by keeping it offline. Its SHA-256 is pinned at enrolment. |
| **Policy-signing key** (P-256) | Management server, ideally in a KMS/HSM | Policies, commands, server time documents | Attacker can tighten (denial of service) and issue neutral commands; cannot loosen and cannot revive an expired approval (6.4) |
| **Approval key(s)** (P-256) | Each human administrator's approver device, non-exportable, user-authentication-bound | Approval statements (6.5) over the exact payload digest, the target device's fresh challenge, the applied base and the effective diff | Attacker can approve loosening the server has also signed, for devices that issued a live challenge |
| **Device key** (P-256) | Each device's Android Keystore, attested | Sync requests, reports, device challenges | That one device's reports can be forged |

The **release (APK) signing key** and the **update-metadata key** of
[`secure-updates.md`](secure-updates.md) stay separate and unchanged.

**Algorithm choice: ECDSA P-256, not Ed25519.** `UpdateEnvelopeVerifier`
already verifies `SHA256withECDSA` on every supported release with no extra
library, WebAuthn's mandatory algorithm (ES256) is the same curve, and Android
Keystore generates and attests P-256 keys on API 26+. Ed25519 is not available
from the platform provider across the supported range (`minSdk 26`); using it
would add Tink or Bouncy Castle to the trusted code base for no security gain.
[Signature algorithms (verify)](https://developer.android.com/reference/java/security/Signature).

---

## 4. Enrolment

### 4.1 QR provisioning payload

The existing payload ([`provisioning.md`](provisioning.md)) gains an admin
extras bundle. Extras used (all already emitted by
`tools/provisioning_payload.py` except the bundle contents):

| Extra | Value |
| --- | --- |
| [`EXTRA_PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#EXTRA_PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME) | Full component, never the abbreviated form (unchanged) |
| [`EXTRA_PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#EXTRA_PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION) | Immutable HTTPS release asset (unchanged) |
| [`EXTRA_PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#EXTRA_PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM) | Signing-certificate SHA-256 (unchanged) |
| [`EXTRA_PROVISIONING_LEAVE_ALL_SYSTEM_APPS_ENABLED`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#EXTRA_PROVISIONING_LEAVE_ALL_SYSTEM_APPS_ENABLED) | `true` (unchanged) |
| [`EXTRA_PROVISIONING_WIFI_*`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#EXTRA_PROVISIONING_WIFI_SSID) | Optional, from the environment only (unchanged) |
| [`EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE) | **New contents**, below |

Admin extras bundle (`PersistableBundle`, string values only):

| Key | Example | Meaning |
| --- | --- | --- |
| `dg.remote.v` | `1` | Bundle schema version |
| `dg.remote.server` | `https://manage.example.org` | Management server base URL. Clean HTTPS, no credentials, query or fragment (same rule as `requireCleanHttpsUrl`) |
| `dg.remote.root` | base64url SHA-256 of the fleet root key SPKI (43 chars) | Trust anchor. The first key set the device accepts must be signed by a key with this digest |
| `dg.remote.tls` | up to two base64url SPKI SHA-256 pins, comma-separated | Optional TLS pins for the server (primary and backup) |
| `dg.remote.ticket` | 32 base64url characters (24 random bytes) | One-time, per-device enrolment ticket (4.4) |
| `dg.remote.fleet` | short fleet label | Display only; never used for authorization |

The bundle stays well under the tool's 1800-byte limit (about 250 bytes).

**Ticket handling in the tool.**

- The generic `--admin-extra` path refuses **every** key that starts with
  `dg.remote.`, and `ticket` is added to `FORBIDDEN_ADMIN_EXTRA_FRAGMENTS`.
  Today the generic path would accept `dg.remote.ticket` (gap 7); a test pins
  the refusal of both the prefix and the fragment.
- Remote keys are written only by dedicated options: `--remote-server`,
  `--remote-root`, `--remote-tls-pin` (at most two), `--remote-fleet`, and
  `--enrolment-ticket-env NAME`, which mirrors `--wifi-password-env`: read from
  the environment only, never echoed, output written with owner-only file
  mode, summary flag `"enrolmentTicketEmbedded": true`, and the same warning
  that the payload and the QR image are credentials.
- One QR carries one ticket and enrols one device. A batch of devices means a
  batch of QR codes; the tool can emit several payloads from a ticket file
  read with the same environment-only rule.

### 4.2 Device-side provisioning contract

The two activities the provisioning runbook flags as missing are added. Both
are declared with:

- `android:exported="true"` (the system must be able to start them);
- an intent filter with the action and `android.intent.category.DEFAULT`;
- `android:permission="android.permission.BIND_DEVICE_ADMIN"`, so only the
  system can start them.

`tools/test_manifest_permissions.py` pins all three properties for both
activities.

1. **`ProvisioningModeActivity`** handles
   [`ACTION_GET_PROVISIONING_MODE`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#ACTION_GET_PROVISIONING_MODE).
   - On API 31+ it reads
     [`EXTRA_PROVISIONING_ALLOWED_PROVISIONING_MODES`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#EXTRA_PROVISIONING_ALLOWED_PROVISIONING_MODES)
     and returns `RESULT_OK` with
     [`EXTRA_PROVISIONING_MODE`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#EXTRA_PROVISIONING_MODE)
     `= PROVISIONING_MODE_FULLY_MANAGED_DEVICE` **only if that mode is in the
     list**. If it is not, it returns `RESULT_CANCELED`; it never offers a
     work profile.
   - If the extra is absent (a release that sends the intent without it), it
     returns fully managed mode (verify on the oldest supported release that
     sends the intent).
   - It parses the admin extras with a pure-Java `EnrolmentConfig.parse` only
     to decide the mode result. It writes nothing.
2. **`PolicyComplianceActivity`** handles
   [`ACTION_ADMIN_POLICY_COMPLIANCE`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#ACTION_ADMIN_POLICY_COMPLIANCE).
   The admin extras `PersistableBundle` can arrive in either activity, so this
   activity **parses and validates the bundle again** and never relies on the
   mode activity's result. It then:
   - decides the management mode from the bundle (4.3) and persists it
     together with the validated `EnrolmentConfig`;
   - for `ENROLLING`, applies the built-in **enrolment baseline** (4.3) and
     reads it back before anything else;
   - starts enrolment (4.5) if the network allows, and returns `RESULT_OK` once
     the baseline is verified, whether or not the server answered. Enrolment
     continues in the background with `JobScheduler` retries and exponential
     backoff. A device is never left unmanaged because the server was down,
     and never loosened because it was down either;
   - if the baseline cannot be verified, it shows a localized retry screen with
     the stable failure code; after three failures it returns `RESULT_OK` with
     the fault `enrolment-baseline-unverified` recorded, and the normal
     lifecycle triggers keep retrying the baseline.
3. **Older releases.** `LockdownAdminReceiver.onProfileProvisioningComplete`
   keeps setting the profile name and additionally reads
   `EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE` from its intent, running the same
   parser and the same mode decision, on releases that do not send the two
   activity intents. This path gets its own hardware test on the oldest
   supported release that provisions by QR.

References: [provisioning a fully managed device](https://developer.android.com/work/dpc/provisioning),
[Android 12 provisioning changes (verify)](https://developer.android.com/work/versions/android-12).

### 4.3 Management mode at enrolment and the enrolment baseline

The bundle decides the mode, and there is **no path from a remote enrolment to
`LOCAL_PIN`**:

| Admin extras | Resulting mode | Why |
| --- | --- | --- |
| No `dg.remote.*` key | `LOCAL_PIN` (today's behaviour) | A QR without remote keys is a deliberate local enrolment by whoever holds the wiped device; first-PIN setup on the device is today's intended local flow |
| Valid remote keys | `ENROLLING` | Remote enrolment in progress |
| Any `dg.remote.*` key present but the bundle is malformed | `ENROLLING`, fault `enrolment-config-invalid` | A device whose QR asked for remote management never silently becomes a PIN device. It stays on the baseline and must be re-provisioned (factory reset), because nothing on it can be trusted to finish enrolment |

**`ENROLLING`** is a separate persisted state, not a flavour of `LOCAL_PIN`:

- **No PIN can be created.** The `NOT_CONFIGURED` → `PIN_SETUP` branch of
  `MainActivity.unlockWith` is unreachable unless the mode is `LOCAL_PIN`; the
  console shows a read-only "Enrolling with <fleet label>" status with the last
  failure code. A JVM test drives `unlockWith` in `ENROLLING` and `REMOTE` and
  asserts that no PIN setup screen is reachable.
- **The baseline is applied and verified.** The enrolment baseline is compiled
  into the APK, versioned, and identified by the SHA-256 of its canonical
  serialisation (`baselineSha256`, pinned by a test). Content:
  - protection `ON`;
  - `ALLOW_SELECTED` with an **empty, configured** selection, so every
    managed user app is hidden (`isAllowlistConfigured` must be true, or
    nothing would be hidden);
  - no system selection, Play compatibility off, no browser exemption;
  - every system control requested as in the `PRODUCTION` profile, except
    `developer_options_and_adb`, which follows the build's profile (a pilot
    build keeps ADB as its documented break-glass until production gate 3);
  - home filter off, kiosk off, no added management pins;
  - accessibility and input-method lists not set (`null`), system update
    policy not set.
- **Exits.** `ENROLLING` ends only by (a) a successful enrolment into `REMOTE`,
  whose first policy is classified against the baseline's effective state
  (section 8) and therefore needs a human approval for anything it opens; or
  (b) a factory reset. Neither a failure nor a timeout nor corrupt storage
  leads to `LOCAL_PIN`: an unreadable mode record is treated as `ENROLLING`
  if an `EnrolmentConfig` exists, and as `LOCAL_PIN` only if none was ever
  stored.

**Converting an existing local device (4.6).** The baseline is the device's own
current effective policy, read back by a verified pass at the moment the local
administrator starts the conversion with a live PIN session. The first remote
policy is classified against that captured state.

### 4.4 Enrolment ticket

- 24 random bytes, created **per device** by the server; the server stores only
  `SHA-256(ticket)`.
- Bound to a fleet and an expiry (default 72 hours, maximum 7 days).
- **Bound to the first device key that presents it.** A retry from the same
  device (for example after a process kill) presents the same device key and
  is answered idempotently. A different device key presenting the same ticket
  is refused with `ticket-bound-to-other-device`, and the server alerts.
- Optionally bound to an expected serial number. On API 28+ the device can
  include ID attestation (`ID_TYPE_SERIAL`) through
  [`DevicePolicyManager.generateKeyPair`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#generateKeyPair(android.content.ComponentName,%20java.lang.String,%20android.security.keystore.KeyGenParameterSpec,%20int))
  with [`ID_TYPE_SERIAL`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#ID_TYPE_SERIAL),
  so the binding is checked from hardware evidence, not from a claimed string.
- Every enrolled device starts on the baseline. The ticket never authorizes
  loosening: the first policy that opens anything needs an approval (8.5).
  Serial binding only decides whether the server lists the device as
  `expected` or `unexpected` on the approver's screen.

A leaked QR therefore lets a stranger enrol at most one device, which lands on
a locked-down baseline in a list the administrators review, with no loosening
ability.

### 4.5 Device identity and attestation

- At enrolment Device Guard generates a non-exportable P-256 signing key in
  Android Keystore with
  [`setAttestationChallenge`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setAttestationChallenge(byte[]))
  set to a server nonce, and
  [`setIsStrongBoxBacked(true)`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setIsStrongBoxBacked(boolean))
  when StrongBox is present, falling back to TEE.
- `deviceId` = base64url SHA-256 of that key's SPKI. Every policy, command and
  approval is bound to it.
- On API 31+ the enrolment also records
  [`getEnrollmentSpecificId`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#getEnrollmentSpecificId())
  after [`setOrganizationId`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#setOrganizationId(java.lang.String))
  so a re-enrolment of the same hardware is recognisable without the serial.
- The server verifies the attestation chain against the Google hardware
  attestation roots and the
  [revocation status list](https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status),
  and records `attestationSecurityLevel`, `verifiedBootState`, `deviceLocked`,
  `verifiedBootKey`, `osPatchLevel` and the `attestationApplicationId`
  (package name and signer digest). Reference:
  [key attestation](https://developer.android.com/privacy-and-security/security-key-attestation).
- Policy decision on the server: a `SOFTWARE` attestation, an unlocked
  bootloader, `UNVERIFIED`/`FAILED` boot state, a revoked chain, or an
  application signer other than the approved release signer marks the device
  **untrusted**. Untrusted devices still receive tightening policy but the
  approver app refuses to approve loosening for them, and the administrator is
  alerted.
- Enrolment sequence (a persisted state machine; each step is resumable):
  `CONFIG_STORED` → `BASELINE_VERIFIED` → `KEY_CREATED` → `ENROL_SENT` →
  `KEYSET_ACCEPTED` → `ENROLLED` (mode becomes `REMOTE`, still on the
  baseline) → first policy through the normal path of section 6.

### 4.6 ADB path for already-used devices

`dpm set-device-owner` only works with no accounts and no other users (see
[`provisioning.md`](provisioning.md), Runbook B). For a used device:

1. Remove every account (Google, OEM, messaging) in Settings → Accounts and
   every secondary user or profile. Removing the Google account first also
   avoids factory reset protection surprises.
2. Install the **release** APK (`adb install`, without `-t`; a test-only build
   is refused for remote mode, section 13.1) and run
   `adb shell dpm set-device-owner <full component>`.
3. ADB cannot pass admin extras, and revision 1's `adb shell am start` with
   extras is **removed**: an exported activity is reachable by every installed
   app, and
   [`Activity.getLaunchedFromUid`](https://developer.android.com/reference/android/app/Activity#getLaunchedFromUid())
   returns a usable UID only when the launcher opted in to share its identity,
   so it cannot authenticate the bench either (verify on API 34+). Instead:
   - Device Guard's first screen, while the device is Device Owner with no PIN
     and not enrolled, offers **Enrol with management server** next to the
     local PIN setup. The screen is a non-exported activity reached only from
     Device Guard's own console.
   - Choosing it moves the device to `ENROLLING` and applies the baseline
     **before** any network call, which also removes the PIN setup option.
   - The operator types the server host. The device fetches the key set and
     shows the root-key fingerprint as eight groups of four characters to
     compare with the fleet card; it proceeds only after the operator confirms
     the match.
   - The operator types a short **bench code** (16 base32 characters, 80 bits,
     single use, one-hour expiry, five attempts, created per device on the
     approver app). It plays the role of the ticket and is bound to the first
     device key exactly as in 4.4.
4. The rest of the flow is identical to 4.5 from `KEY_CREATED` on.

**Converting a device already running in local PIN mode** uses the same screen
from the local console, requires a live PIN session, captures the current
effective state as the baseline (4.3), and switches to `ENROLLING` before any
network call. The first remote policy then goes through the approval path like
any other.

### 4.7 Enrolment failure modes

| Failure | Behaviour |
| --- | --- |
| No remote keys in the admin extras | `LOCAL_PIN`, exactly as today |
| Remote keys present but malformed | `ENROLLING` on the baseline, `enrolment-config-invalid`; re-provision |
| Provisioning mode not allowed by the setup wizard | `RESULT_CANCELED`, no provisioning |
| Server unreachable during setup | Baseline verified, `RESULT_OK`, `enrolment-pending`; `JobScheduler` retries with exponential backoff (same pattern as `UpdateScheduler`) |
| Ticket expired, unknown or bound to another device | Server returns a stable code; device stays `ENROLLING` on the baseline, shows the code, never retries the same ticket automatically |
| Key set not signed by the pinned root | Refused (`key-set-root-mismatch`); never retried with another root |
| TLS pin mismatch | Refused (`tls-pin-mismatch`); no fallback to unpinned TLS |
| Attestation unavailable | Enrolment proceeds; server marks the device untrusted (4.5) |
| Process killed mid-enrolment | The state machine resumes from the last completed step with the same device key; the server answers the retry idempotently |
| Baseline cannot be verified | Fault `enrolment-baseline-unverified`; lifecycle retries; enrolment does not proceed past `BASELINE_VERIFIED` |

### 4.8 Tests

- `tools/test_provisioning_payload.py`: ticket only from the environment,
  never echoed, owner-only mode, summary flag, size limit with all keys,
  root-digest format, URL refusal cases; `--admin-extra dg.remote.anything=…`
  refused; `--admin-extra ticket=…` refused; the existing `token` refusal
  still fires.
- `tools/test_manifest_permissions.py`: both provisioning activities exported,
  `DEFAULT` category, `BIND_DEVICE_ADMIN`.
- JVM: `ProvisioningModeResultTest` (fully managed only when allowed;
  cancelled otherwise; absent extra), `EnrolmentConfigTest` (every malformed
  key, wrong schema, bad URL, bad digest, oversized values),
  `ManagementModeDecisionTest` (the table in 4.3, including an unreadable mode
  record), `EnrolmentBaselineTest` (content and pinned `baselineSha256`; the
  allowlist is configured), `NoPinOutsideLocalModeTest`,
  `EnrolmentStateMachineTest` (resume after each step with the same key,
  retry backoff).
- Hardware, new group in [`hardware-validation.md`](hardware-validation.md):
  QR enrolment on Android 12+ through both activities; the receiver fallback
  on the oldest QR-capable release; server-down enrolment ends on a verified
  baseline; ADB enrolment of a previously used device with the bench code;
  attestation fields recorded.

---

## 5. Managed-remotely mode

### 5.1 Management modes

A new persisted `ManagementMode`:

| Mode | Authority | On-device console |
| --- | --- | --- |
| `LOCAL_PIN` (default, today's behaviour) | Administrator PIN session | Full console, unchanged |
| `ENROLLING` | None; the built-in baseline only (4.3) | Read-only enrolment status. No PIN screen. |
| `REMOTE` | Signed policy and commands only | Read-only status: protection state, "Managed by <fleet>", last sync, last verified apply, open windows and their deadlines. No PIN screen. |

There is deliberately no mixed mode in which local PIN edits and remote desired
state both write the same stores; that produces the "state neither side
believes" failure the single policy thread exists to prevent. Moving from
`REMOTE` back to `LOCAL_PIN` is itself a loosening (section 8).

### 5.2 Desired state

In `REMOTE` mode the signed policy is the source of truth. The existing stores
(`AllowedAppsStore`, `SystemPolicyStore`, `PlayStoreCompatibilityStore`,
`HomeFilterStore`, `KioskConfigStore`, management pins) become projections of
it, written only by `RemotePolicyApplier` on the policy thread, through the
authority gate of 5.3:

```text
accepted policy (journal, 6.6) -> RemotePolicyApplier.project(policy)
   -> AuthorizedPolicyWriter -> stores
   -> LockdownPolicyController.apply / KioskController / HomeFilterController
   -> read-back -> signed report { policyVersion, verified, errors, outcomes }
```

A policy is reported `applied` only when the reconciliation pass returned
`verified == true`. A pass that fails keeps the journaled desired state and is
retried by the normal lifecycle triggers; the report carries the stable error
codes from `PolicyResult.errors`.

### 5.3 Authorization without a UI session

`AdminSession.unlock()` must **not** be called by the remote path: it would also
unlock every console screen for three minutes. Instead a small authority type
is introduced:

```java
public sealed interface AdminAuthority permits LocalSession, VerifiedChange, RecoverySession {}
```

- `LocalSession` is obtainable only while `AdminSession.isUnlocked()` **and**
  the mode is `LOCAL_PIN`, or through a remote `console_session` grant (5.6).
- `VerifiedChange` has a package-private constructor called only by the apply
  journal (6.6) after signature, binding, floors, classification and, where
  required, approval checks. It carries the journal entry id, the scope (the
  set of effective-state components the change may touch) and, for a
  temporary change, a monotonic deadline.
- `RecoverySession` is created only by a successful offline recovery-code
  entry (5.6) and carries the recovery scope.
- **One gate for every writer.** The store setters that today trust their
  caller become package-private and are reachable only through an
  `AuthorizedPolicyWriter` that takes an `AdminAuthority` and refuses any
  write outside the authority's scope. `KioskController` and
  `HomeFilterController` take an `AdminAuthority` instead of reading
  `AdminSession` directly. Their existing property — "no caller can assert that
  it is authenticated" — is preserved, because no variant can be constructed
  from a boolean.
- This refactor lands **before** any remote writer exists (section 14), and a
  JVM test enumerates every store mutator by reflection and fails if one is
  reachable without an authority.

### 5.4 Temporary loosenings and restore obligations

Every loosening that is meant to end (pause, maintenance window, install
window, console session, recovery session) follows one pattern, which extends
today's maintenance write-ahead marker:

1. **Obligation first.** Before the first `DevicePolicyManager` call, a
   `RestoreObligation` record is written with `commit()` to
   **device-protected storage**
   ([`createDeviceProtectedStorageContext`](https://developer.android.com/reference/android/content/Context#createDeviceProtectedStorageContext()))
   so it is readable before the first unlock. It holds the obligation id, the
   monotonic deadline, the boot count, and the exact restriction set and
   package hide set the restore must re-impose. Credential-protected storage
   keeps the full record; the device-protected copy holds only what the
   direct-boot restore needs and no secret.
2. **Clamped deadline.** `deadline = min(receipt + duration, notAfter)`, where
   `notAfter` is converted to the monotonic clock through the trusted-time
   anchor (6.4). If no anchor exists (for example right after a reboot), a
   window with a `notAfter` is not opened (`window-time-unanchored`).
3. **Preconditions re-checked at open.** A scheduled window opens from a job,
   and the job re-checks every condition itself (charging, unmetered network,
   trusted time inside `[notBefore, notAfter]`, no other obligation open, the
   device in a verified state). `JobInfo.Builder.setOverrideDeadline` can run
   a job without its constraints being met, so the constraints on the job are
   only a hint; if the re-check fails, the job reschedules until `notAfter`
   and then reports `window-not-opened`.
4. **Several close triggers, any one sufficient.** All converge on the same
   restore path:
   - an exact alarm,
     [`setExactAndAllowWhileIdle`](https://developer.android.com/reference/android/app/AlarmManager#setExactAndAllowWhileIdle(int,%20long,%20android.app.PendingIntent))
     with `ELAPSED_REALTIME_WAKEUP`, which fires in Doze (rate-limited by the
     platform). On API 31+ it needs the exact-alarm permission; whether a
     Device Owner holds it or can be granted it on API 33+ must be verified
     (verify). Where it is unavailable, the inexact
     `setAndAllowWhileIdle` is used and the measured bound (below) decides
     whether the window may be offered at all;
   - the existing expiry job and the persisted 15-minute sweep;
   - a low-importance foreground service that runs for the life of the
     window, shows the deadline, and registers for `ACTION_SCREEN_ON` and
     `ACTION_USER_PRESENT`, checking the deadline before anything else when
     the device wakes (a Device Owner is exempt from the background
     foreground-service start restrictions,
     [exemptions](https://developer.android.com/develop/background-work/services/fgs/restrictions-bg-start#background-start-restriction-exemptions));
   - process start (the application object checks obligations before any
     other work), `MY_PACKAGE_REPLACED`, `BOOT_COMPLETED`;
   - **`LOCKED_BOOT_COMPLETED`** through a new direct-boot-aware receiver
     (5.5).
5. **Restore and read back.** The restore re-imposes the recorded set and runs
   a full verified pass. The obligation is cleared only after the read-back
   succeeds; a failed restore keeps the obligation, reports a critical fault
   and is retried by every trigger.

**The bound, stated honestly.** Android does not expire a Device Owner
restriction by itself: a relaxed restriction stays relaxed, through reboots,
until Device Guard's code runs and re-imposes it. The window therefore closes
at `deadline + δ`, where δ is the latency of the first trigger that runs. δ is
small when the screen is on (the foreground service and the alarm) and is
bounded by the platform's idle-alarm rate limit in Doze (verify), but it is a
measured property of each firmware family, not a guarantee. Therefore:

- A remote window that relaxes a `CRITICAL` control (debugging, installs,
  unknown sources, factory reset, safe boot, VPN configuration, Private DNS) is
  offered only on firmware families whose hardware evidence shows δ ≤ 5
  minutes in Doze, after a reboot inside the window, and after a process
  kill. Elsewhere the command is refused with `window-bound-unproven`.
- Windows that relax only `ADVISORY` controls or only unhide packages may run
  without that evidence, with the measured δ shown in the approval rendering.

### 5.5 Boot and direct boot

Relaxations survive a reboot, and today nothing runs until the first unlock
(gap 6). A new `DirectBootRestoreReceiver` (`android:directBootAware="true"`,
not exported, `LOCKED_BOOT_COMPLETED`) runs before the first unlock and:

1. reads the device-protected `RestoreObligation`;
2. if one exists and its boot count is older than the current
   `BOOT_COUNT` (a reboot always ends a window, as process death does today),
   re-adds the recorded user restrictions and re-hides the recorded packages;
3. records the outcome in device-protected storage for the full pass that
   follows `BOOT_COMPLETED`.

Whether `addUserRestriction` and `setApplicationHidden` succeed for a Device
Owner before the first unlock must be proven per firmware family (verify). If
they do not, the documented bound becomes "until the first unlock after a
reboot" for that family, and the window rule of 5.4 refuses critical windows
there. The receiver never relaxes anything.

### 5.6 Console session, pause, recovery and local mode

- **Remote console session** (`console_session`, loosening): opens the local
  console for at most 30 minutes, measured on `SystemClock.elapsedRealtime`
  from receipt, with a visible banner. Ends early on `end_sessions`, reboot or
  process death (same fail-closed boundary as maintenance). The approval names
  the scope: `view` (read-only screens), or `full`.
- **Pause** (`pause`, loosening): always carries a duration (maximum 4 hours,
  the maintenance maximum) and follows the restore-obligation pattern (5.4).
- **Offline recovery code.** A device without network (for example after a
  broken home-filter configuration) must still be recoverable without a wipe,
  and no party that can issue the code may use it without a fresh approval:
  - The code is **generated on the approver device**, never on the server. The
    approver app creates 12 random digits and a 16-byte salt, computes
    `PBKDF2-SHA256(code, salt, 210000)`, encrypts `{salt, pbkdf2}` to the
    target device's encryption key (open question 10), and submits it as a
    `set_recovery_verifier` command. The command is itself a loosening, so it
    carries the same approver's approval statement. The code stays in the
    approver's vault; the server sees only ciphertext.
  - The device decrypts, applies its own Keystore HMAC exactly as
    `AdminPinStore.createVerifier` does, and stores the result, so today's
    format and `PinLockoutPolicy` apply.
  - Entering the code opens a **`RecoverySession`**, not a console session:
    at most 30 minutes, monotonic, ended by reboot or process death, and
    limited to the recovery scope: turn off the home filter, end a pause or
    window, exit kiosk, re-run reconciliation, show the server and sync
    diagnostics. It cannot change the app selection, the system controls,
    management pins, the management mode, or set a PIN; the `PIN_SETUP`
    screen that follows a recovery code in `LOCAL_PIN` mode does not exist in
    `REMOTE` mode.
  - The code is single use. Use is reported on the next sync; a new code needs
    a new approved `set_recovery_verifier`.
- **Local PIN mode stays available** per device: `set_management_mode
  LOCAL_PIN` with a PIN verifier produced on the approver device the same way
  is a loosening.

### 5.7 Sync transport

- **Pull.** A `RemoteSyncJobService` (new, `BIND_JOB_SERVICE`, like
  `UpdateCheckJobService`) runs every 15 minutes, the
  [`JobInfo` minimum period](https://developer.android.com/reference/android/app/job/JobInfo.Builder#setPeriodic(long,%20long)),
  plus on boot, on own-package replacement, after every applied command and on
  network change. It is persisted and needs `NETWORK_TYPE_ANY`.
- **Request.** `POST /v1/sync` with body
  `{deviceId, nonce, appliedPolicyVersion, appliedPolicySha256,
  lastCommandSequence, reportSha256, challenges}` and a header signature by the
  device key over method, path, timestamp and body digest. `challenges` are
  the device's live approval challenges (6.4). TLS uses the platform trust
  store plus the optional SPKI pins from enrolment, checked in a custom
  `X509TrustManager` wrapper (network security config pins are static and
  cannot come from the QR). Redirects are refused.
- **Response.** A signed `time` document echoing the nonce; the current key
  set if newer; **every** policy version after the applied one, in order, up
  to 16 (the device applies them one by one, each checked against the state it
  produced); ordered commands after `lastCommandSequence`; `nextPullSeconds`.
  If more than 16 versions are missing, the server issues a **rebase** version
  chained to the device's applied hash, which is classified against the
  device's actual state like any other version. A server that returned only
  the latest version would deadlock against the device's
  `previousPolicySha256` check; a vector pins the catch-up behaviour.
- **Wake without FCM** (optional, off by default). Two options, both carrying
  only a content-free "poke" that can do nothing but trigger a pull, rate
  limited to one pull per minute:
  1. A foreground service holding one long-poll HTTPS request to
     `/v1/wake`. Costs a permanent low-importance notification and radio
     wakeups; Doze still defers network
     ([Doze and App Standby](https://developer.android.com/training/monitoring-device-state/doze-standby)).
  2. A self-hosted [UnifiedPush](https://unifiedpush.org/) distributor. Adds a
     second app to the trusted set and to the management pins.

  Without a wake channel, the worst-case latency of a command is the pull
  period plus Doze deferral. No command promises a latency; `lock_now` in
  particular is bounded only by its validity (section 9).

### 5.8 Tests

- JVM: `AdminAuthorityTest` (no public path constructs `VerifiedChange` or
  `RecoverySession`); `AuthorizedWriterCoverageTest` (every store mutator
  reachable only through the gate; out-of-scope writes refused);
  `RemotePolicyApplierTest` (projection of every field into the stores, then a
  fake gateway apply; a failed verification keeps desired state and reports
  codes); `ConsoleSessionTest` and `RecoverySessionTest` (monotonic expiry,
  reboot and process-death closure, recovery scope refuses every other
  write); `RestoreObligationTest` (obligation written before the first gateway
  call; clamp to `notAfter`; preconditions re-checked; every trigger restores;
  failed restore keeps the obligation); recovery verifier compatibility test
  (an approver-side PBKDF2 value plus local HMAC equals `AdminPinStore` output
  for the same code and salt); `SyncCatchUpTest` (missed versions applied in
  order; rebase accepted only when chained to the applied hash).
- Locale parity: the new read-only strings in English and Hebrew, enforced by
  the existing parity tests.
- Hardware: δ measurement per firmware family (screen on, Doze, reboot inside
  a window, process kill inside a window); direct-boot restore before first
  unlock; sync after Doze, after reboot, with the home filter on, with no
  network for 24 hours.

---

## 6. Signed documents, approvals and the apply journal

### 6.1 Envelope

The update envelope format is generalised rather than replaced, so one
verifier serves updates and management:

```json
{
  "format": "dg-signed/1",
  "keyId": "<base64url SHA-256 of signer SPKI>",
  "payload": "<base64url UTF-8 JSON bytes>",
  "signature": "<base64url DER ECDSA P-256 over the payload bytes>",
  "approvals": [
    {
      "scheme": "keystore-p256",
      "keyId": "<base64url SHA-256 of approver SPKI>",
      "statement": "<base64url approval statement bytes, 6.5>",
      "signature": "<base64url DER ECDSA P-256 over the statement bytes>"
    }
  ]
}
```

The signature covers the exact payload bytes, so no JSON canonicalisation is
needed (the same reason `UpdateEnvelopeVerifier` signs the base64url payload).
Limits follow the update verifier: 64 KiB envelope, `MAX_CLOCK_SKEW_SECONDS`
of 300. The `webauthn-es256` scheme (8.4) carries `authenticatorData` and
`clientDataJSON` in place of the bare signature input, with
`challenge = SHA-256(statement)`.

### 6.2 Common payload header

| Field | Rule |
| --- | --- |
| `schemaVersion` | Integer; unknown versions refused |
| `type` | `keyset`, `policy`, `command`, `time`; a document is only accepted where its type is expected |
| `fleetId` | Must equal the enrolled fleet |
| `deviceId` | Must equal this device's key digest (`keyset` may use `*`) |
| `issuedAt`, `expiresAt` | Epoch seconds; checked against server-anchored trusted time (6.4) with the per-type maximum validity. These fields never make a loosening valid on their own |
| `keySetVersion` | The key set the signer belongs to; must be at least the device's stored key-set floor |

Unknown top-level or nested fields are refused (`doc-field-unknown`); the
schema is closed so that a field an older client ignores can never carry
meaning a newer server intended.

### 6.3 Per-type rules

| Type | Signer | Monotonic field | Maximum validity | Notes |
| --- | --- | --- | --- | --- |
| `keyset` | Fleet root | `keySetVersion` strictly increasing | 400 days | Lists policy-signing keys and approval keys with `notAfter` and the owning administrator; can rotate the root once by naming its successor |
| `policy` | Policy-signing key | `policyVersion` strictly increasing; `previousPolicySha256` must equal the applied policy's hash | 30 days to **install** | An installed policy stays enforced after its `expiresAt`; expiry only prevents installing a stale document. The report flags `policy-stale` after expiry |
| `command` | Policy-signing key | `sequence` strictly increasing per device | Per command (section 9), at most 24 hours to start | `basePolicySha256` must equal the applied policy's hash, so a command cannot be replayed against a different baseline |
| `time` | Policy-signing key | — | 5 minutes | Echoes the request nonce; anchors trusted time for non-loosening checks (6.4) |

The device stores the floors (`keySetVersion`, `policyVersion`, `sequence`,
`policySha256`) with `commit()` in credential-protected storage, exactly as
`UpdateStateStore.recordAuthorizedVersion` does. Floors are raised in the
same commit that journals acceptance (6.6), before Android is touched.

### 6.4 Time and freshness

Three clocks, each used only for what it can prove:

1. **Durations** (sessions, pauses, windows) use
   [`SystemClock.elapsedRealtime`](https://developer.android.com/reference/android/os/SystemClock)
   from receipt, as maintenance already does, clamped as in 5.4.
2. **Server-anchored trusted time** = the last verified `time` document's
   `serverTime` plus elapsed-realtime since it arrived, re-anchored on each
   sync and lost on reboot (detected by `Settings.Global.BOOT_COUNT`, as
   `AdminPinStore` does). It is used for `issuedAt`/`expiresAt` of tightening
   and neutral documents, for policy install expiry, and for mapping a
   window's `notAfter`. It is signed by the policy-signing key, so a
   compromised server can lie about it; that is why it never makes a
   loosening valid.
3. **Device challenges** decide the freshness of every approval, independent
   of the server. The device keeps up to four outstanding challenges (16
   random bytes each), each with its own monotonic issue time, reports them on
   sync, and accepts an approval only if it names a challenge that is
   outstanding, younger than 60 minutes of elapsed-realtime, and unconsumed.
   Consuming a challenge (6.6) invalidates it; a reboot invalidates all of
   them. A compromised server that signs an old time with a new nonce gains
   nothing: the approval's freshness is measured by the device's own clock
   against a value only the device issued.

The approver's wall-clock time is included in the approval statement for the
audit trail only.

The policy enforces `DATE_AND_TIME` (`DISALLOW_CONFIG_DATE_TIME`, API 28+),
already `ENFORCED_SINCE_PILOT`, and, new, automatic time through
[`setAutoTimeEnabled`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#setAutoTimeEnabled(android.content.ComponentName,%20boolean))
on API 30+. Neither is needed for the approval guarantees above.

### 6.5 Approval statement

The approver signs a binary statement, not JSON, so that its meaning is
unambiguous. Encoding: the ASCII magic `DGAPPROVE`, a one-byte version (`1`),
then the fields below in this fixed order, each as a one-byte tag, a two-byte
big-endian length and the value bytes. Unknown tags, repeated tags, missing
tags, out-of-order tags and trailing bytes are refused.

| Tag | Field | Content |
| --- | --- | --- |
| 1 | `fleetId` | UTF-8 |
| 2 | `entries` | 1–64 entries, each: `deviceId` (32 bytes), `deviceChallenge` (16 bytes), `basePolicySha256` (32 bytes, the hash the device reports as applied), `subjectSha256` (32 bytes, SHA-256 of the exact payload bytes the policy key signed), `effectiveDiffSha256` (32 bytes, 8.1) |
| 3 | `subjectType` | `policy` or `command` |
| 4 | `class` | `L` or `H` |
| 5 | `scope` | Sorted, comma-separated list of effective-state components the change touches (8.1), and for a temporary change its duration in minutes |
| 6 | `approverKeyId` | 32 bytes |
| 7 | `approverTime` | Approver wall clock, epoch seconds (audit only) |

One statement can approve the same kind of change for up to 64 devices (for
example the first policy of a batch of enrolments); each device checks only
its own entry. The device verifies: the signature by an approval key in its
current key set whose `notAfter` has not passed by trusted time; its entry's
challenge (6.4); `basePolicySha256` equals its applied hash;
`subjectSha256` equals the payload it received; `effectiveDiffSha256` equals
the diff it computes itself (8.1); `class` and `scope` equal its own
classification.

### 6.6 Accept, journal, apply

The order below closes the gap between Android's state and the recorded
version, and makes a crash at any point safe to resume and impossible to
replay:

1. **Verify** signature, type, binding, floors and chain.
2. **Evaluate** the candidate's effective state against the applied one and
   classify (section 8).
3. **Check approvals** for `L`/`H` (6.5).
4. **Journal** in one `commit()` to credential-protected storage: the entry
   `{id, state: ACCEPTED, payloadBytes, policyVersion or sequence,
   baseSha256, subjectSha256, consumedChallenge}`, the raised floors, and the
   challenge marked consumed. The device-protected `RestoreObligation` is
   written in the same step for a temporary change (5.4). If the commit fails,
   nothing else happens and the document is refused (`journal-write-failed`).
5. **Project** the journaled payload into the stores through
   `AuthorizedPolicyWriter` with a `VerifiedChange` built from the entry.
6. **Apply** on the policy thread and **read back**.
7. **Record** `APPLIED` (verified) or `APPLY_FAILED` (desired state kept,
   lifecycle retries) and report.

On restart, an entry in `ACCEPTED` is resumed from step 5 using its stored
payload; approvals are not re-verified, because the entry itself is the record
that they were verified and their challenge is already consumed. Replaying the
same envelope after a crash is refused by the floors
(`doc-version-rollback`) and by the consumed challenge
(`approval-challenge-consumed`). Tests inject a crash after every step with
the fake gateway and assert the resumed outcome and the replay refusal.

### 6.7 Failure modes

Every refusal produces a stable code (for example `doc-signature-invalid`,
`doc-device-mismatch`, `doc-version-rollback`, `doc-chain-mismatch`,
`doc-expired`, `doc-field-unknown`, `doc-approval-missing`,
`doc-approval-invalid`, `approval-challenge-unknown`,
`approval-challenge-expired`, `approval-challenge-consumed`,
`approval-base-mismatch`, `approval-diff-mismatch`, `doc-type-unexpected`,
`doc-time-unanchored`, `journal-write-failed`), changes nothing on the device,
and is included in the next report. A refused document never lowers a floor
and never consumes a challenge.

### 6.8 Tests

A shared, committed **test-vector set** (JSON envelopes and binary statements
with the public test keys, device facts and expected verdicts, including the
expected effective diff and class) is consumed by the Kotlin verifier tests,
the approver app's tests and the server's tests, so the implementations
cannot drift. Vectors cover: valid; wrong key; key not in key set; key set
rollback; wrong device; wrong fleet; wrong type; expired; issued in the
future; unknown field; policy version replay and downgrade; broken
`previousPolicySha256` chain; catch-up chain; rebase; command sequence replay;
command against another base; loosening without approval; approval over
different bytes; approval for another base; approval with a diff hash that
does not match; approval naming an unknown, expired or consumed challenge;
approval by an unknown or expired key; approval statement with a repeated,
missing or reordered tag or trailing bytes; batch statement without this
device's entry; WebAuthn flag `UV` missing; oversized; malformed base64url.

---

## 7. Policy model

One policy document per device (the server renders fleet templates into
per-device documents). Field names reuse the storage keys that already exist.

```json
{
  "schemaVersion": 1,
  "type": "policy",
  "fleetId": "f-example",
  "deviceId": "<digest>",
  "policyVersion": 42,
  "previousPolicySha256": "<hex>",
  "issuedAt": 1795000000,
  "expiresAt": 1797592000,
  "keySetVersion": 3,

  "managementMode": "REMOTE",
  "protection": { "state": "ON" },

  "apps": {
    "mode": "ALLOW_SELECTED",
    "allowed": ["org.example.reader"],
    "systemSelection": [
      { "package": "com.oem.gallery", "signerSha256": "<hex>", "versionCode": 1234 }
    ],
    "playCompatibility": false
  },

  "browserThroughFilter": {
    "enabled": false, "package": null, "signerSha256": null,
    "evidenceId": null, "canaryMaxAgeMinutes": 60
  },

  "systemControls": {
    "developer_options_and_adb": false,
    "usb_file_transfer": true,
    "unknown_source_installs": true,
    "app_stores_and_installers": true,
    "factory_reset": true,
    "safe_boot": true,
    "date_and_time": true
  },

  "homeFilter": {
    "enabled": true,
    "vpnPackage": "com.tailscale.ipn",
    "vpnSignerSha256": "<hex>",
    "routing": { "tailnetId": "T…", "loginUrl": "https://…", "exitNodeId": "…", "organizationName": "…" },
    "pacUrl": "https://filter.example.org/proxy.pac",
    "caCertificate": null,
    "canary": { "url": "https://check.example.org/", "expectedBody": "filtered" }
  },

  "managementPins": { "com.tailscale.ipn": ["<hex>"] },

  "kiosk": { "mode": "OFF" },

  "permittedAccessibilityServices": [],
  "permittedInputMethods": null,

  "systemUpdates": { "mode": "WINDOWED", "startMinutes": 120, "endMinutes": 300, "freezePeriods": [] },

  "sync": { "pullMinutes": 15, "wake": "NONE" },

  "locale": "iw"
}
```

### 7.1 Missing, null and unknown values

The classifier compares effective states (section 8), so every field needs a
single resolved meaning before evaluation:

| Field | Missing | `null` | Unknown value |
| --- | --- | --- | --- |
| `protection.state` | Refused (required) | Refused | Refused |
| `apps.mode` | Refused (required) | Refused | Refused |
| `apps.allowed` | Refused (required; an empty list is a configured, empty selection) | Refused | Non-package string refused |
| `apps.systemSelection` | Empty | Refused | Refused |
| `apps.playCompatibility` | `false` | Refused | Refused |
| `browserThroughFilter` | `enabled: false` | Refused | Refused |
| `systemControls.<key>` | The built-in default for the device's profile (`ENFORCED_SINCE_PILOT`, `PRODUCTION_ONLY`, `OPT_IN`), then the Play and home-filter floors | Refused | Unknown key refused |
| `homeFilter` | Off | Refused | Refused (validated by the existing record constructors) |
| `managementPins` | Built-in `MANAGEMENT_DEFAULTS` with no pins (so no management package is trusted) | Refused | Refused |
| `kiosk` | `OFF` | Refused | Refused |
| `permittedAccessibilityServices`, `permittedInputMethods` | `null` | No restriction | Refused |
| `systemUpdates` | Not set (platform default) | Clears the policy | Refused |
| `sync`, `locale` | Defaults | Refused | Refused |

"Refused" means the whole document is refused with `doc-field-invalid`; a
partially understood policy is never applied.

### 7.2 Field semantics and existing implementation

| Field | Maps to (exists today) | New behaviour |
| --- | --- | --- |
| `protection.state` `ON`/`PAUSED` | `LockdownPolicyController.apply` / `pause` | `PAUSED` only through a time-limited command, never as a resting policy value in `REMOTE` mode |
| `apps.mode`, `apps.allowed` | `AllowedAppsStore.setProtectionMode`, `setAllowedPackages` | The list is written under the mode it names and marked configured; the other mode's stored selection is cleared so that a later mode switch cannot resurrect it |
| `apps.systemSelection` | `AllowedAppsStore.setAdminSelectedSystemPackages`, `recordSystemRiskAcceptance`, revalidated by `revalidatedSystemSelection` | The identity (signer, version) in the policy is the risk acceptance; a mismatch on device is not applied and is reported |
| `apps.playCompatibility` | `PlayStoreCompatibilityStore.setEnabled` | — |
| `systemControls.<storageKey>` | `SystemPolicyStore.setRequested` for each `SystemPolicyControl.storageKey()` | Missing keys clear the stored choice so the default applies |
| `homeFilter` | `HomeFilterPolicy.Config`, `Routing`, `Canary`; `HomeFilterController.enable`/`disable`/`installCa`/`removeCa` | Validated by the same record constructors before anything is written |
| `managementPins` | `AllowedAppsStore.setManagementCertificatePins` via `ManagementIdentityInspector` | — |
| `kiosk` | `KioskConfig`, `KioskConfigValidator`, `KioskController` transitions | `CONFIGURE`+`ENTER` executed with a `VerifiedChange` authority |
| `browserThroughFilter` | **New** (7.3) | |
| `permittedAccessibilityServices`, `permittedInputMethods` | **New**: [`setPermittedAccessibilityServices`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#setPermittedAccessibilityServices(android.content.ComponentName,%20java.util.List%3Cjava.lang.String%3E)), [`setPermittedInputMethods`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#setPermittedInputMethods(android.content.ComponentName,%20java.util.List%3Cjava.lang.String%3E)) | See 9.3 for success conditions |
| `systemUpdates` | **New** (10.5) | |
| `locale` | `AppLocales.apply` | — |

### 7.3 Per-device "allow browser X through the filter"

**Today:** every browser in `ALWAYS_BLOCKED` and `KNOWN_BROWSER_AND_SOCIAL` is
hidden on every pass — `shouldBlock` starts `true` for them and the allowlist
branch only runs when `shouldBlock` is `false`, so even an allowlisted browser
stays hidden. All `http`/`https` links resolve to `BlockedBrowserActivity`.

**What the existing filter check proves, and what it does not.**
`HomeFilterProbe` makes an HTTPS request from Device Guard's own process.
A pass proves that Device Guard's traffic reached the filter at that moment.
It does not prove that a browser honours the recommended PAC proxy, trusts the
filter's user CA, avoids its own DNS-over-HTTPS or QUIC paths, or that a
Trusted Web Activity or another app's WebView goes the same way. Revision 1
treated the probe as browser evidence; this revision does not.

**Prerequisites before the field can be enabled on a device** (all four):

1. **VPN client installed and signed in.** Today this is manual
   ([`provisioning.md`](provisioning.md#home-filter) steps 1–2). For a
   zero-touch device it becomes an enrolment step: the client is installed
   through Device Guard's own signed-catalogue install path (10.4) or an
   approved install window (10.3), and signed in either through a managed
   sign-in setting the client supports (verify for the chosen client; none is
   documented for the Android client today) or through one named on-device
   step during setup. The device report carries the client's signed-in state
   as the client exposes it, or `vpn-login-unverifiable`.
2. **Direct egress blocked at the gateway.** The filter gateway must deny
   direct connections that bypass the proxy (alternate DNS, DoH endpoints,
   QUIC, IPv6), as [`provisioning.md`](provisioning.md#home-filter) step 5
   already requires. The fleet records a gateway configuration statement and
   its date; without it the field is refused (`filter-egress-unproven`).
3. **Per-browser, per-firmware evidence.** `FILTERABLE_BROWSERS` is an
   evidence catalogue, not a name list. An entry names the package, the
   signer, the tested major-version range and the firmware families, and
   links a hardware evidence record covering: PAC honoured for HTTP and
   HTTPS; user-CA trust (or no CA needed); DoH and QUIC behaviour with direct
   egress denied; link handling through the preferred activity; a Trusted Web
   Activity and a Custom Tab launched by another allowed app; another app's
   WebView while the browser is the WebView provider; behaviour when the
   tunnel drops (traffic must fail, not bypass). The policy names the entry by
   `evidenceId`.
4. **Bound to the active configuration.** The exemption is valid only while
   the active home-filter configuration hash, the browser's signer and its
   major version match the evidence entry. A browser updated outside the range
   (for example in an install window) is hidden again and reported
   `browser-evidence-mismatch` until a new evidence entry and approval exist.

**Device behaviour while enabled:**

- The browser is unhidden **only while the home filter is verified active**:
  Android settings confirmed **and** Device Guard's canary passing within
  `canaryMaxAgeMinutes`. If either lapses, the next pass hides it again (fail
  closed) and reports `browser-filter-unverified`. The canary here is a
  liveness signal for the tunnel, not browser evidence.
- Link routing: while exempt, the persistent preferred activity for
  `http`/`https` points at the chosen browser (`addPersistentPreferredActivity`
  with the browser's resolved `VIEW` activity), read back with the existing
  `eventuallyResolvesTo` probe. When the exemption ends,
  `configureBlockedBrowser` restores today's routing.
- A TWA or Custom Tab runs inside the browser and does not pass through `VIEW`
  routing; that is acceptable only because prerequisite 3 covers it, and it
  means enabling the browser also enables web content inside every allowed app
  that uses one. The approval rendering says so.
- If the chosen browser is also the WebView provider,
  `suspendBrowserBackedWebViewIfNeeded` must not suspend it while exempt.
- Where the browser supports Android managed configurations, the policy may
  carry browser restrictions applied with
  [`setApplicationRestrictions`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#setApplicationRestrictions(android.content.ComponentName,%20java.lang.String,%20android.os.Bundle))
  (for Chrome: proxy mode, incognito availability, DNS-over-HTTPS mode, safe
  search) — [Chrome enterprise policy list (verify which apply on Android)](https://chromeenterprise.google/policies/).
  Read back with `getApplicationRestrictions`. Any change to them is
  classified as part of the browser component (8.2).

Tests: JVM tests in `LockdownPolicyController`'s gateway style — browser stays
hidden with the field off; stays hidden with the field on and the filter
unverified; refused without an evidence entry, with a mismatched signer, with
a version outside the range, or without the gateway statement; unhidden only
with all prerequisites; re-hidden when the canary goes stale; WebView provider
not suspended while exempt; link routing restored on exit. Hardware: the
evidence record of prerequisite 3, per browser and firmware family.

---

## 8. Effective state, classification and human approval

### 8.1 Effective state

Revision 1 classified the raw fields of a policy. That is wrong for this code:
a mode switch from `BLOCK_SELECTED` to `ALLOW_SELECTED` reinterprets the list
and can unhide an app the blocklist hid; turning Play compatibility off removes
the install-control floor, so the install controls fall back to the stored
choices; a missing control means a profile-dependent default. The classifier
therefore compares **effective states**.

`EffectiveState.evaluate(policy, deviceFacts)` is a pure function that mirrors
the decision order of `applyPackagePolicy` and `SystemPolicyStore.baseChoices`
(one implementation in the app, ported to the server and the approver app,
held together by the shared vectors). `deviceFacts` are the installed
packages with signer and version, the firmware's SDK level, and the build
profile. Components:

| # | Component | Value |
| --- | --- | --- |
| E1 | Reachable packages | Installed packages that the pass would leave unhidden and unsuspended, after the built-in block, the mode's selection (and whether it is configured), store maintenance, Play compatibility, kiosk escape surfaces, trusted management, WebView provider, essential system packages, kiosk target, browser exemption and quarantine |
| E2 | New-package default | `DENY` (allowlist mode with a configured selection) or `ALLOW` (blocklist mode, or no configured selection) |
| E3 | Effective restrictions | Each `SystemPolicyControl` resolved through profile default, stored choice, Play floor and home-filter floor, as `SystemPolicyEnforcer.requestedFor` does |
| E4 | Network path | Home filter on/off; VPN package and signer; routing, PAC and canary configuration hash; installed CA set |
| E5 | Web access | Browser exemption (package, signer, evidence id, canary age), link routing target, browser managed restrictions |
| E6 | Input and accessibility | Permitted accessibility services and input methods |
| E7 | Kiosk | State, mode, target |
| E8 | Management and recovery | Management mode, trusted management packages, recovery verifier present, sync interval and wake channel |
| E9 | Update policy | System update mode, window minutes, freeze periods |
| E10 | Quarantine | Packages suspended or hidden by an install-window diff |
| E11 | Presentation | Locale |

`effectiveDiffSha256` is the SHA-256 of the canonical serialisation of the
per-component differences; the approver app shows the same differences it
hashes (8.4).

**Whose facts.** The device evaluates against its own installed packages; the
server and the approver app evaluate against the inventory in the device's
last signed report. If they differ (an app was installed in between), the
device's diff hash will not match the approval and the device refuses with
`approval-diff-mismatch`, reports its own diff, and the approval is redone.
Tightening documents are applied whatever the inventory.

### 8.2 One rule per component, field and transition

Result order: `N` neutral < `T` tighten < `L` loosen; `H` (hazard) is a
change that can cut a recovery path, brick the device or delay security fixes
even if it looks stricter. A document's class is the highest result of any
component; any `L` or `H` requires approval, and `H` is shown separately in
the rendering.

| Component | `T` | `L` | `H` | `N` |
| --- | --- | --- | --- | --- |
| E1 reachable packages | a package leaves the set | a package joins the set (including through a mode switch, a list change, Play compatibility, a system selection or an identity change) | a trusted management package (VPN) or the WebView provider leaves the set | — |
| E2 new-package default | `ALLOW` → `DENY` | `DENY` → `ALLOW` | — | — |
| E3 restrictions | a control turns on | a control turns off (including through removal of the Play floor or the home-filter floor, or a missing key whose default is off) | `developer_options_and_adb` turns on (removes ADB break-glass) | — |
| E4 network path | filter turns on with a configuration this device previously ran verified | filter turns off; any change to VPN identity, routing, PAC, canary or CA | filter turns on with a configuration this device has not run verified before (it can cut sync) | — |
| E5 web access | exemption ends; routing back to `BlockedBrowserActivity`; `canaryMaxAgeMinutes` shrinks | exemption starts or changes package, signer, evidence id; `canaryMaxAgeMinutes` grows; any browser-restriction change that relaxes | — | — |
| E6 input and accessibility | a list narrows; `null` → list | a list widens; list → `null` | narrowing that excludes a currently enabled service the device's recovery depends on (none today; reserved) | — |
| E7 kiosk | — | exit, clear, or target change | configure or enter | — |
| E8 management and recovery | wake channel off | `REMOTE` → `LOCAL_PIN`; a management pin added or its signer changed; recovery verifier set or rotated | a management pin removed (the VPN loses its exemption) | sync interval change; wake channel on |
| E9 update policy | — | — | postpone, freeze, or a window that becomes shorter | `AUTOMATIC` (installs at any time and may reboot; the post-OTA reconciliation of 10.5 applies), a window that becomes longer or moves |
| E10 quarantine | a package added | a package released | — | — |
| E11 presentation | — | — | — | locale |

Commands have fixed classes, listed with their rules in section 9. Every
transition not listed above is a defect in this table, and the vector set has
a case per row and column, including: mode switch in both directions with
overlapping and disjoint lists; mode switch with an unconfigured target
selection; Play compatibility off while the stored install choices are off;
a missing control key whose default differs between profiles; a system
selection with the same package and a new signer; a `null` list; an unknown
value (refused, 7.1).

### 8.3 Who enforces

- **Server:** refuses to sign any `L`/`H` policy or command unless a valid
  approval statement over the exact payload and the device's reported base and
  challenge is attached, and records the approval in the audit log. MCP tools
  have no path to an approval key.
- **Device:** independently evaluates and classifies against its applied state
  and its own inventory, and refuses a loosening document whose approval does
  not match in every field of 6.5. This is what limits a compromised server
  to denial of service.

### 8.4 Approver: renders the change itself

WebAuthn proves that a person used their passkey; it does not prove what that
person was shown. If the server renders the approval page, a compromised
server can show "allow one reading app" and obtain a signature over a
different payload. The approval therefore comes from an **approver** that
does not take its rendering from the management server:

- **Approver app (recommended).** A small separately signed app on the
  administrator's phone. It holds the approval key in Android Keystore (or the
  platform equivalent) with user authentication required for every use. It
  receives from the server only bytes: the signed candidate envelope, the
  device's last signed report (inventory, applied policy hash, live
  challenges), and the applied policy envelope. It verifies all signatures
  against the fleet key set it pinned at registration, runs the shared
  `EffectiveState.evaluate` itself, **renders the per-component diff, the
  class and every `H` item from its own computation**, and signs the statement
  of 6.5 only after the person confirms that rendering.
- **Static approver page (alternative).** A versioned static page served from
  an origin and hosting account that the management server's operators do not
  control, using WebAuthn with that origin pinned on the device
  (`webauthn-es256`). It performs the same verification and rendering in the
  browser. Its residual risk is stated: whoever controls that origin controls
  the rendering.

Either way, the device's own check of `effectiveDiffSha256` (6.5) means a
renderer that showed one diff and signed another hash is refused. What
remains trusted is the approver's code and phone (13.7).

### 8.5 First policy after enrolment

The first policy of a new device is classified against the enrolment baseline
(4.3). The approver sees the device's attestation facts, its `expected` or
`unexpected` status (4.4) and the diff from the baseline. A batch statement
can approve the first policy of up to 64 devices in one confirmation.

---

## 9. Command contract and full management parity

### 9.1 Rules common to every command

- Every mutation, whatever its class, is a **prepare/confirm** pair in MCP
  (11.2). Read-only tools query the server's database and never create a
  command.
- Every command carries `sequence`, `basePolicySha256`, `issuedAt` and a
  per-command start validity; an expired command is not executed and is
  reported `command-expired`.
- `L` and `H` commands carry an approval statement (6.5). Wipe needs **two**
  statements from approval keys owned by two different administrators in the
  key set; a fleet with one administrator must register a second approval key
  held separately (for example a hardware key in a safe) before wipe is
  available.
- Agent credentials (11.2) have scopes; no scope can approve.

### 9.2 Contract table

**Class:** `T` tighten (applies at once), `N` neutral (applies at once), `L`
loosen (needs approval), `H` hazard (needs approval). **PR** refers to
section 14. **Evidence** is what the signed report must contain before the
server marks the action done; until then it is `delivered` or `pending`.

| Console action today (where) | Signed command / policy field | MCP tool | Class | Approval scope | PR | Evidence of success |
| --- | --- | --- | --- | --- | --- | --- |
| Apply protection (`MainActivity` → `LockdownPolicyController.apply`) | `protection.state = ON` | `protection_set_prepare` | per 8.2 | components touched | 7 | `PolicyResult.verified`, error codes, package census |
| Pause protection (`LockdownPolicyController.pause`) | command `pause {minutes ≤ 240}`, validity 1 h | `protection_pause_prepare` | L | `E1,E3` + duration | 14 | `markPauseSucceeded`; restore obligation; verified re-apply at expiry |
| Choose allowlist or blocklist (`AllowedAppsActivity` → `setProtectionMode`) | `apps.mode` (+ `apps.allowed`) | `apps_set_mode_prepare` | per 8.2 (E1, E2) | `E1,E2` | 7 | `isApplicationHidden` per managed package |
| Allow or block apps (`setAllowedPackages`) | `apps.allowed` | `apps_set_list_prepare` | per 8.2 (E1) | `E1` | 7 | per-package hidden state; `package-policy-state-mismatch` |
| Select system apps with risk acceptance | `apps.systemSelection` | `apps_set_system_selection_prepare` | per 8.2 (E1) | `E1` | 7 | `revalidatedSystemSelection` identity match, hidden state |
| Google Play compatibility (`SystemPolicyActivity` → `PlayStoreCompatibilityStore.setEnabled`) | `apps.playCompatibility` | `play_compat_set_prepare` | per 8.2 (E1, E3) | `E1,E3` | 7 | `PlayStoreCompatibility.State`; install lock `APPLIED` |
| Allow a browser through the filter (new) | `browserThroughFilter` | `browser_filter_set_prepare` | enable/change `L`; disable `T` | `E1,E5` | 18 | prerequisites of 7.3, hidden state, preferred-activity probe, canary age |
| System control switches (`SystemPolicyStore.setRequested`) | `systemControls.<key>` | `system_control_set_prepare` | per 8.2 (E3) | `E3` | 7 | `SystemPolicyReport` per control |
| Home filter enable with routing, PAC, canary (`HomeFilterController.enable`) | `homeFilter` | `home_filter_set_prepare` | per 8.2 (E4, E3) | `E3,E4` | 7 | `HomeFilterController.read` snapshot |
| Install or remove CA (`installCa`, `removeCa`) | `homeFilter.caCertificate` | `home_filter_ca_set_prepare` | L | `E4` | 7 | `hasCaCertInstalled` |
| Turn off home filter (`disable`) | `homeFilter.enabled = false` | `home_filter_set_prepare` | L | `E3,E4` | 7 | cleared VPN, config, proxy, CA; released restrictions |
| Retry home filter (`retry`) | command `reconcile` (no payload; re-applies the journaled desired state only) | `device_reconcile_prepare` | N | — | 13 | fresh `PolicyResult` |
| Home filter check (`HomeFilterProbe`) | command `filter_check` (schedules a probe; not a read) | `filter_check_prepare` | N | — | 13 | canary result and time in the next report |
| Management identity pins (`ManagementIdentityActivity`) | `managementPins` | `management_pins_set_prepare` | add/change `L`, remove `H` | `E1,E8` | 7 | `ManagementIdentityInspector` verdict per package |
| Configure and enter kiosk | `kiosk {mode, target}` | `kiosk_set_prepare` | H | `E7` | 14 | `KioskState.ACTIVE`, lock-task packages, HOME preference |
| Exit or clear kiosk | `kiosk.mode = OFF` | `kiosk_set_prepare` | L | `E7` | 14 | `KioskState.OFF`, preferences cleared |
| Open a maintenance window (`MaintenanceCoordinator.open`) | command `maintenance_open {capabilities, minutes ≤ 240}`, validity 1 h | `maintenance_open_prepare` | L; `ADB_DEBUGGING` is `L` with its warning; critical controls only where δ is proven (5.4) | `E3` + capabilities + duration | 14 | `MaintenanceOutcome`, `residualBlockers`, obligation id |
| Cancel a maintenance window (`cancel`) | command `maintenance_cancel` | `maintenance_cancel_prepare` | T | — | 13 | `restoreVerified`, obligation cleared |
| Install window (new, 10.3) | command `install_window` | `install_window_prepare` | L (states "permits new installs") | `E1,E2,E3` + stores + duration | 16 | window outcome, restore, diff, quarantine |
| Release a package from quarantine (new) | command `quarantine_release {package, signerSha256, versionCode}` | `quarantine_release_prepare` | L | `E1,E10` | 16 | unsuspended/unhidden, identity matched |
| Check for a Device Guard update now (`SecureUpdateManager.checkNow`) | command `self_update_check` | `self_update_check_prepare` | N | — | 13 | `UpdateSnapshot.phase`, installed version |
| Create or change PIN (`AdminPinStore.setNewPin`) | command `set_local_pin_verifier` + `managementMode = LOCAL_PIN` | `local_admin_enable_prepare` | L | `E8` | 14 | `hasPin`, mode in report |
| Rotate recovery code (`rotateRecoveryCode`) | command `set_recovery_verifier` (from the approver app, 5.6) | `recovery_code_rotate_prepare` | L | `E8` | 14 | verifier present, rotation time |
| Lock the console (`AdminSession.lock`) | command `end_sessions` | `sessions_end_prepare` | T | — | 13 | no live session in report |
| Unlock the console (PIN entry) | command `console_session {minutes ≤ 30, scope}`, validity 1 h | `console_session_prepare` | L | `E8` + scope + duration | 14 | session deadline in report |
| Device health report and export (`DeviceHealthActivity`) | signed report on every sync; command `report_now` | `device_report_now_prepare` (command); `device_status` (read) | N | — | 11 | the report itself, signed by the attested device key |
| Audit log view (`AuditLog.formatted`) | report section (event codes) | `device_audit` (read) | — | — | 11 | hash-chained server copy |
| Display language (`AppLocales.apply`) | `locale` | `device_locale_set_prepare` | N | — | 7 | `AppLocales.current` |
| Lock screen now (new) | command `lock_now` → [`lockNow`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#lockNow()), validity 15 min by trusted time, executed at most once | `lock_now_prepare` | T | — | 13 | executed-at time in report, or `command-expired` |
| Reboot (new) | command `reboot` → [`reboot`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#reboot(android.content.ComponentName)), validity 1 h | `reboot_prepare` | N when no restore obligation is open and the last pass verified; otherwise refused (`reboot-while-unrestored`) unless sent as `H` with approval | — / `E3` | 13 | `BOOT_COUNT` increased **and** a verified pass after boot |
| Restrict accessibility services / keyboards (new) | `permittedAccessibilityServices`, `permittedInputMethods` | `accessibility_permit_set_prepare` | per 8.2 (E6) | `E6` | 17 | 9.3 |
| System update policy (new, 10.5) | `systemUpdates` | `system_updates_set_prepare` | per 8.2 (E9) | `E9` | 17 | 10.5 |
| Wipe (new; no console equivalent) | command `wipe` → [`wipeDevice`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#wipeDevice(int)) on API 34+, `wipeData` below | `wipe_prepare` | H, two approvals | `wipe` | 14 | see 9.3; never "device disappeared" |
| Move device to local PIN mode | `managementMode = LOCAL_PIN` | `local_admin_enable_prepare` | L | `E8` | 14 | mode in report |

Parity is enforced by a test: a JVM test enumerates every console action (a
registry each activity registers into) and fails if any has no row here, and
the server has the mirror test for MCP tools and for the PR and evidence
columns.

### 9.3 Success conditions for the newer APIs

- **Accessibility services.** `setPermittedAccessibilityServices` returns
  `false` when a non-system service that is currently enabled is missing from
  the list (verify current wording). System services stay permitted
  regardless. Permitting a service does not enable it, and does not bypass
  Restricted Settings. Evidence: the call's return value, the getter
  read-back, and the list of enabled services. A `false` is reported as
  `accessibility-permit-refused` with the blocking service, never as applied.
- **Input methods.** `setPermittedInputMethods` behaves the same way for an
  enabled third-party input method (verify); same evidence and code
  (`input-method-permit-refused`).
- **System updates.** See 10.5.
- **Wipe.** With the current `targetSdk` (36), a Device Owner must use
  `wipeDevice` on API 34+ (verify whether `wipeData` throws for a Device Owner
  targeting 34+). Before calling it, the device sends a signed
  `wipe-accepted` report and waits up to 60 seconds for the server's
  acknowledgement; then it calls the API. The server state moves
  `wipe-requested` → `wipe-accepted` (signed report received) →
  `retired` only when an administrator confirms it or the same hardware
  re-enrols (same enrollment-specific ID on API 31+, or the attested serial).
  Silence is reported as `wipe-unconfirmed`, never as success.
- **Reboot.** `reboot` can refuse during an ongoing call (verify); that is
  reported as `reboot-refused`.
- **`lock_now`.** Executed at most once, only inside its validity; no
  delivery latency is promised (5.7).

---

## 10. Install windows, self-update and system OTA

### 10.1 What Android allows, and what this section offers

`APP_STORES_AND_INSTALLERS` (`DISALLOW_INSTALL_APPS`) is part of
`HomeFilterPolicy.REQUIRED_CONTROLS`, and `permitsRelaxing` refuses any
maintenance window that touches it, so on a home-filter device apps cannot be
updated at all today. Google Play compatibility pins the same restriction on.

`DISALLOW_INSTALL_APPS` applies to the whole managed user. Lifting it lets
every visible installer with install rights install anything, not only the
stores a command names, and not only updates. There is no DPC control for
"updates only". Revision 1 presented its window as an update window; it was
not. This revision offers three separate mechanisms with honest limits:

| Mechanism | What it permits | Class |
| --- | --- | --- |
| Self-update window (10.2) | Device Guard's own verified package, for minutes | N (no server lever) |
| Install window (10.3) | New installs and updates from the named stores, for a bounded time, with quarantine of anything new | L |
| Signed private catalogue (10.4, later) | The only update-only path: exact APKs pinned by hash, installed by Device Guard | L per catalogue change |

### 10.2 Device Guard self-update window

Unchanged channel ([`secure-updates.md`](secure-updates.md)): separate metadata
key, version floor, signer lineage. `DISALLOW_INSTALL_APPS` also blocks the
Device Owner's own `PackageInstaller` session (documented in
[`play-store-compatibility.md`](play-store-compatibility.md#what-the-mode-costs)),
so a narrow window is needed:

- It opens only from the device's own update path, after the update metadata
  was verified against the update key and floor **and** the APK was
  downloaded and verified (hash, size, signer, lineage). The server cannot open
  it; `self_update_check` only asks the device to check. At most one window
  per verified version.
- It relaxes exactly `DISALLOW_INSTALL_APPS`. Stores stay hidden, unknown
  sources stay restricted, debugging stays as it was.
- It follows the restore-obligation pattern (5.4) with a 10-minute deadline.
- It closes on the first of: the `PackageInstaller` result in
  `UpdateInstallReceiver` (the commit is asynchronous; success or failure),
  `MY_PACKAGE_REPLACED` (the new process restores before anything else), the
  deadline, or any other trigger of 5.4.
- A snapshot and diff (10.3, steps 2 and 6) run around it; anything other than
  Device Guard that changed is quarantined.
- Hardware evidence per firmware family: success, install failure, process
  death mid-install, reboot mid-install; each must end restored.
- On a home-filter device, `HomeFilterController.restrictionsMatch` reads the
  filter as unverified while the restriction is lifted (it requires every
  required control on); the filter state and any browser exemption drop for
  those minutes, which is the fail-closed direction.

### 10.3 Install window

**Command** `install_window` (class `L`; the approval rendering states in
plain words that the window permits installing new apps, not only updates):

```json
{ "kind": "install_window",
  "args": { "notBefore": 1795003600, "notAfter": 1795010800,
            "minutes": 60, "stores": ["com.android.vending"],
            "requireCharging": true, "requireUnmetered": true } }
```

Sequence on the device:

1. **Schedule.** A one-off job with the charging and unmetered constraints as
   hints. The job re-checks every precondition itself (5.4 step 3); a job that
   runs at its override deadline with a constraint unmet does not open.
2. **Snapshot.** Before any relaxation, record every package of the managed
   user with `versionCode`, signing-certificate digests, installer and enabled
   state, querying with
   [`MATCH_UNINSTALLED_PACKAGES`](https://developer.android.com/reference/android/content/pm/PackageManager#MATCH_UNINSTALLED_PACKAGES)
   so packages this DPC hid are included, and then keeping only entries whose
   `ApplicationInfo.flags` has `FLAG_INSTALLED` (the flag also returns
   packages uninstalled with data kept). The snapshot is written durably
   (`commit()`) with its SHA-256 in the obligation record, before step 3.
3. **Open.** `RestoreObligation` first, then `MaintenanceCoordinator.open`
   with `MaintenanceCapability.APP_STORE_ACCESS`, which relaxes
   `DISALLOW_INSTALL_APPS` and makes the named stores visible through
   `MaintenanceAppPolicy`. On a home-filter device a new `INSTALL_WINDOW`
   window kind is accepted by `HomeFilterPolicy.permitsRelaxing` for exactly
   `APP_STORES_AND_INSTALLERS`, only with a `VerifiedChange` authority. The
   VPN lockdown, PAC, Private DNS, unknown-source restrictions and every other
   required control stay enforced, so store traffic still passes the family
   filter, which must allow the store's domains. As in 10.2, the home filter
   and any browser exemption read as unverified for the window.
4. **During.** The `PACKAGE_ADDED` handler of `LockdownDeviceAdminService`
   gains a window rule: any package not in the snapshot is quarantined
   (step 6) as soon as the broadcast arrives, **in both modes**. This matters
   for `BLOCK_SELECTED`, where today a new app is allowed by default (E2).
   There is still a race between install and broadcast; the approval
   rendering says so.
5. **Close.** At the clamped monotonic deadline (or on cancel, reboot, process
   death, or any trigger of 5.4) the verified restore puts back the base
   policy.
6. **Diff and quarantine.** After the restore is read back, compare with the
   snapshot: new packages, packages whose signer set changed, packages whose
   identity was replaced, and packages whose version went down are
   quarantined. Quarantine uses
   [`setPackagesSuspended`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#setPackagesSuspended(android.content.ComponentName,%20java.lang.String[],%20boolean)),
   whose return value lists packages that could not be suspended; each of
   those is hidden with `setApplicationHidden` instead; each result is read
   back (`isPackageSuspended`, `isApplicationHidden`). A package that can be
   neither suspended nor hidden is a critical fault
   (`install-window-quarantine-failed`). Updated packages with the same signer
   are reported as updated. The diff runs even if the window closed early, and
   again after a reboot if the obligation was closed by the boot path.
7. **Report.** One signed report with the window outcome, restore
   verification, measured close latency, the diff and the quarantine results.
   Release is the separate `quarantine_release` command (`L`).

**Known limitation.** Device Guard cannot make the Play Store update apps on
demand; Play decides when to run auto-updates. A window may close with nothing
updated, and Play may install updates or apps the administrator did not
intend; the quarantine catches new and re-signed packages, not unwanted
updates of allowed ones.

**Tests.** JVM: snapshot/diff logic (new, removed, updated, downgraded,
signer-changed, hidden packages included, `FLAG_INSTALLED` filtering);
quarantine fallback to hide when suspension is refused; `permitsRelaxing`
accepts only `APP_STORES_AND_INSTALLERS` and only for `INSTALL_WINDOW` with a
verified authority; precondition re-check; clamp to `notAfter`; early close
still diffs; process restart closes. Hardware: Play updates an allowed app
through the filter; a new app installed during the window is quarantined in
both modes; restore verified after a reboot mid-window; close latency δ.

### 10.4 Signed private catalogue (later)

The robust update-only path: signed manifests per app (package, version,
signer, APK hash), installed by Device Guard through `PackageInstaller`
exactly like its own self-update, inside a self-update-style window. It is
also the zero-touch install path for the VPN client (7.3). It raises APK
redistribution licensing questions (section 15).

### 10.5 System OTA

New policy field `systemUpdates`:

| Mode | API |
| --- | --- |
| `AUTOMATIC` | [`SystemUpdatePolicy.createAutomaticInstallPolicy`](https://developer.android.com/reference/android/app/admin/SystemUpdatePolicy#createAutomaticInstallPolicy()) |
| `WINDOWED` (minutes after midnight, device local time) | [`createWindowedInstallPolicy`](https://developer.android.com/reference/android/app/admin/SystemUpdatePolicy#createWindowedInstallPolicy(int,%20int)) |
| `POSTPONE` | [`createPostponeInstallPolicy`](https://developer.android.com/reference/android/app/admin/SystemUpdatePolicy#createPostponeInstallPolicy()) (30 days) |
| freeze periods | [`setFreezePeriods`](https://developer.android.com/reference/android/app/admin/SystemUpdatePolicy#setFreezePeriods(java.util.List%3Candroid.app.admin.FreezePeriod%3E)) (API 28+) |

Validation before signing and again on the device:

- `startMinutes` and `endMinutes` each in `0–1439`; a window with
  `startMinutes > endMinutes` crosses midnight (verify the platform's
  handling, and test a crossing window on hardware).
- Each freeze period at most 90 days, and at least 60 days between freeze
  periods; the platform also counts the device's recorded freeze history, so a
  valid-looking list can still be refused. The platform's validation error is
  reported (`system-update-policy-invalid` with the reason), never retried
  with a different policy.
- Applied with
  [`setSystemUpdatePolicy`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#setSystemUpdatePolicy(android.content.ComponentName,%20android.app.admin.SystemUpdatePolicy))
  and read back with `getSystemUpdatePolicy`; the report also carries the
  pending update from
  [`getPendingSystemUpdate`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#getPendingSystemUpdate(android.content.ComponentName))
  ([`onSystemUpdatePending`](https://developer.android.com/reference/android/app/admin/DeviceAdminReceiver#onSystemUpdatePending(android.content.Context,%20android.content.Intent,%20long)))
  and `Build.VERSION.SECURITY_PATCH`. Guide:
  [managing system updates](https://developer.android.com/work/dpc/system-updates).

Boundary: OEMs honour these policies to different degrees; some ignore them.
The report states what Android returned, not what the OEM will do. An OTA can
change OEM behaviour, so the first boot after a build-fingerprint change
triggers a full reconciliation and a report (the fingerprint is already in
`DeviceHealthSnapshot.Platform`). Postponing, freezing or narrowing the
window delays security patches, hence `H`. `AUTOMATIC` is `N`, not `T`: it
improves patching but can reboot the device at any time.

---

## 11. Management server and MCP interface

### 11.1 Scope

A deliberately small service, kept in a **separate repository** so the DPC
repository stays a client and holds no server secrets. A minimal **test
server** with the same API and the shared vectors is built first (section 14)
so the device client is developed against real responses. Data model:

| Table | Content |
| --- | --- |
| `fleets` | id, label, root-key digest, current key set |
| `devices` | `deviceId`, fleet, state (`enrolling`, `active`, `untrusted`, `wipe-requested`, `wipe-accepted`, `retired`), `expected`/`unexpected`, attestation facts, applied policy version and hash, live challenges, last report, last seen |
| `policies` | immutable versions per device: payload bytes, hash, previous hash, class, effective diff, approval reference |
| `commands` | per-device sequence, payload bytes, class, approval reference, state (`queued`, `delivered`, `applied`, `failed`, `expired`) |
| `approvals` | statement bytes, approver key, devices covered, consumed-by |
| `audit` | append-only, each row includes the SHA-256 of the previous row; periodically exported off the server |

Device API: `POST /v1/enrol`, `POST /v1/sync`, `POST /v1/report`, optional
`GET /v1/wake`. Approver API: fetch pending approvals as signed bytes, submit
statements. Administrator API: the MCP interface below.

### 11.2 MCP tools: prepare and confirm

Every mutating tool is two-step, including `T` and `N`:

1. `*_prepare(args)` validates, renders the candidate per-device payload,
   evaluates and classifies against each device's last report, and returns
   `{preparationId, devices, diff, class, approvalRequired}`. Nothing is
   signed.
2. `confirm(preparationId)`:
   - `T`/`N`: signs and queues at once, returns the policy version or command
     sequence;
   - `L`/`H`: returns `awaiting-approval`; the approval request appears in the
     approver app; when a valid statement arrives, the server signs and queues.
     If the device's inventory or applied hash changed meanwhile, the request
     is re-prepared and re-approved.

Read-only tools (no command is created): `device_status`, `device_list`,
`device_audit`, `policy_get`, `approval_status`.

**Agent credential scopes.** Each MCP credential is issued with an explicit
set of scopes, per fleet or device group: `read`, `prepare`, `confirm:N`,
`confirm:T`, and `request:L` (may create approval requests for `L`
preparations). `H` requests and wipe need a human-held administrator
credential. No scope can approve; approval exists only in the approver app.

Server-side invariants (each has a test): the policy-signing code path refuses
`L`/`H` without a verified approval matching the exact payload, base, diff and
a live device challenge; approvals are single use; the evaluator and
classifier are the shared ones; a policy is never edited, only superseded;
sync returns the full catch-up chain or a rebase (5.7); an MCP request can
never select the signing key or set `policyVersion`/`sequence`; a credential
cannot exceed its scopes.

### 11.3 Failure modes

| Failure | Effect |
| --- | --- |
| Server down | Devices keep their last verified policy; running windows close on their monotonic deadlines; nothing loosens |
| Signing key unavailable | Nothing new is issued; reads still work |
| Approver app unreachable | Loosening waits; tightening unaffected |
| Device offline | No fresh challenges, so no new approvals for it; tightening queues |
| Device silent past `3 × pullMinutes + 1 h` | `device-silent` alert (possible wipe, flash, or network loss) |
| Report says `verified: false` or a restore obligation is overdue | Alert with the stable error codes |

---

## 12. Optional pilot: on-device content check through Accessibility

This is an optional, separately reviewed pilot. It changes a public claim — the
README says Device Guard "does not use Accessibility to simulate control" — and
the pilot keeps that claim true by **observing only**, never performing
actions; the README must then say so explicitly.

**What an `AccessibilityService` can see.** Window and view hierarchy text via
`AccessibilityNodeInfo`, the foreground package and class through
`TYPE_WINDOW_STATE_CHANGED`, and on API 30+ a screenshot through
[`takeScreenshot`](https://developer.android.com/reference/android/accessibilityservice/AccessibilityService#takeScreenshot(int,%20java.util.concurrent.Executor,%20android.accessibilityservice.AccessibilityService.TakeScreenshotCallback))
when the service declares `canTakeScreenshot`. Windows with `FLAG_SECURE` are
not captured. Reference:
[`AccessibilityService`](https://developer.android.com/reference/android/accessibilityservice/AccessibilityService).

**Design.**

- Scope: only packages listed in the policy (typically the browser allowed
  through the filter), only while the screen is on and that package is in the
  foreground.
- On-device-only classification: a small image classifier (for example a
  LiteRT/TFLite model shipped in the APK and pinned by hash) and a text
  keyword list from the policy. **No image, text or URL leaves the device.**
  The report carries only counts per category and time bucket.
- Action on a hit: none in the pilot beyond a local, non-sensitive log and the
  counter. A later phase may hide the package or return HOME, which is a
  separate design decision.
- Battery: event-driven, at most one screenshot every N seconds (policy, default
  10), none on battery saver or below 20 %, inference on a background thread,
  model kept small. Measured on hardware before any rollout.
- Permitting and enabling: Device Guard must be in its own permitted list
  (9.3: the call fails while another enabled non-system service is missing
  from the list). Permitting does not enable. There is no documented API to
  **enable** a service silently, and Android 13+ "restricted settings" can
  block enabling for some sideloaded apps
  ([Android 13 behaviour changes (verify)](https://developer.android.com/about/versions/13/behavior-changes-all)).
  Whether a provisioning-installed or self-updated Device Guard is treated as
  restricted on Android 15+ must be tested. Enabling therefore likely needs
  one on-device tap (or `adb shell settings put secure
  enabled_accessibility_services` on the ADB path), which conflicts with
  zero-touch and is listed as an open question.
- Privacy and consent: the device user (or a guardian for a minor) must be told
  before enabling, in plain language, what is analysed and that nothing leaves
  the device; a persistent indicator is shown while active; the policy field
  is `L` class (approval) to enable. Organisations must check local privacy and
  employment law before using it.

**Tests.** JVM: scope gating, rate limiting, report contains no content (a
redaction test like `DeviceHealthRedactionTest`). Hardware: battery drain over
8 hours, restricted-settings behaviour per Android version, `FLAG_SECURE`
behaviour.

---

## 13. Threat model

For each threat: what the mitigation does, and what it does **not** cover.

### 13.1 ADB removal of a test-only build

- **Threat.** The debug manifest sets `android:testOnly="true"`; Android allows
  `dpm remove-active-admin` and uninstall for test-only Device Owners
  ([`provisioning.md`](provisioning.md) already notes this).
- **Mitigation.** Remote mode refuses to enrol when `ApplicationInfo.FLAG_TEST_ONLY`
  or `FLAG_DEBUGGABLE` is set; the server also rejects an attestation whose
  `attestationApplicationId` signer is not the approved release signer. Release
  builds ignore `remove-active-admin`.
- **Does not cover.** Someone deliberately building and enrolling their own
  test-only device; it simply cannot join a real fleet.

### 13.2 USB debugging

- **Threat.** ADB grants a privileged shell: package management, `dpm`, file
  access.
- **Mitigation.** `DEVELOPER_OPTIONS_AND_ADB` (`DISALLOW_DEBUGGING_FEATURES`)
  exists today. In remote mode it is set by policy (an `H` change) once the
  signed self-update drill has passed on that firmware family (the existing
  production gate), and ADB returns only through an approved `ADB_DEBUGGING`
  maintenance window on a family with a proven close bound (5.4).
  Optional: [`setUsbDataSignalingEnabled(false)`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#setUsbDataSignalingEnabled(boolean))
  on API 31+ devices that support it. Hiding developer options also hides the
  "OEM unlocking" toggle on most builds (verify per OEM).
- **Does not cover.** OEM service modes, vendor diagnostic ports, a device where
  the restriction is refused (reported as a critical fault, never as active).

### 13.3 Recovery wipe and flashing on an unlocked bootloader

- **Threat.** Recovery-mode factory reset removes Device Guard;
  `DISALLOW_FACTORY_RESET` only removes the Settings entry. An unlocked
  bootloader allows flashing anything.
- **Mitigation.** Detection, not prevention: the server raises `device-silent`;
  re-enrolment needs a new ticket and starts on the baseline. Optional
  [`setFactoryResetProtectionPolicy`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#setFactoryResetProtectionPolicy(android.content.ComponentName,%20android.app.admin.FactoryResetProtectionPolicy))
  (API 30+) makes a wiped device require an administrator Google account
  during setup. Attestation reveals an unlocked bootloader at enrolment and on
  each re-attestation (planned monthly).
- **Does not cover.** Devices without Google services (FRP needs them), a thief
  who keeps the device offline, or bootloaders that are unlockable without the
  OEM toggle.

### 13.4 Custom ROMs spoofing verified-boot properties

- **Threat.** `ro.boot.verifiedbootstate` and similar properties are just
  strings a modified system can fake.
- **Mitigation.** Device Guard never trusts properties. It relies on hardware
  key attestation verified **on the server** against Google's roots and the
  revocation list; StrongBox preferred.
- **Does not cover.** A leaked but unrevoked attestation keybox, devices that
  only offer software attestation (marked untrusted, not refused), or a
  compromise after enrolment until the next re-attestation.

### 13.5 Clock tampering and forged server time

- **Threat.** Moving the device clock to extend a window or revive an expired
  document; a compromised server signing an old time to revive an approval.
- **Mitigation.** Durations on the monotonic clock; approval freshness from
  device-issued challenges measured on the device's monotonic clock, single
  use and voided by reboot (6.4), so neither the device's wall clock nor the
  server's time can revive an approval; server-anchored time only for
  non-loosening validity; `DISALLOW_CONFIG_DATE_TIME` (API 28+) and automatic
  time (API 30+); the existing wall-versus-monotonic jump detection
  (`MaintenanceStateMachine.BOOT_GAP_TOLERANCE_MILLIS`).
- **Does not cover.** A compromised server issuing a stale-looking tightening
  (harmless by class); API 26–27, where the date/time restriction does not
  exist (approvals are unaffected).

### 13.6 Replayed or downgraded policy, and crashes

- **Threat.** Replaying an older, looser signed policy, command or approval;
  a crash between applying and recording that leaves the device and its
  record disagreeing.
- **Mitigation.** Strictly increasing `policyVersion`, `sequence` and
  `keySetVersion`; `previousPolicySha256` chain; `basePolicySha256` on commands
  and approvals; device binding; consumed challenges; floors and challenge
  consumption committed in the journal before Android is touched; resume from
  the journal after a crash (6.6).
- **Does not cover.** An attacker with root who resets app storage; a wipe
  (which also removes Device Guard).

### 13.7 Server compromise and misleading approval

- **Threat.** Full control of the management server, including its signing key
  and anything it renders.
- **Mitigation.** The device requires an approval statement for every `L`/`H`
  change; the approval keys are not on the server; the approver renders the
  change from signed bytes with its own evaluator (8.4); the device checks the
  diff hash, base and challenge. Key-set changes need the offline root. The
  audit chain is exported off the server. The offline recovery code, generated
  on the approver device, recovers a device that a malicious tightening made
  unreachable.
- **Does not cover.** Denial of service by tightening (for example blocking
  every allowed app); disclosure of device reports; a compromised approver
  phone or approver app, or a malicious administrator; whoever controls a
  static approver origin, if that alternative is used; compromise of the
  release or update metadata keys (separate trust chain).

### 13.8 Window overrun, Doze and reboot

- **Threat.** A relaxed restriction outliving its window because the process
  is not running, the device is in Doze, or it rebooted (restrictions persist).
- **Mitigation.** Restore obligation in device-protected storage before the
  first relaxation; several close triggers including an idle-capable alarm,
  a foreground service with screen-on checks, and a direct-boot restore;
  clamped deadlines; critical windows only on families with a measured bound
  (5.4, 5.5).
- **Does not cover.** The measured δ itself; firmware where the direct-boot
  restore is refused (bound becomes the first unlock, and critical windows are
  refused there).

### 13.9 Enrolment

- **Threat.** A forced fallback from remote enrolment to local mode, where the
  first PIN is set without any prior verification; a leaked or replayed
  ticket; a rogue bench enrolment.
- **Mitigation.** `ENROLLING` with a verified baseline and no PIN path (4.3);
  per-device tickets bound to the first device key (4.4); no exported
  enrolment entry point and a root-fingerprint comparison on the bench (4.6);
  first loosening always approved.
- **Does not cover.** A person who holds a wiped device and provisions it with
  a local QR; that is the intended local mode, not an attack on a fleet.

### 13.10 Additional threats

| Threat | Mitigation | Not covered |
| --- | --- | --- |
| Leaked enrolment QR | Single use, per device, key-bound, short expiry, baseline-only until approved | A stranger enrolling one spare device into the review list |
| Network attacker | TLS plus optional SPKI pins; every document signed; wake pokes carry no data | Traffic analysis; blocking sync (devices keep the last policy) |
| Malicious MCP agent | Scoped credentials; no approval capability; prepare/confirm with visible class; server and device enforcement | Abuse of tightening and neutral commands within the agent's scopes |
| Other apps' accessibility services | `permittedAccessibilityServices` with refusal reported (9.3) | Services built into the system image |
| Browser traffic escaping the filter | Evidence-backed browser catalogue, gateway egress denial, canary as tunnel liveness (7.3) | Paths not covered by the evidence for that browser version and firmware |

---

## 14. Phased delivery plan

Small PRs, in dependency order. Each lands with its tests; hardware groups are
added to [`hardware-validation.md`](hardware-validation.md) and evidenced in
[`device-matrix.md`](device-matrix.md). No PR enables `REMOTE` mode on a real
device before PR 14's gate.

| # | PR | Depends on | Tests |
| --- | --- | --- | --- |
| 1 | This design document | — | Review only |
| 2 | `AuditLog` event codes alongside prose (closes known gap 1) | — | Code stability test; health export carries the allowlisted tail |
| 3 | `GET_PROVISIONING_MODE` and `ADMIN_POLICY_COMPLIANCE` activities per the 4.2 contract, receiver fallback, no network yet | — | JVM result tests; manifest test; hardware QR enrolment on Android 12+ and the fallback release |
| 4 | **Shared security contract**: effective-state evaluator specification, classification table, approval statement encoding, time and challenge rules, apply journal, catch-up and rebase, as committed vectors | 1 | Vectors only; reviewed by a second agent before any implementation |
| 5 | `AdminAuthority`, `AuthorizedPolicyWriter`, `ManagementMode` with `ENROLLING`, store setters behind the gate, no PIN outside `LOCAL_PIN` | 4 | `AuthorizedWriterCoverageTest`, `NoPinOutsideLocalModeTest`; existing kiosk and home-filter tests unchanged |
| 6 | Restore obligations: device-protected record, exact/idle alarm, window foreground service, direct-boot receiver, clamp and precondition re-check — applied first to today's maintenance windows | 5 | `RestoreObligationTest`; hardware δ measurement, Doze, reboot and process-kill drills per family |
| 7 | Signed-document verifier generalised from `UpdateEnvelopeVerifier`, `EffectiveState.evaluate`, `classify`, apply journal and `RemotePolicyApplier` writing through the gate (no network) | 4, 5 | Vector tests (6.8); crash-injection tests; projection into every store |
| 8 | `tools/provisioning_payload.py`: dedicated remote options, `dg.remote.*` and `ticket` refused on the generic path | 1 | Python tests (4.8) |
| 9 | Minimal test server (separate repository) implementing enrol, sync with catch-up, report, approval submission against the vectors | 4 | Same vectors; catch-up and rebase |
| 10 | Device key, attestation, `EnrolmentConfig`, enrolment baseline, enrolment state machine against the test server | 3, 5, 7, 9 | State machine resume tests; baseline verified; hardware enrolment against the test server |
| 11 | `RemoteSyncJobService`, trusted time, device challenges, signed reports from the redacted health snapshot | 7, 10 | Fake-server sync tests; time anchoring; challenge lifecycle; report redaction |
| 12 | Approver app (or the static approver page) with its own evaluator and rendering, statement signing, batch approval | 4, 9 | Shared vectors; rendering equals hashed diff; UI test of the `H` presentation |
| 13 | Remote mode console (read-only) and neutral/tightening commands: `reconcile`, `filter_check`, `report_now`, `lock_now`, `reboot`, `end_sessions`, `maintenance_cancel`, `self_update_check` | 11 | Command vectors; parity registry test (partial) |
| 14 | Loosening and hazard commands with device-side approval verification: `pause`, `console_session`, `maintenance_open`, kiosk, management mode, recovery verifier, wipe (two approvals). **Gate:** PRs 6 and 12 merged with hardware evidence, end-to-end test against the test server | 6, 12, 13 | Approval vectors; missing/expired/consumed/foreign approval refused; end-to-end |
| 15 | Self-update window (10.2) | 6, 14 | Hardware: success, failure, process death and reboot mid-install, per family |
| 16 | Install window, quarantine, `quarantine_release` (10.3); needs the explicit security review of blocker 5 | 15 | Diff and relaxation tests; hardware group |
| 17 | `systemUpdates`, `permittedAccessibilityServices`, `permittedInputMethods`, automatic time | 14 | Read-back and refusal tests with a fake gateway; hardware per OEM |
| 18 | VPN client install and sign-in step, gateway statement, evidence catalogue, `browserThroughFilter` | 16 (or 10.4), per-browser hardware evidence | Tests in 7.3; evidence records |
| 19 | Production server hardening: KMS/HSM signing, hash-chained audit export, scoped credentials | 9, 14 | Refusal of unapproved loosening; audit chain verification; scope tests |
| 20 | MCP interface with prepare/confirm, only after end-to-end tests pass | 14, 19 | Every console action has a tool (mirror parity test); no scope can approve |
| 21 | Optional wake channel | 11 | Rate limit; poke carries no data |
| 22 | Optional accessibility content-check pilot (separate opt-in) | 17 | Section 12 tests; README claim updated |

PRs 2–8 need no server and no network; they can merge while the production
identity is still provisional. PR 10 onward must not enrol a real customer
device before the production application ID and signer are fixed
([`production-release.md`](production-release.md)).

---

## 15. Open questions and blockers

### Blockers

1. **Before enabling remote management on any device:** classification by
   effective state, the enrolment baseline with no PIN path, approval
   independent of the server (approver renderer, device challenges), replay
   protection, and crash-safe journaling — PRs 4, 5, 7, 11, 12 with vectors and
   an independent review.
2. **Before enrolling a fleet:** final production application ID and signer;
   stable audit event codes (PR 2); a server with a decided owner, hosting and
   signing-key protection (an owner decision; nothing in this repository may
   name it); QR enrolment proven on Android 12+ hardware, including the
   server-down path ending on a verified baseline.
3. **Before removing ADB by remote policy or opening any remote window:** the
   signed self-update drill and the restore drills (Doze, reboot, process
   kill, install failure, direct boot) passing on every supported firmware
   family, with measured close latency.
4. **Before offering a filtered browser:** VPN client install and sign-in on
   the device, gateway denial of direct egress, and per-browser, per-firmware
   evidence including TWA, Custom Tabs and WebView (7.3).
5. **Install windows conflict with the home filter by design today**
   (`HomeFilterPolicy.permitsRelaxing`). The narrow `INSTALL_WINDOW` exception
   in 10.3 needs an explicit security review before implementation.

### Open questions

1. Approver: native approver app (recommended, 8.4) or a static approver page
   on an independent origin?
2. Should `HAZARD` tightenings (enter kiosk, disable ADB, remove a management
   pin) require approval, as proposed, or apply at once like other
   tightenings?
3. Can Device Guard trigger Play Store updates inside a window, or is a signed
   private app catalogue (10.4) needed — and is redistributing those APKs
   permitted by their licences?
4. Is FRP (`setFactoryResetProtectionPolicy`), which needs a Google account,
   acceptable for the target fleets?
5. Which browsers trust a user-installed CA and honour managed proxy settings
   on current Android releases? Answered only by the evidence records of 7.3.
6. Accessibility pilot: is one on-device tap to enable the service acceptable
   given the zero-touch goal, and how does Android 15+ restricted settings
   treat a provisioning-installed DPC?
7. Wake channel: long-poll foreground service, UnifiedPush, or pull only?
8. Should re-attestation be monthly, and should an untrusted result tighten the
   device automatically or only alert?
9. Google zero-touch enrolment or Samsung Knox Mobile Enrollment for
   reseller-purchased devices — worth supporting later, given they re-enrol
   automatically after a wipe?
10. Recovery verifier delivery on API 26–30: Keystore `PURPOSE_AGREE_KEY`
    (ECDH) exists only from API 31; use RSA-OAEP Keystore keys below that, or
    deliver it only over the pinned TLS channel?
11. Does a Device Owner hold, or can it be granted, the exact-alarm permission
    on API 33+, and what is the measured idle-alarm latency per family (5.4)?
12. Does the chosen VPN client offer a managed sign-in, so that the home filter
    needs no on-device step (7.3)?

---

## Appendix A: Review resolution

An independent review of revision 1 (a different AI model, read-only against
the code) raised four P1, five P2 and one P3 finding. Each was checked
against the code before acting; none was rejected.

| Finding | Verified against | Resolution in revision 2 |
| --- | --- | --- |
| **P1.1** Classification compared raw fields; mode switch, Play compatibility, missing keys and `reconcile` were misclassified | `LockdownPolicyController.applyPackagePolicy` (built-in block, `isAllowlistConfigured`, inverted meaning of the list per mode, exception order); `AllowedAppsStore.setProtectionMode` (non-destructive, per-mode selections); `PlayStoreCompatibility.baseChoices` (floor removed when off); `SystemPolicyControl.DefaultPolicy` (profile-dependent defaults) | Confirmed. New effective-state evaluator (8.1) with one rule per component and transition (8.2), including identity replacement, browser and VPN signer changes, canary age, browser restrictions, recovery-channel removal, OTA narrowing and `AUTOMATIC`; missing/`null`/unknown table (7.1); closed schema (6.2); `reconcile` carries no payload and re-applies only the journaled state (9.2); browser-exemption disable is `T` in 9.2 |
| **P1.2** Enrolment and recovery bypass the approval boundary | `MainActivity.unlockWith` (`NOT_CONFIGURED` → `PIN_SETUP` with no prior verification) and `savePin`; `AdminPinStore.rotateRecoveryCode` (device-generated code) | Confirmed. Separate `ENROLLING` mode with a compiled, pinned, verified baseline and no PIN path; no route from remote enrolment to `LOCAL_PIN` (4.3); first policy classified against the baseline and always approved for loosening (8.5); recovery code generated on the approver device, server sees ciphertext only, use limited to a scoped 30-minute `RecoverySession` (5.6) |
| **P1.3** Replay through forged server time; approval does not prove what was shown; apply-then-record gap | Revision 1 §§6.4, 8.2 (time from the policy-signing key; server-rendered approval page); `UpdateStateStore` floor pattern | Confirmed. Device-issued, monotonic, single-use challenges for approval freshness (6.4); binary approval statement binding device, challenge, applied base, payload digest and effective-diff digest (6.5); approver renders from signed bytes with its own evaluator (8.4); journal with floors and challenge consumption committed before any Android call, crash resume and replay refusal tests (6.6) |
| **P1.4** Monotonic expiry is measured, but nothing re-imposes restrictions on time; no direct-boot path; `lock_now` unbounded | `MaintenanceGuard` (expiry job with override deadline plus 15-minute sweep, process-bound); manifest `PolicyRefreshReceiver` `directBootAware="false"` | Confirmed. Restore obligations in device-protected storage, clamped deadlines, precondition re-check at open, idle-capable alarm, window foreground service, direct-boot receiver (5.4, 5.5); critical windows only where the close bound is measured; `lock_now` validity 15 minutes, executed once, no latency promise (9.2, 9.3) |
| **P2.1** QR and ADB contract details | `tools/provisioning_payload.py` (`FORBIDDEN_ADMIN_EXTRA_FRAGMENTS` has no `ticket`, so the generic path accepts `dg.remote.ticket`); `LockdownAdminReceiver` (no admin-extras handling) | Confirmed. Exported activities with `DEFAULT` and `BIND_DEVICE_ADMIN`, fully managed only when allowed, bundle re-validated in the compliance activity, receiver fallback with its own hardware test (4.2); generic path refuses `dg.remote.*` and `ticket` (4.1); `am start` path removed, bench code typed into a non-exported screen with root-fingerprint comparison (4.6); per-device ticket bound to the first device key, idempotent retry (4.4) |
| **P2.2** The update window is not update-only | `HomeFilterPolicy.REQUIRED_CONTROLS` and `HomeFilterController.restrictionsMatch`; `MaintenanceCapability.APP_STORE_ACCESS`; `SecureUpdateManager` asynchronous `session.commit` | Confirmed. Split into a server-independent self-update window, an explicitly "permits new installs" install window, and a later signed catalogue as the only update-only path (10.1–10.4); durable snapshot with `FLAG_INSTALLED` filtering, version and identity checks, quarantine in both modes during the window, suspend-refusal fallback to hide, close on the installer result |
| **P2.3** Filter proof is not browser proof | `HomeFilterProbe` (request from Device Guard's process); [`provisioning.md`](provisioning.md#home-filter) (manual VPN install and sign-in) | Confirmed. Four prerequisites: VPN install and sign-in step, gateway egress denial statement, per-browser and per-firmware evidence including TWA, Custom Tabs, WebView and tunnel drop, binding to configuration, signer and version (7.3) |
| **P2.4** API success conditions missing | Revision 1 §§9, 10.3, 12 | Accepted (platform documentation, marked verify where not yet checked). Return-value handling for permitted accessibility services and input methods, OTA minute range, midnight crossing, freeze spacing and history, `wipeDevice` on API 34+, wipe evidence states, reboot refusal (9.3, 10.5) |
| **P2.5** PR order has dependency inversions; latest-only sync deadlocks the chain | Revision 1 §14 and §5.5 | Confirmed. Shared contract PR first, authority gate before any writer, restore hardening before any remote loosening, test server before the client, approver before loosening commands, MCP last (14); catch-up chain or rebase in sync (5.7) |
| **P3** Command contract incomplete | Revision 1 §§9, 11 | Accepted. Status reads separated from `filter_check`; every mutation is prepare/confirm; scoped agent credentials; two approvals by two administrators' keys for wipe; per-action class, approval scope, PR and success evidence, including `reboot`, `wipe` and `quarantine_release` (9, 11.2) |
