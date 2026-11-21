# Remote management design

**Status: design proposal. Nothing in this document is implemented yet unless a
section says "exists today".** It describes how Device Guard can be managed by a
family or organisation administrator across many devices, with no manual
on-device setup and no on-device administrator PIN, in the way a supervised iOS
device is managed by an MDM server.

Remote management is an **optional mode**. The local, PIN-protected mode that
ships today stays the default and keeps working without any server, so the
README statement that the project has "no required management cloud" remains
true.

Every Android API named here links to its Android developer reference. Links
marked **(verify)** are written from memory and must be checked against the
current documentation before the implementing PR is merged.

## Contents

1. [Goals and non-goals](#1-goals-and-non-goals)
2. [What exists today](#2-what-exists-today)
3. [Architecture overview](#3-architecture-overview)
4. [Enrolment](#4-enrolment)
5. [Managed-remotely mode](#5-managed-remotely-mode)
6. [Signed documents](#6-signed-documents)
7. [Policy model](#7-policy-model)
8. [Tightening, loosening and human approval](#8-tightening-loosening-and-human-approval)
9. [Full management parity](#9-full-management-parity)
10. [Update window, self-update and system OTA](#10-update-window-self-update-and-system-ota)
11. [Management server and MCP interface](#11-management-server-and-mcp-interface)
12. [Optional pilot: on-device content check through Accessibility](#12-optional-pilot-on-device-content-check-through-accessibility)
13. [Threat model](#13-threat-model)
14. [Phased delivery plan](#14-phased-delivery-plan)
15. [Open questions and blockers](#15-open-questions-and-blockers)

---

## 1. Goals and non-goals

### Goals

- **Zero-touch-style enrolment.** A wiped device is enrolled from the setup
  wizard by scanning one QR code. It downloads Device Guard, becomes Device
  Owner, registers with the management server and applies its policy without
  anyone opening the Device Guard console.
- **No on-device administrator PIN in remote mode.** All administration arrives
  as signed documents. The on-device console becomes a read-only status screen.
- **Full management parity.** Every action available in the on-device console
  is also available as a signed remote command and as an MCP tool, so an
  administrator never needs the device in hand (section 9).
- **The server cannot loosen a device on its own.** Tightening applies at once.
  Loosening needs a separate approval object produced by a human approval step
  and verified by the server **and** by the device.
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

---

## 2. What exists today

Remote management is built on parts that already exist and are tested. This
section is the inventory the rest of the design refers to.

| Area | Exists today | Where |
| --- | --- | --- |
| Device Owner check before any policy | `isDeviceOwnerApp` gate in every apply, pause and update path | `policy/LockdownPolicyController.java` (`apply`, `pause`), `updates/SecureUpdateManager.kt` (`performCheck`) |
| Verified policy apply and pause | Every package visibility change and user restriction is read back; partial results are failures | `LockdownPolicyController.apply`, `applyPackagePolicy`, `policy/SystemPolicyEnforcer.java` |
| Single policy thread | All `DevicePolicyManager` writers run on one FIFO executor | `policy/PolicyReconciliationCoordinator.java` (`runOnPolicyThread`, `callOnPolicyThread`) |
| Lifecycle reconciliation | Boot, own-package replacement, `PACKAGE_ADDED` via `DeviceAdminService`, periodic sweep | `receivers/PolicyRefreshReceiver.java`, `admin/LockdownDeviceAdminService.java`, [`package-reconciliation.md`](package-reconciliation.md) |
| App policy | Allowlist (`ALLOW_SELECTED`) or blocklist (`BLOCK_SELECTED`); built-in store/browser catalogue; reviewed system-app selection with risk acceptance | `policy/AllowedAppsStore.java`, `policy/LockdownPackages.java`, `policy/SystemAppClassifier.java`, `policy/SystemAppSelection.java` |
| Browser blocking | Browsers in `ALWAYS_BLOCKED` and `KNOWN_BROWSER_AND_SOCIAL` are hidden unconditionally (the allowlist branch never unhides them); `http`/`https` `VIEW` intents are routed to `BlockedBrowserActivity` through `addPersistentPreferredActivity`; a browser-backed WebView provider in `ALWAYS_BLOCKED` is suspended unless it is the home-filter VPN | `LockdownPolicyController.applyPackagePolicy`, `configureBlockedBrowser`, `suspendBrowserBackedWebViewIfNeeded` |
| System controls | 16 named controls mapped to `UserManager.DISALLOW_*` restrictions, each `CRITICAL` or `ADVISORY` with a default | `policy/SystemPolicyControl.java`, `policy/SystemPolicyStore.java` (`baseChoices`) |
| Google Play compatibility | Opt-in that keeps `com.android.vending` available only while the install lock is read back as on | `policy/PlayStoreCompatibility.java`, [`play-store-compatibility.md`](play-store-compatibility.md) |
| Home filter network | Always-on VPN with lockdown, VPN managed configuration, recommended global PAC proxy, opportunistic Private DNS, optional user CA, HTTPS canary check, and a set of required controls maintenance cannot relax | `policy/HomeFilterPolicy.java` (`REQUIRED_CONTROLS`, `permitsRelaxing`), `policy/HomeFilterController.java`, `policy/HomeFilterProbe.java`, [`provisioning.md`](provisioning.md#home-filter) |
| Management identity pins | Signing-certificate pins decide which management package (default: the VPN client) keeps its exemption | `policy/ManagementIdentityInspector.java`, `LockdownPackages.MANAGEMENT_DEFAULTS` |
| Kiosk | Single-app and single-site Lock Task with an authenticated state machine; `BOOT_RESTORE` is the only unauthenticated path and only into `ACTIVE` | `kiosk/KioskStateMachine.java`, `kiosk/KioskController.java`, [`kiosk-mode.md`](kiosk-mode.md) |
| Timed maintenance | Named capabilities, at most four hours, monotonic-clock expiry, process-bound, verified restore of the base policy, audit | `maintenance/` (`MaintenanceCapability`, `MaintenanceStateMachine.MAX_DURATION_MILLIS`, `MaintenanceStore.belongsToCurrentProcess`, `MaintenanceGuard`) |
| Local administrator authority | 6–12 digit PIN (PBKDF2-SHA256 210 000 iterations, then HMAC with an Android Keystore key), progressive lockout bound to `Settings.Global.BOOT_COUNT`, 12-digit one-time recovery code, three-minute in-memory session | `security/AdminPinStore.java`, `security/PinLockoutPolicy.java`, `security/AdminSession.java` |
| Signed self-update | ECDSA P-256 (`SHA256withECDSA`) envelope `{payload, signature}` in base64url, schema version, package binding, 91-day maximum validity, 5-minute clock-skew allowance, persistent version floor, HTTPS-only redirects, APK hash/size/signer/lineage checks, `PackageInstaller` session with `INSTALL_REASON_POLICY` | `updates/UpdateEnvelopeVerifier.kt`, `updates/SecureUpdateManager.kt`, `updates/UpdateStateStore.kt` (`highestAuthorizedVersion`), `updates/UpdateScheduler.kt`, [`secure-updates.md`](secure-updates.md) |
| Provisioning payload | Verified QR payload builder: full component name, signer checksum from the APK, refuses credential-like admin-extras keys (including `token`), 1800-byte limit | `tools/provisioning_payload.py`, [`provisioning.md`](provisioning.md) |
| Health report | Redacted, allowlisted snapshot of policy, controls, kiosk, maintenance, updates, management identity and platform | `health/DeviceHealthSnapshot.java`, `health/DeviceHealthRedaction.java` |
| Audit log | 50 entries of localized prose with a timestamp, no machine-readable event code | `policy/AuditLog.java` |

### Gaps this design depends on

These are existing, already documented gaps. Remote management cannot ship
before the first two are closed.

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
   `HomeFilterController` ("derives the administrator session from
   `AdminSession` itself"). `LockdownPolicyController.apply`/`pause` check
   nothing and rely on their callers. A remote command path must not fake a UI
   session (section 5.3).
4. **Accessibility services are not restricted.** No code calls
   `setPermittedAccessibilityServices` or `setPermittedInputMethods`;
   [`kiosk-mode.md`](kiosk-mode.md) lists externally installed accessibility
   services as out of scope. Section 7 adds this as a tightening field.
5. **No hardware key attestation, no `SystemUpdatePolicy`, no automatic-time
   enforcement.** Searches of the source find none of these APIs.

---

## 3. Architecture overview

```text
        administrator phone                    agent (MCP client)
   (approval key: passkey / approver app)            |
                 |  approval objects                 | prepare / confirm
                 v                                   v
   +-------------------------------------------------------------+
   |                 management server (minimal)                 |
   |  devices | policies (immutable versions) | commands |       |
   |  approvals | audit log (hash-chained)                       |
   |  online policy-signing key (KMS/HSM)                        |
   |  enforces: loosening requires a valid approval object       |
   +-------------------------------------------------------------+
                 ^  HTTPS pull (device-signed request)
                 |  signed policy, commands, key set, time
                 |  optional content-free wake "poke"
                 v
   +-------------------------------------------------------------+
   |  Device Guard (Device Owner)                                |
   |  RemoteSync job -> SignedDocumentVerifier -> classify()     |
   |   -> RemotePolicyApplier -> existing stores                 |
   |   -> LockdownPolicyController.apply on the policy thread    |
   |   -> signed report (redacted health snapshot + read-back)   |
   +-------------------------------------------------------------+
```

Three keys, three roles:

| Key | Holder | Signs | Compromise means |
| --- | --- | --- | --- |
| **Fleet root key** (P-256) | Offline, in the administrator's vault | Key-set documents only (which policy and approval keys are valid, their versions) | Full fleet control; mitigated only by keeping it offline. Its SHA-256 is pinned at enrolment. |
| **Policy-signing key** (P-256) | Management server, ideally in a KMS/HSM | Policies, commands, time documents | Attacker can tighten (denial of service) and issue neutral commands; cannot loosen |
| **Approval key(s)** (P-256 / WebAuthn ES256) | Each human administrator's phone | Approval objects over the exact bytes of a loosening document | Attacker can approve loosening the server has also signed |

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

### 4.1 QR provisioning from the setup wizard

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
| `dg.remote.ticket` | 32 base64url characters (24 random bytes) | One-time enrolment ticket (see 4.3) |
| `dg.remote.fleet` | short fleet label | Display only; never used for authorization |

The bundle stays well under the tool's 1800-byte limit (about 250 bytes).

**Ticket versus the existing refusal.** `parse_admin_extras` deliberately
refuses any key containing `token`, `secret`, `pin`, and similar, because a QR
code is printed and photographed. The enrolment ticket is a credential, so it
must not travel through the generic `--admin-extra` option. The tool gains a
dedicated `--enrolment-ticket-env NAME` option, mirroring
`--wifi-password-env`: read from the environment only, never echoed, written
with owner-only file mode, summary flag `"enrolmentTicketEmbedded": true`, and
the same warning that the payload and the QR image are credentials. The
generic refusal stays unchanged. The ticket is designed so that a leaked QR is
low value (4.3).

### 4.2 Device-side flow (new)

The two activities the provisioning runbook flags as missing are added, with
`android:permission="android.permission.BIND_DEVICE_ADMIN"` so only the system
can start them.

1. **`ProvisioningModeActivity`** handles
   [`ACTION_GET_PROVISIONING_MODE`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#ACTION_GET_PROVISIONING_MODE).
   It reads `EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE` from the intent, validates
   it with a pure-Java `EnrolmentConfig.parse` (no network), and returns
   `RESULT_OK` with
   [`EXTRA_PROVISIONING_MODE`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#EXTRA_PROVISIONING_MODE)
   `= PROVISIONING_MODE_FULLY_MANAGED_DEVICE`. A malformed bundle still returns
   fully managed mode (so the device becomes a locally managed Device Guard
   device) but records `enrolment-config-invalid`; it never falls back to a
   work profile.
2. **`PolicyComplianceActivity`** handles
   [`ACTION_ADMIN_POLICY_COMPLIANCE`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#ACTION_ADMIN_POLICY_COMPLIANCE).
   The setup wizard still has network here. The activity:
   - persists the validated `EnrolmentConfig` in credential-protected storage;
   - generates the **device key** (4.4) with an attestation challenge obtained
     from the server;
   - calls `POST /v1/enrol` with the ticket, the attestation chain and the
     platform facts;
   - receives and verifies the key set (signed by the pinned root) and the
     first policy, applies it through `RemotePolicyApplier`
     (section 5) and only then returns `RESULT_OK`;
   - on failure shows a localized retry screen with the stable failure code;
     after three failures it returns `RESULT_OK` anyway and schedules
     enrolment retries with `JobScheduler`. The device is then a Device Owner
     with the built-in defaults (`DefaultPolicy.ENFORCED_SINCE_PILOT`
     controls) and is reported as `enrolment-pending` once it reaches the
     server. A device is never left unmanaged because the server was down.
3. `LockdownAdminReceiver.onProfileProvisioningComplete` keeps setting the
   profile name and additionally reads the admin extras from the intent as a
   fallback on releases that do not send the two activity intents.

References: [provisioning a fully managed device](https://developer.android.com/work/dpc/provisioning),
[Android 12 provisioning changes (verify)](https://developer.android.com/work/versions/android-12).

### 4.3 Enrolment ticket

- 24 random bytes, single use, created per enrolment batch by the server.
- Bound to a fleet and an expiry (default 72 hours, maximum 7 days).
- Optionally bound to an expected serial number. On API 28+ the device can
  include ID attestation (`ID_TYPE_SERIAL`) through
  [`DevicePolicyManager.generateKeyPair`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#generateKeyPair(android.content.ComponentName,%20java.lang.String,%20android.security.keystore.KeyGenParameterSpec,%20int))
  with [`ID_TYPE_SERIAL`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#ID_TYPE_SERIAL),
  so the binding is checked from hardware evidence, not from a claimed string.
- The server stores only `SHA-256(ticket)`.
- A device enrolled with an unbound ticket lands in state **`pending-approval`**
  and receives a tightening-only default policy until an administrator
  approves it (an approval object, section 8). A device enrolled with a
  serial-bound ticket whose attestation matches is accepted at once.

A leaked QR therefore lets a stranger enrol at most one device, into a fleet
whose administrators see it as pending, with no loosening ability.

### 4.4 Device identity and attestation

- At enrolment Device Guard generates a non-exportable P-256 signing key in
  Android Keystore with
  [`setAttestationChallenge`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setAttestationChallenge(byte[]))
  set to a server nonce, and
  [`setIsStrongBoxBacked(true)`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setIsStrongBoxBacked(boolean))
  when StrongBox is present, falling back to TEE.
- `deviceId` = base64url SHA-256 of that key's SPKI. Every policy and command is
  bound to it.
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
  **untrusted**. Untrusted devices still receive tightening policy but never a
  loosening approval, and the administrator is alerted.

### 4.5 ADB path for already-used devices

`dpm set-device-owner` only works with no accounts and no other users (see
[`provisioning.md`](provisioning.md), Runbook B). For a used device:

1. Remove every account (Google, OEM, messaging) in Settings → Accounts and
   every secondary user or profile. Removing the Google account first also
   avoids factory reset protection surprises.
2. Install the **release** APK (`adb install`, without `-t`; a test-only build
   is refused for remote mode, section 13.1) and run
   `adb shell dpm set-device-owner <full component>`.
3. ADB cannot pass admin extras. Device Guard therefore offers an
   **Enrol with management server** screen that is reachable only while the
   device is Device Owner, not enrolled, and either has no PIN yet or has a live
   PIN session. The operator types the server URL and ticket, or launches it
   from the bench:

   ```bash
   adb shell am start -n <package>/<enrol activity> \
     --es dg.remote.server https://manage.example.org \
     --es dg.remote.root <root-key-digest> \
     --es dg.remote.ticket "$TICKET"
   ```

   Because an exported activity is reachable by any installed app, the screen
   never acts on extras silently: it shows the server host, the fleet label and
   the root-key fingerprint and requires an on-screen confirmation. On API 34+
   it additionally refuses a launch whose
   [`Activity.getLaunchedFromUid` (verify)](https://developer.android.com/reference/android/app/Activity#getLaunchedFromUid())
   is neither the shell UID nor its own. The ticket on the command line is
   visible in the bench's shell history; use an environment variable and a
   short-lived ticket.
4. The rest of the flow is identical to 4.2 from the enrolment request on.

The same screen is how a device already running in local PIN mode is moved to
remote mode without a wipe: an administrator with a live PIN session enrols it,
and the first remote policy replaces the local choices (section 5.4).

### 4.6 Enrolment failure modes

| Failure | Behaviour |
| --- | --- |
| Admin extras missing or malformed | Fully managed Device Owner in local mode; `enrolment-config-invalid` in the health report |
| Server unreachable during setup | Retry screen, then local defaults with `enrolment-pending`; `JobScheduler` retries with exponential backoff (same pattern as `UpdateScheduler`) |
| Ticket expired, reused or unknown | Server returns a stable code; device stays local, shows the code, never retries the same ticket automatically |
| Key set not signed by the pinned root | Refused (`key-set-root-mismatch`); never retried with another root |
| TLS pin mismatch | Refused (`tls-pin-mismatch`); no fallback to unpinned TLS |
| Attestation unavailable | Enrolment proceeds; server marks the device untrusted (4.4) |
| Process killed mid-enrolment | Enrolment state machine is persisted; the next boot or job resumes from the last completed step; the ticket is consumed only when the server has stored the device key |

### 4.7 Tests

- `tools/test_provisioning_payload.py`: ticket only from the environment,
  never echoed, owner-only mode, summary flag, size limit with all keys,
  root-digest format, URL refusal cases; the generic `token` refusal still
  fires for `--admin-extra`.
- JVM: `EnrolmentConfigTest` (every malformed key, wrong schema, bad URL, bad
  digest, oversized values), `EnrolmentStateMachineTest` (resume after each
  step, ticket consumption, retry backoff).
- Hardware, new group in [`hardware-validation.md`](hardware-validation.md):
  QR enrolment on Android 12+ through both activities; server-down enrolment;
  ADB enrolment of a previously used device; attestation fields recorded.

---

## 5. Managed-remotely mode

### 5.1 Management modes

A new persisted `ManagementMode`:

| Mode | Authority | On-device console |
| --- | --- | --- |
| `LOCAL_PIN` (default, today's behaviour) | Administrator PIN session | Full console, unchanged |
| `REMOTE` | Signed policy and commands only | Read-only status: protection state, "Managed by <fleet>", last sync, last verified apply, pending window. No PIN screen. |

There is deliberately no mixed mode in which local PIN edits and remote desired
state both write the same stores; that produces the "state neither side
believes" failure the single policy thread exists to prevent. Moving from
`REMOTE` back to `LOCAL_PIN` is itself a loosening command (section 9).

### 5.2 Desired state

In `REMOTE` mode the signed policy is the source of truth. The existing stores
(`AllowedAppsStore`, `SystemPolicyStore`, `PlayStoreCompatibilityStore`,
`HomeFilterStore`, `KioskConfigStore`, management pins) become projections of
it, written only by a new `RemotePolicyApplier` on the policy thread:

```text
verified policy -> RemotePolicyApplier.project(policy) -> stores
               -> LockdownPolicyController.apply / KioskController / HomeFilterController
               -> read-back -> signed report { policyVersion, verified, errors, outcomes }
```

The applier writes the stores and then runs the same reconciliation the console
runs. Nothing about verification changes: a policy is reported `applied` only
when that pass returned `verified == true`. A pass that fails keeps the stored
desired state and is retried by the normal lifecycle triggers; the report
carries the stable error codes from `PolicyResult.errors`.

### 5.3 Authorization without a UI session

`AdminSession.unlock()` must **not** be called by the remote path: it would also
unlock every console screen for three minutes. Instead a small authority type
is introduced:

```java
public sealed interface AdminAuthority permits LocalSession, VerifiedCommand {}
```

- `LocalSession` is obtainable only while `AdminSession.isUnlocked()`.
- `VerifiedCommand` has a package-private constructor called only by
  `SignedDocumentVerifier` after signature, binding, freshness and (for
  loosening) approval checks. It carries the command scope and a monotonic
  deadline.
- `KioskController` and `HomeFilterController` take an `AdminAuthority`
  instead of reading `AdminSession` directly. Their existing property — "no
  caller can assert that it is authenticated" — is preserved, because neither
  variant can be constructed from a boolean.
- In `REMOTE` mode `LocalSession` is unobtainable except through a remote
  `console_session` grant (below).

### 5.4 Unlock, pause and break-glass

- **Remote console session** (`console_session`, loosening): opens the local
  console for at most 30 minutes, measured on `SystemClock.elapsedRealtime`
  from receipt, with a visible banner. Ends early on `end_sessions`, reboot or
  process death (same fail-closed boundary as maintenance).
- **Pause** (`pause`, loosening): unlike the local console's indefinite pause,
  a remote pause always carries a duration (maximum 4 hours, the maintenance
  maximum) and re-applies the policy at expiry through `MaintenanceGuard`-style
  arming.
- **Offline break-glass code.** A device without network (for example after a
  broken home-filter configuration) must still be recoverable without a wipe.
  The existing recovery-code mechanism is reused: the server generates a
  12-digit code, keeps it only in the administrator's vault, and sends the
  device `salt` and `PBKDF2-SHA256(code, salt, 210000)` inside a
  `set_recovery_verifier` command encrypted to the device. The device applies
  its own Keystore HMAC exactly as `AdminPinStore.createVerifier` does, so the
  stored verifier has today's format and today's `PinLockoutPolicy` applies.
  Using the code opens a local session and is reported on the next sync. The
  code is single use; the server rotates it after any use.
- **Local PIN mode stays available** per device: `set_management_mode LOCAL_PIN`
  plus a provisioned PIN verifier is a loosening command.

### 5.5 Sync transport

- **Pull.** A `RemoteSyncJobService` (new, `BIND_JOB_SERVICE`, like
  `UpdateCheckJobService`) runs every 15 minutes, the
  [`JobInfo` minimum period](https://developer.android.com/reference/android/app/job/JobInfo.Builder#setPeriodic(long,%20long)),
  plus on boot, on own-package replacement, after every applied command and on
  network change. It is persisted and needs `NETWORK_TYPE_ANY`.
- **Request.** `POST /v1/sync` with body
  `{deviceId, nonce, appliedPolicyVersion, lastCommandSequence, reportSha256}`
  and a header signature by the device key over method, path, timestamp and
  body digest. TLS uses the platform trust store plus the optional SPKI pins
  from enrolment, checked in a custom `X509TrustManager` wrapper (network
  security config pins are static and cannot come from the QR). Redirects are
  refused.
- **Response.** A signed `time` document echoing the nonce, the current key
  set if newer, the latest policy if newer than the applied one, ordered
  commands after `lastCommandSequence`, and `nextPullSeconds`.
- **Wake without FCM** (optional, off by default). Two options, both carrying
  only a content-free "poke" that can do nothing but trigger a pull, rate
  limited to one pull per minute:
  1. A foreground service holding one long-poll HTTPS request to
     `/v1/wake`. A Device Owner is exempt from the background
     foreground-service start restrictions
     ([exemptions](https://developer.android.com/develop/background-work/services/fgs/restrictions-bg-start#background-start-restriction-exemptions)).
     Costs a permanent low-importance notification and radio wakeups; Doze
     still defers network
     ([Doze and App Standby](https://developer.android.com/training/monitoring-device-state/doze-standby)).
  2. A self-hosted [UnifiedPush](https://unifiedpush.org/) distributor. Adds a
     second app to the trusted set and to the management pins.

  Without a wake channel, the worst-case latency of a command is the pull
  period plus Doze deferral. The design treats that as acceptable for every
  command except `lock_now`, and documents it in the MCP tool descriptions.

### 5.6 Tests

- JVM: `AdminAuthorityTest` (no public path constructs `VerifiedCommand`;
  `KioskController`/`HomeFilterController` reject a missing authority);
  `RemotePolicyApplierTest` (projection of every field into the stores, then a
  fake gateway apply; a failed verification keeps desired state and reports
  codes); `ConsoleSessionTest` (monotonic expiry, reboot and process-death
  closure, reusing the `MaintenanceClock` fake); recovery verifier
  compatibility test (a server-computed PBKDF2 value plus local HMAC equals
  `AdminPinStore` output for the same code and salt).
- Locale parity: the new read-only strings in English and Hebrew, enforced by
  the existing parity tests.
- Hardware: sync after Doze, after reboot, with the home filter on, with no
  network for 24 hours.

---

## 6. Signed documents

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
      "keyId": "<base64url SHA-256 of approver SPKI>",
      "authenticatorData": "<base64url>",
      "clientDataJSON": "<base64url>",
      "signature": "<base64url DER ES256>"
    }
  ]
}
```

The signature covers the exact payload bytes, so no JSON canonicalisation is
needed (the same reason `UpdateEnvelopeVerifier` signs the base64url payload).
Limits follow the update verifier: 64 KiB envelope, `MAX_CLOCK_SKEW_SECONDS`
of 300.

### 6.2 Common payload header

| Field | Rule |
| --- | --- |
| `schemaVersion` | Integer; unknown versions refused |
| `type` | `keyset`, `policy`, `command`, `time`, `approval-request`; a document is only accepted where its type is expected |
| `fleetId` | Must equal the enrolled fleet |
| `deviceId` | Must equal this device's key digest (`keyset` may use `*`) |
| `issuedAt`, `expiresAt` | Epoch seconds; `issuedAt` not after trusted-now plus skew; `expiresAt` after trusted-now; per-type maximum validity |
| `keySetVersion` | The key set the signer belongs to; must be at least the device's stored key-set floor |

### 6.3 Per-type rules

| Type | Signer | Monotonic field | Maximum validity | Notes |
| --- | --- | --- | --- | --- |
| `keyset` | Fleet root | `keySetVersion` strictly increasing | 400 days | Lists policy-signing keys and approval keys with `notAfter`; can rotate the root once by naming its successor |
| `policy` | Policy-signing key | `policyVersion` strictly increasing; `previousPolicySha256` must equal the applied policy's hash | 30 days to **install** | An installed policy stays enforced after its `expiresAt`; expiry only prevents installing a stale document. The report flags `policy-stale` after expiry. |
| `command` | Policy-signing key | `sequence` strictly increasing per device | 24 hours to start; duration-bearing commands carry their own maximum | `basePolicyVersion` must equal the applied policy, so a command cannot be replayed against a different baseline |
| `time` | Policy-signing key | — | 5 minutes | Echoes the request nonce; anchors trusted time (6.4) |

The device stores the floors (`keySetVersion`, `policyVersion`, `sequence`,
`policySha256`) with `commit()` in credential-protected storage, exactly as
`UpdateStateStore.recordAuthorizedVersion` does, and raises a floor only after
the document has been fully verified and accepted.

### 6.4 Trusted time

- Durations (sessions, pauses, windows) use `SystemClock.elapsedRealtime` from
  receipt, as maintenance already does
  ([`SystemClock`](https://developer.android.com/reference/android/os/SystemClock)).
- Validity checks use a **trusted now** = the last verified `time` document's
  `serverTime` plus elapsed-realtime since it arrived, re-anchored on each sync.
  After a reboot (detected by `Settings.Global.BOOT_COUNT`, as `AdminPinStore`
  does) the anchor is lost; until the next `time` document only tightening
  documents and already-running deadlines are honoured.
- The policy enforces `DATE_AND_TIME` (`DISALLOW_CONFIG_DATE_TIME`, API 28+)
  — already `ENFORCED_SINCE_PILOT` — and, new, automatic time through
  [`setAutoTimeEnabled`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#setAutoTimeEnabled(android.content.ComponentName,%20boolean))
  on API 30+.

### 6.5 Failure modes

Every refusal produces a stable code (for example `doc-signature-invalid`,
`doc-device-mismatch`, `doc-version-rollback`, `doc-chain-mismatch`,
`doc-expired`, `doc-approval-missing`, `doc-approval-invalid`,
`doc-type-unexpected`, `doc-time-unanchored`), changes nothing on the device,
and is included in the next report. A refused document never lowers a floor.

### 6.6 Tests

A shared, committed **test-vector set** (JSON envelopes with the public test
keys and expected verdicts) is consumed by both the Kotlin verifier tests and
the server's tests, so the two implementations cannot drift. Vectors cover:
valid; wrong key; key not in key set; key set rollback; wrong device; wrong
fleet; wrong type; expired; issued in the future; policy version replay and
downgrade; broken `previousPolicySha256` chain; command sequence replay;
command against another `basePolicyVersion`; loosening without approval;
approval over different bytes; approval expired; approval by unknown key;
WebAuthn flag `UV` missing; oversized; malformed base64url.

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

  "browserThroughFilter": { "enabled": false, "package": null },

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

Field semantics and their existing implementation:

| Field | Maps to (exists today) | New behaviour |
| --- | --- | --- |
| `protection.state` `ON`/`PAUSED` | `LockdownPolicyController.apply` / `pause` | `PAUSED` only through a time-limited command, never as a resting policy value in `REMOTE` mode |
| `apps.mode`, `apps.allowed` | `AllowedAppsStore.setProtectionMode`, `setAllowedPackages` | — |
| `apps.systemSelection` | `AllowedAppsStore.setAdminSelectedSystemPackages`, `recordSystemRiskAcceptance`, revalidated by `revalidatedSystemSelection` | The identity (signer, version) in the policy is the risk acceptance; a mismatch on device is not applied and is reported |
| `apps.playCompatibility` | `PlayStoreCompatibilityStore.setEnabled` | — |
| `systemControls.<storageKey>` | `SystemPolicyStore.setRequested` for each `SystemPolicyControl.storageKey()` | Missing keys mean "built-in default" (`DefaultPolicy`) |
| `homeFilter` | `HomeFilterPolicy.Config`, `Routing`, `Canary`; `HomeFilterController.enable`/`disable`/`installCa`/`removeCa` | Validated by the same record constructors before anything is written |
| `managementPins` | `AllowedAppsStore.setManagementCertificatePins` via `ManagementIdentityInspector` | — |
| `kiosk` | `KioskConfig`, `KioskConfigValidator`, `KioskController` transitions | `CONFIGURE`+`ENTER` executed with a `VerifiedCommand` authority |
| `browserThroughFilter` | **New** (7.1) | |
| `permittedAccessibilityServices`, `permittedInputMethods` | **New**: [`setPermittedAccessibilityServices`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#setPermittedAccessibilityServices(android.content.ComponentName,%20java.util.List%3Cjava.lang.String%3E)), [`setPermittedInputMethods`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#setPermittedInputMethods(android.content.ComponentName,%20java.util.List%3Cjava.lang.String%3E)); read back with the matching getters | Empty list = only system services; `null` = no restriction (today's behaviour) |
| `systemUpdates` | **New** (10.3) | |
| `locale` | `AppLocales.apply` | — |

### 7.1 Per-device "allow browser X through the filter"

**Today:** every browser in `ALWAYS_BLOCKED` and `KNOWN_BROWSER_AND_SOCIAL` is
hidden on every pass — `shouldBlock` starts `true` for them and the allowlist
branch only runs when `shouldBlock` is `false`, so even an allowlisted browser
stays hidden. All `http`/`https` links resolve to `BlockedBrowserActivity`.

**New field** `browserThroughFilter { enabled, package }`, default
`{ false, null }`:

- `package` must be a member of a reviewed `FILTERABLE_BROWSERS` catalogue
  (initially from `KNOWN_BROWSER_AND_SOCIAL`'s browser half and
  `com.android.chrome`), installed, and — new check — signed by a certificate
  pinned in the policy (same mechanism as `managementPins`). An unknown package
  is refused with `browser-not-filterable`.
- The browser is unhidden **only while the home filter is verified active**:
  Android settings confirmed **and** the canary passing within the last
  `canaryMaxAgeMinutes` (default 60). If either lapses, the next pass hides it
  again (fail closed) and reports `browser-filter-unverified`. The current
  `HomeFilterController` already distinguishes "Android settings confirmed"
  from "home filter active"; this field consumes the stricter one.
- Link routing: while exempt, the persistent preferred activity for
  `http`/`https` points at the chosen browser instead of
  `BlockedBrowserActivity` (`addPersistentPreferredActivity` with the browser's
  resolved `VIEW` activity), and is read back with the existing
  `eventuallyResolvesTo` probe. When the exemption ends,
  `configureBlockedBrowser` restores today's routing.
- If the chosen browser is also the WebView provider,
  `suspendBrowserBackedWebViewIfNeeded` must not suspend it while exempt.
- Where the browser supports Android managed configurations, the policy may
  carry browser restrictions applied with
  [`setApplicationRestrictions`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#setApplicationRestrictions(android.content.ComponentName,%20java.lang.String,%20android.os.Bundle))
  (for Chrome: proxy mode, incognito availability, DNS-over-HTTPS mode, safe
  search) — [Chrome enterprise policy list (verify which apply on Android)](https://chromeenterprise.google/policies/).
  Read back with `getApplicationRestrictions`, as the VPN configuration is.
- Boundary, stated in the console and the report: the filter sees only traffic
  that goes through the always-on VPN to the family gateway. Browsers that use
  their own DNS-over-HTTPS, QUIC, or ignore the recommended PAC proxy must be
  constrained at the gateway (deny direct egress), as
  [`provisioning.md`](provisioning.md#home-filter) already requires. Whether a
  given browser trusts the user CA for TLS inspection is browser-specific and
  must be proven per browser on hardware.

Tests: JVM tests in `LockdownPolicyController`'s gateway style — browser stays
hidden with the field off; stays hidden with the field on and the filter
unverified; unhidden only with both; re-hidden when the canary goes stale;
refused for a non-catalogue or wrongly signed package; WebView provider not
suspended while exempt; link routing restored on exit. Hardware: one exempt
browser per firmware family through the filter, canary failure re-hides it.

---

## 8. Tightening, loosening and human approval

### 8.1 Classification

A pure function, implemented twice from one specification and tested against
the shared vectors:

```text
classify(appliedPolicy, candidate) -> TIGHTEN | NEUTRAL | LOOSEN | HAZARD
```

- A change is classified per field and the **most permissive** result wins
  (`LOOSEN` and `HAZARD` both require approval; any mix with them requires
  approval).
- **`HAZARD`** is a tightening that can remove a recovery path or brick a
  device, so it also needs approval: disabling ADB/debugging, entering kiosk,
  adding system packages to the managed selection, removing a management pin,
  enabling a wipe, freezing system updates.
- Commands carry a fixed class (section 9).

| Field | Tighten | Loosen |
| --- | --- | --- |
| `protection.state` | `PAUSED` → `ON` | any pause |
| `apps.mode` | `BLOCK_SELECTED` → `ALLOW_SELECTED` | the reverse |
| `apps.allowed` (allowlist mode) | removal | addition |
| `apps.allowed` (blocklist mode; the list is the blocked set) | addition | removal |
| `apps.systemSelection` | — | removal is loosen; addition is `HAZARD` |
| `apps.playCompatibility` | `true` → `false` | `false` → `true` |
| `browserThroughFilter` | disable | enable or change package |
| `systemControls.*` | `false` → `true` | `true` → `false`; `developer_options_and_adb` `false` → `true` is `HAZARD` |
| `homeFilter.enabled` | `false` → `true` (with a config already approved) | `true` → `false` |
| `homeFilter` routing, PAC, VPN package, CA | — | any change (it redirects or inspects traffic) |
| `managementPins` | — | adding a pin loosens; removing is `HAZARD` |
| `kiosk` | — | exit/clear loosen; configure/enter is `HAZARD` |
| `permittedAccessibilityServices` / `InputMethods` | narrowing | widening |
| `systemUpdates` | `AUTOMATIC` | `WINDOWED` is neutral; `POSTPONE`/freeze is `HAZARD` |
| `sync`, `locale` | — | neutral |
| `managementMode` | — | `REMOTE` → `LOCAL_PIN` loosens |

### 8.2 Approval object

The approver signs over the exact payload bytes. With WebAuthn (preferred,
because a passkey on the administrator's phone needs no extra app):

- `challenge = SHA-256("dg-approval/1" || payloadSha256 || deviceId || approvalExpiresAt)`;
- the device and the server both verify: `clientDataJSON.type == "webauthn.get"`,
  the challenge, the pinned origin, `rpIdHash`, flags `UP` and `UV` set, and the
  ES256 signature over `authenticatorData || SHA-256(clientDataJSON)` with an
  approval key listed in the current key set. All of this is plain
  `SHA256withECDSA` and SHA-256 in `java.security`.
- An approval expires 15 minutes after it is made (the document must be signed
  and delivered by then; the device checks it against trusted time on
  receipt).
- Specification: [Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/).

The alternative is a small approver app with a Keystore key; the envelope
field stays the same shape.

### 8.3 Who enforces

- **Server:** refuses to sign any `LOOSEN`/`HAZARD` policy or command unless a
  valid approval object over the exact payload is attached, and records the
  approval in the audit log. MCP tools have no path to an approval key.
- **Device:** independently runs `classify` against its applied policy and
  refuses `doc-approval-missing` if a loosening document lacks a valid approval
  by a key from the current key set. This is what limits a compromised server
  to denial of service.

---

## 9. Full management parity

Every console action, its signed command or policy field, its MCP tool, and the
read-back that proves it. **Class:** `T` tighten (applies at once), `N` neutral
(applies at once), `L` loosen (needs approval), `H` hazard (tightening that needs
approval). MCP tools come in `*_prepare` / `confirm` pairs (section 11); the
table names the prepare tool.

| Console action today (where) | Signed command / policy field | MCP tool | Class | Read-back / verification |
| --- | --- | --- | --- | --- |
| Apply protection (`MainActivity` → `LockdownPolicyController.apply`) | `protection.state = ON` | `protection_set_prepare` | T | `PolicyResult.verified`, error codes, package census in the report |
| Pause protection (`LockdownPolicyController.pause`) | command `pause {minutes ≤ 240}` | `protection_pause_prepare` | L | `markPauseSucceeded` state; auto re-apply verified at expiry |
| Choose allowlist or blocklist (`AllowedAppsActivity` → `setProtectionMode`) | `apps.mode` | `apps_set_mode_prepare` | T or L (8.1) | `isApplicationHidden` per managed package |
| Allow or block apps (`setAllowedPackages`) | `apps.allowed` | `apps_set_list_prepare` | T or L | per-package hidden state; `package-policy-state-mismatch` |
| Select system apps with risk acceptance (`setAdminSelectedSystemPackages`, `recordSystemRiskAcceptance`) | `apps.systemSelection` | `apps_set_system_selection_prepare` | H / L | `revalidatedSystemSelection` identity match, hidden state |
| Google Play compatibility (`SystemPolicyActivity` → `PlayStoreCompatibilityStore.setEnabled`) | `apps.playCompatibility` | `play_compat_set_prepare` | T or L | `PlayStoreCompatibility.State`; install lock `APPLIED`; `play-compatibility-install-lock-unverified` |
| Allow a browser through the filter (new) | `browserThroughFilter` | `browser_filter_set_prepare` | L | hidden state, preferred-activity probe, canary age |
| System control switches (`SystemPolicyStore.setRequested`) | `systemControls.<key>` | `system_control_set_prepare` | T / L / H | `SystemPolicyReport` per control (`SystemPolicyOutcome`) |
| Home filter enable with routing, PAC, canary (`HomeFilterActivity` → `HomeFilterController.enable`) | `homeFilter` | `home_filter_set_prepare` | L for config change, T for re-enable of an approved config | `HomeFilterController.read` snapshot: VPN signer, always-on lockdown, managed config, PAC, Private DNS, restrictions |
| Install CA (`installCa`) | `homeFilter.caCertificate` | `home_filter_ca_set_prepare` | L | `hasCaCertInstalled` |
| Remove CA (`removeCa`) | `homeFilter.caCertificate = null` | `home_filter_ca_remove_prepare` | L | `hasCaCertInstalled == false` |
| Turn off home filter (`disable`) | `homeFilter.enabled = false` | `home_filter_set_prepare` | L | cleared VPN, config, proxy, CA; released restrictions |
| Retry home filter (`retry`) | command `reconcile` | `device_reconcile` | N | fresh `PolicyResult` |
| Home filter check (canary, `HomeFilterProbe`) | command `filter_check` | `filter_check` | N | canary result and time in the report |
| Management identity pins (`ManagementIdentityActivity`) | `managementPins` | `management_pins_set_prepare` | L (add) / H (remove) | `ManagementIdentityInspector` verdict per package |
| Configure and enter kiosk (`KioskController.requestConfigure`, `requestEnter`) | `kiosk {mode, target}` | `kiosk_set_prepare` | H | `KioskState.ACTIVE`, lock-task packages, HOME preference, `isLockTaskPermitted` |
| Exit or clear kiosk (`requestExit`, `requestClear`) | `kiosk.mode = OFF` | `kiosk_set_prepare` | L | `KioskState.OFF`, preferences cleared |
| Open a maintenance window (`MaintenanceActivity` → `MaintenanceCoordinator.open`) | command `maintenance_open {capabilities, minutes ≤ 240}` | `maintenance_open_prepare` | L (`ADB_DEBUGGING` always with its warning) | `MaintenanceOutcome`, `residualBlockers` |
| Cancel a maintenance window (`cancel`) | command `maintenance_cancel` | `maintenance_cancel` | T | `restoreVerified` |
| Update window (new, 10.1) | command `update_window` | `update_window_prepare` | L | window outcome, restore, package diff |
| Check for a Device Guard update now (`SecureUpdateManager.checkNow`) | command `self_update_check` | `self_update_check` | N | `UpdateSnapshot.phase`, installed version |
| Create or change PIN (`AdminPinStore.setNewPin`) | command `set_local_pin_verifier` + `managementMode = LOCAL_PIN` | `local_admin_enable_prepare` | L | `hasPin`, mode in report |
| Rotate recovery code (`rotateRecoveryCode`) | command `set_recovery_verifier` | `recovery_code_rotate_prepare` | L | verifier present, rotation time |
| Lock the console (`AdminSession.lock`) | command `end_sessions` | `sessions_end` | T | no live session in report |
| Unlock the console (PIN entry) | command `console_session {minutes ≤ 30}` | `console_session_prepare` | L | session deadline in report |
| Device health report and export (`DeviceHealthActivity`) | signed report on every sync; command `report_now` | `device_status` | N | the report itself, signed by the attested device key |
| Audit log view (`AuditLog.formatted`) | report section (event codes) | `device_audit` | N | hash-chained server copy |
| Display language (`AppLocales.apply`) | `locale` | `device_locale_set_prepare` | N | `AppLocales.current` |
| Lock screen now (new) | command `lock_now` → [`lockNow`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#lockNow()) | `lock_now` | T | acknowledged in report |
| Reboot (new) | command `reboot` → [`reboot`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#reboot(android.content.ComponentName)) | `reboot_prepare` | N | new `BOOT_COUNT` in report |
| Restrict accessibility services / keyboards (new) | `permittedAccessibilityServices`, `permittedInputMethods` | `accessibility_permit_set_prepare` | T or L | getter read-back |
| System update policy (new, 10.3) | `systemUpdates` | `system_updates_set_prepare` | N / H | `getSystemUpdatePolicy`, pending update, patch level |
| Wipe (new; no console equivalent, see [`provisioning.md`](provisioning.md)) | command `wipe` → [`wipeDevice` (API 34)](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#wipeDevice(int)) / `wipeData` | `wipe_prepare` | H, plus a second approval | device disappears; server marks retired |
| Move device to local PIN mode | `managementMode = LOCAL_PIN` | `local_admin_enable_prepare` | L | mode in report |

Parity is enforced by a test: a JVM test enumerates every console action
(a registry each activity registers into) and fails if any has no command
mapping, and the server has the mirror test for MCP tools.

---

## 10. Update window, self-update and system OTA

### 10.1 Update window

**Why it is needed.** `APP_STORES_AND_INSTALLERS` (`DISALLOW_INSTALL_APPS`) is
part of `HomeFilterPolicy.REQUIRED_CONTROLS`, and `permitsRelaxing` refuses any
maintenance window that touches it, so on a home-filter device apps cannot be
updated at all today. Google Play compatibility pins the same restriction on.

**Command** `update_window` (class `L`):

```json
{ "kind": "update_window",
  "args": { "notBefore": 1795003600, "notAfter": 1795010800,
            "minutes": 60, "stores": ["com.android.vending"],
            "requireCharging": true, "requireUnmetered": true,
            "selfUpdate": true } }
```

Sequence on the device:

1. **Schedule.** A one-off `JobScheduler` job with the charging/unmetered
   constraints, runnable between `notBefore` and `notAfter`. On-demand windows
   have `notBefore` = now.
2. **Snapshot.** Before any relaxation, record every package with
   `versionCode`, signing-certificate digests and installer, using
   [`MATCH_UNINSTALLED_PACKAGES`](https://developer.android.com/reference/android/content/pm/PackageManager#MATCH_UNINSTALLED_PACKAGES)
   so packages this DPC hid are included (bulk queries otherwise omit them, as
   `LockdownPolicyController.pause` already works around). Its SHA-256 is
   stored in the window record.
3. **Open.** Reuse `MaintenanceCoordinator.open` with
   `MaintenanceCapability.APP_STORE_ACCESS`, which already relaxes
   `DISALLOW_INSTALL_APPS` and makes managed stores visible through
   `MaintenanceAppPolicy`. New: an `UPDATE_WINDOW` window kind that
   `HomeFilterPolicy.permitsRelaxing` accepts for exactly
   `APP_STORES_AND_INSTALLERS`, only with a `VerifiedCommand` authority. The VPN
   lockdown, PAC, Private DNS, unknown-source restrictions and every other
   required control stay enforced, so store traffic still passes the family
   filter, which must allow the store's domains. Only the `stores` listed are
   unhidden.
4. **During.** The existing `PACKAGE_ADDED` reconciliation keeps running: in
   `ALLOW_SELECTED` mode a newly installed app is hidden as soon as the
   broadcast arrives, exactly as today.
5. **Close.** At the monotonic deadline (or on cancel, reboot or process death)
   the existing verified restore puts back the base policy.
6. **Diff.** After the restore is read back: compare installed packages with
   the snapshot. Every **new** package and every package whose **signer set
   changed** is suspended with
   [`setPackagesSuspended`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#setPackagesSuspended(android.content.ComponentName,%20java.lang.String[],%20boolean))
   and verified with `isPackageSuspended`, then reported as
   `update-window-new-package` / `update-window-signer-changed`. Updated
   packages with the same signer are reported as updated. Suspension, not
   uninstall, so an administrator can approve (loosen) or remove it. The diff
   runs even if the window closed early.
7. **Report.** One signed report with the window outcome, restore verification
   and the diff.

**Process-bound windows.** Maintenance authorisations die with the process
(`MaintenanceStore` version 2). A Device Guard self-update inside the window
restarts the process and closes the window early, which is safe (fail
closed). The self-update step therefore runs last (10.2).

**Known limitation.** Device Guard cannot make the Play Store update apps on
demand; Play decides when to run auto-updates. A window may close with nothing
updated. The robust alternative is a later "managed private app catalogue":
signed manifests per app, installed by Device Guard through `PackageInstaller`
exactly like its own self-update. That raises APK redistribution licensing
questions (section 15).

**Tests.** JVM: snapshot/diff logic (new, removed, updated, signer-changed,
hidden packages included); `permitsRelaxing` accepts only
`APP_STORES_AND_INSTALLERS` and only for `UPDATE_WINDOW` with a verified
authority; schedule boundaries; early close still diffs; process restart closes.
Hardware: group P/M style runs on a home-filter device: Play updates an
allowed app through the filter, a new app installed during the window is
suspended and reported, restore verified after reboot mid-window.

### 10.2 Device Guard self-update

Unchanged channel ([`secure-updates.md`](secure-updates.md)): separate metadata
key, version floor, signer lineage. Two additions:

- `DISALLOW_INSTALL_APPS` also blocks the Device Owner's own
  `PackageInstaller` session (already documented in
  [`play-store-compatibility.md`](play-store-compatibility.md#what-the-mode-costs)).
  An `update_window` with `selfUpdate: true` runs `SecureUpdateManager.checkNow`
  as its final step, after the store phase.
- The remote report carries `UpdateSnapshot` so the server can see devices that
  are behind and schedule windows for them.

### 10.3 System OTA

New policy field `systemUpdates`:

| Mode | API |
| --- | --- |
| `AUTOMATIC` | [`SystemUpdatePolicy.createAutomaticInstallPolicy`](https://developer.android.com/reference/android/app/admin/SystemUpdatePolicy#createAutomaticInstallPolicy()) |
| `WINDOWED` (minutes after midnight, device local time) | [`createWindowedInstallPolicy`](https://developer.android.com/reference/android/app/admin/SystemUpdatePolicy#createWindowedInstallPolicy(int,%20int)) |
| `POSTPONE` | [`createPostponeInstallPolicy`](https://developer.android.com/reference/android/app/admin/SystemUpdatePolicy#createPostponeInstallPolicy()) (30 days) |
| freeze periods | [`setFreezePeriods`](https://developer.android.com/reference/android/app/admin/SystemUpdatePolicy#setFreezePeriods(java.util.List%3Candroid.app.admin.FreezePeriod%3E)) (API 28; at most 90 days each, platform-validated) |

Applied with
[`setSystemUpdatePolicy`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#setSystemUpdatePolicy(android.content.ComponentName,%20android.app.admin.SystemUpdatePolicy))
and read back with `getSystemUpdatePolicy`. Pending updates are observed via
[`DeviceAdminReceiver.onSystemUpdatePending`](https://developer.android.com/reference/android/app/admin/DeviceAdminReceiver#onSystemUpdatePending(android.content.Context,%20android.content.Intent,%20long))
and [`getPendingSystemUpdate`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#getPendingSystemUpdate(android.content.ComponentName))
and reported with `Build.VERSION.SECURITY_PATCH`. Guide:
[managing system updates](https://developer.android.com/work/dpc/system-updates).

Boundary: OEMs honour these policies to different degrees; some ignore them.
The report states what Android returned, not what the OEM will do. An OTA can
change OEM behaviour, so the first boot after a build-fingerprint change
triggers a full reconciliation and a report (the fingerprint is already in
`DeviceHealthSnapshot.Platform`). Postponing or freezing delays security
patches, hence its `HAZARD` class.

---

## 11. Management server and MCP interface

### 11.1 Scope

A deliberately small service, kept in a **separate repository** so the DPC
repository stays a client and holds no server secrets. Data model:

| Table | Content |
| --- | --- |
| `fleets` | id, label, root-key digest, current key set |
| `devices` | `deviceId`, fleet, state (`pending-approval`, `active`, `untrusted`, `retired`), attestation facts, applied policy version, last report, last seen |
| `policies` | immutable versions per device: payload bytes, hash, previous hash, class, approval reference |
| `commands` | per-device sequence, payload bytes, class, approval reference, state (`queued`, `delivered`, `applied`, `failed`, `expired`) |
| `approval_requests` | subject hash, requested by, approved by, approval object, expiry |
| `audit` | append-only, each row includes the SHA-256 of the previous row; periodically exported off the server |

Device API: `POST /v1/enrol`, `POST /v1/sync`, `POST /v1/report`,
optional `GET /v1/wake`. Administrator API: the MCP interface below plus an
approval web page that drives WebAuthn on the administrator's phone.

### 11.2 MCP tools: prepare and confirm

Every mutating tool is two-step:

1. `*_prepare(args)` validates, renders the candidate per-device payload,
   computes `classify`, and returns `{preparationId, devices, diff, class,
   approvalUrl?}`. Nothing is signed.
2. `confirm(preparationId)`:
   - `T`/`N`: signs and queues at once, returns the policy version or command
     sequence;
   - `L`/`H`: returns `awaiting-approval` until a human completes the approval
     page; then signs and queues. The MCP credential has no approval capability.

Read-only tools: `device_status`, `device_list`, `device_audit`,
`policy_get`, `filter_check` (queues a neutral command and returns the next
report). The full mutating list is the "MCP tool" column of section 9.

Server-side invariants (each has a test): the policy-signing code path refuses
`L`/`H` without a verified approval over the exact payload hash; approvals are
single use; the classifier is the shared one; a policy is never edited, only
superseded; an MCP request can never select the signing key or set
`policyVersion`/`sequence`.

### 11.3 Failure modes

| Failure | Effect |
| --- | --- |
| Server down | Devices keep their last verified policy; running windows close on their monotonic deadlines; nothing loosens |
| Signing key unavailable | Nothing new is issued; reads still work |
| Approval page unreachable | Loosening waits; tightening unaffected |
| Device silent past `3 × pullMinutes + 1 h` | `device-silent` alert (possible wipe, flash, or network loss) |
| Report says `verified: false` | Alert with the stable error codes |

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
- Restricted settings: Android 13 introduced "restricted settings" that block
  enabling accessibility for some sideloaded apps, and later releases extended
  it ([Android 13 behaviour changes (verify)](https://developer.android.com/about/versions/13/behavior-changes-all)).
  Device Guard is installed by the provisioning flow or by its own
  `PackageInstaller` session; whether it is treated as restricted on
  Android 15+ must be tested. A Device Owner can **permit** services with
  `setPermittedAccessibilityServices` but there is no documented API to
  **enable** one silently, so enabling likely needs one on-device tap (or
  `adb shell settings put secure enabled_accessibility_services` on the ADB
  path). This conflicts with zero-touch and is listed as an open question.
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
  exists today. In remote mode it is set by policy once the signed self-update
  drill has passed on that firmware family (the existing production gate), and
  ADB returns only through an approved `ADB_DEBUGGING` maintenance window.
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
  re-enrolment needs a new ticket. Optional
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

### 13.5 Clock tampering

- **Threat.** Moving the clock to extend a window or revive an expired document.
- **Mitigation.** Durations on the monotonic clock (as maintenance already
  does), validity against server-anchored trusted time (6.4),
  `DISALLOW_CONFIG_DATE_TIME` (API 28+) and automatic time (API 30+), and the
  existing wall-versus-monotonic jump detection
  (`MaintenanceStateMachine.BOOT_GAP_TOLERANCE_MILLIS`).
- **Does not cover.** API 26–27, where the date/time restriction does not exist;
  a device that never reaches the server after reboot (only tightening applies
  until it does).

### 13.6 Replayed or downgraded policy

- **Threat.** Replaying an older, looser signed policy or command.
- **Mitigation.** Strictly increasing `policyVersion`, `sequence` and
  `keySetVersion`; `previousPolicySha256` chain; `basePolicyVersion` on
  commands; device binding; expiry; floors raised only after acceptance —
  the same pattern as the update channel's `highestAuthorizedVersion`.
- **Does not cover.** An attacker with root who resets app storage; a wipe
  (which also removes Device Guard).

### 13.7 Server compromise

- **Threat.** Full control of the management server, including its signing key.
- **Mitigation.** The device itself requires a human approval signature for
  every loosening or hazardous change, and the approval keys are not on the
  server. Key-set changes need the offline root. The audit chain is exported
  off the server. The offline break-glass code recovers a device that a
  malicious tightening made unusable.
- **Does not cover.** Denial of service by tightening (for example blocking
  every allowed app), disclosure of device reports, a compromised approver
  phone or a malicious administrator, and compromise of the release or update
  metadata keys (separate trust chain).

### 13.8 Additional threats

| Threat | Mitigation | Not covered |
| --- | --- | --- |
| Leaked enrolment QR | Single use, short expiry, optional serial binding, `pending-approval` | A stranger enrolling one spare device into the pending list |
| Rogue enrolment into another fleet on an unenrolled device (4.5) | On-screen confirmation of host and root fingerprint; launcher UID check on API 34+ | Social engineering of the operator at the bench |
| Network attacker | TLS plus optional SPKI pins; every document signed; wake pokes carry no data | Traffic analysis; blocking sync (devices keep the last policy) |
| Malicious MCP agent | No approval capability; prepare/confirm with visible class; server-side enforcement | Abuse of tightening and neutral commands within the agent's credential |
| Other apps' accessibility services | New `permittedAccessibilityServices` field | Services built into the system image |

---

## 14. Phased delivery plan

Small PRs, in order. Each lands with its tests; hardware groups are added to
[`hardware-validation.md`](hardware-validation.md) and evidenced in
[`device-matrix.md`](device-matrix.md).

| # | PR | Tests |
| --- | --- | --- |
| 1 | This design document | Review only |
| 2 | `AuditLog` event codes alongside prose (closes known gap 1) | Code stability test; health export now carries the allowlisted tail |
| 3 | `GET_PROVISIONING_MODE` and `ADMIN_POLICY_COMPLIANCE` activities, no network yet; manifest permission | JVM result-intent tests; manifest permission test in `tools/test_manifest_permissions.py`; hardware QR enrolment on Android 12+ (unblocks provisioning issue) |
| 4 | Signed-document verifier generalised from `UpdateEnvelopeVerifier` (`keyId`, type, device binding, floors, key set) plus the shared test-vector set | Vector tests (6.6); existing update tests unchanged |
| 5 | Policy schema, `classify`, `RemotePolicyApplier` projection (pure Java) | Classification vectors; projection into every store; no Android calls |
| 6 | `AdminAuthority` refactor of `KioskController` and `HomeFilterController` | No public constructor for `VerifiedCommand`; existing kiosk and home-filter tests pass unchanged |
| 7 | `tools/provisioning_payload.py`: remote admin extras and `--enrolment-ticket-env` | Python tests (4.7) |
| 8 | Device key, attestation, `EnrolmentConfig`, enrolment state machine and client against a fake transport | JVM state machine and parsing tests |
| 9 | `RemoteSyncJobService`, trusted time, signed reports from the redacted health snapshot | Fake-server sync tests; time anchoring; report redaction |
| 10 | Remote mode console (read-only), offline recovery verifier, mode switching | Locale parity; recovery verifier compatibility test |
| 11 | Neutral and tightening commands: `reconcile`, `filter_check`, `report_now`, `lock_now`, `end_sessions`, `maintenance_cancel` | Command vectors; parity registry test (partial) |
| 12 | Loosening commands with device-side approval verification: `pause`, `console_session`, `maintenance_open`, kiosk, management mode | WebAuthn verification vectors; missing/expired/foreign approval refused |
| 13 | Update window: snapshot, `UPDATE_WINDOW` relaxation under the home filter, diff, suspension | Diff and relaxation tests (10.1); hardware group |
| 14 | `browserThroughFilter` | Tests in 7.1; hardware per browser |
| 15 | `systemUpdates`, `permittedAccessibilityServices`, `permittedInputMethods`, automatic time | Read-back tests with a fake gateway; hardware per OEM |
| 16 | Server (separate repository): data model, enrol/sync/report, signing, approval page, hash-chained audit | Same vectors; refusal of unapproved loosening; audit chain verification |
| 17 | MCP interface with prepare/confirm | Every console action has a tool (mirror parity test); agent credential cannot approve |
| 18 | Optional wake channel | Rate limit; poke carries no data |
| 19 | Optional accessibility content-check pilot (separate opt-in) | Section 12 tests; README claim updated |

PRs 2–6 need no server and no network; they can merge while the production
identity is still provisional. PR 8 onward must not enrol a real customer
device before the production application ID and signer are fixed
([`production-release.md`](production-release.md)).

---

## 15. Open questions and blockers

### Blockers

1. **QR provisioning on Android 12+ is expected to fail today** because the
   `GET_PROVISIONING_MODE` and `ADMIN_POLICY_COMPLIANCE` activities are missing
   (PR 3). Zero-touch-style enrolment is blocked until this lands and a QR
   enrolment passes on real hardware.
2. **Production identity is not fixed.** Enrolled devices cannot move between
   application IDs without a wipe, so no real fleet can be enrolled before the
   final ID and signer exist.
3. **No hardware evidence yet** for provisioning, signed self-update or
   maintenance restore. Disabling ADB by remote policy is blocked on the signed
   self-update drill passing per firmware family.
4. **`AuditLog` has no event codes** (PR 2), which the remote audit trail needs.
5. **Update windows conflict with the home filter by design today**
   (`HomeFilterPolicy.permitsRelaxing`). The narrow `UPDATE_WINDOW` exception in
   10.1 needs an explicit security review before implementation.
6. **Hosting of the management server** (where it runs, who operates it, how
   the policy-signing key is protected) needs an owner decision; nothing in
   this repository may name it.

### Open questions

1. Approval mechanism: WebAuthn passkey on the administrator's phone
   (recommended) or a dedicated approver app?
2. Should `HAZARD` tightenings (enter kiosk, disable ADB, add system packages to
   the managed set) require approval, as proposed, or apply at once like other
   tightenings?
3. Can Device Guard trigger Play Store updates inside a window, or is a signed
   private app catalogue (Device Guard installing third-party APKs) needed — and
   is redistributing those APKs permitted by their licences?
4. Is FRP (`setFactoryResetProtectionPolicy`), which needs a Google account, acceptable for the target fleets?
5. Which browsers trust a user-installed CA and honour managed proxy settings on
   current Android releases? Needs per-browser hardware evidence before
   `browserThroughFilter` is offered for each one.
6. Accessibility pilot: is one on-device tap to enable the service acceptable
   given the zero-touch goal, and how does Android 15+ restricted settings treat
   a provisioning-installed DPC?
7. Wake channel: long-poll foreground service, UnifiedPush, or pull only?
8. Should re-attestation be monthly, and should an untrusted result tighten the
   device automatically or only alert?
9. Google zero-touch enrolment or Samsung Knox Mobile Enrollment for
   reseller-purchased devices — worth supporting later, given they re-enrol
   automatically after a wipe?
10. Recovery verifier delivery on API 26–30: Keystore `PURPOSE_AGREE_KEY`
    (ECDH) exists only from API 31; use RSA-OAEP Keystore keys below that, or
    deliver it only over the pinned TLS channel?
11. Pull interval and Doze: is 15 minutes plus Doze deferral acceptable for
    `lock_now`, or is a wake channel required for that one command?
