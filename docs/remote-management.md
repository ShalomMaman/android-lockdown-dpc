# Remote management design

**Status: design proposal, revision 3. Nothing in this document is implemented
yet unless a section says "exists today".**

Two independent reviews of the earlier revisions each found new P1 issues in
the parts that let a remote party *loosen* a device: approval flows, timed
windows, install windows, browser exemptions and wipe. Revision 3 therefore
splits the design:

- **v1 (build now)** — sections 1–13. A device enrols from a QR code into a
  verified, locked-down baseline. After that, the management server can only
  **keep or tighten** it. It also receives status reports, can lock the screen
  remotely, and can be recovered offline with a recovery code. Every way of
  opening a device in v1 is a complete policy document signed with an
  **offline fleet-policy key** that the administrator holds. The online server
  never holds that key.
- **Later (separate design, not reviewed here)** — section 14. Remote
  loosening with human approval, timed windows, install and update windows,
  browser exemptions, wipe, accessibility and input-method allowlists, and MCP
  write actions beyond tightening. Each has a short note on the open problems
  the reviews found. None of it may be built from this document.

Every finding of both reviews and its disposition (fixed, moved to Later, or
rejected) is listed in [Appendix A](#appendix-a-review-resolution).

Remote management is an **optional mode**. The local, PIN-protected mode that
ships today stays the default and keeps working without any server, so the
README statement that the project has "no required management cloud" remains
true.

Links and statements marked **(verify)** come from documentation or platform
behaviour that has not yet been confirmed on the target hardware. They must be
checked before the PR that implements them is merged.

## Contents

1. [Goals, non-goals and scope](#1-goals-non-goals-and-scope)
2. [What exists today](#2-what-exists-today)
3. [Architecture and keys](#3-architecture-and-keys)
4. [Enrolment](#4-enrolment)
5. [Signed documents, sync and the apply journal](#5-signed-documents-sync-and-the-apply-journal)
6. [Policy model and the keep-or-tighten rule](#6-policy-model-and-the-keep-or-tighten-rule)
7. [Commands, reports and MCP](#7-commands-reports-and-mcp)
8. [Recovery code](#8-recovery-code)
9. [Management server](#9-management-server)
10. [Admin tooling](#10-admin-tooling)
11. [Threat model](#11-threat-model)
12. [v1 delivery plan](#12-v1-delivery-plan)
13. [Blockers and open questions](#13-blockers-and-open-questions)
14. [Later (separate design, not reviewed here)](#14-later-separate-design-not-reviewed-here)
- [Appendix A: Review resolution](#appendix-a-review-resolution)

---

## 1. Goals, non-goals and scope

### v1 goals

- **Zero-touch-style enrolment into a verified baseline.** A wiped device is
  enrolled from the setup wizard by scanning one QR code. Device Guard becomes
  Device Owner, applies a built-in baseline and reads it back, and only then
  lets setup finish. It then registers with the management server.
- **Only the administrator's offline key can open a device.** The policy that
  decides what a device may use is a complete document signed with the fleet
  policy key. That key is kept offline and used only from the admin tooling
  (section 10). The online server can only keep that policy or make it
  stricter (section 6.4).
- **No on-device administrator PIN in remote mode.** The on-device console
  becomes a read-only status screen with one exception: the recovery-code
  entry (section 8).
- **Every change is read back.** As today, a policy is reported applied only
  after Android confirms it. The read-back goes to the server in a signed
  report.

### Non-goals

- Replacing Android Enterprise or managed Google Play. Device Guard stays a
  self-hosted DPC; the `afw#` token path does not apply (see
  [`provisioning.md`](provisioning.md)).
- Making consumer hardware impossible to reset or reflash. The boundary in the
  README and [`SECURITY.md`](../SECURITY.md) still applies; section 11 states
  what v1 adds.
- Silent enrolment without consent. The platform consent screen stays;
  `PROVISIONING_SKIP_USER_CONSENT` is never emitted.
- Anything in section 14.

### Scope at a glance

| Capability | v1 | Later |
| --- | --- | --- |
| QR enrolment into a verified baseline; ADB bench enrolment | ✓ | |
| Complete policies signed with the offline fleet policy key (the only way to open a device) | ✓ | |
| Server overlays that keep or tighten the fleet policy | ✓ | |
| Signed status reports (heartbeat), `report_now` | ✓ | |
| `lock_now` | ✓ | |
| Offline recovery code with a fixed, durable scope | ✓ | |
| MCP: read tools and tighten-only tools | ✓ | |
| Server-originated loosening with human approval | | ✓ |
| Pause, maintenance and console windows opened remotely | | ✓ |
| Install, update and self-update windows | | ✓ |
| Browser through the filter | | ✓ |
| Remote wipe and reboot | | ✓ |
| Accessibility and input-method allowlists; system update policy | | ✓ |
| Kiosk changes outside a fleet policy | | ✓ |
| MCP write actions beyond tightening | | ✓ |

---

## 2. What exists today

| Area | Exists today | Where |
| --- | --- | --- |
| Device Owner check | `isDeviceOwnerApp` gate in every apply, pause and update path | `policy/LockdownPolicyController.java`, `updates/SecureUpdateManager.kt` |
| Verified apply | Every package visibility change and user restriction is read back; partial results are failures | `LockdownPolicyController.apply`, `applyPackagePolicy`, `policy/SystemPolicyEnforcer.java` |
| Single policy thread | All `DevicePolicyManager` writers run on one FIFO executor | `policy/PolicyReconciliationCoordinator.java` |
| Lifecycle reconciliation | Boot (`BOOT_COMPLETED`, not direct-boot aware), own-package replacement, `PACKAGE_ADDED`/`PACKAGE_REMOVED`, periodic sweep | `receivers/PolicyRefreshReceiver.java`, `admin/LockdownDeviceAdminService.java` |
| App policy | `ALLOW_SELECTED` or `BLOCK_SELECTED`, each with its own stored selection and "configured" flag; a mode switch is non-destructive; managed packages are hidden only when the current mode's selection is configured | `policy/AllowedAppsStore.java` (`setProtectionMode`, `isAllowlistConfigured`) |
| Package decision order | Built-in block (`ALWAYS_BLOCKED`, `KNOWN_BROWSER_AND_SOCIAL`), then the mode's selection (managed and admin-selected system packages only), then these exceptions: store maintenance, Play compatibility, kiosk escape surfaces, trusted management packages, WebView provider, essential system packages, kiosk target | `LockdownPolicyController.applyPackagePolicy` |
| Management trust | A management package is trusted when its signer matches a pin **or when it has no pin** (`UNPINNED`); a pinned package with another signer is forced hidden | `policy/LockdownPackages.java` (`verifySigner`, `grantsManagementTrust`) |
| System controls | 16 controls mapped to `UserManager.DISALLOW_*`, each with a default of `ENFORCED_SINCE_PILOT`, `PRODUCTION_ONLY` (debugging) or `OPT_IN`. The base policy is the stored choices raised by two floors: Play compatibility pins the install controls on, and the home filter pins `REQUIRED_CONTROLS` on | `policy/SystemPolicyControl.java`, `policy/SystemPolicyStore.java` (`baseChoices`), `policy/PlayStoreCompatibility.java`, `policy/HomeFilterPolicy.java` |
| Home filter | Always-on VPN with lockdown, managed configuration, PAC proxy, Private DNS, optional CA, HTTPS canary from Device Guard's process; the VPN client is installed and signed in by hand | `policy/HomeFilterController.java`, [`provisioning.md`](provisioning.md#home-filter) |
| Local authority | PIN (PBKDF2-SHA256 210 000 iterations, then a Keystore HMAC), lockout bound to `BOOT_COUNT`, device-generated 12-digit recovery code, three-minute in-memory session | `security/AdminPinStore.java`, `security/PinLockoutPolicy.java`, `security/AdminSession.java` |
| First-PIN path | With no PIN, `initialScreen()` opens `PIN_SETUP` directly, and `savePin()` checks the session only when replacing a PIN. `AdminPinStore.verify` returns `NOT_CONFIGURED` without a PIN, so a recovery code can only be checked once a PIN exists, and the `commit()` that consumes the code is not checked | `ui/MainActivity.kt` (`initialScreen`, `savePin`, `unlockWith`), `AdminPinStore.verify` |
| Signed self-update | ECDSA P-256 envelope `{payload, signature}`, version floor, signer lineage, `PackageInstaller` with an asynchronous result; blocked while `DISALLOW_INSTALL_APPS` is on | `updates/`, [`secure-updates.md`](secure-updates.md), [`play-store-compatibility.md`](play-store-compatibility.md#what-the-mode-costs) |
| Offline signing tool pattern | Signs envelopes with OpenSSL from an external PEM key that is never copied, with the passphrase taken from a named environment variable | `tools/publish_update.py` |
| Provisioning payload | Verified QR payload builder; refuses admin-extras keys containing `credential`, `passcode`, `passphrase`, `password`, `pin`, `recovery`, `secret` or `token` (not `ticket`); 1800-byte limit | `tools/provisioning_payload.py` |
| Health report | Redacted, allowlisted snapshot (package census as counts, not identities) | `health/DeviceHealthSnapshot.java`, `health/DeviceHealthRedaction.java` |
| Audit log | 50 prose entries, no event codes | `policy/AuditLog.java` |

### Gaps v1 must close

1. No `GET_PROVISIONING_MODE` / `ADMIN_POLICY_COMPLIANCE` activities, so QR
   provisioning on current releases is expected to fail
   ([`provisioning.md`](provisioning.md)).
2. `AuditLog` has no event codes.
3. Store setters trust their caller (`SystemPolicyStore.setRequested`: "the
   caller owns authentication"); a remote writer needs one authority gate.
4. The first-PIN path above opens for anyone holding a Device Owner device
   without a PIN.
5. The generic admin-extras option accepts `dg.remote.ticket`.

---

## 3. Architecture and keys

```text
  administrator workstation (offline keys)          agent (MCP client)
  tools/fleet_admin.py: key sets, fleet policies,     read + tighten only
  recovery codes                                             |
          | signed files (uploaded through the server)       |
          v                                                  v
  +--------------------------------------------------------------+
  |  management server (minimal; holds only the server key)      |
  |  stores fleet policies as opaque signed bytes                |
  |  signs: overlays (keep/tighten), lock_now, report_now, time  |
  +--------------------------------------------------------------+
          ^  HTTPS pull, device-signed request
          v
  +--------------------------------------------------------------+
  |  Device Guard (Device Owner)                                 |
  |  verify -> authority check (fleet key, or keep-or-tighten)   |
  |  -> apply journal -> AuthorizedPolicyWriter -> stores        |
  |  -> LockdownPolicyController.apply -> read-back -> report    |
  +--------------------------------------------------------------+
```

| Key | Holder | Signs | If compromised |
| --- | --- | --- | --- |
| **Fleet root key** (P-256) | Offline vault, used only for rotations | Key sets: which fleet policy and server keys are valid, and the server URL | Full fleet control |
| **Fleet policy key** (P-256) | Administrator, offline (hardware token or encrypted PEM on an offline workstation) | Fleet policies (complete, per listed devices) and recovery documents | Attacker can set any policy on enrolled devices |
| **Server key** (P-256) | Management server, ideally in a KMS/HSM | Overlays, commands, time | Attacker can keep or tighten policies and lock screens (denial of service); cannot open anything |
| **Device key** (P-256) | Device Keystore, attested | Sync requests and reports | That device's reports can be forged |

The release (APK) signing key and the update-metadata key of
[`secure-updates.md`](secure-updates.md) stay separate and unchanged.

**ECDSA P-256** is used because `UpdateEnvelopeVerifier` already verifies
`SHA256withECDSA` across the supported range with no extra library, and
Keystore generates and attests P-256 keys from API 26. Ed25519 is only
available from API 33 ([`Signature`](https://developer.android.com/reference/java/security/Signature)).

---

## 4. Enrolment

### 4.1 QR payload and the provisioning tool

The existing payload gains an admin extras bundle (`PersistableBundle`, string
values):

| Key | Example | Meaning |
| --- | --- | --- |
| `dg.remote.v` | `1` | Bundle schema version |
| `dg.remote.server` | `https://manage.example.org` | Server base URL; clean HTTPS, no credentials, query or fragment |
| `dg.remote.root` | base64url SHA-256 of the root key SPKI | Trust anchor for the first key set |
| `dg.remote.tls` | up to two base64url SPKI pins | Optional server TLS pins |
| `dg.remote.ticket` | 32 base64url characters | One-time, per-device enrolment ticket (4.5) |
| `dg.remote.fleet` | short label | Display only |

Tool changes in `tools/provisioning_payload.py`:

- The generic `--admin-extra` option refuses every key that starts with
  `dg.remote.`, and `ticket` joins `FORBIDDEN_ADMIN_EXTRA_FRAGMENTS`.
- Remote keys come only from dedicated options: `--remote-server`,
  `--remote-root`, `--remote-tls-pin` (at most two), `--remote-fleet`, and
  `--enrolment-ticket-env NAME`. The ticket is read only from that environment
  variable, never echoed, and the output is written with owner-only mode. The
  summary carries `"enrolmentTicketEmbedded": true`.
- **Batch input** has one form only: `--enrolment-tickets-file-env NAME`,
  where the environment variable holds the **path** of an owner-only file (mode
  `0600` is checked) with one ticket per line. The tool writes one payload per
  ticket. Errors and summaries name the line number, never a ticket value.
  Tests assert that no ticket value appears in stdout, stderr or the summary.

### 4.2 Provisioning activities

Both activities are declared `android:exported="true"`, with an intent filter
holding the action and `android.intent.category.DEFAULT`, and
`android:permission="android.permission.BIND_DEVICE_ADMIN"`.
`tools/test_manifest_permissions.py` pins all three.

**Remote intent is persisted before anything is parsed.** The first statement
of each activity's `onCreate` (and of the receiver fallback below) checks
whether the raw admin extras bundle has any key starting with `dg.remote.`. If
it does, it writes `remoteIntent = true` to **device-protected** storage with
`commit()`, before any parsing. If that commit fails, the activity returns
`RESULT_CANCELED`. The marker is never cleared except by a factory reset.

1. **`ProvisioningModeActivity`** (`ACTION_GET_PROVISIONING_MODE`):
   - On API 31+, it returns `RESULT_OK` with
     `PROVISIONING_MODE_FULLY_MANAGED_DEVICE` only if
     [`EXTRA_PROVISIONING_ALLOWED_PROVISIONING_MODES`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#EXTRA_PROVISIONING_ALLOWED_PROVISIONING_MODES)
     is present **and** contains that mode. Otherwise it returns
     `RESULT_CANCELED`. It never offers a work profile.
   - On API 29–30, where that extra does not exist, it returns fully managed
     mode.
   - It writes nothing except the remote-intent marker.
2. **`PolicyComplianceActivity`** (`ACTION_ADMIN_POLICY_COMPLIANCE`):
   - It writes the marker as above, then parses the bundle **itself**. It never
     trusts the other activity, because the bundle can arrive in either
     activity, and some flows skip the mode activity.
   - It decides the mode (4.3) and applies the baseline when the mode is
     `ENROLLING` (4.4).
   - It returns `RESULT_OK` **only after the baseline is read back as
     verified**. If the baseline fails, it shows a retry screen with the stable
     failure code, offering **Retry** and **Cancel setup**. Cancel returns
     `RESULT_CANCELED`, so setup does not finish (verify what each target
     setup wizard does next; a factory reset is expected). There is no
     attempt counter and no `RESULT_OK` after failures.
   - Server reachability does not matter here. The baseline is local, so a
     device whose server is down still finishes setup on a verified baseline,
     and enrolment continues in the background (4.6).
3. **Receiver fallback.** `LockdownAdminReceiver.onProfileProvisioningComplete`
   writes the marker from its intent's admin extras and runs the same mode
   decision. It only defends against flows that skip both activities.
   **Remote QR enrolment is supported only on setup wizards that are shown on
   hardware to invoke `PolicyComplianceActivity`.** Elsewhere the bench path
   (4.8) is used.

### 4.3 Management modes

| Mode | Authority | Console |
| --- | --- | --- |
| `UNDECIDED` | None | Device Owner set over ADB with no bundle: local PIN setup **or** bench enrolment (4.8). This is today's ADB flow. |
| `LOCAL_PIN` | PIN session | Full console, unchanged |
| `ENROLLING` | Built-in baseline only | Read-only enrolment status and the recovery entry (8) |
| `REMOTE` | Fleet policies, keep-or-tighten overlays, `lock_now`, `report_now` | Read-only status and the recovery entry |

Mode decision, applied on every start before any screen is chosen:

| Facts | Mode |
| --- | --- |
| `remoteIntent` marker present | `ENROLLING` or `REMOTE`, never `LOCAL_PIN` or `UNDECIDED`, whatever the parse result or the stored mode record says |
| Compliance or receiver saw a bundle with no remote keys | `LOCAL_PIN` (written explicitly) |
| No marker and no mode record | `UNDECIDED` |
| Malformed or unreadable mode record with the marker | `ENROLLING` |
| Malformed or unreadable mode record without the marker | `UNDECIDED` (no PIN path opens until a person at the bench chooses, as today) |

**The first-PIN path is closed outside local modes.** `initialScreen()`
returns `PIN_SETUP` only in `LOCAL_PIN` or `UNDECIDED`. `savePin()` refuses
unless the mode is `LOCAL_PIN` or `UNDECIDED`, and in `UNDECIDED` the bench
choice of local mode writes `LOCAL_PIN` first. `unlockWith()` never routes to
`PIN_SETUP` in other modes. `NoPinOutsideLocalModeTest` drives all three entry
points in `ENROLLING` and `REMOTE`, both with and without a stored PIN.

### 4.4 Enrolment baseline

The baseline is compiled into the APK and versioned. It is identified by the
SHA-256 of its canonical serialisation (`baselineSha256`), which a test pins.
Its content:

- protection `ON`;
- `ALLOW_SELECTED` with an **empty, configured** selection, so every managed
  user app is hidden;
- no system selection, Play compatibility off, home filter off, kiosk off;
- every control requested as in the `PRODUCTION` profile, except
  `developer_options_and_adb`, which follows the build profile. A pilot keeps
  ADB as its documented break-glass until production gate 3;
- management pins: the built-in `MANAGEMENT_DEFAULTS` with no pins. As in
  today's code, an `UNPINNED` management package is **trusted** and stays
  visible if it is installed. This is the existing pilot gap that the health
  report already shows as `UNPINNED`. It is stated here, not changed.

`ENROLLING` ends only through a successful enrolment, which moves the device
to `REMOTE` on the baseline until the first fleet policy arrives, or through a
factory reset.

### 4.5 Enrolment ticket

- 24 random bytes, created **per device**. The server stores only
  `SHA-256(ticket)`. Default expiry 72 hours, maximum 7 days.
- Bound to the **first device key that presents it**. A retry with the same
  key (for example after a process kill) is answered idempotently. Another key
  is refused with `ticket-bound-to-other-device`.
- Optionally bound to an expected serial, checked from ID attestation on
  API 28+ through `DevicePolicyManager.generateKeyPair` with `ID_TYPE_SERIAL`.
- The ticket never opens anything. An enrolled device stays on the baseline
  until the administrator signs a fleet policy that lists it (10).

### 4.6 Identity, attestation and trust bootstrap

Enrolment is a persisted state machine whose steps resume after a crash with
the same device key:

1. `CONFIG_STORED` — validated bundle stored in credential-protected storage.
2. `BASELINE_VERIFIED` — baseline applied and read back.
3. `KEY_CREATED` — non-exportable P-256 key generated with an attestation
   challenge from the server, StrongBox when present. `deviceId` = base64url
   SHA-256 of its SPKI. On API 31+ `getEnrollmentSpecificId` is recorded
   after `setOrganizationId`.
4. `ENROL_SENT` — `POST /v1/enrol` with the ticket, the attestation chain and
   platform facts.
5. `KEYSET_ACCEPTED` — the key set is verified **by signature alone** against
   the root digest from the QR. No time check happens at this step, so there
   is no circular dependency on a time document. The key set names the server
   key and the fleet policy keys. Only after this does the device accept a
   `time` document (verified with the server key named in the key set) or any
   other document.
6. `ENROLLED` — mode `REMOTE`, still on the baseline.

The server verifies the attestation chain against Google's roots and the
[revocation list](https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status).
It records security level, verified boot state, bootloader lock, boot key,
patch level and the application signer. A device with software attestation,
an unlocked bootloader, failed boot state, a revoked chain or an unexpected
signer is marked **untrusted**. The admin tooling refuses to list untrusted
devices in a fleet policy without an explicit override flag that is written
to the audit trail.

**Key-set rotation.** A key set is replaced only by a higher `keySetVersion`
signed by the current root, or by the successor root that the current key set
names. Key sets carry no time-based expiry in v1: the device has no time
source that the server key cannot influence, so an expiry would not be a real
boundary. Revocation is by a newer version. Section 11 states the limit this
leaves.

### 4.7 Failure modes

| Failure | Behaviour |
| --- | --- |
| No remote keys in the bundle | `LOCAL_PIN`, as today |
| Remote keys present but malformed | `ENROLLING`, `enrolment-config-invalid`; re-provision |
| Allowed modes missing or exclude fully managed (API 31+) | `RESULT_CANCELED` |
| Marker commit fails | `RESULT_CANCELED` |
| Baseline not verified | Retry or cancel; never `RESULT_OK` |
| Server unreachable | Setup finishes on the verified baseline; `enrolment-pending`; background retries with exponential backoff |
| Ticket expired, unknown or bound elsewhere | Stable code shown; device stays `ENROLLING` |
| Key set not signed by the pinned root | `key-set-root-mismatch`; never retried with another root |
| TLS pin mismatch | `tls-pin-mismatch`; no unpinned fallback |
| Process killed | Resume from the last step with the same key |

### 4.8 ADB bench path

1. Remove every account and secondary user. Install the **release** APK
   without `-t`, and run `adb shell dpm set-device-owner <full component>`.
   The device starts `UNDECIDED`.
2. Device Guard's first screen offers **Local PIN** or **Enrol with management
   server**. That screen is a non-exported activity. Choosing enrolment writes
   the remote-intent marker, moves to `ENROLLING` and applies the baseline
   **before** any network call.
3. The operator types the server host. The device fetches the key set and
   shows the root fingerprint as eight groups of four characters, to compare
   with the fleet card. The operator then types a **bench code** created per
   device by the admin tooling: 16 base32 characters (80 bits), single use,
   one-hour expiry, five attempts, bound to the first device key.
4. Enrolment continues from `KEY_CREATED`.

`adb shell am start` with extras is not used. An exported activity can be
started by any app, and `Activity.getLaunchedFromUid` identifies the caller
only in specific cases (an opted-in launcher, the same UID, platform-signed
callers, and some result-based launches on newer releases). It cannot tell a
bench shell from another app, so it cannot authenticate the bench.

**Converting a `LOCAL_PIN` device** uses the same screen from the local
console with a live PIN session. The device writes the marker, switches to
`ENROLLING` and applies the baseline before any network call. Its previous
local choices are discarded. The first fleet policy then sets everything.

### 4.9 Tests

- Python: the remote options; ticket from the environment only; batch file
  through an environment-named path with mode checks; no ticket value in any
  output; `dg.remote.*` and `ticket` refused on the generic path; size limit.
- Manifest: both activities exported, `DEFAULT`, `BIND_DEVICE_ADMIN`.
- JVM: `ProvisioningModeResultTest` (API 31+: allowed list missing → cancel,
  list without fully managed → cancel; API 29–30 → fully managed);
  `RemoteIntentMarkerTest` (written before parsing; commit failure cancels);
  `ComplianceCompletionTest` (no `RESULT_OK` without a verified baseline,
  whatever the number of failures); `ManagementModeDecisionTest` (the table
  in 4.3); `NoPinOutsideLocalModeTest`; `EnrolmentBaselineTest` (content and
  pinned hash; the selection is configured; `UNPINNED` trust matches
  `LockdownPackages.grantsManagementTrust`); `EnrolmentStateMachineTest`
  (resume after each step with the same key; key set accepted before any time
  document).
- Hardware, new group in [`hardware-validation.md`](hardware-validation.md):
  QR enrolment through both activities on each supported setup wizard;
  baseline failure ends in cancel; server-down enrolment ends on a verified
  baseline; bench enrolment of a used device; attestation fields recorded.

---

## 5. Signed documents, sync and the apply journal

### 5.1 Envelope

The update envelope is generalised so that one verifier serves updates and
management:

```json
{
  "format": "dg-signed/1",
  "keyId": "<base64url SHA-256 of signer SPKI>",
  "payload": "<base64url UTF-8 JSON bytes>",
  "signature": "<base64url DER ECDSA P-256 over the payload bytes>"
}
```

The signature covers the exact payload bytes, so no canonicalisation is
needed. The envelope is limited to 64 KiB.

### 5.2 Common header and closed schema

| Field | Rule |
| --- | --- |
| `schemaVersion` | Integer; unknown versions are refused |
| `type` | `keyset`, `fleet-policy`, `overlay`, `command`, `time`, `recovery` |
| `fleetId` | Must equal the enrolled fleet |
| `devices` / `deviceId` | `fleet-policy` and `recovery` list device IDs (1–256) and the device accepts only if it is listed; other types bind exactly one `deviceId` (`keyset` uses `*`) |
| `keySetVersion` | Must be at least the device's key-set floor |

The schema is closed: unknown fields at any level are refused
(`doc-field-unknown`). A document that is only partly understood is never
applied.

### 5.3 Document types

| Type | Signer | Authority | Ordering | Time rule |
| --- | --- | --- | --- | --- |
| `keyset` | Fleet root | Defines the other keys | `keySetVersion` strictly increasing | None (4.6) |
| `fleet-policy` | Fleet policy key | May set any policy (it is the administrator) | `fleetPolicyVersion` strictly increasing per fleet; **no predecessor hash**, so any newer version is accepted directly | None |
| `overlay` | Server key | Keep or tighten only (6.4), relative to the **accepted** desired state | `overlayVersion` strictly increasing; `baseFleetPolicyVersion` must equal the accepted fleet policy; `previousSha256` must equal the accepted desired-state hash | `expiresAt` checked against server time; harmless if forged, because an overlay can only tighten |
| `command` | Server key | `lock_now`, `report_now` only (7) | `sequence` strictly increasing | 15-minute start validity, checked against server time and pinned to the device's monotonic clock at acceptance (5.5) |
| `time` | Server key | Anchors server time for the rules above | Echoes the request nonce | 5 minutes |
| `recovery` | Fleet policy key | Installs a recovery verifier (8) | `recoveryVersion` per device strictly increasing | None |

**Why there is no stall.** A fleet policy needs no predecessor, so a device
that missed versions jumps straight to the newest one it receives. Overlays
are rendered per device on every sync against the accepted hash that the
device reports. There is no chain of stored overlays to replay, so an
expired, revoked or failing link never blocks progress: the server simply
renders the next overlay against what the device reports. A newer fleet
policy resets the overlay: the accepted state becomes the fleet policy
itself.

### 5.4 Time

The device uses server time only for overlay and command validity, and both
can only keep, tighten or lock. A compromised server that lies about time
gains nothing it could not get by signing a fresh document. Fleet policies,
key sets and recovery documents never depend on time.

Durations measured on the device (command start validity after acceptance,
recovery session length) use `SystemClock.elapsedRealtime` together with the
boot count at acceptance. A reboot ends them.

**No delivery latency is promised.** The pull period is a request to
`JobScheduler`. Doze and lost connectivity can defer delivery indefinitely,
so the observable limits are the command's validity and its delivery status
in the report.

### 5.5 Accept, journal, apply

Device state is kept in credential-protected storage. Each step that changes
it is one `commit()`. The device keeps two hashes apart:

- `acceptedSha256` — the desired state (fleet policy plus overlay) the device
  has accepted. Ordering checks and the keep-or-tighten comparison use this.
- `verifiedSha256` — the last desired state that a reconciliation pass read
  back as verified. This is evidence only, and the report carries both.

For a **policy** (fleet policy or overlay):

1. Verify the signature, type, binding, floors and ordering.
2. Check authority: a fleet policy needs the fleet policy key; an overlay must
   pass 6.4 against the accepted state.
3. In one commit: raise the floors, store the payload bytes as the new
   accepted state, and set `acceptedSha256`. If the commit fails, refuse with
   `journal-write-failed` and change nothing.
4. Project the accepted state into the stores through `AuthorizedPolicyWriter`
   (6.5).
5. Reconcile and read back. On success, set `verifiedSha256`; on failure,
   record the error codes. The lifecycle triggers retry, and accepted state is
   kept.

After a crash, a device whose `verifiedSha256` differs from `acceptedSha256`
runs steps 4–5 again from the stored bytes. That is safe at any age: the
accepted state was authorised when it was accepted, and an overlay can only
be stricter than the fleet policy it rests on. A replay of the same envelope
is refused by the floors.

For a **command**:

1. Verify, then commit an entry `{sequence, kind, state: ACCEPTED,
   cutoffElapsed, bootCount}` together with the raised `sequence` floor.
   `cutoffElapsed` is the remaining validity mapped onto the monotonic clock
   at acceptance.
2. Before dispatch, check that the boot count is unchanged and that
   `elapsedRealtime < cutoffElapsed`. If not, record `command-expired` and
   stop.
3. Commit `state: DISPATCHING`, call the platform once, then commit
   `state: DONE` with the result.
4. After a crash, an entry in `ACCEPTED` repeats step 2, so an entry from a
   previous boot is expired. An entry in `DISPATCHING` is **never dispatched
   again**; it is reported as `dispatch-outcome-unknown`. Commands therefore
   run at most once.

Fault-injection tests kill the process after every commit and at the
dispatch boundary, then assert the resumed outcome and the replay refusal.

v1 has no device-protected restore record, because nothing in v1 relaxes a
device temporarily. There is therefore no second store to keep consistent.
The remote-intent marker is a single write-once flag.

### 5.6 Sync transport

- **Pull.** `RemoteSyncJobService` (`BIND_JOB_SERVICE`, persisted,
  `NETWORK_TYPE_ANY`). It runs on a requested 15-minute period, at boot, on
  own-package replacement and on network change.
- **Request.** `POST /v1/sync` with `{deviceId, nonce, keySetVersion,
  fleetPolicyVersion, acceptedSha256, verifiedSha256, lastCommandSequence,
  report}`. A header carries a device-key signature over the method, path,
  timestamp and body digest. TLS uses the platform trust store plus the
  optional SPKI pins from enrolment, checked in a wrapping `X509TrustManager`.
  Redirects are refused.
- **Response.** A `time` document echoing the nonce; a newer key set if one
  exists; the newest fleet policy listing this device if newer; an overlay
  rendered against the reported `acceptedSha256` if the desired state differs;
  pending commands.

### 5.7 Failure codes

Every refusal carries a stable code, changes nothing and is reported:
`doc-signature-invalid`, `doc-key-unknown`, `doc-device-not-listed`,
`doc-version-rollback`, `doc-base-mismatch`, `doc-field-unknown`,
`doc-field-invalid`, `doc-expired`, `doc-type-unexpected`,
`overlay-not-tightening` (with the first offending field),
`journal-write-failed`, `command-expired`, `dispatch-outcome-unknown`.

### 5.8 Test vectors

A committed vector set (envelopes, public test keys, prior state, expected
verdict and code) is consumed by the device tests, the server tests and the
admin tooling tests. It covers:

- valid documents of every type;
- wrong key, wrong role and unknown key;
- key-set rollback, key set before time, successor root;
- device not listed; wrong fleet; unknown field;
- fleet policy version jump and replay;
- overlay with a wrong base or previous hash;
- every keep-or-tighten case of 6.4, including absent packages, mode
  switches, unconfigured selections, missing control keys, the Play floor,
  the debugging control, and fields that only a fleet policy may change;
- command expiry by time, by monotonic cutoff and by reboot; dispatch replay;
- oversized and malformed input.

---

## 6. Policy model and the keep-or-tighten rule

### 6.1 Policy document

Fleet policies and overlays carry the same complete policy body:

```json
{
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
  "sync": { "pullMinutes": 15 },
  "locale": "iw"
}
```

### 6.2 Missing, null and unknown values

| Field | Missing | `null` | Unknown value |
| --- | --- | --- | --- |
| `protection.state` | Refused | Refused | Refused (only `ON` is valid in `REMOTE`) |
| `apps.mode`, `apps.allowed` | Refused (an empty list is a configured, empty selection) | Refused | Refused |
| `apps.systemSelection` | Empty | Refused | Refused |
| `apps.playCompatibility` | `false` | Refused | Refused |
| `systemControls.<key>` | The profile default (`ENFORCED_SINCE_PILOT`, `PRODUCTION_ONLY`, `OPT_IN`), then the Play and home-filter floors | Refused | Unknown key refused |
| `homeFilter` | Off | Refused | Refused (validated by the existing record constructors) |
| `managementPins` | `MANAGEMENT_DEFAULTS` without pins (`UNPINNED`, trusted, as today) | Refused | Refused |
| `kiosk` | `OFF` | Refused | Refused |
| `sync.pullMinutes` | 15 | Refused | Outside 15–240 refused |
| `locale` | Device default | Refused | Refused |

### 6.3 Projection into today's stores

| Field | Store (exists today) | Note |
| --- | --- | --- |
| `apps.mode`, `apps.allowed` | `AllowedAppsStore.setProtectionMode`, `setAllowedPackages` | Written under the named mode and marked configured. The other mode's selection is **cleared**, so a later mode switch cannot bring it back |
| `apps.systemSelection` | `setAdminSelectedSystemPackages`, `recordSystemRiskAcceptance` | The signer and version are the risk acceptance; a mismatch is not applied and is reported |
| `apps.playCompatibility` | `PlayStoreCompatibilityStore.setEnabled` | — |
| `systemControls` | `SystemPolicyStore.setRequested` | A missing key clears the stored choice |
| `homeFilter` | `HomeFilterController.enable`/`disable`/`installCa`/`removeCa` | Validated before anything is written |
| `managementPins` | `AllowedAppsStore.setManagementCertificatePins` | — |
| `kiosk` | `KioskController` transitions | Fleet policy only |
| `locale` | `AppLocales.apply` | — |

### 6.4 The keep-or-tighten rule for overlays

An overlay is accepted only if its policy grants **no permission** that the
accepted state does not grant. The comparison is made over **policy rules,
not installed packages**. It therefore covers packages that are not
installed yet, and it gives the same answer on the device, on the server and
in the admin tooling, because no device inventory is involved.

**Fields an overlay may change**, and how:

| Field | Overlay may | Comparison |
| --- | --- | --- |
| `apps.mode`, `apps.allowed` | Narrow the permitted set | See below |
| `systemControls.<key>` except `developer_options_and_adb` | Turn a control on | Each control's effective request (profile default, stored choice, Play floor, home-filter floor), computed exactly as `SystemPolicyEnforcer.requestedFor`, is on in the candidate wherever it is on in the accepted state. The floors come from fields that must be equal (below), so they are the same on both sides |
| `sync.pullMinutes` | Any value from 15 to 240 | Neutral |
| `locale` | Any value | Neutral |

**Fields an overlay must leave equal to the accepted state** (value-equal
after resolving 6.2). These are fields where either direction can open
something or cut a recovery path, so only a fleet policy may change them:

- `protection` and `managementMode`;
- `apps.systemSelection`: removing a package un-manages it, and an
  un-managed package is no longer hidden;
- `apps.playCompatibility`: turning it on makes Play available, and turning
  it off removes the install-control floor;
- `developer_options_and_adb`: turning it on removes ADB break-glass;
- `homeFilter`: routing, CA and VPN identity;
- `managementPins`: under today's code an `UNPINNED` package is trusted, a
  new pin can hide a working VPN, and a changed pin can trust another
  signer;
- `kiosk`.

**The app rule.** Let `permitted(policy)` be the set of package names the
mode's selection leaves visible. This is the part the policy controls. The
built-in catalogue, the WebView provider, essential system packages, trusted
management packages, the kiosk target and Play compatibility act identically
on both sides: they depend on the build, on fields that must be equal, or on
device facts the policy does not change.

| Accepted | Candidate | Accepted only if |
| --- | --- | --- |
| `ALLOW` with list `A` | `ALLOW` with `A'` | `A' ⊆ A` |
| `BLOCK` with list `B` | `BLOCK` with `B'` | `B' ⊇ B` |
| `BLOCK` with list `B` | `ALLOW` with `A'` | `A' ∩ B = ∅` |
| `ALLOW` with list `A` | `BLOCK` with any list | Never (a blocklist permits every unlisted name) |

Entries for absent packages count like any other name. This closes the gap
the reviews found, where adding a not-yet-installed package changed neither
the installed set nor the default.

**Runtime inputs** that the writer uses but no field controls are named, so
that the evaluator and `applyPackagePolicy` cannot drift:

- the WebView provider resolved at apply time;
- the Play install-lock verification state;
- trusted management packages (including `UNPINNED`);
- the kiosk containment state.

There are no live maintenance windows in `REMOTE`, because local maintenance
is unavailable there and remote windows are Later. A shared test runs the
evaluator and `applyPackagePolicy` (with a fake gateway) over the vector
corpus. It asserts that every package visible under the candidate is also
visible under the accepted state, for each combination of runtime inputs.

### 6.5 One authority gate for every writer

```java
public sealed interface AdminAuthority permits LocalSession, AcceptedPolicy, RecoverySession {}
```

- `LocalSession` exists only while `AdminSession.isUnlocked()` and the mode is
  `LOCAL_PIN`.
- `AcceptedPolicy` is created only by the journal (5.5) for the stored
  accepted state.
- `RecoverySession` is created only by a successful recovery-code entry (8)
  and carries its fixed scope.
- The store setters that trust their caller today become package-private and
  are reachable only through `AuthorizedPolicyWriter`. That writer requires an
  `AdminAuthority` and refuses any write outside the authority's scope.
  `KioskController` and `HomeFilterController` take an `AdminAuthority`
  instead of reading `AdminSession`. A reflection test enumerates every store
  mutator and fails if one can be reached without the gate.

---

## 7. Commands, reports and MCP

### 7.1 Commands (v1)

| Command | Class | Validity | Platform call | Evidence in the report |
| --- | --- | --- | --- | --- |
| `lock_now` | Tighten | 15 min start, pinned to the monotonic clock at acceptance; at most once (5.5) | [`lockNow`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#lockNow()) | `DONE` with time, `command-expired`, or `dispatch-outcome-unknown` |
| `report_now` | Neutral | 15 min start | none (triggers a sync) | the report |

### 7.2 Reports (heartbeat)

Every sync carries a report signed with the device key. It contains the
redacted health snapshot (package census as counts, as today), the mode,
`keySetVersion`, `fleetPolicyVersion`, `acceptedSha256`, `verifiedSha256`,
the error codes from the last pass, the outcomes of recent commands, recovery
events and active recovery overrides (8.4), and the audit tail as event codes.
The server raises `device-silent` after `3 × pullMinutes + 1 h` without a
report. That is a signal, not proof of anything.

### 7.3 MCP in v1

- **Read tools** (no document is created): `device_list`, `device_status`,
  `device_audit`, `policy_get`.
- **Tighten tools**, each a prepare/confirm pair:
  - `apps_restrict_prepare` (remove names from an allowlist, add names to a
    blocklist, or switch from `BLOCK` to `ALLOW` with a disjoint list);
  - `system_control_enable_prepare` (any control except debugging);
  - `lock_now_prepare`;
  - `report_now_prepare`;
  - `sync_interval_set_prepare`;
  - `device_locale_set_prepare`.

  Prepare renders the overlay and runs the 6.4 rule. Confirm signs and queues
  it. The device runs the rule again.
- **Credential scopes:** `read`, `prepare`, `confirm`. No scope reaches the
  fleet policy key, which is not on the server. Every other console action is
  either set by a fleet policy (10) or Later (14).

**Parity in v1** means every console action is registered in one of three
classes: *overlay-tighten*, *fleet-policy only*, or *Later*. A JVM test fails
if a console action has no class, and the server's mirror test fails if an
overlay-tighten action has no MCP tool.

---

## 8. Recovery code

### 8.1 Purpose

The recovery code lets the person holding a device recover it **without
network**: for example after a broken home-filter configuration, a lost
server, or a malicious tightening by a compromised server. It is the
administrator's authority, used offline, and it has a fixed scope.

### 8.2 Generation and delivery

- The admin tooling generates the code **offline**: 20 base32 characters
  (100 bits), printed in groups of four. It also generates a 16-byte salt and
  computes `PBKDF2-SHA256(code, salt, 210000)`. At 100 bits, guessing the
  code from that value is infeasible even if the server leaks it, so v1 does
  not encrypt it to the device (this removes the earlier open question about
  encryption keys before API 31).
- The salt and value travel in a `recovery` document signed with the fleet
  policy key, listing the one device. The server only relays it.
- The device applies its own Keystore HMAC to the value and stores the result
  in a new `RecoveryCodeStore`, separate from `AdminPinStore`, so no PIN is
  needed. Lockout reuses `PinLockoutPolicy`, bound to `BOOT_COUNT`.
- A device has no recovery code until the administrator issues one after
  enrolment. Until then, recovery means a factory reset.

### 8.3 Use

The read-only console has a **Recovery** entry in `ENROLLING` and `REMOTE`.
Entering a valid code:

1. commits the consumption (the verifier is removed and the use recorded) and
   **checks the `commit()` result**; if the commit fails, the code is refused
   (`recovery-consume-failed`) and no session opens;
2. opens a `RecoverySession` for at most 30 minutes on the monotonic clock,
   ended by a reboot or process death;
3. offers only the actions in 8.4. It cannot change the app selection,
   controls, pins, kiosk or mode, and cannot set a PIN.

The use is reported on the next sync. A new code needs a new `recovery`
document.

### 8.4 Recovery actions and which state wins

Each action is a **durable override** stored in the journal. It is not a
timed relaxation, so it needs no restore timing:

| Override | Effect | Ends when |
| --- | --- | --- |
| `drop-overlay` | The accepted state becomes the accepted fleet policy without any overlay | Immediately applied; later overlays apply normally |
| `fleet-policy-only` | Overlays are refused (`overlay-suspended-by-recovery`); fleet policies still apply. This neutralises a compromised server key, which can then only withhold | A newer fleet policy arrives |
| `network-off` | The home filter is disabled (VPN lockdown, proxy and CA cleared) so that the device can reach the network and the server again | A newer fleet policy arrives (it re-applies whatever it says) |

**Precedence** in each reconciliation: the fleet policy, then any active
override, then the overlay (unless suspended). An overlay can never re-enable
the home filter while `network-off` is active, because `homeFilter` must
equal the accepted state, and the accepted state carries the override. The
report lists the active overrides. The diagnostics screen (server host, last
sync, last error codes) is read-only and needs no code.

---

## 9. Management server

A deliberately small service in a **separate repository**. The DPC repository
stays a client and holds no server secrets. A minimal **test server** with the
same API and the shared vectors is built before the device client (section
12).

| Table | Content |
| --- | --- |
| `fleets` | id, label, root digest, current key set bytes |
| `devices` | `deviceId`, state (`enrolling`, `active`, `untrusted`, `retired`), attestation facts, versions and hashes from the last report, last seen |
| `fleet_policies` | signed bytes as uploaded, version, listed devices |
| `overlays` | per device: desired overlay body, last rendered envelope |
| `commands` | per device: sequence, bytes, state (`queued`, `delivered`, `done`, `expired`, `unknown`) |
| `recovery` | signed bytes as uploaded, per device |
| `audit` | append-only, each row with the SHA-256 of the previous row, exported off the server |

Device API: `POST /v1/enrol`, `POST /v1/sync`. Admin API: upload signed key
sets, fleet policies and recovery documents (the server verifies them but
cannot create them), plus MCP (7.3).

| Failure | Effect |
| --- | --- |
| Server down | Devices keep their accepted state; nothing changes |
| Server key unavailable | No new overlays or commands; fleet policies still delivered as stored bytes |
| Server compromised | Can keep, tighten and lock; cannot open; a recovery `fleet-policy-only` override confines it to withholding (11) |
| Device silent | `device-silent` alert |
| Report not verified | Alert with the error codes |

---

## 10. Admin tooling

A new `tools/fleet_admin.py` follows the pattern of `tools/publish_update.py`.
It signs with OpenSSL from an external PEM key that is never copied, and reads
the passphrase from a named environment variable. Subcommands:

- `keyset` — build and sign a key set with the root key.
- `policy` — validate a policy body against the same schema, list the target
  devices (refusing untrusted devices without `--allow-untrusted`, which is
  written to the audit trail), render a human-readable summary and a field
  diff against the previous fleet policy, and sign with the fleet policy key.
  The rendering comes from the tool, not from the server.
- `recovery` — generate a code for one device, print it once for the
  administrator's vault, and sign the `recovery` document.
- `tickets` / `bench-code` — create enrolment tickets and bench codes.

The tool runs the shared vectors in its tests.

---

## 11. Threat model

For each threat: what v1 does, and what it does **not** cover.

- **Test-only build removal.** Remote mode refuses to enrol a build with
  `FLAG_TEST_ONLY` or `FLAG_DEBUGGABLE`, and the server rejects an attested
  signer that is not the release signer. *Not covered:* someone's own
  test-only device; it cannot join a real fleet.
- **USB debugging.** `developer_options_and_adb` is set only by a fleet
  policy. A pilot keeps ADB until production gate 3. *Not covered:* OEM
  service modes; a device that refuses the restriction (reported as a
  critical fault).
- **Recovery wipe or reflash.** Detection only: `device-silent`, and
  re-enrolment needs a new ticket and starts on the baseline. *Not covered:*
  prevention on consumer hardware.
- **Spoofed boot properties.** Hardware attestation is verified on the server;
  properties are never trusted. *Not covered:* a leaked, unrevoked
  attestation keybox; software-only attestation (marked untrusted).
- **Clock tampering.** No authority in v1 depends on time beyond overlay and
  command validity, which can only tighten or lock. *Not covered:* nothing
  security-relevant.
- **Replay.** Strict version floors per type; device listing; the
  accepted-hash base for overlays; at-most-once commands. *Not covered:* an
  attacker with root who resets app storage.
- **Compromised server (including the server key).** The attacker can keep,
  tighten, lock screens and read reports; it cannot open anything. It can also
  withhold newer fleet policies and key sets. A device that has not yet
  received a fleet policy can be held at an older, still-unseen version, but
  never at one below its floor. The recovery override `fleet-policy-only`
  ends overlay abuse on a device. *Not covered:* withholding, and
  disclosure of reports.
- **Compromised fleet policy key.** Full policy control over the listed
  devices until a key set without that key reaches them. *Not covered:* this
  is the administrator's authority by design; keep the key offline.
- **Enrolment attacks.** The remote-intent marker is written before parsing;
  there is no `RESULT_OK` without a verified baseline; there is no PIN path
  outside local modes; tickets are per device and bound to the first key;
  there is no exported bench entry. *Not covered:* someone who holds a wiped
  device and provisions it with a local QR. That is the intended local mode,
  not an attack on a fleet.
- **Leaked recovery code.** The holder gets the fixed scope of 8.4 on that one
  device, once. *Not covered:* the actions in that scope (dropping an overlay,
  turning the network filter off until the next fleet policy).
- **Malicious MCP agent.** Scopes limited to read and tighten; the device
  enforces 6.4 independently. *Not covered:* abuse of tightening and
  `lock_now`.

---

## 12. v1 delivery plan

Each PR lands with its tests. Hardware groups go into
[`hardware-validation.md`](hardware-validation.md) and are evidenced in
[`device-matrix.md`](device-matrix.md). **Remote activation is off in every
build until PR 10.** Before that, no device can reach `REMOTE` except a test
device enrolled against the test server with a debug activation flag.

| # | PR | Depends on | Tests and gate |
| --- | --- | --- | --- |
| 1 | This design document (v1 scope) | — | Independent review |
| 2 | `AuditLog` event codes alongside prose | — | Code stability; health export carries codes |
| 3 | Management modes (`UNDECIDED`, `LOCAL_PIN`, `ENROLLING`, `REMOTE`), remote-intent marker storage, first-PIN path closed, `AdminAuthority` and `AuthorizedPolicyWriter` around every store setter | 1 | `ManagementModeDecisionTest`, `NoPinOutsideLocalModeTest`, writer coverage by reflection; existing kiosk and home-filter tests unchanged |
| 4 | Shared contract: schema, document types, keep-or-tighten rule, journal states, recovery document, as committed vectors | 1 | Vectors reviewed by a second agent before any code consumes them |
| 5 | Provisioning activities per 4.2 (marker first, allowed-mode rule, compliance completes only on a verified baseline), receiver fallback, enrolment baseline; no network | 3 | Result, marker and completion tests; hardware QR provisioning to a verified baseline on each supported setup wizard, and the cancel path |
| 6 | Document verifier generalised from `UpdateEnvelopeVerifier`, the 6.4 evaluator, the journal (5.5) and `RemotePolicyApplier` through the gate; no network | 3, 4 | Vector tests; evaluator-versus-writer equivalence test; crash injection at every commit and dispatch boundary |
| 7 | `tools/provisioning_payload.py` remote options and batch input; `tools/fleet_admin.py` | 4 | Python tests (4.9); vectors |
| 8 | Test server (separate repository); device key, attestation, trust bootstrap, enrolment state machine, sync, reports, `lock_now`, `report_now` against it, behind the debug activation flag | 5, 6, 7 | Enrolment resume; key set before time; at-most-once commands; hardware enrolment against the test server, including server down |
| 9 | Recovery code: `RecoveryCodeStore`, lockout, checked consumption, `RecoverySession`, the three overrides and their precedence, read-only console entry | 6, 7 | Recovery tests; locale parity; hardware: `network-off` restores connectivity after a broken filter |
| 10 | **Activation.** Read-only remote console; activation enabled in release builds | 8, 9 | Gate: PRs 2–9 merged; hardware evidence for each supported provisioning path; production application ID and signer fixed; server hosting decided; independent review |
| 11 | Production server hardening (KMS/HSM server key, audit export) and MCP read and tighten tools with scopes | 10 | Scope tests; the server refuses non-tightening overlays; the mirror parity test |

PRs 2–7 need no server and no network.

---

## 13. Blockers and open questions

### Blockers for activation (PR 10)

1. Hardware evidence for QR provisioning to a verified baseline, on every
   supported setup wizard: activities invoked, baseline verified, cancel on
   failure, and server-down completion. Plus bench enrolment.
2. Final production application ID and signer: enrolled devices cannot move
   between application IDs without a wipe.
3. Audit event codes (PR 2).
4. An owner decision on server hosting, operation and server-key protection.
   Nothing in this repository may name it.
5. Fleet policy key custody: where the offline key lives and who may sign.

### Open questions

1. Does each target setup wizard invoke `PolicyComplianceActivity` for QR
   provisioning, and what does it do after `RESULT_CANCELED`?
2. Monthly re-attestation, and should an untrusted result only alert (v1) or
   also trigger a fleet-policy review?
3. Should v1 overlays be allowed to move freely **below** the fleet policy
   (for example to undo an earlier MCP tightening) instead of only keeping or
   tightening the accepted state? That is safe as long as the fleet policy is
   the ceiling, but it gives a compromised server the power to undo tightening.
   v1 says no; undoing a tightening means re-signing the fleet policy.
4. Google zero-touch or Samsung Knox Mobile Enrollment for devices bought
   through a reseller, later.

---

## 14. Later (separate design, not reviewed here)

Nothing in this section may be built from this document. Each item needs its
own design and review. The notes record what the reviews found, so that the
next design starts from it.

### 14.1 Server-originated loosening with human approval

The reviews showed that a WebAuthn page rendered by the server proves who
approved, not what they saw. A fix needs an approver that renders the change
from signed bytes with its own evaluator, and a binary statement bound to the
payload, base and diff. Fresh device-issued challenges stop stale approvals
from being replayed. Open problems:

- The signer and the approver wait on each other. A signed, never-executable
  proposal is needed, plus a minimal signed facts bundle for the approver,
  which the redacted health report deliberately does not carry.
- Approval-key expiry still depends on server time.
- Rebase and approval need an ordering in which a blocked chain link cannot
  stall a device.

*Why v1 is safe without it:* in v1 only the offline fleet policy key can open
anything, and the tool that signs renders the policy itself.

### 14.2 Remote pause, maintenance and console windows

Android does not expire a Device Owner restriction by itself, and
relaxations persist through reboots. The reviews found the following gaps:

- Doze rate limiting does not bound how late a close can be.
- Exact alarms need special access that a Device Owner is not exempt from
  (verify `canScheduleExactAlarms()` per build).
- A pre-unlock restore must also undo the link handlers, the blocked-browser
  component and the browser-provider suspensions that `pause()` changes, not
  only the restrictions and hidden packages.
- A credential-protected journal and a device-protected restore record need
  a crash protocol across their two commits.
- A window's start and end were mapped through the server-controlled time
  anchor, so an approved window could open outside the interval the human
  approved. A device-issued monotonic interval bound to the approval is
  needed.
- A `full` console grant authorises edits nobody reviewed.

*Why v1 is safe without it:* v1 has no temporary relaxation, and the
recovery overrides are durable states with a defined precedence.

### 14.3 Install, update and self-update windows

`DISALLOW_INSTALL_APPS` is user-wide, so lifting it, even for Device Guard's
own update, opens every visible installer. The current maintenance predicate
also unhides the entire managed-store set, with no per-store input. A later
design must either prove that every other install route stays closed on each
supported device, or render and approve the operation as a global install
window. Snapshot quarantine acts only after changes happen. A signed private
catalogue is the only update-only path. *Effect on v1:* the existing
limitation stays. While `app_stores_and_installers` is on, neither apps nor
Device Guard can update. Lifting it is a fleet policy decision with that
global meaning.

### 14.4 Browser through the filter

Device Guard's canary proves only that Device Guard's own traffic is
filtered. A browser exemption needs:

- per-browser and per-firmware evidence, including TWA, Custom Tabs,
  WebView and tunnel drop;
- gateway egress denial, backed by evidence from an authenticated issuer
  with an expiry and a revision the device can enforce;
- separate verification that the browser enforces its managed restrictions.
  Chrome documents `ProxyMode`, `IncognitoModeAvailability`,
  `DnsOverHttpsMode` and `ForceGoogleSafeSearch` on Android (verify per
  version). The Device Policy Manager getter confirms only the stored bundle.

Tailscale documents an Android `AuthKey` managed setting for automatic
sign-in. That is a credential, so it can never travel in a QR code, and
activating it zero-touch on the pinned APK is still unknown. *Effect on v1:*
browsers stay blocked as today.

### 14.5 Remote wipe and reboot

Wipe needs two root-registered administrator identities. Both statements
must be verified against the same exact request before the challenge is
consumed atomically. Single-administrator fleets cannot have it. On API 34+
`wipeDevice()` is required (`wipeData()` can throw for a Device Owner
targeting 34+), and silence is never proof of a wipe. `reboot()` throws
during a call. *Effect on v1:* neither is offered.

### 14.6 Accessibility and input-method allowlists, system update policy

The permit APIs return `false` when an enabled non-system service is left
out. Input-method policy also has a foreground-user condition. Restricted
Settings may affect Device Guard itself on Android 13+. OTA policy needs
window minutes of `0–1439`, a later start crosses midnight, and freeze
history can invalidate a policy. Postponing and freezing delay patches.
*Effect on v1:* not set; today's behaviour.

### 14.7 MCP write actions beyond tightening, wake channel, content check

These depend on 14.1. The accessibility content-check pilot also changes a
README claim and needs its own privacy review.

---

## Appendix A: Review resolution

Two independent reviews by a different AI model, run read-only against the
code, examined revisions 1 and 2. **Fixed** means v1 contains the change.
**Later** means the capability is no longer in v1, so the risk cannot arise
from v1. **Rejected** means the finding was checked against the code and did
not hold. No finding was rejected; one platform claim in the round 2 review
was corrected in the reviewer's favour.

### Round 2 findings (revision 2)

| Finding | Verified against | Disposition | Where / why |
| --- | --- | --- | --- |
| **P1-A** The evaluator compares installed packages, missing later permissions; missing runtime inputs; `UNPINNED` trust mismatch | `applyPackagePolicy` (selection applies only to managed and admin-selected names; WebView provider, Play lock and management trust are exceptions); `LockdownPackages.grantsManagementTrust` (`UNPINNED` grants trust) | **Fixed** | 6.4 compares policy rules over names, including absent packages; the runtime inputs are named and an equivalence test ties them to the writer; fields whose effect depends on runtime trust (pins, Play, system selection, home filter, kiosk) may change only through a fleet policy; the baseline mirrors `UNPINNED` trust (4.4) |
| **P1-B** `ENROLLING` can finish without a verified baseline or expose first-PIN setup | `MainActivity.initialScreen` (no PIN → `PIN_SETUP`), `savePin` (guards only replacement) | **Fixed** | 4.2: marker written before parsing, commit failure cancels, no `RESULT_OK` without a verified baseline; 4.3: the mode table and closed `initialScreen`, `savePin` and `unlockWith` paths |
| **P1-C** Journal resume restarts expired work, can double-dispatch, and conflates the accepted and applied hash | Revision 2 §6.6 | **Fixed** for v1 | 5.5: `acceptedSha256` separate from `verifiedSha256`; command entries carry a monotonic cutoff and boot count; `DISPATCHING` is never re-dispatched |
| **P1-D** Direct-boot restore is partial; two-store crash protocol missing | `LockdownPolicyController.pause` side effects | **Later** (14.2) | v1 has no temporary relaxation and no device-protected restore record; recovery overrides are durable journal states (8.4) |
| **P1-E** Approved window timing depends on server time | Revision 2 §§5.4, 6.4 | **Later** (14.1, 14.2) | v1 has no windows and no approvals; no v1 authority depends on time (5.4) |
| **P2-A** Console and recovery grants unbounded; recovery needs a PIN and ignores the consuming commit | `AdminPinStore.verify` (`NOT_CONFIGURED` without a PIN; unchecked `commit()`) | Console: **Later** (14.2). Recovery: **Fixed** | 8: separate `RecoveryCodeStore`, checked consumption, three durable overrides with defined precedence |
| **P2-B** Signer and approver deadlock; approver lacks facts | Revision 2 §§8.3–8.5, `DeviceHealthRedaction` | **Later** (14.1) | v1 has no approval flow; the offline tool signs complete documents and renders them itself (10) |
| **P2-C** Catch-up stalls behind an unusable link; bootstrap ordering | Revision 2 §5.7 | **Fixed** | 5.3: fleet policies need no predecessor; overlays are rendered against the reported accepted hash on every sync; 4.6: key set verified by signature before any time document; no key-set time expiry |
| **P2-D** Browser evidence lifecycle | Revision 2 §7.3 | **Later** (14.4) | Browsers stay blocked in v1 |
| **P2-E** Install windows wider than labelled | `MaintenanceAppPolicy` (whole managed-store set) | **Later** (14.3) | No install windows in v1 |
| **P2-F** PR plan inverts safety dependencies | Revision 2 §14 | **Fixed** | 12: 11 PRs with dependency columns; provisioning plumbing (PR 5) separate from activation (PR 10); activation off until the gate |
| **P2-G** Wipe quorum conflict | Revision 2 §9.1 | **Later** (14.5) | No wipe in v1; the note records the two-identity rule |
| **P3** Worst-case pull latency claim | — | **Fixed** | 5.4 promises no latency |
| **P3** Batch ticket input ambiguous | `tools/provisioning_payload.py` env-only pattern | **Fixed** | 4.1: an environment variable holds the path of an owner-only file; outputs never carry ticket values |
| Platform: allowed-modes fallback | Android 12 contract | **Fixed** | 4.2: rule by API level; API 31+ cancels without the list |
| Platform: launcher UID wording | Activity reference | **Fixed** (wording) | 4.8 lists the cases; the conclusion stands |
| Platform: alarms and Doze bound | — | **Later** (14.2) | — |
| Platform: managed VPN sign-in "undocumented" | Tailscale system policies (`AuthKey`) | **Corrected** in the reviewer's favour | 14.4; it is a credential and cannot travel in a QR code |
| Platform: Chrome policies, permit APIs, wipe, reboot, OTA | — | **Later** | 14.4–14.6 carry the confirmed facts |

### Round 1 findings (revision 1) — final disposition

| Finding | Disposition |
| --- | --- |
| P1.1 Raw-field classification | **Fixed** in v1 by the rule-based comparison of 6.4 (see P1-A) |
| P1.2 Enrolment and recovery authority | **Fixed** (4.2–4.4, 8) |
| P1.3 Replay, misleading approval, apply ordering | Replay and ordering: **Fixed** (5.3, 5.5). Approval: **Later** (14.1) |
| P1.4 Restore timing, Direct Boot, `lock_now` | `lock_now`: **Fixed** (5.5, 7.1). Restore timing: **Later** (14.2) |
| P2.1 QR and ADB contract | **Fixed** (4.1, 4.2, 4.5, 4.8) |
| P2.2 Update-only claim | **Later** (14.3) |
| P2.3 Filter proof is not browser proof | **Later** (14.4) |
| P2.4 API success conditions | **Later** (14.5, 14.6) |
| P2.5 PR order and latest-only sync | **Fixed** (5.3, 12) |
| P3 Command contract completeness | **Fixed** for v1 (7); the rest is **Later** |
