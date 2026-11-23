# Remote management design

**Status: accepted direction (v1); implementation PRs must meet the acceptance
criteria in [section 15](#15-acceptance-criteria-carried-into-prs). Revision 4,
final. Nothing in this document is implemented yet unless a section says
"exists today".**

Three independent reviews found new P1 issues each time the design let the
online server change what a device may do. Revision 4 therefore keeps v1 to the
smallest useful core:

- **v1 (build now)**, sections 1–13. A **fresh** device enrols into a
  verified, locked-down baseline. From then on it applies only **complete
  fleet policies signed with an offline key** held by the administrator. The
  online server relays those signed documents, collects status, and can send
  exactly two commands: `lock_now` and `reapply` (re-apply the current policy).
  An offline recovery code covers the device losing its network.
- **Later (separate design, not reviewed here)**, section 14. Server overlays,
  converting an already-managed device, approval-based loosening, timed and
  install windows, browser exemptions, wipe, the accessibility and
  input-method allowlists, and MCP actions that change policy. Each has a short
  note on the open problems the reviews found. None of it may be built from
  this document.

Every review finding and its disposition is listed in
[Appendix A](#appendix-a-review-resolution).

Remote management is an **optional mode**. The local, PIN-protected mode that
ships today stays the default and works without any server, so the README
statement that the project has "no required management cloud" remains true.

Statements marked **(verify)** rely on documentation or platform behaviour not
yet proven on the target hardware. They must be checked before the PR that
depends on them is merged.

## Contents

1. [Goals, non-goals and scope](#1-goals-non-goals-and-scope)
2. [What exists today](#2-what-exists-today)
3. [Architecture and keys](#3-architecture-and-keys)
4. [Enrolment](#4-enrolment)
5. [Signed documents, sync and the policy journal](#5-signed-documents-sync-and-the-policy-journal)
6. [Policy model](#6-policy-model)
7. [Commands, reports and MCP](#7-commands-reports-and-mcp)
8. [Recovery code](#8-recovery-code)
9. [Management server](#9-management-server)
10. [Admin tooling](#10-admin-tooling)
11. [Threat model](#11-threat-model)
12. [v1 delivery plan](#12-v1-delivery-plan)
13. [Blockers and open questions](#13-blockers-and-open-questions)
14. [Later (separate design, not reviewed here)](#14-later-separate-design-not-reviewed-here)
15. [Acceptance criteria carried into PRs](#15-acceptance-criteria-carried-into-prs)
- [Appendix A: Review resolution](#appendix-a-review-resolution)

---

## 1. Goals, non-goals and scope

### v1 goals

- **Zero-touch-style enrolment of fresh devices into a verified baseline.** A
  factory-reset device enrols by scanning one QR code. Device Guard becomes
  Device Owner, applies a built-in baseline, reads it back, and only then lets
  setup finish.
- **Only the administrator's offline key decides what a device may use.** Every
  policy a device applies is a complete document signed with the fleet policy
  key. That key is never on the server.
- **The online server cannot change any policy.** It relays signed documents,
  stores reports, and can send `lock_now` and `reapply`.
- **No on-device administrator PIN in remote mode.** The console is a read-only
  status screen with one entry for the recovery code.
- **Every change is read back**, as today. The read-back goes to the server in
  a signed report.

### Non-goals

- Replacing Android Enterprise or managed Google Play. Device Guard stays a
  self-hosted DPC.
- Making consumer hardware impossible to reset or reflash. See
  [`SECURITY.md`](../SECURITY.md) and section 11.
- Silent enrolment. The platform consent screen stays, and
  `PROVISIONING_SKIP_USER_CONSENT` is never emitted.
- Converting a device that is already managed locally. That includes the
  pilot device already deployed (section 14.2).
- Anything else in section 14.

### Scope

| Capability | v1 | Later |
| --- | --- | --- |
| QR enrolment after a factory reset; bench enrolment of a never-managed device | ✓ | |
| Complete fleet policies signed offline; the only way a policy changes | ✓ | |
| Signed status reports (heartbeat) | ✓ | |
| `lock_now`, `reapply` | ✓ | |
| Offline recovery code with fixed, durable actions | ✓ | |
| MCP: read tools, `lock_now`, `reapply` | ✓ | |
| Server overlays (server-signed policy changes, even tightening) | | ✓ 14.1 |
| Converting a locally managed device to remote | | ✓ 14.2 |
| Loosening with human approval; remote pause, maintenance and console windows | | ✓ 14.3–14.4 |
| Install, update and self-update windows | | ✓ 14.5 |
| Browser through the filter | | ✓ 14.6 |
| Remote wipe and reboot | | ✓ 14.7 |
| Accessibility and input-method allowlists; system update policy | | ✓ 14.8 |
| MCP actions that change policy | | ✓ 14.9 |

---

## 2. What exists today

| Area | Exists today | Where |
| --- | --- | --- |
| Verified apply | Every package visibility change and user restriction is read back; partial results are failures | `policy/LockdownPolicyController.java`, `policy/SystemPolicyEnforcer.java` |
| Single policy thread | All `DevicePolicyManager` writers run on one FIFO executor | `policy/PolicyReconciliationCoordinator.java` |
| Lifecycle reconciliation | `PolicyRefreshReceiver` (`BOOT_COMPLETED`, `MY_PACKAGE_REPLACED`; not direct-boot aware) chooses **apply or pause from the stored protection flag**; `PACKAGE_ADDED`/`PACKAGE_REMOVED`; periodic sweep | `receivers/PolicyRefreshReceiver.java`, `admin/LockdownDeviceAdminService.java` |
| App policy storage | Mode and selection are separate preference writes, and both use asynchronous `apply()` (`setProtectionMode`, `setAllowedPackages`); each mode has its own selection and "configured" flag; an unconfigured selection hides no managed app | `policy/AllowedAppsStore.java` |
| Package decision order | Built-in block, then the mode's selection (managed and admin-selected system names), then exceptions: store maintenance, Play compatibility, kiosk escape surfaces, trusted management, WebView provider, essential system, kiosk target | `LockdownPolicyController.applyPackagePolicy` |
| Management trust | A management package is trusted when its signer matches a pin **or when it has no pin** (`UNPINNED`) | `policy/LockdownPackages.java` (`grantsManagementTrust`) |
| Maintenance | A stored live window changes the restrictions and store visibility that a pass applies and verifies against | `maintenance/`, `LockdownPolicyController.liveMaintenanceWindow` |
| System controls | 16 controls; base policy = stored choices raised by the Play and home-filter floors; profile defaults | `policy/SystemPolicyControl.java`, `policy/SystemPolicyStore.java` |
| Local authority | PIN and a device-generated recovery code; with no PIN, `initialScreen()` opens `PIN_SETUP`; `savePin()` checks the session only when replacing; `AdminPinStore.verify` returns `NOT_CONFIGURED` without a PIN and does not check the commit that consumes a recovery code | `security/AdminPinStore.java`, `ui/MainActivity.kt` |
| Signed self-update | Version floor, signer lineage, `PackageInstaller`; blocked while `DISALLOW_INSTALL_APPS` is on | `updates/`, [`secure-updates.md`](secure-updates.md) |
| Offline signing pattern | OpenSSL with an external PEM key never copied; passphrase from a named environment variable | `tools/publish_update.py` |
| Provisioning payload | QR builder; refuses admin-extras keys containing `credential`, `passcode`, `passphrase`, `password`, `pin`, `recovery`, `secret`, `token` (not `ticket`) | `tools/provisioning_payload.py` |
| Health report | Redacted snapshot; package census as counts | `health/` |
| Audit log | PR 2 implemented: stable event codes in storage and the redacted health export; existing prose stays readable on-device | `policy/AuditLog.java`, `policy/AuditEvent.java` |

### Gaps v1 must close

1. No `GET_PROVISIONING_MODE` / `ADMIN_POLICY_COMPLIANCE` activities
   ([`provisioning.md`](provisioning.md)).
2. Audit event codes implemented (PR 2).
3. Store setters trust their caller and write asynchronously.
4. The first-PIN path is open to anyone holding a Device Owner device with no
   PIN.
5. The generic admin-extras option accepts `dg.remote.ticket`.
6. The boot receiver and the maintenance store act on legacy local state with
   no notion of a remote mode.

---

## 3. Architecture and keys

```text
  administrator workstation (offline keys)         agent (MCP client)
  tools/fleet_admin.py: key sets, fleet policies,   read, lock_now, reapply
  recovery codes, tickets, attestation checks              |
          | signed files                                    |
          v                                                 v
  +-------------------------------------------------------------+
  |  management server (holds only the server key)              |
  |  relays signed documents as opaque bytes                    |
  |  signs only nonce-bound lock_now / reapply commands         |
  +-------------------------------------------------------------+
          ^  HTTPS pull, device-signed request with a fresh nonce
          v
  +-------------------------------------------------------------+
  |  Device Guard (Device Owner)                                |
  |  verify -> policy journal (one commit) -> ensureProjected   |
  |  -> LockdownPolicyController.apply -> read-back -> report   |
  +-------------------------------------------------------------+
```

| Key | Holder | Signs | If compromised |
| --- | --- | --- | --- |
| **Fleet root key** (P-256) | Offline vault; rotations only | Key sets (fleet policy keys, server key, server URL) | Full fleet control |
| **Fleet policy key** (P-256) | Administrator, offline | Fleet policies and recovery documents | Any policy on the listed devices |
| **Server key** (P-256) | Server, ideally KMS/HSM | `lock_now` and `reapply` commands bound to a device's sync nonce | Lock screens and trigger re-applies; nothing else |
| **Device key** (P-256) | Device Keystore, attested | Enrolment transcript, sync requests, reports | That device's reports can be forged |

The release (APK) signing key and the update-metadata key of
[`secure-updates.md`](secure-updates.md) stay separate and unchanged. P-256 is
chosen because `UpdateEnvelopeVerifier` already verifies `SHA256withECDSA`
across the supported range, and Keystore attests P-256 keys. Platform Ed25519
starts at API 33.

---

## 4. Enrolment

v1 enrols **only fresh devices**: a device that is factory reset and
provisioned from a QR code, or a device that a bench operator has just made
Device Owner over ADB and that has never been managed by Device Guard (4.8).

### 4.1 QR payload and the provisioning tool

Admin extras bundle (`PersistableBundle`, string values):

| Key | Meaning |
| --- | --- |
| `dg.remote.v` | Schema version (`1`) |
| `dg.remote.server` | Server base URL; clean HTTPS, no credentials, query or fragment |
| `dg.remote.root` | base64url SHA-256 of the root key SPKI |
| `dg.remote.tls` | Up to two base64url SPKI pins (optional) |
| `dg.remote.ticket` | One-time, per-device ticket (4.5) |
| `dg.remote.fleet` | Display label only |

`tools/provisioning_payload.py`:

- The generic `--admin-extra` option refuses every `dg.remote.*` key, and
  `ticket` joins `FORBIDDEN_ADMIN_EXTRA_FRAGMENTS`.
- Dedicated options: `--remote-server`, `--remote-root`, `--remote-tls-pin`
  (at most two), `--remote-fleet`, `--enrolment-ticket-env NAME`. The ticket
  is read only from that variable, never echoed, and the output is written
  owner-only. The summary carries `"enrolmentTicketEmbedded": true`.
- Batch: `--enrolment-tickets-file-env NAME`. The variable holds the **path**
  of an owner-only (`0600`, checked) file with one ticket per line. Errors and
  summaries name line numbers, never ticket values, and tests assert that no
  ticket value reaches any output.

### 4.2 Provisioning activities

Both activities are declared `android:exported="true"`, with an intent filter
holding the action and `android.intent.category.DEFAULT`, and
`android:permission="android.permission.BIND_DEVICE_ADMIN"`. This is the same
shape Google's Test DPC uses, and `tools/test_manifest_permissions.py` pins it.

**Build gate.** A build constant `REMOTE_ENROLMENT_ENABLED` is `false` in
release builds until PR 9 (section 12). One shared check,
`RemoteEnrolmentGate.permits()`, runs first in **every** entry point that can
start a remote mode: both provisioning activities, the receiver fallback and
the bench option. While it is false, a bundle with any `dg.remote.*` key makes
both activities return `RESULT_CANCELED` before anything is written, the
receiver writes nothing and records `remote-enrolment-disabled`, and the bench
option is not shown. A device never enters a remote mode from a build that
cannot finish enrolment.

**Remote intent first.** With the gate on, the first statement of each
activity's `onCreate` checks the raw bundle for any `dg.remote.*` key. If one
is present, it writes `remoteIntent = true` to device-protected storage with
`commit()`, before any parsing. A failed commit returns `RESULT_CANCELED`. The
marker is cleared only by a factory reset.

1. **`ProvisioningModeActivity`**: on API 31+ it returns fully managed mode
   only if `EXTRA_PROVISIONING_ALLOWED_PROVISIONING_MODES` is present and
   contains it, and `RESULT_CANCELED` otherwise. On API 29–30 it returns fully
   managed mode. It writes nothing but the marker. Setup may skip this
   activity when only one option is valid.
2. **`PolicyComplianceActivity`** writes the marker, parses the bundle
   **itself**, decides the mode (4.3) and applies the baseline (4.4). It
   returns `RESULT_OK` **only after the baseline is read back as verified**.
   On failure it shows the stable code with **Retry** and **Cancel setup**.
   Cancel returns `RESULT_CANCELED` (verify each target setup wizard's
   behaviour; a factory reset is expected). It never returns `RESULT_OK` after
   failures. Server reachability is irrelevant here: the baseline is local, and
   enrolment with the server continues in the background (4.6).
3. **The admin receiver is not a substitute.** Older platform paths forward
   admin extras to `onProfileProvisioningComplete` after setup has already
   finished, so the receiver cannot hold setup until a baseline is verified. If
   it sees remote keys and no record that the compliance activity completed, it
   writes the marker and applies the baseline as damage control, and reports
   `compliance-gate-skipped`. **Remote QR enrolment is supported only on setup
   wizards shown on hardware to invoke `PolicyComplianceActivity`.**

### 4.3 Management modes and the mode boundary

| Mode | Authority | Console |
| --- | --- | --- |
| `UNDECIDED` | None | Device Owner set over ADB with no bundle: local PIN setup, or bench enrolment if the device is fresh (4.8). Today's ADB flow. |
| `LOCAL_PIN` | PIN session | Full console, unchanged |
| `ENROLLING` | Built-in baseline on first enrolment. After re-anchor, existing restrictions stay in effect while the device waits for a signed replacement policy. | Read-only status and storage recovery |
| `REMOTE` | Fleet policies; `lock_now`, `reapply` | Read-only status and the recovery entry |

Mode decision, applied on every start before any screen or reconciliation:

| Facts | Mode |
| --- | --- |
| Marker present | `ENROLLING` until enrolment completes, then `REMOTE`; never `LOCAL_PIN` or `UNDECIDED`, whatever the parse result or mode record |
| Compliance or receiver saw a bundle with no remote keys | `LOCAL_PIN`, written explicitly |
| No marker and no mode record | `UNDECIDED` |
| Unreadable mode record without the marker | `UNDECIDED` |

**The boundary.** In `ENROLLING` and `REMOTE`:

- **No first PIN.** `initialScreen()` returns `PIN_SETUP` only in `LOCAL_PIN`
  or `UNDECIDED`. `savePin()` refuses in any other mode. `unlockWith()` never
  routes to `PIN_SETUP`.
- **No legacy writer.** `PolicyRefreshReceiver` and the periodic sweep do not
  choose between apply and pause from the legacy stores. They call the remote
  path, `RemotePolicyApplier.reconcile()` (5.5), which leaves current
  restrictions in effect during storage refusal and re-anchor.
- **No maintenance.** Writing the marker also clears `MaintenanceStore` in the
  same flow. `liveMaintenanceWindow` returns no window outside `LOCAL_PIN`, and
  `MaintenanceCoordinator.open` refuses. A fresh device has none anyway; this
  is defence in depth.
- **Marker-only recovery.** If the process dies after the marker and before
  the baseline is verified, the next start sees the marker with no verified
  baseline and applies the baseline again before anything else.

`ModeBoundaryTest` drives every entry point (`initialScreen`, `savePin`,
`unlockWith`, the boot receiver, the sweep, maintenance open) in `ENROLLING`
and `REMOTE`.

### 4.4 Enrolment baseline

The baseline is compiled into the APK, versioned, and identified by
`baselineSha256` over its canonical serialisation, which a test pins. It is a
complete policy in the format of section 6 with:

- protection `ON`;
- `ALLOW_SELECTED` with an empty, configured selection;
- no system selection; Play compatibility, home filter and kiosk off;
- every control as in the `PRODUCTION` profile, except
  `developer_options_and_adb`, which follows the build profile (a pilot keeps
  ADB break-glass until production gate 3);
- `MANAGEMENT_DEFAULTS` without pins: as in today's code, an `UNPINNED`
  management package is trusted. This is the existing pilot gap that the
  health report shows as `UNPINNED`; it is stated here, not changed.

The baseline is applied through the same journal and projection as a fleet
policy (5.5), with a `Baseline` authority (6.4). Its journal hash is
`baselineSha256`.

### 4.5 Enrolment ticket

- 24 random bytes, per device. The server stores only `SHA-256(ticket)`.
  Expiry defaults to 72 hours, with a maximum of 7 days.
- Bound atomically to the first device key that completes the challenge (4.6).
  A retry with the same key is answered idempotently. Any other key is refused
  with `ticket-bound-to-other-device`.
- It never opens anything: an enrolled device stays on the baseline until a
  fleet policy lists it.

### 4.6 Enrolment protocol and trust bootstrap

A persisted state machine; each step resumes after a crash with the same
device key.

1. `CONFIG_STORED` — the validated bundle is stored in credential-protected
   storage.
2. `BASELINE_VERIFIED` — baseline applied through the journal and read back.
3. `CHALLENGED` — `POST /v1/enrol/start {ticket}`. The server checks the ticket
   and returns a fresh 32-byte challenge bound to that ticket: single
   outstanding challenge per ticket, 10-minute lifetime, stored server-side.
   Before the ticket is bound, a repeated start replaces the old challenge.
4. `KEY_CREATED` — a non-exportable P-256 key is generated in Keystore with
   `setAttestationChallenge(challenge)`, StrongBox when present, and ID
   attestation of the serial on API 28+ where supported. `deviceId` =
   base64url SHA-256 of its SPKI. On API 31+, `getEnrollmentSpecificId` is
   read after `setOrganizationId`.
5. `ENROL_SENT` — `POST /v1/enrol/finish {ticket, attestationChain, facts,
   transcriptSignature}`. The **enrolment transcript** is the canonical bytes
   of `{"dg-enrol/1", challenge, SHA-256(ticket), SHA-256(attestationChain),
   SHA-256(facts)}`. It is signed with the new device key, which proves
   possession. The server checks:
   - the chain against Google's attestation roots and the revocation list;
   - that the leaf's attestation challenge equals the issued challenge;
   - that the leaf key verifies the transcript signature;
   - the attested application signer.

   It then atomically consumes the challenge and binds ticket → `deviceId`.
   The server stores the chain, facts and signed transcript as an
   **enrolment record**.
6. `KEYSET_ACCEPTED` — the key set is verified **by signature alone** against
   the root digest from the QR. No time check is involved, so there is no
   circular dependency.
7. `ENROLLED` — mode `REMOTE`, still on the baseline.

**Independent trust check.** The admin tooling does not rely on the server's
`trusted` flag. Before it lists a device in a fleet policy, it downloads the
device's enrolment record and verifies it offline: the chain against Google's
roots and a revocation list the administrator fetches, the challenge, the
transcript signature, the security level, the boot state, the bootloader lock
and the application signer. A device that fails is refused without
`--allow-untrusted`, which is recorded in the policy's audit note.

**Key-set rotation.** A key set is replaced only by a higher `keySetVersion`
signed by the current root, or by the successor root that the current key set
names. Key sets have no time-based expiry; revocation is by a newer version.

### 4.7 Failure modes

| Failure | Behaviour |
| --- | --- |
| Build gate off and remote keys present | `RESULT_CANCELED`, nothing written |
| No remote keys | `LOCAL_PIN`, as today |
| Remote keys malformed | `ENROLLING`, `enrolment-config-invalid`; re-provision |
| Allowed modes missing or without fully managed (API 31+) | `RESULT_CANCELED` |
| Marker commit fails | `RESULT_CANCELED` |
| Baseline not verified | Retry or cancel; never `RESULT_OK` |
| Server unreachable | Setup finishes on the verified baseline; background retry with backoff |
| Ticket expired, unknown or bound elsewhere; challenge expired | Stable code; device stays `ENROLLING` |
| Key set not signed by the pinned root | `key-set-root-mismatch`; never retried with another root |
| TLS pin mismatch | `tls-pin-mismatch`; no unpinned fallback |
| Process killed | Resume from the last step; the marker alone is enough to re-apply the baseline |

### 4.8 Bench enrolment of a never-managed device

1. Remove every account and secondary user. Install the release APK (no `-t`)
   and run `adb shell dpm set-device-owner <full component>`. The device
   starts `UNDECIDED`.
2. **Freshness check.** The **Enrol with management server** option appears
   only if Device Guard has never managed the device. That means: no PIN, no
   stored app selection or managed-package record, no explicit system-control
   choices, no Play compatibility, home filter, kiosk or management-pin
   records, no maintenance window or pending restore, and an empty audit log.
   Otherwise the option is absent and the console shows
   `bench-enrol-not-fresh` (conversion is Later, 14.2). The screen is a
   non-exported activity.
3. Choosing it runs one operation on the policy thread: it **checks the gate
   and freshness again** and, only if both still hold, writes the marker in the
   same step. It then moves to `ENROLLING` and applies the baseline before any
   network call. A device that stopped being fresh between showing the option
   and choosing it is refused with `bench-enrol-not-fresh`.
4. The operator types the server host. The device fetches the key set and
   shows the root fingerprint (eight groups of four characters) to compare
   with the fleet card. The operator then types a **bench code** created per
   device by the admin tooling: 16 base32 characters (80 bits), single use,
   one-hour expiry, five attempts. It plays the role of the ticket in 4.6.

`adb shell am start` with extras is not used. `Activity.getLaunchedFromUid`
exists from API 34 and identifies the launcher only in specific cases: an
opted-in launcher, the same UID, or a launched activity whose package is
platform-signed, plus some result-based launches. It cannot tell a bench shell
from another app, so it cannot authenticate the bench.

### 4.9 Tests

- Python: remote options, environment-only ticket, batch path through an
  environment variable with mode checks, no ticket value in any output,
  `dg.remote.*` and `ticket` refused on the generic path.
- Manifest: both activities exported, `DEFAULT`, `BIND_DEVICE_ADMIN`.
- JVM: build gate off cancels before any write; allowed-mode rule per API
  level; marker before parsing; no `RESULT_OK` without a verified baseline;
  mode decision table; `ModeBoundaryTest`; marker-only recovery; baseline
  content and pinned hash; bench freshness check, with one case per state
  listed in 4.8; enrolment state machine resume; key set accepted before any
  other document.
- Hardware ([`hardware-validation.md`](hardware-validation.md)): QR enrolment
  through both activities on each supported setup wizard; baseline failure
  ends in cancel; server-down completion on a verified baseline; bench
  enrolment of a never-managed device; refusal on a device with local state;
  attestation fields.

---

## 5. Signed documents, sync and the policy journal

### 5.1 Envelope and schema

```json
{
  "format": "dg-signed/1",
  "keyId": "<base64url SHA-256 of signer SPKI>",
  "payload": "<base64url UTF-8 JSON bytes>",
  "signature": "<base64url DER ECDSA P-256 over the payload bytes>"
}
```

The envelope is at most 64 KiB. Common header: `schemaVersion` (unknown
refused), `type`, and `fleetId`. Sync payloads also carry `keySetVersion`
(at least the floor). The schema
is **closed**: unknown fields at any level, and any field or command named in
section 14 (for example `browserThroughFilter`, `permittedAccessibilityServices`,
`systemUpdates`, `pause`, `wipe`), are refused with `doc-field-unknown` or
`command-unknown`. The vectors include one rejection case per Later field and
command.

### 5.2 Signed document types

| Type | Signer | Binding | Ordering |
| --- | --- | --- | --- |
| `keyset` | Fleet root | `*` | `keySetVersion` strictly increasing |
| `fleet-policy` | Fleet policy key | Lists 1–256 device IDs; the device must be listed | `fleetPolicyVersion` strictly increasing per fleet; no predecessor hash, so a device jumps straight to the newest version it receives |
| `recovery` | Fleet policy key | Lists exactly one device | `recoveryVersion` per device strictly increasing |
| `command` | Server key | One device and **the nonce of the sync request it answers** | `sequence` strictly increasing |
| `re-anchor` | Root of the latest committed keyset, or the binding root before the first keyset | One fleet, device and console challenge | Single-use, expiring nonce. Restores all four sync floors. |

There are no server-signed policy documents and no time documents. No v1 rule
depends on wall-clock time.

### 5.3 Sync

- **Scheduling.** At enrolment the device registers a **persisted periodic
  job** (requested every 15 minutes, `NETWORK_TYPE_ANY`). The scheduler
  reloads it at boot and runs it subject to its constraints. It also
  re-registers on `MY_PACKAGE_REPLACED`. The device enqueues a **one-shot**
  sync after:
  - enrolment completes;
  - a fleet policy is applied (to report it);
  - a recovery action;
  - a `reapply` command.

  No delivery latency is promised: Doze and lost connectivity can defer any
  job indefinitely.
- **Request.** `POST /v1/sync` with:
  - `deviceId`;
  - a fresh 32-byte `nonce`;
  - `keySetVersion`, `fleetPolicyVersion`;
  - `committedSha256`, the active recovery overrides and their
    `generationSha256`;
  - `verifiedGeneration` (5.3, hashes);
  - `lastCommandSequence`;
  - the report.

  A header carries a device-key signature over the method, path, timestamp and
  body digest. TLS uses the platform trust store plus the optional SPKI pins.
  Redirects are refused.
- **Nonce ownership.** The device holds at most **one outstanding nonce**, in
  memory, together with its boot count and the `elapsedRealtime` at sending.
  A response is processed only if it answers that nonce, arrives in the same
  boot within 120 seconds, and the nonce has not been used. The nonce is
  discarded at the first response, at timeout or at process death. A stale or
  second response is dropped (`sync-response-stale`).
- **Response order.** The device processes the response strictly in this
  order, and each step uses only what earlier steps accepted:
  1. a newer `keyset`, verified by the root (or the named successor root);
  2. the newest `fleet-policy` listing this device, verified with a fleet
     policy key from the key set as it stands after step 1;
  3. `recovery` documents, verified the same way;
  4. `command` documents, verified with the server key from the step-1 key
     set and bound to the request nonce.

  A refusal at one step does not stop later steps. Outside re-anchor recovery,
  a command does not depend on the policy state.

  After a storage re-anchor, a bound device with verified trust and no
  committed generation sends JSON `null` for `fleetPolicyVersion`,
  `committedSha256`, `generationSha256` and `verifiedGeneration`, and `[]`
  for `overrides`. It reports its verified `keySetVersion` and stored command
  floor as usual. The server sends the newest fleet policy listing the device
  in step 2 and omits recovery documents and commands. The device keeps its
  live restrictions and refuses commands until the replacement passes read-back.
- **Hashes both sides can reproduce.** Every hash is a raw 32-byte SHA-256
  digest. On the wire, in reports and in the journal it is written as
  **lowercase hexadecimal, 64 characters**. Hashes are always concatenated as
  raw bytes, never as text.
  - `committedSha256` = SHA-256 of the exact signed payload bytes (the
    base64url-decoded `payload`) of the fleet policy the journal holds. For
    the baseline, it is `baselineSha256` over the canonical baseline bytes.
  - The **generation** is the committed policy plus the active recovery
    overrides, a fixed enumeration (8.4).
    `generationSha256 = SHA-256("dg-gen/1" ‖ 0x00 ‖ committedSha256[32 raw
    bytes] ‖ n ‖ for each override in ascending ASCII order: len ‖ ASCII
    code)`, where `n` and `len` are single unsigned bytes.
  - Example vectors (also committed in PR 4): with `committedSha256 =
    SHA-256("example") =
    50d858e0985ecc7f60418aaf0cc5ab587f42c2570a884095a9e8ccacd0f6545c`:
    - no overrides →
      `6248175361a6f10d6e60c31f0ccdd4e91630402b1651e10fcdf5fc6be732f28f`;
    - `network-off` →
      `41acce4f35ad932540247e3c3f56c732e481280be5201f3b6e1a54c9e23fd1cb`.
  - `verifiedSha256` is the `generationSha256` of the last generation a
    read-back verified. It is stored and reported **together with that
    generation's own** `fleetPolicyVersion` (or `baseline`),
    `committedSha256` and override list (`verifiedGeneration`), so it can be
    reproduced even after the current generation has moved on.

### 5.4 Commands are fresh by construction

A command is valid only inside the sync that requested it. There is no queue
on the device and no expiry to compute from time:

1. Verify the signature, the nonce binding and the `sequence` floor.
2. Raise the replay floor in the guard, then commit
   `{sequence, kind, state: ACCEPTED, bootCount, cutoffElapsed}` with
   that floor in the journal, where `cutoffElapsed = requestSentElapsed + 120 s`.
3. Commit `state: DISPATCHING`.
4. **After that commit**, check again that the boot count is unchanged,
   that `elapsedRealtime < cutoffElapsed`, **and that `commands-off` is not
   active**. If any check fails, commit `command-expired` or
   `cancelled-by-recovery` and stop.
5. Call the platform once. Commit `state: DONE` with the evidence.

Steps 2–5 and the recovery commit (8.3) run on the **same single policy
thread**. A recovery that lands before step 4 therefore cancels the command,
and a command whose platform call has already happened is reported as
executed. There is no third outcome.
6. After a crash, `ACCEPTED` becomes `command-expired` (the nonce cannot
   survive a process death), and `DISPATCHING` is reported as
   `dispatch-outcome-unknown` and **never dispatched again**.

### 5.5 Policy journal and projection: one rule

The journal holds, in one preferences file written only with `commit()`:

- the committed policy payload bytes and `committedSha256`;
- the version floors;
- the active recovery overrides;
- the recovery verifier;
- the command entries;
- `verifiedSha256`.

**Accepting a policy** (baseline, or a fleet policy that passed 5.2) commits
the payload bytes, `committedSha256` and its floor together in the journal.
The Keystore-authenticated guard records a raised floor before that commit.
If the journal commit fails, the policy is refused (`journal-write-failed`),
the prior policy remains active, and the higher replay floor stays in force.

**The single rule.** On every process start, on every lifecycle trigger (boot,
package replaced, package added or removed, sweep), on `reapply`, and before
every reconciliation pass, the writer runs `ensureProjected()` on the policy
thread before any `DevicePolicyManager` call:

1. Read `committedSha256` and the overrides from the journal. The **target
   generation** is `committedSha256 ‖ overrides`.
2. (No shortcut: the projection stamp is a consistency check, never a reason
   to skip step 3; see A2 in section 15.)
3. Re-project the **full** effective policy into every legacy store. Every
   write uses `commit()`, through package-private setters that only
   `AuthorizedPolicyWriter` reaches, and readers see only successfully stored
   state (A2). Then write the projection stamp, **last**, with `commit()`.
   Projection overwrites every field, so it is idempotent: a partial
   projection from a crash is simply written again in full.
4. Run the reconciliation pass with the target generation as a parameter.
5. After the read-back, write `verifiedSha256` **only if** the pass verified
   **and** the journal's target generation is still the one the pass
   projected. If the journal changed in the meantime, the result is discarded
   and the next trigger runs again.

Because every reader in a remote mode goes through `ensureProjected()` first,
and the projection stamp is written last, no pass can run on a mix of two
generations. That covers the new mode with an unconfigured selection, and the
boot receiver choosing pause. This rule removes the earlier difference between
"accepted" and "applied" states: there is one committed generation, and one
verified hash written only after read-back.

**Crash vectors** (fault injection after every commit, with a simulated boot
between some of them):

1. after the journal commit, before projection;
2. after each individual store write inside projection;
3. after projection, before the stamp;
4. after the stamp, before the pass;
5. after the pass, before `verifiedSha256`;
6. a new policy committed while a pass for the previous one is running;
7. a recovery override committed mid-projection;
8. the boot receiver firing in states 1–3.

In every case, the next run converges on the committed generation, no pass
reads a mixed generation, and `verifiedSha256` never names a generation that
was not read back.

#### Storage re-anchor

When a journal or its guard fails closed, the device console names the problem,
shows a copyable one-time challenge, and takes the signed document on a
dedicated screen. Where only the finalized independent bind record survives,
the administrator also enters the current root fingerprint. The console
requires a factory reset and enrolment if the device cannot authenticate the
current identity or its authenticated sources disagree. Devices that rotated
before PR8 and already lost both main records cannot use total-loss recovery.

The fleet administrator signs the challenge, device, fleet and latest issued
version of every sync document type using the latest committed root. The
device refuses smaller values than any locally readable floors. The full
[wire and storage contract](remote-contract/README.md#console-re-anchor)
specifies optional payload hashes for resending the exact keyset and policy at
the same versions. That same root signs the replacement keyset accepted by
the rebuilt device.

An authorized re-anchor changes only remote management records and enters
`ENROLLING`. Existing Android restrictions and projected stores stay in force
while the device waits. A replacement keyset and policy must pass the normal
verification path, and projection must read the new policy back before
returning the device to `REMOTE`. Old command outcomes and recovery codes
do not carry over. Unverified package releases are retained only when still
provable, so the next policy pass can undo them. Apps exposed before the loss
stay visible until a replacement policy arrives. The build gate remains off.
Signing recovery documents for the console and delivering the replacement keyset
and policy are responsibilities of the fleet server or offline operator.

**Accepted residual risks.**

- An attacker with write access to app storage, an old bind-record file, the
  retired root signing key, and the on-screen nonce could re-anchor with that
  root. Only a Keystore-backed monotonic counter would prevent that rollback.
- A device stuck mid-rotation with its bind record still `pending` fails closed.
  Factory reset is the only recovery path.

### 5.6 Failure codes

`doc-signature-invalid`, `doc-key-unknown`, `doc-device-not-listed`,
`doc-version-rollback`, `doc-field-unknown`, `doc-field-invalid`,
`doc-type-unexpected`, `command-unknown`, `command-nonce-mismatch`,
`sync-response-stale`, `journal-write-failed`, `command-expired`,
`dispatch-outcome-unknown`, `commands-suspended-by-recovery`. Each refusal
changes nothing and is reported.

---

## 6. Policy model

### 6.1 Policy body

Fleet policies and the baseline share one complete body:

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

| Field | Missing | `null` | Unknown |
| --- | --- | --- | --- |
| `protection.state` | Refused | Refused | Refused (only `ON`) |
| `apps.mode`, `apps.allowed` | Refused (empty list = configured, empty) | Refused | Refused |
| `apps.systemSelection` | Empty | Refused | Refused |
| `apps.playCompatibility` | `false` | Refused | Refused |
| `systemControls.<key>` | Profile default, then the Play and home-filter floors | Refused | Refused |
| `homeFilter` | Off | Refused | Refused (existing record constructors) |
| `managementPins` | `MANAGEMENT_DEFAULTS` without pins (`UNPINNED`, trusted) | Refused | Refused |
| `kiosk` | `OFF` | Refused | Refused |
| `sync.pullMinutes` | 15 | Refused | Outside 15–240 refused |
| `locale` | Device default | Refused | Refused |

### 6.3 Projection

| Field | Store | Note |
| --- | --- | --- |
| `apps.mode`, `apps.allowed` | `AllowedAppsStore` | Mode, the selection and its configured flag are written in **one** `commit()`; the other mode's selection is cleared in the same commit |
| `apps.systemSelection` | `setAdminSelectedSystemPackages`, `recordSystemRiskAcceptance` | Signer and version are the acceptance; a mismatch is reported, not applied |
| `apps.playCompatibility` | `PlayStoreCompatibilityStore` | — |
| `systemControls` | `SystemPolicyStore` | A missing key clears the stored choice |
| `homeFilter` | `HomeFilterStore` via `HomeFilterController` | Validated before writing |
| `managementPins` | `AllowedAppsStore.setManagementCertificatePins` | — |
| `kiosk` | `KioskConfigStore` via `KioskController` | — |
| `locale` | `AppLocales` | — |

Because fleet policies come only from the offline key, v1 needs no
classification of changes, and no evaluator. Whatever a signed fleet policy
says is what the administrator decided.

### 6.4 Authority gate

```java
public sealed interface AdminAuthority permits LocalSession, Baseline, CommittedPolicy, RecoveryAction {}
```

- `LocalSession` exists only while `AdminSession.isUnlocked()` in `LOCAL_PIN`.
- `Baseline` is created only by the enrolment flow for the compiled baseline.
- `CommittedPolicy` is created only by `ensureProjected()` for the journal's
  target generation.
- `RecoveryAction` is created only by the atomic recovery commit (8.3).

The store setters become package-private and are reachable only through
`AuthorizedPolicyWriter`, which requires an authority. `KioskController` and
`HomeFilterController` take an `AdminAuthority` instead of reading
`AdminSession`. A reflection test fails if any store mutator can be reached
without the gate.

---

## 7. Commands, reports and MCP

### 7.1 Commands

| Command | Effect | Evidence |
| --- | --- | --- |
| `lock_now` | [`lockNow`](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#lockNow()) | `DONE` with `secureLock: true` when `KeyguardManager.isDeviceSecure()` was true at dispatch, otherwise `secureLock: false` and the code `lock-screen-off-only`. Without a secure lock type, `lockNow` may only turn the screen off. `command-expired` and `dispatch-outcome-unknown` are reported as such |
| `reapply` | Runs `ensureProjected()` and a full reconciliation pass of the committed generation; no payload | The pass result and `verifiedSha256` |

Both follow 5.4. v1 does not set a password policy. A fleet that needs a
secure lock must set one on the device during setup, and the report shows
`secureLock` so the administrator can see it.

### 7.2 Reports (heartbeat)

Every sync carries a report signed with the device key:

- the redacted health snapshot (package census as counts);
- the mode, `keySetVersion`, `fleetPolicyVersion`;
- `committedSha256`, the overrides and `generationSha256`;
- `verifiedGeneration` (`verifiedSha256` with its own policy version,
  `committedSha256` and overrides);
- the error codes of the last pass;
- command outcomes;
- recovery events;
- the audit tail as event codes.

The server raises `device-silent` after `3 × pullMinutes + 1 h`. That is a
signal, not proof.

### 7.3 MCP in v1

- Read tools: `device_list`, `device_status`, `device_audit`, `policy_get`.
- Command tools: `lock_now_prepare` and `reapply_prepare`, each followed by
  `confirm`. The command is queued on the server and signed into the next
  sync response from that device.
- Scopes: `read` and `command`. No scope can change a policy; the fleet policy
  key is not on the server.

**Parity in v1:** every console action is registered as *fleet-policy*
(changed only by signing a new fleet policy), *command* (`lock_now`,
`reapply`), *read*, or *Later*. A JVM test fails on any unregistered action.

---

## 8. Recovery code

### 8.1 Purpose

The person holding the device can recover it **without network**: after a
broken home-filter configuration, a lost server, or command abuse by a
compromised server.

### 8.2 Generation and delivery

- The admin tooling generates the code offline: 20 base32 characters
  (100 bits), printed in groups of four, plus a 16-byte salt and
  `PBKDF2-SHA256(code, salt, 210000)`. At 100 bits, guessing from a leaked
  value is infeasible, so it is not encrypted to the device.
- The salt and value travel in a `recovery` document signed with the fleet
  policy key. The server only relays it.
- The device applies its Keystore HMAC and stores the verifier **in the
  journal file** (5.5), separate from `AdminPinStore`; no PIN is needed.
  Lockout reuses `PinLockoutPolicy` bound to `BOOT_COUNT`.
- Until a recovery document arrives, recovery means a factory reset.

### 8.3 Use: choose first, then one atomic commit

The console's **Recovery** entry first shows the actions (8.4). The person
chooses one or more, **then** enters the code. A valid code leads to **one**
`commit()` to the journal file that together:

- removes the verifier;
- records the use;
- writes the chosen overrides;
- marks every command entry in `ACCEPTED` or `DISPATCHING` whose platform
  call has not been made as `cancelled-by-recovery`. The commit runs on the
  policy thread, which also makes the final dispatch decision (5.4), so no
  command can slip past it.

If that commit fails, nothing is consumed or changed
(`recovery-commit-failed`). If the process dies before it, nothing happened.
If it dies after it, the overrides are durable and `ensureProjected()` applies
them on the next start. There is no session: the code buys exactly the chosen
actions, once.

### 8.4 Overrides

| Override | Effect | Ends when |
| --- | --- | --- |
| `network-off` | The projected `homeFilter` becomes off (VPN lockdown, proxy and CA cleared). **Every other field keeps the committed fleet policy's value**, so app restrictions and controls are unchanged, except the home-filter floor on controls, which falls away with the filter | A newer fleet policy is committed |
| `commands-off` | Every command is refused (`commands-suspended-by-recovery`). With this override, a compromised server key can no longer lock the screen and is left with withholding documents and reading reports | A newer fleet policy is committed |

Overrides are part of the target generation (5.5), so projection always
equals the fleet policy plus the active overrides. They are a fixed
enumeration, and the report lists them. A diagnostics screen (server host,
last sync, last codes) is read-only and needs no code.

---

## 9. Management server

A small service in a **separate repository**. The DPC repository stays a
client and holds no server secrets. A test server with the same API and the
shared vectors comes first (section 12).

| Table | Content |
| --- | --- |
| `fleets` | id, label, root digest, key set bytes |
| `devices` | `deviceId`, state, enrolment record (chain, facts, signed transcript), last report, last seen |
| `tickets` | `SHA-256(ticket)`, expiry, outstanding challenge, bound `deviceId` |
| `fleet_policies`, `recovery` | Signed bytes as uploaded; the server verifies them but cannot create them |
| `commands` | Queued `lock_now`/`reapply` per device, then signed into a sync response with that sync's nonce; state |
| `audit` | Append-only, hash-chained, exported off the server |

Device API: `POST /v1/enrol/start`, `POST /v1/enrol/finish`, `POST /v1/sync`.
Admin API: upload signed documents, download enrolment records, and the MCP
tools of 7.3.

| Failure | Effect |
| --- | --- |
| Server down | Devices keep their committed policy; nothing changes |
| Server key unavailable | No commands; documents are still relayed |
| Server compromised | Can withhold documents, read reports, lock screens and trigger re-applies; cannot change any policy; `commands-off` removes the lock and re-apply abuse on a device |
| Device silent | `device-silent` alert |

---

## 10. Admin tooling

`tools/fleet_admin.py` follows `tools/publish_update.py`: OpenSSL with an
external PEM key that is never copied, and the passphrase from a named
environment variable. Subcommands:

- `keyset` — build and sign a key set with the root key.
- `verify-enrolment` — verify a downloaded enrolment record offline (4.6).
- `policy` — validate a policy body against the schema; list target devices
  (only devices with a verified enrolment record, unless `--allow-untrusted`);
  render a readable summary and a field diff against the previous version;
  sign with the fleet policy key. Two guards apply:
  - **ADB guard:** the tool refuses `developer_options_and_adb: true` for a
    device whose firmware family has no recorded pass of the signed
    self-update drill ([`secure-updates.md`](secure-updates.md)).
  - **Install guard:** it labels any policy that turns
    `app_stores_and_installers` off as **global install exposure** (14.5).
- `recovery` — generate a code, print it once for the vault, and sign the
  `recovery` document.
- `tickets`, `bench-code` — create enrolment tickets and bench codes.

**Updating Device Guard in v1.** While `app_stores_and_installers` is on,
Device Guard cannot update itself; that is today's behaviour. The v1 update
path is explicit:

1. Sign a fleet policy that turns the control off (labelled as global install
   exposure).
2. Let the signed self-update run.
3. Sign the next policy, which turns the control back on.

The drill evidence above must exist before this path is used on a firmware
family.

---

## 11. Threat model

- **Test-only build removal.** Remote enrolment refuses `FLAG_TEST_ONLY` and
  `FLAG_DEBUGGABLE`. The attested application signer must be the release
  signer for production fleets. *Not covered:* someone's own test device,
  which cannot join a real fleet.
- **USB debugging.** Set only by a fleet policy, behind the ADB guard (10).
  *Not covered:* OEM service modes.
- **Recovery wipe or reflash.** Detection only (`device-silent`); re-enrolment
  needs a new ticket and starts on the baseline.
- **Spoofed boot properties.** Hardware attestation, verified by the server
  and again offline by the admin tooling. *Not covered:* a leaked, unrevoked
  attestation keybox.
- **Clock tampering.** No v1 rule uses wall-clock time.
- **Replay.** Strict version floors per type; device listing;
  nonce-bound, at-most-once commands. *Not covered:* root access that resets
  app storage.
- **Compromised server.** Can withhold documents, read reports, lock screens
  and trigger re-applies. A device can be held at an older fleet policy it has
  not yet received, but never below its floor. `commands-off` removes the
  command abuse. *Not covered:* withholding and report disclosure.
- **Compromised fleet policy key.** Full policy control over the listed
  devices until a newer key set without that key reaches them. This is the
  administrator's authority by design; keep the key offline.
- **Enrolment.** Build gate; marker before parsing; no `RESULT_OK` without a
  verified baseline; mode boundary; per-device tickets with challenge and
  proof of possession; no exported bench entry; fresh devices only. *Not
  covered:* whoever holds a wiped device can provision it with a local QR.
  That is the intended local mode.
- **Reboot before first unlock.** Nothing of Device Guard runs before the
  first unlock: the journal is in credential-protected storage, and the boot
  receiver is not direct-boot aware. v1 never relaxes a device temporarily,
  and Android keeps Device Owner restrictions and hidden packages across a
  reboot, so the device stays as the last pass left it (verify per firmware,
  as a hardware check).
- **Leaked recovery code.** One use on one device, limited to `network-off`
  and `commands-off`.
- **Malicious MCP agent.** Limited to reads, `lock_now` and `reapply`.

---

## 12. v1 delivery plan

Each PR lands with its tests. Hardware groups go into
[`hardware-validation.md`](hardware-validation.md), with evidence in
[`device-matrix.md`](device-matrix.md).

- `REMOTE_ENROLMENT_ENABLED` is `false` in release builds until **PR 9**.
- PRs 5–8 run remote enrolment only in a dedicated **remote-test artifact**.
  It is a non-debuggable, non-test-only build type signed with a test key
  (never the release key) with the gate on. The release-build refusals of 11
  therefore hold, and only the test server accepts that signer.
- `RemoteProvisioning.baseline()` keeps ADB available for the recovery drill.
  Revisit that baseline before PR 9 enables remote enrolment in release.

| # | PR | Depends on | Tests and gate |
| --- | --- | --- | --- |
| 1 | This design (v1 scope) | — | Independent review |
| 2 | `AuditLog` event codes | — | Code stability; health export carries codes |
| 3 | Mode boundary: `ManagementMode`, marker storage, build gate (off), first-PIN closure, `AdminAuthority`/`AuthorizedPolicyWriter` with `commit()`-only package-private setters, boot receiver, sweep and maintenance routed by mode | 1 | `ModeBoundaryTest`, writer coverage, mode table; existing tests unchanged |
| 4 | Shared contract and vectors: four document types, closed schema with Later-field and Later-command rejections, sync order and nonce rules, hash definitions, journal and projection crash vectors (5.5), command dispatch vectors, recovery atomic-commit vectors | 1 | Vectors reviewed by a second agent before any code consumes them |
| 5 | Verifier, journal, `ensureProjected()` and the apply order, recovery verifier and overrides; no network. Must meet acceptance criteria A1–A3, A5 | 3, 4 | Vector tests; crash and write-failure injection at every listed point; Android-call failure injection; recovery tests; locale parity for the recovery screen |
| 6 | Provisioning activities (4.2), baseline through the PR 5 journal, marker-only recovery, shared enrolment gate, atomic freshness check; remote branch compiled but gated. Must meet A6 | 3, 5 | JVM tests (4.9); hardware with the remote-test artifact: QR to a verified baseline, cancel path, bench refusal on a device with local state |
| 7 | `tools/provisioning_payload.py` remote options; `tools/fleet_admin.py` (including `verify-enrolment` and both guards) | 4 | Python tests; vectors |
| 8 | Test server (separate repository) and device client: enrolment challenge and transcript, sync order and nonce, commands, reports; in the remote-test artifact | 5, 6, 7 | End-to-end tests; hardware: enrolment with the server up and down, interrupted apply, reboot before first unlock, `lock_now` with and without a secure lock |
| 9 | **Gate PR — activation.** Production server hardening (KMS/HSM server key, audit export), MCP read and command tools with scopes, read-only remote console, `REMOTE_ENROLMENT_ENABLED` on in release builds | 8 | Gate: section 13 blockers closed; acceptance criteria A1–A7 met (A7 lands here); independent review |
| 10+ | Anything from section 14 | 9 and its own design | Behind the gate; separate design and review |

PRs 2–5 and 7 need no server and no network. PR 5 lands before PR 6, because
the baseline is applied through its journal.

---

## 13. Blockers and open questions

### Blockers for PR 9 (activation)

1. Hardware evidence on every supported setup wizard. QR enrolment through
   both activities, the cancel path, server-down completion on a verified
   baseline, and bench enrolment with refusal of a non-fresh device. Also
   interrupted-apply recovery, and the state after a reboot before first
   unlock.
2. Enrolment identity proven end to end: challenge, proof of possession, and
   offline verification by the admin tooling.
3. Final production application ID and signer.
4. Resolved by PR 2: audit event codes are stored and exported with timestamps.
5. An owner decision on server hosting, operation and server-key protection.
   Nothing in this repository may name it.
6. Fleet policy key custody: where the offline key lives and who may sign.
7. The signed self-update drill passing on each firmware family before
   **anything** disables ADB there: a fleet policy (enforced by the admin
   tool's ADB guard) **or the baseline itself**. A production-profile build,
   whose baseline turns `developer_options_and_adb` on, may enrol devices only
   on firmware families with a recorded drill pass.
8. Acceptance criteria A1–A7 (section 15) met by their PRs.

### Open questions

1. Does each target setup wizard invoke `PolicyComplianceActivity` for QR, and
   what does it do after `RESULT_CANCELED`?
2. Should a fleet policy require a secure lock type, so that `lock_now`
   always locks? That needs a password policy, which v1 does not set.
3. Monthly re-attestation: alert only, or also block listing in new fleet
   policies?
4. Google zero-touch or Samsung Knox enrolment for reseller-bought devices,
   later.

---

## 14. Later (separate design, not reviewed here)

Nothing here may be built from this document. Each item needs its own design
and review. The notes record what the reviews found.

### 14.1 Server overlays

Overlays let the online server change policy, even if only to tighten. Round 3
found that "tighten" cannot be checked on list contents alone. In
`BLOCK_SELECTED`, adding a name to the blocked list passes any set rule. But
list membership also makes an ordinary system package eligible for a
visibility write, and the writer ignores the list when deciding `shouldBlock`.
A package left hidden by an earlier policy could therefore become **visible**
during a "tightening" overlay. A later design must:

- separate the package-discovery set from the decision;
- prove that the evaluator and the writer are equivalent over every
  visibility write, not over the resulting set alone;
- define sync ordering and a base hash both sides reproduce when a fleet
  policy and an overlay arrive together.

### 14.2 Converting a locally managed device

The pilot device already deployed has local state: a PIN, a selection, choices
and possibly a live maintenance window. The controller reads a stored
maintenance window when it chooses restrictions and store visibility, and can
report a pass as verified against the relaxed choices. A conversion design
must define:

- a verified handoff that ends every local relaxation and the PIN authority
  before the marker;
- what authority applies the baseline;
- the resume path if the process dies after the marker;
- how legacy writers are excluded during the handoff.

Until then, a non-fresh device is refused (`bench-enrol-not-fresh`) and must
be factory reset to enrol.

### 14.3 Loosening with human approval

A server-rendered approval page proves who approved, not what they saw. A
design needs:

- an approver that renders from signed bytes with its own evaluator;
- a binary statement bound to the payload, base and diff;
- device-issued challenges;
- a never-executable signed proposal, to break the signer-approver
  deadlock;
- a minimal facts bundle, which the redacted health report does not carry;
- approval-key expiry that does not depend on server time.

### 14.4 Remote pause, maintenance and console windows

Android does not expire a Device Owner restriction by itself, and relaxations
persist through reboots. Open problems:

- Doze rate limits do not bound how late a close fires.
- No exact-alarm exemption applies to a Device Owner as such.
- A pre-unlock restore cannot read a credential-protected journal, and must
  also undo the link handlers, the blocked-browser component and the
  browser-provider suspensions that `pause()` changes.
- The journal and a device-protected restore record need a crash protocol
  across both stores.
- Window timing must not depend on server time.
- A writable console grant authorises edits nobody reviewed.

### 14.5 Install, update and self-update windows

`DISALLOW_INSTALL_APPS` is user-wide, and the maintenance predicate unhides
the whole managed-store set. A design must prove that every other install
route stays closed, or approve the operation as a global install window.
Snapshot quarantine acts only after the fact. A signed private catalogue is
the only update-only path. v1 uses the explicit global path in section 10.

### 14.6 Browser through the filter

Device Guard's canary proves only Device Guard's own traffic. A browser
exemption needs:

- per-browser and per-firmware evidence (TWA, Custom Tabs, WebView, tunnel
  drop);
- authenticated, expiring gateway egress evidence;
- separate proof that the browser enforces its managed restrictions. The
  Device Policy Manager getter confirms only the stored bundle.

Tailscale documents an Android `AuthKey` setting for automatic sign-in. It is
a credential and can never travel in a QR code.

### 14.7 Remote wipe and reboot

- Wipe needs two root-registered administrator identities and atomic
  validation of both statements.
- On API 34+, `wipeDevice()` is required, and silence is never proof of a
  wipe.
- `reboot()` throws during a call.

### 14.8 Accessibility and input-method allowlists, system update policy

- The permit APIs return `false` when an enabled non-system service is left
  out, and input methods also have a foreground-user condition.
- Restricted Settings may affect Device Guard on Android 13+.
- OTA windows use minutes `0–1439`, a later start crosses midnight, and freeze
  history can invalidate a policy.

### 14.9 MCP actions that change policy, wake channel, content check

These depend on 14.1 and 14.3. The accessibility content-check pilot also
changes a README claim and needs its own privacy review.

---

## 15. Acceptance criteria carried into PRs

The fourth review confirmed that the v1 cuts removed the earlier design risks.
What remains are properties of the **current code** that v1 relies on. They
are carried as acceptance criteria: the named PR is not merged until the
criterion holds and its regression test passes. Two pure-specification items
were fixed in this document directly (5.3 hash encoding; 5.4 and 8.3
`commands-off` at dispatch).

| # | Finding (round 4) | Code today | PR | Required fix | Regression test |
| --- | --- | --- | --- | --- | --- |
| A1 | **P1-1** A policy change can make an app visible before the protection it depends on is verified | `LockdownPolicyController.apply` runs `applyPackagePolicy` before `HomeFilterController.reconcile`; a later VPN failure is reported, but the unhide stays | 5 | In remote modes, the pass applies and reads back the protections that a newly visible package depends on (system controls, home filter, VPN lockdown) **before** any hide-to-visible write. If they fail, or the pass is interrupted, packages that the previous verified generation hid stay hidden. Visible-to-hidden writes are not delayed | Gateway fault injection: the VPN lockdown fails, or the process dies between Android calls, during a change that unhides a package → the package is still hidden, the pass is not verified, and `verifiedSha256` is unchanged |
| A2 | **P1-2** A failed `commit()` can still become live policy, because Android updates the in-memory `SharedPreferences` copy first | `SharedPreferencesImpl` applies edits in memory before writing; current setters ignore the result or use `apply()` | 5 (vectors in 4) | The engine reads only from a **snapshot that was stored successfully**: the journal is read back from disk after each commit, or written to a temporary file that is then atomically renamed, and an unsuccessful write is never visible to readers in the same process. `ensureProjected()` re-projects the full generation before **every** pass; the stamp is a consistency check, not a reason to skip writing | Write-failure injection with the process **still running**: for the journal, each projection store, and recovery consumption, the next pass in the same process applies the previous committed generation, and the recovery code is not consumed |
| A3 | **P1-3** A pass can be reported verified while a signed value is not enforced | `SystemPolicyControlStatus.faultsProtection()` faults only for a requested **critical** control that **failed**; advisory failures and unsupported controls never fault. CA removal is checked only when the new settings still carry the certificate, and an unconfigured filter returns early without cleanup | 5 | In remote modes, every value a fleet policy sets explicitly must be enforced and read back. An advisory failure or an unsupported requested control makes the generation **not verified** (the console still shows it as today). The admin tool refuses to list a device whose reported SDK cannot enforce a requested control. Projection keeps the previous CA and filter configuration until a read-back proves they are removed. `verifiedSha256` advances only after that | Vectors: `wifi_configuration: true` refused by the OEM → not verified; `date_and_time: true` on API 26–27 → not verified; CA installed → `caCertificate: null` → the CA is removed and proven before verification; filter on → off without the old configuration → cleanup still runs |
| A4 | **P2-1** Hash encoding and the previous verified generation are ambiguous | — | Doc (vectors in 4) | Fixed in 5.3: raw-byte concatenation, hex on the wire, `verifiedGeneration` reported with its own version, hash and overrides | The two example vectors in 5.3 plus override-order vectors |
| A5 | **P2-2** A command in `DISPATCHING` can escape `commands-off` | — | Doc (implemented in 5) | Fixed in 5.4 and 8.3: the final dispatch check reads `commands-off`, and dispatch and recovery share the policy thread | Recovery committed between the `DISPATCHING` commit and the platform call → `cancelled-by-recovery`, and `lockNow` is never called |
| A6 | **P2-3** The enrolment gate does not cover every entry point and dependency | `LockdownAdminReceiver.onProfileProvisioningComplete` has no gate; production baseline disables ADB (`SystemPolicyControl.DEVELOPER_OPTIONS_AND_ADB`, `PRODUCTION_ONLY`) | 6 | One shared gate in all four entry points (4.2); freshness re-checked in the operation that writes the marker (4.8); journal (PR 5) before the baseline (PR 6); signed-update drill before any ADB withdrawal, including the baseline (13, blocker 7) | Gate off: each entry point leaves no marker and no store change; a device that gains local state between showing and choosing the bench option is refused; the PR dependency is checked in review |
| A7 | **P2-4** Offline attestation proves possession, but not that this is the device the administrator meant to enrol | The server supplies both the challenge and the enrolment record | 9 (tool in 7) | The admin tool keeps its **own enrolment inventory**, written when it creates the ticket: ticket hash, fleet, and the expected device identity (attested serial, or the enrollment-specific ID recorded at the bench). Before signing, it derives `deviceId` from the attested leaf key and requires a match with the inventory entry for that ticket | A genuine enrolment record from another device, or for another ticket or fleet, is refused by the tool even though every signature verifies |

---

## Appendix A: Review resolution

Four independent reviews by a different AI model, run read-only against the
code, examined revisions 1–4. The design loop ends with round 4; its remaining
items are acceptance criteria for the implementing PRs (section 15). **Fixed** means v1 contains the change.
**Later** means the capability is no longer in v1, so the risk cannot arise
from v1; the reason is given. **Rejected** means the finding did not hold
against the code. No finding was rejected.

### Round 4 (revision 4) — final

| Finding | Disposition |
| --- | --- |
| P1-1 unhide before the protection is verified | **Carried to PR 5** (A1) |
| P1-2 failed `commit()` visible in memory; projection skipped on a matching stamp | **Carried to PR 5**, vectors in PR 4 (A2) |
| P1-3 verified despite advisory or unsupported failures; CA and filter cleanup | **Carried to PR 5** (A3) |
| P2-1 hash encoding and previous verified generation | **Fixed in doc** (5.3, 7.2); vectors in PR 4 (A4) |
| P2-2 `DISPATCHING` versus `commands-off` | **Fixed in doc** (5.4, 8.3); implemented in PR 5 (A5) |
| P2-3 gate entry points, freshness at write, journal order, drill before the baseline disables ADB | **Fixed in doc** (4.2, 4.8, 12, 13); **carried to PR 6** (A6) |
| P2-4 offline match to the intended device | **Carried to PR 9**, tool in PR 7 (A7) |

### Round 3 (revision 3)

| Finding | Verified against | Disposition | Where / why |
| --- | --- | --- | --- |
| **P1.1** An overlay can unhide a package via list membership | `applyPackagePolicy` (list membership adds names to the reconcile set; `shouldBlock` for non-managed system names ignores the list) | **Later** (14.1) | v1 has no overlays; every policy is a complete fleet policy signed offline, applied as the administrator wrote it |
| **P1.2** Crash leaves the journal and writer on different generations | `AllowedAppsStore.setProtectionMode`/`setAllowedPackages` (`apply()`, separate writes); `PolicyRefreshReceiver` (apply or pause from stores) | **Fixed** | 5.5: one rule — `ensureProjected()` before every pass re-projects the full generation with `commit()` writes, stamp last; `verifiedSha256` only after read-back of the same generation; 6.3: mode and selection in one commit; 4.3: receiver routed through the remote path; eight crash vectors |
| **P1.3** Local conversion carries a live relaxation into `ENROLLING` | `LockdownPolicyController.liveMaintenanceWindow` | **Later** (14.2) for conversion; boundary **Fixed** | 4.8: fresh devices only, checked state by state; 4.3: marker clears maintenance, no maintenance outside `LOCAL_PIN`, `Baseline` authority, marker-only recovery |
| **P2.1** Sync order and base-hash contract | Revision 3 §5.6 | **Fixed** | 5.3: fixed four-step order; hashes defined over signed bytes plus a fixed override enumeration |
| **P2.2** Command freshness, nonce ownership, `lockNow` evidence | Platform lock contract | **Fixed** | 5.3: one outstanding nonce per boot, 120 s, single use; 5.4: cutoff re-checked after the dispatching commit; 7.1: `secureLock` evidence and `lock-screen-off-only` |
| **P2.3** Recovery does not isolate a compromised server; consumption before choice | Revision 3 §8 | **Fixed** | 8.3: choose first, then one atomic commit; 8.4: `commands-off` removes lock abuse; `network-off` keeps every other field; accepted commands cancelled |
| **P2.4** Gate must cover the first mutation; test artifact; server before activation; update path | Revision 3 §12 | **Fixed** | 4.2: build gate cancels before any write; 12: remote-test artifact, server hardening inside the activation PR, ADB guard and drill blocker; 10: explicit update path |
| **P2.5** Enrolment proof of possession and offline trust | Revision 3 §4.6 | **Fixed** | 4.6: ticket-bound challenge, signed transcript, atomic binding, enrolment record verified offline by the admin tool |
| **P3** `getLaunchedFromUid` wording | Activity reference | **Fixed** | 4.8 |
| **P3** Scheduling wording | JobInfo reference | **Fixed** | 5.3 |
| Platform: receiver is no compliance gate | AOSP legacy path | **Fixed** | 4.2 item 3 |
| Platform: `lockNow` without a secure lock | Lock contract | **Fixed** | 7.1 |
| Platform: Direct Boot cannot read the journal | Manifest (`directBootAware="false"`) | **Fixed** (stated) | 11: v1 relies on persisted restrictions, not a pre-unlock restore |
| Later fields and commands need rejection vectors | — | **Fixed** | 5.1, PR 4 |

### Round 2 (revision 2)

| Finding | Disposition |
| --- | --- |
| P1-A evaluator over installed packages | **Later** (14.1): v1 has no evaluator, because there are no overlays |
| P1-B `ENROLLING` completion and first PIN | **Fixed** (4.2, 4.3) |
| P1-C journal resume and dispatch | **Fixed** (5.4, 5.5) |
| P1-D partial direct-boot restore | **Later** (14.4) |
| P1-E window timing on server time | **Later** (14.3, 14.4) |
| P2-A console and recovery grants | Console: **Later** (14.4). Recovery: **Fixed** (8) |
| P2-B signer-approver deadlock | **Later** (14.3) |
| P2-C catch-up stall and bootstrap | **Fixed** (4.6, 5.2) |
| P2-D browser evidence | **Later** (14.6) |
| P2-E install windows | **Later** (14.5); v1 path in 10 |
| P2-F PR order | **Fixed** (12) |
| P2-G wipe quorum | **Later** (14.7) |
| P3 latency claim; batch tickets | **Fixed** (5.3, 4.1) |

### Round 1 (revision 1)

| Finding | Disposition |
| --- | --- |
| P1.1 raw-field classification | **Later** (14.1): no server-originated policy in v1 |
| P1.2 enrolment and recovery authority | **Fixed** (4, 8) |
| P1.3 replay, approval, apply ordering | Replay and ordering **Fixed** (5); approval **Later** (14.3) |
| P1.4 restore timing, `lock_now` | `lock_now` **Fixed** (5.4, 7.1); restore **Later** (14.4) |
| P2.1 QR and ADB contract | **Fixed** (4.1, 4.2, 4.8) |
| P2.2 update-only claim | **Later** (14.5) |
| P2.3 filter proof | **Later** (14.6) |
| P2.4 API success conditions | **Later** (14.7, 14.8) |
| P2.5 PR order, latest-only sync | **Fixed** (5.2, 12) |
| P3 command contract | **Fixed** for v1 (7) |
