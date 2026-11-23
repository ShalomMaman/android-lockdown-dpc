# Remote management v1 — threat model and privacy

The [accepted ADR](remote-v1-adr.md) defines what each key can authorize. The
Android client in this repository provides device evidence. Consent, roles,
revocation and audit service requirements below are activation gates for the
separate control plane. [Design sections 7–9](remote-management.md#7-commands-reports-and-mcp).

## Assets, actors and trust boundaries

Protect the owner's authority and consent history, signing keys, device identity,
enrolment tickets and recovery codes, current restrictions and version floors,
private fleet metadata and independently verifiable evidence.

| Boundary | Allowed flow and authority |
| --- | --- |
| Owner / offline operator → service | The owner authorizes scope and revocation. A delegated filtering admin can propose in-scope changes after approval for the write phase. An authorized offline operator reviews targets and the exact diff before invoking [`fleet_admin.py`](../tools/fleet_admin.py). The service receives signed artifacts and ticket hashes. The root, policy private key and clear recovery codes stay in owner-controlled offline custody. |
| Admin phone / support / MCP → service | Separate tenant-scoped grants for delegated administrators, read-only support and release/operators. Every request checks identity, role, fleet and device scope. Release and service access provide no policy signing authority. The view-only pilot issues no command or write grants. |
| Service ↔ device | [`RemoteHttps`](../app/src/main/java/com/example/lockdowndpc/remote/RemoteHttps.kt) requires HTTPS. The device presents its one-use ticket during enrolment and proves possession of its Keystore key. Store only the ticket hash and exclude the raw ticket from logs. The device signs sync requests including the report body digest. The service receives enrolment proof and redacted reports and relays signed documents. The DPC checks signer role, schema, fleet, target and floors before Android writes. [`RemoteClientWire`](../app/src/main/java/com/example/lockdowndpc/remote/RemoteClientWire.kt), [`RemoteVerifier`](../app/src/main/java/com/example/lockdowndpc/remote/RemoteVerifier.kt). |
| Device journal → Android Device Owner | The authenticated journal and separate guard protect committed state and version floors. A serialized pass reads back Android enforcement and records the verified generation. The on-device user can see status and uses owner-authorized local recovery. [`RemoteJournalGuard`](../app/src/main/java/com/example/lockdowndpc/remote/RemoteJournalGuard.kt), [`RemotePolicyRuntime`](../app/src/main/java/com/example/lockdowndpc/policy/RemotePolicyRuntime.kt). |
| Service → independent audit store | Export ordered, hash-linked audit records and checkpoints to storage administered independently of the relay. Owner and incident reviewers can verify exports and cross-check device evidence. |

## Abuse cases

| Scenario | Protection and residual exposure |
| --- | --- |
| Lost or stolen admin phone | Revoke the grant, sessions, passkey and invitations. Until revoked, the actor could read data or exercise granted service capabilities. The phone has neither offline signing key. |
| Stolen server or command key | The relay can read held metadata, withhold updates, or abuse `lock_now` and `reapply`. It lacks policy authority. Isolate it, rotate the command key and use local command suspension on affected devices when available. A device that cannot receive the replacement remains pending. |
| Malicious delegated admin | Scope proposals to the consented tenant and targets. The offline signer reviews the full diff and owner approval. Prevent cross-tenant access and audit denied requests. A malicious authorized offline signer or stolen policy key can sign within its actual fleet authority until trust changes on devices. |
| Replay | A sync exchange consumes one fresh nonce. Commands bind to that nonce, device and increasing sequence. Signed documents must pass their version floors. A captured command cannot be replayed as an independent request. [`RemoteSync`](../app/src/main/java/com/example/lockdowndpc/remote/RemoteSync.kt), [contract vectors](remote-contract/README.md). |
| Rollback | The journal guard makes a stale or inconsistent store fail closed. Supported repair uses a live console challenge and the current root. Offline or withheld updates leave existing restrictions in force. Recovery wipe, reflash and compromised platform trust remain outside this guarantee. [Residual risks](remote-management.md#storage-re-anchor). |
| Coerced loosening | An approver on the phone, the relay and MCP cannot authorize a weaker policy. Any loosening of fleet policy requires the owner's offline policy key. A custodian can halt signing and escalate suspected coercion. Physical coercion of the offline signer or holder of a recovery code remains possible. Recovery codes can apply only the fixed local emergency overrides. |

## Consent, revocation and pilot scope

- Before enrolment, record affirmative owner consent covering the fleet, devices,
  delegate and scopes, allowed changes, collected data, revocation and exit.
  Keep Android's provisioning consent screen. Give the owner persistent
  access to the active delegate, scope and latest verified state. Require
  recent strong authentication (passkey or MFA) for accepting delegation,
  scope changes and approving writes. Let the owner revoke without the delegate.
- Revoke human access at the service immediately, including sessions,
  invitations and pending or unissued requests. Record that separately from
  device confirmation. The v1 device protocol uses root-signed key-set versions
  and per-document floors. It has no human-role epoch or fleet-policy expiry.
  Already-issued signed bytes remain eligible until superseded by a higher
  accepted policy or invalidated by accepted key-set rotation. An offline device
  keeps its enforced state. Use the [revocation runbook](remote-v1-runbooks.md#revoke-access-or-a-key).
- Start with view-only fleet and device status. Prove tenant isolation, scope
  revocation and reporting of requested, committed and verified state before
  exposing edits, uploads or commands. For the first write pilot, permit only
  allow/block of ordinary user apps and an explicitly approved list of low-risk
  rules with verified recovery. Keep kiosk, ADB/developer/USB, network/VPN,
  accounts, ownership, raw system packages, recovery operations and remote
  commands outside the pilot. Require a physical production-verification device
  with hardware-attested Verified Boot and a locked bootloader. Confirm the
  production package and signer against the independent inventory using
  [`android_attestation.py`](../tools/android_attestation.py) and
  [`fleet_admin.py verify-enrolment`](../tools/README.md#offline-fleet-administration).
  Fixture identities and `--allow-untrusted` are lab-only.

## Data and audit

- Retain only fleet-scoped pseudonymous device IDs, minimum identity and
  attestation proof for enrolment, consent and role records, signed policy
  versions/digests, last-seen status, package counts, read-back state, stable
  failure/audit codes and command or recovery outcomes. Limit raw enrolment
  evidence and the offline identity inventory to operators who verify them.
  Treat pseudonymous IDs and attestation records as private. Keep report payloads,
  QR material, tickets and recovery codes out of public issues and evidence.
  Exclude browsing history, location, messages, contacts, screenshots, app
  contents, kiosk URL paths/queries and local credentials from telemetry.
  [`RemotePolicyRuntime.report`](../app/src/main/java/com/example/lockdowndpc/policy/RemotePolicyRuntime.kt),
  [`DeviceHealthRedaction`](../app/src/main/java/com/example/lockdowndpc/health/DeviceHealthRedaction.java).
- Record consent, grants, denials, revocations, signing/upload, delivery,
  refusals, read-back and recovery with a fleet-scoped actor reference, action,
  timestamp, target and relevant versions/digests. Check export sequence and
  hash continuity against independently stored checkpoints. For enforcement,
  verify the device signature against the enrolled key, recompute the generation
  hash from the exact signed policy and reported overrides, and match it to
  `verifiedGeneration`. Report gaps, stale evidence and mismatches. Upload or
  journal acceptance alone gives no read-back proof.
  [`AuditLog`](../app/src/main/java/com/example/lockdowndpc/policy/AuditLog.java),
  [sync and hashes](remote-management.md#53-sync).
- Approve a pilot retention schedule for each record type and backups before
  enrolment. Restrict and log access. Export evidence to the owner securely and
  delete or anonymize on expiry or exit, subject to a documented incident hold
  with owner, scope and review date. Use bounded audit segments with exported
  checkpoints so permitted deletion preserves verification of retained segments.
  Complete the applicable privacy and accessibility review before customer use.
