# Device Guard remote contract v1

This is the offline contract for [PR 4](../remote-management.md#12-v1-delivery-plan).
`v1.schema.json` uses JSON Schema Draft 2020-12. Its top level accepts one
decoded v1 payload. The `$defs/envelope` entry describes the signed wrapper.
`protocol.json` records the rules that depend on bytes, trust, ordering or
durable state. Production verification and Android fault injection belong to
PR 5.

Run the fixture check from the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tools -p 'test_*.py'
```

The check uses only the Python standard library. All key material and the
recovery code in the fixtures are **TEST ONLY**. The files contain public
SPKIs and deterministic P-256 signatures over synthetic documents. The tests
verify them locally, compute the SHA-256 and PBKDF2 values, validate the
closed schemas and replay the state transitions in an in-memory model.

Release builds and `fleet_admin` must refuse every fixture key ID, whether
presented as a signer or derived from SPKI in a key role.

The app validates documents against its own packaged copy of the schema,
`app/src/main/assets/v1.schema.json`. It must stay byte-identical to
`v1.schema.json` here. `RemoteContractTest` fails when the two differ, and
when a vector file or section is added without a Kotlin test that replays it.

| Fixture key | Key ID |
| --- | --- |
| `root` | `wqxIfMAeuyha6pKbj8Ob-aoDUU9-ZGwnbb-EgRBEaZU` |
| `successor` | `UJp-JBAqRc7SuBFldywo2TmT8pYAXWLrlBjKp_XGf5A` |
| `policy` | `yuBMSRn_FyWj104OArTzeExdiHdbYIs7RguY37aICpI` |
| `server` | `AC_1Ky9Jg9KideBpZ_zXxvTKlcp-USbj1h9Rl4z51QM` |
| `policy-next` | `htxuEHubuWZIGu6bTg0LBRTPuH64WYhbyaVB6pyldnk` |
| `server-next` | `8iXZ83US03Z5z5ZaTwn9ifumVvnNpaOHHyghOAyGJTw` |
| `device` | `0N7UdpZGSywqoLCZa9dcI5BE7QtTB04SaEykPmwe74I` |
| `other-device` | `yry0uOnre8zDLuLKEy0BbEzndWUotWqG1JSNz18Rh5o` |
| `review-root` | `Ihuz3CXaARD5vI17XSYr3rE4zuHGSUphX-gk-9Nav70` |
| `review-successor` | `bBiF1hHDuE3iZhUHVRdArxFAUamsy29m94F8d7jc000` |
| `review-policy` | `Wt5dqGUiOGEOmQnsjREkEhaDTi-Gwutlowxos8oCfYw` |
| `review-server` | `GcH_iCSKuBg3eIxngwpuYtYDy-GlCwjyfzHejbgNCZg` |
| `reanchor-root` | `zFpgccW8b2hDsgIYtmCFrf3OcBrhtx8ahFN8skRU-Pg` |

## Wire decisions for review

- **Payload names.** The design gives a common header and a policy body
  example. This contract puts the body under `policy`, with `deviceIds`
  and `fleetPolicyVersion` alongside it. The optional `auditNote`
  carries the section 4.6 exception note. A keyset has implicit fleet-wide
  binding and carries at least one `fleetPolicyKeys` entry, a `serverKey`,
  a `serverUrl` and an optional `successorRoot`. Recovery uses `deviceId`,
  `recoveryVersion`, `salt` and `verifier`. Commands use `deviceId`, `sequence`, `nonce`
  and `kind`. The reserved Later names beyond the design's explicit
  examples are representative spellings grouped by section 14. The closed
  schemas also refuse any other spelling that is outside the v1 allowlists.
- **Encoding.** Bytes use unpadded base64url with zero unused bits unless
  the field has a more specific encoding. Identity fields keep the
  base64url SPKI-digest definition in sections 4.6 and 5.1. Policy and
  generation digests are lowercase hex. SPKIs use DER with the named P-256
  curve and an uncompressed point. A decoder must verify the curve point,
  parse strict UTF-8 JSON, refuse duplicate member names and lone
  surrogates, and enforce the 65,536-byte limit on the incoming envelope.
  Integer tokens use decimal notation with absolute value at most 2⁵³ − 1.
  Refuse a decimal point, an exponent, and `-0` at the decoder. The schema
  then applies each field's own range. Wire override lists must use unique
  codes in ascending ASCII order.
- **Canonical bytes.** Producers and the compiled baseline use compact
  UTF-8 JSON, with ASCII object keys sorted by byte value and array order
  preserved. There is no Unicode normalization, BOM, whitespace outside
  strings or final newline. Escape quotation marks, backslashes and
  U+0000–U+001F. Use the short JSON escapes for backspace, tab, newline,
  form feed and carriage return. Write every other control in that range
  with `\u` and four lowercase hexadecimal digits, as in `\u001f`. Emit
  every other Unicode scalar as raw UTF-8, including DEL (U+007F) and
  characters above U+FFFF. In Java, encode supplementary characters as
  UTF-8 from their code points and refuse unpaired surrogates. Sign and
  verify the original payload bytes. A fleet policy
  may arrive with other valid field ordering or whitespace. Its
  `committedSha256` always hashes the exact decoded signed bytes. For the
  baseline the input is the canonical policy body. The generation hash
  uses the domain, binary digest and length-prefixed override codes in
  section 5.3. The example input `example` is a hash sample, while the
  separate pilot baseline fixture illustrates a section 4.4 policy body.
- **Policy records.** The schema uses the current 16 control IDs, the
  existing two app selection modes and the existing kiosk modes. Locale
  accepts `en`, `he` and the design's `iw` alias. Pins can target the
  current `MANAGEMENT_DEFAULTS` package. The `apps.allowed` list identifies
  the packages selected for the chosen mode, so it identifies allowed
  packages in `ALLOW_SELECTED` and blocked packages in `BLOCK_SELECTED`.
  System selections have at most one signer/version acceptance per package.
  A home filter can be omitted or explicitly disabled with
  `{"enabled": false}`. An enabled filter requires
  its VPN package and PAC URL. The CA, when present, is one X.509 CA encoded
  as padded standard base64 of canonical DER. `null` explicitly requests
  removal. The consumer also validates URLs and certificates with the
  existing policy validators and performs device-dependent checks before
  accepting a requested value as enforced.
- **Sync.** Response and dispatch use the half-open elapsed-time window
  `[sent, sent + 120000)` in the same boot. The first response for the
  outstanding exchange consumes its nonce, including a response whose nonce
  mismatches or whose documents are refused. A reply from a different
  exchange, including one that timed out, reports `sync-response-stale`
  and leaves the outstanding nonce usable.
  Verify the signature first, then validate the closed schema before
  checking `fleetId` or using any version to sort candidates or compare
  floors. A foreign `fleetId` is `doc-field-invalid` because the field fails
  the fleet binding for a recognized document type. The server key must be
  distinct from the root and successor roots and from all fleet policy
  keys. Fleet policy keys also sign recovery and must be distinct from
  those roots. A collision reports `doc-field-invalid`.
  The highest admissible listed fleet policy is selected. Once it advances
  the floor, lower authenticated candidates report rollback. Only an
  accepted keyset changes the active keys. When the named successor signs
  an accepted keyset, it becomes the current root. `sync.json` models decoded
  batches and request events. Transport framing and report serialization
  are left to PR 8.
- **Durability and codes.** A failed policy journal write leaves the live
  target unchanged. A failed projection write aborts the pass. After restart,
  reconciliation uses the covered durable target and rewrites every store.
  A matching stamp still requires a full projection. If the target changes
  mid-projection, the model restarts projection before starting a pass. If it
  changes during a pass, its read-back cannot advance the verified generation. The named
  projection checkpoints are based on section 6.3. The production tests
  must inject faults at the actual commits, including any per-package
  risk-acceptance writes. Fixture fields `passReadsMixedGeneration` and
  `verifiedAfterRetry` express the expected behavior of the in-memory
  model. The negative vector refuses a pass on a partial projection even
  with a matching stamp. The fixtures use `journal-write-failed` for
  projection and dispatch commit refusals. When the `DISPATCHING` write
  fails, the durable `ACCEPTED` entry becomes `command-expired` on restart.
  A restart with a durable `DISPATCHING` entry reports
  `dispatch-outcome-unknown` and closes the command without a second platform
  call.
  `cancelled-by-recovery`, `recovery-commit-failed` and
  `lock-screen-off-only` come from sections 5.4, 8.3 and 7.1 respectively.
  An outcome with no specified failure code carries `null`.
- **Recovery.** The public code fixture removes grouping spaces before
  deriving 32 bytes with PBKDF2-HMAC-SHA256. The wrong-code count is durable.
  The fifth failure starts the first `PinLockoutPolicy` penalty, and an
  attempt during it is refused before code verification. The lockout
  vectors cover the first penalty in one boot. Recovery adds the selected
  overrides to any active ones and cancels pending calls in the same
  durable transaction. After a failed `DONE` commit, a call-made flag on
  the live policy thread is evidence that the call executed. The live
  thread cancels a `DISPATCHING` entry if it knows the call has yet to run.
  After restart the flag is gone and a stranded `DISPATCHING` entry has an
  unknown outcome. Only a successful commit of a newer fleet policy clears
  the active overrides. The command sequence floor survives recovery.

## What the device adds to the contract

The schema says which documents are well formed. The device also refuses, with
`doc-field-invalid` and before the journal commit, a policy it could store but
never verify or safely leave:

- an enabled `homeFilter` without `routing`, because the VPN read-back needs
  the routing settings;
- a `homeFilter.vpnPackage` or `apps.systemSelection` entry that names a
  built-in blocked or protected package;
- any `kiosk.mode` other than `OFF`. A kiosk needs a local way out, and the
  remote console has no recovery entry yet. Remote kiosk comes back with that
  console;
- a `locale` or kiosk mode this build does not know. Nothing unknown is read as
  the default.

On Android 10–12 the device refuses an explicit `locale` with
`remote-locale-sdk-unsupported` before commit. Only Android 13 and later keep
the application language where a pass can read it back. When a new enabled
filter would exceed the 16-entry cleanup limit, the device refuses it with
`remote-filter-cleanup-limit` before commit. Turning the filter off is still
available. Both reasons appear inline in the device console.

Other device rules:

- **Android 10 or later.** `bindFleet` answers `enrolment-sdk-unsupported`
  below API 29, where the default controls cannot all be enforced.
- **No local extras.** The strict remote pass applies only what the fleet
  policy carries. It does not apply night or work schedules, built-in block
  exemptions, the Chrome exemption or the credentials lock
  (`DISALLOW_CONFIG_CREDENTIALS`) that belongs to it. A fleet that needs the
  credentials lock has no field for it in v1.
- **Filter changes.** The device is never left with less than it had. A new
  filter is brought up and read back before anything older is removed. If any
  part fails after the VPN lockdown or the proxy already moved, the previous
  lockdown and proxy are put back and read back, and a certificate that the
  attempt added is withdrawn. The application behind the VPN in force is not
  hidden until the replacement is verified. A teardown removes the PAC proxy
  and the certificates, then the uninstall block, the routing settings and the
  profile restrictions, each read back, and releases the VPN lockdown as its
  last Android call. The cleanup list is capped at 16 superseded filters. The
  cap refuses another replacement and never refuses turning the filter off.
- **Releases.** A pass records in the journal which hidden packages it is about
  to show, including a hidden filter application it needs for the VPN
  read-back. If that pass does not end verified, they are hidden again, at once
  or at the next start, before any command is handled. The application behind
  the VPN lockdown in force is the one exception: it stays visible, and
  recorded, until a pass verifies.
- **Kiosk.** A kiosk left in the store of a device with remote intent is not
  restored at boot, and its HOME screen neither locks the task nor starts the
  target. The journal pass turns it off.
- **Journal protection.** The creation marker is stored first. The no-backup
  guard record uses format 4, with a device-specific Android Keystore HMAC-SHA256
  tag over the canonical JSON fields `format`, `current`, `previous` and
  `pending`. Each snapshot pins the fleet/device `bindingFingerprint`, the
  active `rootFingerprint`, and the four durable `floors` (key set, policy,
  recovery and command). `policySha256` pins the committed policy hash, which
  is checked against the exact stored payload bytes on read. The hash is null
  before any policy, including the version-zero baseline, is committed.
  `stateSha256` digests the canonical persisted journal state, including full
  trust, recovery verifier and usage, lockout, overrides and pending app
  releases. The seal treats two top-level fields specially:

  - `commands` contains command entries and outcomes that are updated and
    trimmed independently. A platform call requires a live acceptance in the
    current process, and the durable sequence floor stays sealed.
  - `verified` supplies the last verified generation for reapply command
    reports. Ordinary journals exclude it, and rebuilt journals seal it
    because it also gates commands and local recovery. Every projection still
    requires live read-back.
- **Pending writes and rotation.** The guard is atomically replaced before a
  protected journal write. The `pending` map is keyed by document type and
  records the version and SHA-256 of the canonical signed payload. For key sets
  it also records the signer fingerprint, since that signer becomes the active
  root. A pending version raises the replay floor immediately. At that floor,
  only the matching document can retry, and only while its version is absent
  from the journal. Signature, binding and command nonce checks still apply.
  A command in a new exchange normally needs a higher sequence because the
  new nonce changes its payload. Unrelated saves preserve outstanding retries.
  A higher accepted version supersedes a reservation for the same type.
  During a write, `previous` pins the entire pre-write snapshot and `current`
  pins the proposed snapshot. During root rotation, `previous.rootFingerprint`
  is the previous root fingerprint. The journal must match one whole snapshot.
  The committed trust remains in force until the journal write succeeds, and
  non-key-set documents wait for the reserved key set to commit. After the
  journal commits, the guard drops the previous snapshot and any fulfilled
  reservation. A restart that reads the new snapshot finishes this cleanup
  before using it. If `commit()` reports failure after the new journal has
  reached disk and a rollback cannot restore the live preference view, the
  next check observes a mismatch against the live journal and reports
  `journal-guard-mismatch` for the rest of that process. On restart, the
  durable journal matches the guard's `current` snapshot and cleanup resumes.
  Remote mode is committed after the first successful bind.
- **Storage refusals.** A missing or damaged committed journal reports
  `journal-lost`, even when all journal files are missing. A missing
  guard reports `journal-guard-missing`. A corrupt guard or unusable MAC key
  reports `journal-guard-unreadable`. Guard formats 1 through 3 fail closed
  with `journal-guard-reenrolment-needed`. A journal that
  matches neither authenticated snapshot reports `journal-guard-mismatch`.
  These failures leave existing restrictions in force. Before remote mode
  is committed, a creation marker and a valid guard with initial floors can
  resume an interrupted first bind to the same fleet, device and root when
  the journal file is absent. When a version-zero baseline is already in the
  journal, an interrupted first bind preserves both the baseline and the
  proposed binding. Only that binding can finish enrolment. Until it does,
  writes that would change the sealed baseline state are refused.
- **Command history.** The journal keeps the sequence floor and the last 16
  finished commands for the next report. Replay protection needs only the floor.

## Console re-anchor

A re-anchor is a local signed recovery document for the five storage refusals
above. It is separate from the four sync document types and has no sync version
or response slot. The console displays a copyable 32-byte random nonce,
encoded as unpadded base64url. The challenge exists only in the device process
and expires after 15 minutes of elapsed time or on a reboot. The device consumes
it before attempting any authorized write. After an interrupted write the
operator requests a new document for the new challenge.

The operator looks up the device and fleet in the existing fleet inventory.
The root from the latest committed keyset signs a standard `dg-signed/1`
envelope no larger than 65,536 bytes. Before the first keyset, the binding root
signs. The closed payload contains these fields.

- `schemaVersion: 1`, `type: "re-anchor"`, `fleetId`, `deviceId`, `nonce`,
  `rootFingerprint` and `rootSpki`. The root fingerprint is the key ID of
  the current root SPKI. The device verifies its independently stored
  binding fingerprint, `base64url(SHA-256(canonical([fleetId, deviceId])))`.
- `floors` with the latest issued versions for `keyset`, `fleet-policy`,
  `recovery` and `command`, including issued versions the device may never
  have received. Use zero for a type with no issuance. The device refuses
  any lower value than it can recover locally, including a reserved version.
  When local floors are unreadable the fleet's issuance inventory is required.
- Optional `floorPayloadSha256` with `keyset` and/or `fleet-policy` entries.
  These are lowercase hex SHA-256 digests of the exact decoded payload bytes.
  To resend the latest keyset or policy at its floor, its digest must be in
  this root-signed object. Without the digest, issue a version above the floor.
  A recovery code and a command always need versions above their floors.
  This preserves strict replay protection when two signed payloads share a version.

The bind record in no-backup storage protects the root SPKI, its fingerprint
and the binding fingerprint with an independent Android Keystore HMAC. A
rotation first writes the guard and stages the new recovery root in the bind
record, then commits the journal and finalizes the bind record. On restart the
guarded journal can finish or retry an interrupted rotation. A staged bind
record alone cannot authorize recovery.

An authenticated guard can prove the current root. With only a finalized bind
record, the operator also enters its root fingerprint. A journal proof
can corroborate either source. Disagreeing authenticated sources require a
factory reset and re-enrolment. The stored SPKI, when available, lets the
device check the signature before parsing the payload.

Readable legacy guards can contribute higher floors. A healthy older binding
can upgrade a matching legacy bind record, and a newly verified keyset can
replace a legacy record that still names the original root. The legacy
96-byte bind record alone cannot prove that its root is still current.
Devices that rotated before PR8 and already lost both main records have no
total-loss recovery path.

After verification, a durable mode record puts the device in `ENROLLING` and
the fresh guard reserves every floor before writing the new journal. A missing
guard HMAC key can be created at this point. An interruption keeps the device
locked down and preserves any floors already reserved. The rebuild discards
the old policy, recovery verifier, overrides, and command history. A verifiable
pending package-release ledger is retained for the next policy pass, so an
interrupted release can still be reversed. Apps exposed before the loss stay
visible until a replacement policy arrives. The recovered root must sign the
next keyset. Recovery codes and command processing
resume after the first replacement policy passes live read-back. The device
then returns to `REMOTE`.

## Fixture layout

| File | Coverage |
| --- | --- |
| `vectors/signed-documents.json` | Signed sync documents and key roles, including distinct exact encodings of the same policy |
| `vectors/document-shapes.json` | Valid and invalid decoded shapes, one mutation per vector, Later sections 14.1–14.9, malformed JSON and signed-envelope limits |
| `vectors/hashes.json` | The two section 5.3 goldens, override hash input order and wire order, canonical bytes, baseline, exact signed payloads and an older verified generation |
| `vectors/sync.json` | Nonce lifecycle and exact cutoff, order, current and successor roots, signer/device/version refusals and progression after a refusal |
| `vectors/dispatch.json` | Dispatch commits, crashes, recovery before and after the call, secure lock evidence and reapply outcomes |
| `vectors/journal.json` | The eight section 5.5 crash scenarios, each projection checkpoint, write failures and section 15 read-back requirements |
| `vectors/recovery.json` | Code derivation, lockout, atomic-use outcomes, replay, in-flight commands and override lifetime |
| `vectors/re-anchor.json` | Pinned-root signature, fleet and device binding, console nonce and replay floors |

Shape fixtures apply a JSON Pointer mutation to a decoded signed document.
Their outcomes describe schema and decoder validation. `device-id-range`
replaces the referenced list with the specified count of unpadded base64url
IDs, formed from successive 32-byte big-endian integers starting at zero.
The signed fixtures test wire integrity separately. A signature that verifies
with a fixture key still needs the document-specific trust, device and
version checks in the sync case. Journal and dispatch fixtures refer to the
named generations in `hashes.json` so the expected hashes have a single
source.
