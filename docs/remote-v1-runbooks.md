# Remote management v1 — operating runbooks

Use the [accepted ADR](remote-v1-adr.md) for key authority and the
[security model](remote-v1-security.md) for consent and evidence handling.
The production service and owner controls are activation requirements. Rehearse
with the [remote-test artifact](hardware-validation.md#remote-test-artifact) and
record redacted outcomes in the [device matrix](device-matrix.md).

## Revoke access or a key

1. For a lost admin phone or withdrawn consent, revoke the role, sessions,
   invitations and affected authenticator at the service. Cancel pending
   commands, proposals and unpublished requests. Verify denial with the old
   grant. Review what was already signed or dispatched. If an issued policy
   must be undone, stop relaying it and deliver a newer offline-signed policy
   or rotate the signing key if compromised. Neither action retracts a copy
   already received by an offline device.
2. For a lost or exposed server or fleet policy key, identify affected fleets
   and the latest issued versions from independent records. Use the offline
   root with `fleet_admin.py keyset` to sign a higher version replacing the
   affected public key. Omit the compromised key. For a device key, deny that
   identity at the service, stop listing it in future policies and investigate
   forged status. A replacement device identity requires fresh enrolment.
3. For suspected root compromise, freeze writes and enrolment. Use a trusted,
   previously named successor only if the accepted device trust can be
   verified independently. Isolate uncertain devices and use an owner-approved
   reset and fresh enrolment under a clean root if trust cannot be established.
4. Confirm each reachable device's new key-set version in a verified signed
   sync. For any replacement policy, match its recomputed expected generation
   to signed `verifiedGeneration`. Record unreachable devices as pending.
   Rotation updates trust and leaves the currently applied policy in force.
   [Fleet tooling](../tools/README.md#offline-fleet-administration),
   [`RemoteVerifier`](../app/src/main/java/com/example/lockdowndpc/remote/RemoteVerifier.kt).

## Server compromise

1. Isolate the relay, suspend uploads, enrolment and commands, and revoke
   service sessions, credentials and command-signing access. Preserve a private
   snapshot and retrieve independently exported audit checkpoints. Establish
   which reports and records were exposed and which commands were issued.
2. Treat server-only claims as untrusted. Compare previously saved signed
   documents and device requests against the independent export. If reachable
   devices face command abuse, use `commands-off` through the owner-approved
   local recovery path once that path has been proven on hardware.
3. Rebuild the relay with clean credentials and protected command signing.
   Restore only independently verified state, rotate the command key using
   the first runbook, and reissue affected enrolment tickets. Use a trusted
   HTTPS endpoint that enrolled clients can reach with their enrolled trust
   settings. The merged [`RemoteTestJobService`](../app/src/main/java/com/example/lockdowndpc/policy/RemoteTestJobService.kt)
   connects using the stored provisioning URL and pins, so rehearse endpoint
   recovery before relying on a migration. Resume view-only service first.

## Recover without factory reset

1. For a bad filter or command abuse, pre-stage a one-use signed recovery
   verifier with `fleet_admin.py recovery` and verify delivery before pilot
   enrolment is considered complete. Give the clear code only through owner
   custody. On the device, choose `network-off`, `commands-off`, or both as
   needed, then enter the code. The journal consumes it and records the
   overrides in one durable commit. Verify the resulting restrictions and
   recovery evidence, then issue a fresh verifier. A newer fleet policy
   clears the overrides, so review when to deliver it. The recovery engine
   is merged, and the owner-facing code-entry flow and physical drill remain
   activation gates. [`RemoteEngine.recover`](../app/src/main/java/com/example/lockdowndpc/remote/RemoteEngine.kt),
   [recovery semantics](remote-management.md#8-recovery-code).
2. For a supported journal fault, open the device's re-anchor screen and take
   the one-use challenge to the offline root operator. Verify the fleet,
   device and current root through independent records. Run
   `fleet_admin.py reanchor` using the latest issued key-set, fleet-policy,
   recovery and command floors. Supply the original signed envelopes if
   exact same-version re-delivery is required. Submit the signed response in
   the console, then relay the replacement key set and policy. Confirm
   Android read-back and return to `REMOTE` before re-enabling commands.
   Existing live restrictions remain during repair. Old recovery codes and
   command outcomes do not carry over. Issue and verify a new recovery
   verifier. [`RemoteConsole`](../app/src/main/java/com/example/lockdowndpc/ui/RemoteConsole.kt),
   [re-anchor contract](remote-contract/README.md#console-re-anchor).
3. Stop if the console requires reset, identity cannot be authenticated, or
   authenticated trust records disagree. A pending bind after interrupted
   rotation can require reset. Preserve evidence and obtain the owner's
   approval before any destructive exit.

## Device exit (unenrol)

1. Confirm the owner's withdrawal or retirement decision. Retire the device
   in the service, deny future sync for its old identity, revoke outstanding
   tickets and queued work, remove it from future policy targets, and revoke
   any associated delegated grants. Record service retirement separately
   from physical release. Android restrictions remain in place until release.
2. Back up permitted data and confirm reset access requirements with the
   custodian. The supported release for a Device Guard Device Owner is an
   owner-approved, local factory reset using the documented OEM recovery
   path. The DPC has no ownership transfer, self-unenrol or remote wipe.
   [Provisioning and release](provisioning.md#recovering-a-device-with-the-wrong-component-or-identity).
3. Verify the device starts fresh with the previous owner and identity gone,
   and that the old identity stays denied at the service. Apply the retention
   and incident-hold rules to device records and backups. A device that later
   returns needs a fresh ticket and verified enrolment.

## Incident handling

1. Assign an incident owner and timestamp the scope, first detection and last
   reliable device evidence. Freeze new grants, policy publication and command
   dispatch for the affected scope. Contact the custodian through a verified
   channel and keep tickets, identifiers and raw evidence private.
2. Preserve signed request/envelope bytes, relevant versions and digests,
   exported audit checkpoints and redacted device outcomes. Verify the chain
   against the independent checkpoint and corroborate impact with signed device
   read-back. Track unreachable devices and evidence gaps explicitly.
3. Follow the appropriate runbook above. Resume view-only after clean access
   and device evidence are verified. Require owner approval and reviewed
   incident evidence before resuming writes. Record residual exposure and review
   any evidence hold when closing the incident.
