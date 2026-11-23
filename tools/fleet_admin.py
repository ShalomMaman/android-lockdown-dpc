#!/usr/bin/env python3
"""Issue and verify Device Guard remote-management files offline."""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
import re
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import android_attestation as attestation
import publish_update
from remote_contract import (
    CONTRACT,
    PROTOCOL,
    SCHEMA,
    TICKET_BYTES,
    b64url,
    canonical,
    decode,
    envelope_error,
    hash_hex,
    load,
    parse_wire,
    payload_error,
    pointer,
    schema_error,
    spki_point,
    write_private_bundle,
)


class FleetError(ValueError):
    """An operator-facing refusal with no credential values."""


FIXTURE_KEY_IDS = frozenset(
    key["keyId"] for key in load(CONTRACT / "vectors" / "signed-documents.json")["keys"].values()
)
IDENTITY_TYPES = {"serial", "enrollmentSpecificId"}
MAX_INPUT_BYTES = 4 * 1024 * 1024
DEFAULT_REVOCATION_MAX_AGE_DAYS = 7
REVOCATION_CLOCK_TOLERANCE_SECONDS = 5 * 60


def read_bytes(path: Path, limit: int = MAX_INPUT_BYTES) -> bytes:
    with path.expanduser().open("rb") as source:
        data = source.read(limit + 1)
    if len(data) > limit:
        raise FleetError("input file is too large")
    return data


def read_json(path: Path) -> object:
    try:
        return parse_wire(read_bytes(path))
    except (ValueError, RecursionError):
        raise FleetError(f"invalid strict JSON input: {path.name}") from None


def check_definition(name: str, value: object, label: str) -> None:
    if error := schema_error(SCHEMA["$defs"][name], value):
        raise FleetError(f"{label}: {error[0]} at {error[1] or '/'}")


def check_document(document: object) -> None:
    if error := payload_error(document):
        raise FleetError(f"{error[0]} at {error[1] or '/'}")


def key_id(spki: bytes) -> str:
    fingerprint = b64url(hashlib.sha256(spki).digest())
    if fingerprint in FIXTURE_KEY_IDS:
        raise FleetError("contract fixture keys are refused")
    return fingerprint


def require_p256(raw: bytes) -> str:
    encoded = b64url(raw)
    if spki_point(encoded) is None:
        raise FleetError("key must use named P-256 with an uncompressed public point")
    key_id(raw)
    return encoded


def public_spki(path: Path) -> str:
    try:
        raw = attestation.openssl(["pkey", "-pubin", "-inform", "PEM", "-in",
                                   str(path.expanduser().resolve()), "-outform", "DER"])
    except attestation.AttestationError:
        raise FleetError("OpenSSL could not read the PEM public key") from None
    return require_p256(raw)


@dataclass(frozen=True)
class SigningKey:
    path: Path
    passin: str
    spki: bytes
    fingerprint: str

    @classmethod
    def open(cls, args: argparse.Namespace) -> SigningKey:
        path = args.private_key.expanduser().resolve()
        if not path.is_file() or path.is_relative_to(CONTRACT.parents[1]):
            raise FleetError("--private-key must name a PEM file outside the checkout")
        check_output(args.output, path)
        passin = publish_update.openssl_passin(args.key_passphrase_env)
        try:
            spki = attestation.openssl(["pkey", "-inform", "PEM", "-in", str(path),
                                        "-passin", passin, "-pubout", "-outform", "DER"])
        except attestation.AttestationError:
            raise FleetError("OpenSSL could not read the private PEM; check the key and passphrase variable") from None
        require_p256(spki)
        return cls(path, passin, spki, key_id(spki))

    def sign(self, payload: bytes) -> bytes:
        try:
            return attestation.openssl(
                ["dgst", "-sha256", "-passin", self.passin, "-sign", str(self.path)], payload,
            )
        except attestation.AttestationError:
            raise FleetError("OpenSSL could not sign the document") from None


def check_output(output: Path, *inputs: Path) -> None:
    path = output.expanduser().resolve()
    if path.is_relative_to(CONTRACT.parents[1]):
        raise FleetError("write fleet files outside the Device Guard checkout")
    for source in inputs:
        other = source.expanduser().resolve()
        if path == other or (path.exists() and other.exists() and path.samefile(other)):
            raise FleetError("output must not overwrite an input file")


def signed_envelope(document: dict, key: SigningKey) -> bytes:
    check_document(document)
    payload = canonical(document)
    limit = PROTOCOL["envelope"]["maxEncodedBytes"]
    if len(payload) > limit:
        raise FleetError("payload exceeds the signed envelope size limit")
    signature = key.sign(payload)
    # Catch a key file replacement between deriving the public key and signing.
    attestation.verify_signature(key.spki, payload, signature)
    envelope = canonical({"format": "dg-signed/1", "keyId": key.fingerprint,
                          "payload": b64url(payload), "signature": b64url(signature)})
    if envelope_error(envelope):
        raise FleetError("signed envelope exceeds the wire limit or is malformed")
    return envelope


def emit(args: argparse.Namespace, document: dict, key: SigningKey) -> None:
    publish_update.write_atomic(args.output, signed_envelope(document, key), args.force)


def header(fleet: str, kind: str) -> dict:
    return {"schemaVersion": 1, "type": kind, "fleetId": fleet}


def checked_key_roles(document: dict, root: str) -> None:
    successor = document.get("successorRoot")
    roles = [root, document["serverKey"], *document["fleetPolicyKeys"]]
    if successor is not None:
        roles.append(successor)
    for role in roles:
        key_id(decode(role))
    if len(set(roles)) != len(roles):
        raise FleetError("the root, successor, server and fleet policy keys must be distinct")


def keyset(args: argparse.Namespace) -> None:
    key = SigningKey.open(args)
    public_inputs = [*args.policy_public_key, args.server_public_key]
    if args.successor_root_public_key:
        public_inputs.append(args.successor_root_public_key)
    check_output(args.output, *public_inputs)
    document = {
        **header(args.fleet_id, "keyset"),
        "keySetVersion": args.key_set_version,
        "serverUrl": args.server_url,
        "fleetPolicyKeys": [public_spki(path) for path in args.policy_public_key],
        "serverKey": public_spki(args.server_public_key),
    }
    if args.successor_root_public_key is not None:
        document["successorRoot"] = public_spki(args.successor_root_public_key)
    checked_key_roles(document, b64url(key.spki))
    emit(args, document, key)
    print(f"Signed key set version {args.key_set_version}. Root fingerprint {key.fingerprint}")


def read_envelope(path: Path) -> tuple[dict, bytes]:
    raw = read_bytes(path, PROTOCOL["envelope"]["maxEncodedBytes"])
    if envelope_error(raw):
        raise FleetError("invalid signed document envelope")
    envelope = parse_wire(raw)
    if envelope["keyId"] in FIXTURE_KEY_IDS:
        raise FleetError("contract fixture keys are refused")
    return envelope, decode(envelope["payload"])


def signed_payload(raw: bytes, expected_type: str) -> dict:
    try:
        document = parse_wire(raw)
    except (ValueError, RecursionError):
        raise FleetError("invalid signed JSON payload") from None
    check_document(document)
    if document["type"] != expected_type:
        raise FleetError(f"expected a {expected_type} document")
    return document


def policy_signing_key(args: argparse.Namespace) -> SigningKey:
    check_output(args.output, args.keyset, args.root_public_key)
    root = public_spki(args.root_public_key)
    envelope, payload = read_envelope(args.keyset)
    if envelope["keyId"] != key_id(decode(root)):
        raise FleetError("key set signer does not match --root-public-key")
    attestation.verify_signature(decode(root), payload, decode(envelope["signature"]))
    document = signed_payload(payload, "keyset")
    checked_key_roles(document, root)
    if document["fleetId"] != args.fleet_id or document["keySetVersion"] != args.key_set_version:
        raise FleetError("key set fleet or version does not match the document")
    key = SigningKey.open(args)
    if b64url(key.spki) not in document["fleetPolicyKeys"]:
        raise FleetError("private key is not a fleet policy key in the verified key set")
    return key


def identity_fields(value: object) -> None:
    if (not isinstance(value, dict) or not {"identityType", "identity", "firmwareFamily"} <= value.keys()
            or any(not isinstance(value[field], str) or not value[field].strip()
                   for field in ("identityType", "identity", "firmwareFamily"))
            or value["identityType"] not in IDENTITY_TYPES):
        raise FleetError("inventory requires an identityType, identity and firmwareFamily for each device")


def issue_credentials(args: argparse.Namespace) -> None:
    check_output(args.output, args.devices)
    if not args.fleet_id.strip():
        raise FleetError("--fleet-id must not be empty")
    devices = read_json(args.devices)
    if not isinstance(devices, list) or not devices or (args.command == "bench-code" and len(devices) != 1):
        raise FleetError("provide a nonempty device list (exactly one device for bench-code)")
    for device in devices:
        identity_fields(device)
        if set(device) != {"identityType", "identity", "firmwareFamily"}:
            raise FleetError("unexpected field in the device list")
    identities = {(device["identityType"], device["identity"]) for device in devices}
    if len(identities) != len(devices):
        raise FleetError("the device list repeats an identity")
    bench = args.command == "bench-code"
    hours = 1 if bench else args.valid_for_hours
    if not 1 <= hours <= 168:
        raise FleetError("enrolment tickets must expire within 1 to 168 hours")
    now = int(time.time())
    inventory, server, codes = [], [], []
    for device in devices:
        random_bytes = secrets.token_bytes(10 if bench else TICKET_BYTES)
        code = base64.b32encode(random_bytes).decode("ascii") if bench else b64url(random_bytes)
        digest = hash_hex(code.encode("ascii") if bench else random_bytes)
        registration = {"ticketSha256": digest, "fleetId": args.fleet_id,
                        "expiresAt": now + hours * 3600, "maxUses": 1}
        if bench:
            registration["maxAttempts"] = 5
        server.append(registration)
        inventory.append({"ticketSha256": digest, "fleetId": args.fleet_id, **device})
        codes.append(code)
    write_private_bundle(args.output.expanduser().resolve(), {
        "bench-code.txt" if bench else "tickets.txt": ("\n".join(codes) + "\n").encode("ascii"),
        "inventory.json": canonical(inventory) + b"\n",
        "server.json": canonical(server) + b"\n",
    })
    print(f"Created {len(codes)} one-use enrolment credential(s) with a {hours}-hour lifetime.")


def load_inventory(paths: list[Path]) -> dict[str, dict]:
    entries = {}
    for path in paths:
        inventory = read_json(path)
        if not isinstance(inventory, list):
            raise FleetError("expected a list of local enrolment inventory entries")
        for entry in inventory:
            identity_fields(entry)
            digest = entry.get("ticketSha256")
            check_definition("sha256Hex", digest, "inventory ticket digest")
            if not isinstance(entry.get("fleetId"), str) or not entry["fleetId"].strip():
                raise FleetError("inventory fleetId is missing")
            if digest in entries:
                raise FleetError("inventory repeats a ticket digest")
            entries[digest] = entry
    return entries


def load_revocations(path: Path, max_age_days: int) -> set[str]:
    if max_age_days <= 0:
        raise FleetError("--revocation-max-age-days must be positive")
    with path.expanduser().open("rb") as source:
        age = time.time() - os.fstat(source.fileno()).st_mtime
        if age < -REVOCATION_CLOCK_TOLERANCE_SECONDS:
            raise FleetError("Android attestation revocation list has a future modification time")
        if age > max_age_days * 24 * 3600:
            raise FleetError(f"Android attestation revocation list is older than {max_age_days} day(s)")
        raw = source.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise FleetError("Android attestation revocation list is too large")
    try:
        status = parse_wire(raw)
    except (ValueError, RecursionError):
        raise FleetError("invalid Android attestation revocation list") from None
    if not isinstance(status, dict) or not isinstance(status.get("entries"), dict):
        raise FleetError("invalid Android attestation revocation list")
    serials = set()
    for serial, entry in status["entries"].items():
        if (not re.fullmatch(r"[0-9a-fA-F]+", serial) or not isinstance(entry, dict)
                or entry.get("status") not in ("REVOKED", "SUSPENDED")):
            raise FleetError("invalid Android attestation revocation entry")
        serials.add(serial.lower().lstrip("0") or "0")
    return serials


def enrolment_transcript(record: dict) -> bytes:
    return canonical([
        "dg-enrol/1", record["challenge"], record["ticketSha256"],
        hash_hex(canonical(record["attestationChain"])), hash_hex(canonical(record["facts"])),
    ])


@dataclass(frozen=True)
class EnrolmentVerifier:
    inventory: dict
    roots: list[attestation.Certificate]
    revoked: set[str]
    package: str
    signer: bytes

    @classmethod
    def open(cls, args: argparse.Namespace) -> EnrolmentVerifier:
        if not all((args.inventory, args.attestation_roots, args.revocation_list,
                    args.expected_package, args.expected_signer_sha256)):
            raise FleetError("offline verification requires inventory, attestation roots, "
                             "revocation list, expected package and APK signer SHA-256")
        check_definition("packageName", args.expected_package, "expected package")
        signer = publish_update.normalize_certificate_sha256(args.expected_signer_sha256)
        roots = read_bytes(args.attestation_roots).decode("ascii")
        if roots.lstrip().startswith("["):
            roots = read_json(args.attestation_roots)
            if not isinstance(roots, list):
                raise FleetError("expected an array of attestation roots")
        return cls(
            load_inventory(args.inventory), attestation.root_certificates(roots),
            load_revocations(args.revocation_list, args.revocation_max_age_days), args.expected_package,
            bytes.fromhex(signer),
        )

    def verify(self, record: object, fleet: str) -> tuple[str, str, int]:
        if not isinstance(record, dict):
            raise FleetError("enrolment record must be an object")
        if record.get("fleetId") != fleet:
            raise FleetError("enrolment record belongs to a different fleet")
        ticket_sha = record.get("ticketSha256")
        check_definition("sha256Hex", ticket_sha, "enrolment ticket digest")
        entry = self.inventory.get(ticket_sha)
        if entry is None or entry["fleetId"] != fleet:
            raise FleetError("enrolment ticket is absent from the local fleet inventory")
        check_definition("base64url32", record.get("deviceId"), "device ID")
        check_definition("base64url32", record.get("challenge"), "challenge")
        check_definition("base64url", record.get("transcriptSignature"), "transcript signature")
        encoded_chain = record.get("attestationChain")
        if not isinstance(encoded_chain, list) or not 1 <= len(encoded_chain) <= 16:
            raise FleetError("attestation chain must contain 1 to 16 DER certificates")
        chain = []
        for encoded_cert in encoded_chain:
            check_definition("base64url", encoded_cert, "attestation certificate")
            chain.append(attestation.certificate(decode(encoded_cert)))
        attestation.verify_chain(chain, self.roots, self.revoked)
        serial = attestation.verify_android_fields(
            chain, decode(record["challenge"]), self.package, self.signer,
        )
        device_id = key_id(chain[0].spki)
        if device_id != record["deviceId"]:
            raise FleetError("device ID does not match the attested leaf key")
        facts = record.get("facts")
        if not isinstance(facts, dict) or type(facts.get("sdk")) is not int or facts["sdk"] < 29:
            raise FleetError("enrolment facts must report a supported Android SDK")
        try:
            attestation.verify_signature(chain[0].spki, enrolment_transcript(record),
                                         decode(record["transcriptSignature"]))
        except attestation.AttestationError:
            raise FleetError("enrolment transcript signature does not match the attested key") from None
        identity = serial if entry["identityType"] == "serial" else facts.get("enrollmentSpecificId")
        if entry["identityType"] == "enrollmentSpecificId" and facts["sdk"] < 31:
            raise FleetError("enrollment-specific identity requires Android 12 or newer")
        if identity != entry["identity"]:
            raise FleetError("device identity does not match the local enrolment inventory")
        if facts.get("firmwareFamily") != entry["firmwareFamily"]:
            raise FleetError("firmware family does not match the local enrolment inventory")
        return device_id, entry["firmwareFamily"], facts["sdk"]


def verify_enrolment(args: argparse.Namespace) -> None:
    verifier = EnrolmentVerifier.open(args)
    verifier.verify(read_json(args.record), args.fleet_id)
    print("Enrolment record verified against the local fleet inventory.")


def drill_passes(path: Path | None) -> set[str]:
    if path is None:
        return set()
    records = read_json(path)
    if not isinstance(records, list):
        raise FleetError("drill evidence must list records by firmware family")
    passed = set()
    seen = set()
    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("firmwareFamily"), str):
            raise FleetError("drill evidence requires a firmwareFamily for each record")
        family = record["firmwareFamily"]
        if not family.strip() or family in seen:
            raise FleetError("drill evidence has an empty or repeated firmware family")
        seen.add(family)
        offline = record.get("offline")
        if (isinstance(offline, dict) and offline.get("tool") == "tools/update_drill.py"
                and offline.get("scope") == "offline-half-only" and offline.get("verdict") == "PASS"
                and record.get("onDevice") == "PASS"
                and isinstance(record.get("onDeviceEvidence"), str)
                and record["onDeviceEvidence"].strip()):
            passed.add(family)
    return passed


def policy_diff(before: object, after: object, path: str = "") -> list[str]:
    if before is MISSING and isinstance(after, dict) and after:
        before = {}
    if after is MISSING and isinstance(before, dict) and before:
        after = {}
    if isinstance(before, dict) and isinstance(after, dict):
        lines = []
        for field in sorted(before.keys() | after.keys()):
            lines.extend(policy_diff(before.get(field, MISSING), after.get(field, MISSING),
                                     pointer(path, field)))
        return lines
    if before is not MISSING and after is not MISSING and canonical(before) == canonical(after):
        return []
    return [f"{path}: {display_value(before)} -> {display_value(after)}"]


MISSING = object()


def display_value(value: object) -> str:
    return "(absent)" if value is MISSING else canonical(value).decode("utf-8")


def validate_policy_body(body: dict) -> None:
    if body.get("kiosk", {}).get("mode", "OFF") != "OFF":
        raise FleetError("the v1 device cannot accept remote kiosk mode")
    home_filter = body.get("homeFilter", {})
    if home_filter.get("enabled") and "routing" not in home_filter:
        raise FleetError("an enabled home filter requires routing for device read-back")
    ca = home_filter.get("caCertificate")
    if ca is not None:
        raw = base64.b64decode(ca, validate=True)
        try:
            canonical_der = attestation.openssl(["x509", "-inform", "DER", "-outform", "DER"], raw)
            constraints = attestation.openssl(["x509", "-inform", "DER", "-noout",
                                               "-ext", "basicConstraints"], raw)
        except attestation.AttestationError:
            raise FleetError("homeFilter CA must be a single DER X.509 CA certificate") from None
        if raw != canonical_der or b"CA:TRUE" not in constraints:
            raise FleetError("homeFilter CA must be a single DER X.509 CA certificate")


def policy(args: argparse.Namespace) -> None:
    inputs = [args.body, *args.enrolment_record, *args.inventory]
    inputs.extend(path for path in (args.attestation_roots, args.revocation_list,
                                    args.previous, args.drill_evidence) if path is not None)
    check_output(args.output, *inputs)
    body = read_json(args.body)
    document = {
        **header(args.fleet_id, "fleet-policy"), "keySetVersion": args.key_set_version,
        "fleetPolicyVersion": args.version, "deviceIds": args.device_id, "policy": body,
    }
    if args.audit_note is not None:
        document["auditNote"] = args.audit_note
    check_document(document)
    validate_policy_body(body)
    if FIXTURE_KEY_IDS.intersection(args.device_id):
        raise FleetError("contract fixture keys are refused as device IDs")

    previous = None
    if args.previous is not None:
        _, previous_raw = read_envelope(args.previous)
        previous = signed_payload(previous_raw, "fleet-policy")
        if previous["fleetId"] != args.fleet_id or previous["fleetPolicyVersion"] >= args.version:
            raise FleetError("previous policy must be for the same fleet and have a lower version")

    verified = {}
    supplied = set()
    if args.enrolment_record:
        verifier = EnrolmentVerifier.open(args)
        for path in args.enrolment_record:
            record = read_json(path)
            device = record.get("deviceId") if isinstance(record, dict) else None
            check_definition("base64url32", device, "enrolment record device ID")
            if device in supplied or device not in args.device_id:
                raise FleetError("enrolment records must be unique and belong to a policy target")
            supplied.add(device)
            try:
                _, family, sdk = verifier.verify(record, args.fleet_id)
            except (FleetError, attestation.AttestationError, UnicodeError) as exc:
                if not args.allow_untrusted:
                    raise FleetError(f"untrusted device: {exc}") from None
            else:
                verified[device] = (family, sdk)
    untrusted = set(args.device_id) - verified.keys()
    if untrusted:
        if not args.allow_untrusted:
            raise FleetError("untrusted device: each target requires a verified enrolment record")
        exception = "--allow-untrusted used for " + ", ".join(sorted(untrusted))
        document["auditNote"] = f"{args.audit_note}; {exception}" if args.audit_note else exception

    controls = body.get("systemControls", {})
    if "locale" in body and any(sdk < 33 for _, sdk in verified.values()):
        raise FleetError("a verified target cannot enforce locale before Android 13")
    # An omitted control inherits the blocking default on production devices.
    if controls.get("developer_options_and_adb", True):
        passed = drill_passes(args.drill_evidence)
        if untrusted or any(family not in passed for family, _ in verified.values()):
            raise FleetError("ADB guard: every target needs a verified firmware family with a "
                             "locally recorded self-update drill PASS")
    key = policy_signing_key(args)
    emit(args, document, key)
    print(f"Signed fleet policy version {args.version} for {len(args.device_id)} device(s).")
    print(f"Verified enrolment records: {len(verified)}. Untrusted targets: {len(untrusted)}.")
    if controls.get("app_stores_and_installers") is False:
        print("GLOBAL INSTALL EXPOSURE: app stores and installers are allowed.")
    if previous is None:
        print("Policy fields:")
        comparison = {}
    else:
        print(f"Field changes from supplied version {previous['fleetPolicyVersion']}:")
        comparison = previous
    # Versions and fleet are already named above. Include targets and any audit-note changes.
    fields = ("deviceIds", "policy", "auditNote")
    lines = policy_diff({field: comparison[field] for field in fields if field in comparison},
                        {field: document[field] for field in fields if field in document})
    print("\n".join(lines) if lines else "No field changes.")


def recovery(args: argparse.Namespace) -> None:
    if args.device_id in FIXTURE_KEY_IDS:
        raise FleetError("contract fixture keys are refused as device IDs")
    output = args.output.expanduser()
    if output.exists() or output.is_symlink():
        raise FileExistsError("recovery output directory already exists")
    output = output.resolve()
    key = policy_signing_key(args)
    spec = PROTOCOL["recovery"]
    code = "".join(secrets.choice(spec["codeAlphabet"]) for _ in range(spec["codeCharacters"]))
    salt = secrets.token_bytes(spec["saltBytes"])
    verifier = hashlib.pbkdf2_hmac("sha256", code.encode("ascii"), salt,
                                   spec["iterations"], dklen=spec["derivedBytes"])
    document = {
        **header(args.fleet_id, "recovery"), "keySetVersion": args.key_set_version,
        "recoveryVersion": args.version, "deviceId": args.device_id,
        "salt": b64url(salt), "verifier": b64url(verifier),
    }
    size = spec["displayGroupSize"]
    grouped_code = " ".join(code[start:start + size] for start in range(0, len(code), size))
    code_file = "recovery-code.txt"
    write_private_bundle(output, {
        "recovery.json": signed_envelope(document, key),
        code_file: (grouped_code + "\n").encode("ascii"),
    })
    print(output / code_file)


def reanchor(args: argparse.Namespace) -> None:
    if args.device_id in FIXTURE_KEY_IDS:
        raise FleetError("contract fixture keys are refused as device IDs")
    if args.policy_envelope is not None and args.keyset_envelope is None:
        raise FleetError("--policy-envelope requires --keyset-envelope")
    key = SigningKey.open(args)
    if args.root_fingerprint != key.fingerprint:
        raise FleetError("private key does not match the current root fingerprint")
    floors = {"keyset": args.keyset_floor, "fleet-policy": args.policy_floor,
              "recovery": args.recovery_floor, "command": args.command_floor}
    document = {
        **header(args.fleet_id, "re-anchor"), "deviceId": args.device_id, "nonce": args.nonce,
        "rootFingerprint": key.fingerprint, "rootSpki": b64url(key.spki), "floors": floors,
    }
    verified_payloads = {}
    trusted_signers = {"keyset": (key.spki,)}
    for kind, path, version_field in (
        ("keyset", args.keyset_envelope, "keySetVersion"),
        ("fleet-policy", args.policy_envelope, "fleetPolicyVersion"),
    ):
        if path is None:
            continue
        check_output(args.output, path)
        envelope, raw = read_envelope(path)
        payload = signed_payload(raw, kind)
        if payload["fleetId"] != args.fleet_id or payload[version_field] != floors[kind]:
            raise FleetError(f"{kind} envelope must match the re-anchor fleet and floor version")
        signer = next((spki for spki in trusted_signers[kind] if key_id(spki) == envelope["keyId"]), None)
        if signer is None:
            raise FleetError(f"{kind} envelope signer is not trusted")
        try:
            attestation.verify_signature(signer, raw, decode(envelope["signature"]))
        except attestation.AttestationError:
            raise FleetError(f"{kind} envelope signature is invalid") from None
        if kind == "fleet-policy" and payload["keySetVersion"] < floors["keyset"]:
            # The device refuses a policy whose keySetVersion is below its active key set.
            raise FleetError("fleet-policy envelope must be bound to the re-anchor key set version or later")
        if kind == "keyset":
            checked_key_roles(payload, b64url(key.spki))
            trusted_signers["fleet-policy"] = tuple(decode(spki) for spki in payload["fleetPolicyKeys"])
        verified_payloads[kind] = raw
    if verified_payloads:
        document["floorPayloadSha256"] = {kind: hash_hex(raw) for kind, raw in verified_payloads.items()}
    emit(args, document, key)
    print("Signed the re-anchor document for the supplied console nonce.")


def add_signing_options(parser: argparse.ArgumentParser, *, fleet_policy: bool = False,
                        bundle_output: bool = False) -> None:
    parser.add_argument("--private-key", required=True, type=Path, help="External PEM private key")
    parser.add_argument("--key-passphrase-env", metavar="NAME", help="Environment variable read by OpenSSL")
    parser.add_argument("--fleet-id", required=True)
    if bundle_output:
        parser.add_argument("--output", type=Path, required=True,
                            help="New private output directory outside the checkout")
    else:
        parser.add_argument("--output", type=Path, required=True, help="Output file outside the checkout")
        parser.add_argument("--force", action="store_true", help="Atomically replace an existing output file")
    if fleet_policy:
        parser.add_argument("--keyset", type=Path, required=True, help="Root-signed key set envelope")
        parser.add_argument("--root-public-key", type=Path, required=True, help="Trusted fleet root PEM public key")
        parser.add_argument("--key-set-version", required=True, type=int)
        parser.add_argument("--version", required=True, type=int)


def add_enrolment_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--inventory", action="append", default=[], type=Path, help="Local issuance inventory JSON")
    parser.add_argument("--attestation-roots", type=Path, help="Offline Google hardware attestation roots")
    parser.add_argument("--revocation-list", type=Path, help="Offline Google attestation status JSON")
    parser.add_argument("--revocation-max-age-days", type=int, default=DEFAULT_REVOCATION_MAX_AGE_DAYS,
                        help="Maximum age of the local revocation list by modification time (default: %(default)s)")
    parser.add_argument("--expected-package", help="Expected Device Guard application ID")
    parser.add_argument("--expected-signer-sha256", help="Expected APK signing certificate SHA-256")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    keys = subcommands.add_parser("keyset", help="Build and root-sign a fleet key set")
    add_signing_options(keys)
    keys.add_argument("--key-set-version", required=True, type=int)
    keys.add_argument("--server-url", required=True)
    keys.add_argument("--server-public-key", type=Path, required=True, help="PEM server public key")
    keys.add_argument("--policy-public-key", action="append", type=Path, required=True, help="PEM policy public key")
    keys.add_argument("--successor-root-public-key", type=Path, help="PEM successor root public key")
    keys.set_defaults(run=keyset)

    enrolment = subcommands.add_parser("verify-enrolment", help="Verify a downloaded enrolment record offline")
    enrolment.add_argument("--record", type=Path, required=True)
    enrolment.add_argument("--fleet-id", required=True)
    add_enrolment_options(enrolment)
    enrolment.set_defaults(run=verify_enrolment)

    policies = subcommands.add_parser("policy", help="Validate, review and sign a fleet policy")
    add_signing_options(policies, fleet_policy=True)
    policies.add_argument("--body", type=Path, required=True, help="Policy body JSON")
    policies.add_argument("--device-id", action="append", required=True, help="Target device ID (repeatable)")
    policies.add_argument("--enrolment-record", action="append", default=[], type=Path)
    policies.add_argument("--allow-untrusted", action="store_true", help="Record an exception in the signed audit note")
    policies.add_argument("--previous", type=Path, help="Previous policy envelope for local comparison")
    policies.add_argument("--audit-note")
    policies.add_argument("--drill-evidence", type=Path, help="Recorded offline and on-device passes by firmware family")
    add_enrolment_options(policies)
    policies.set_defaults(run=policy)

    recover = subcommands.add_parser("recovery", help="Write a private recovery code and signed verifier bundle")
    add_signing_options(recover, fleet_policy=True, bundle_output=True)
    recover.add_argument("--device-id", required=True)
    recover.set_defaults(run=recovery)

    for name, help_text in (("tickets", "Issue per-device enrolment tickets"),
                            ("bench-code", "Issue one bench enrolment code")):
        issue = subcommands.add_parser(name, help=help_text)
        issue.add_argument("--fleet-id", required=True)
        issue.add_argument("--devices", required=True, type=Path, help="Local JSON list of device identities and families")
        issue.add_argument("--output", required=True, type=Path, help="New private output directory outside the checkout")
        if name == "tickets":
            issue.add_argument("--valid-for-hours", type=int, default=72, help="Ticket lifetime (default 72, max 168)")
        issue.set_defaults(run=issue_credentials)

    anchor = subcommands.add_parser("reanchor", help="Sign a device's local storage re-anchor challenge")
    add_signing_options(anchor)
    anchor.add_argument("--device-id", required=True)
    anchor.add_argument("--nonce", required=True)
    anchor.add_argument("--root-fingerprint", required=True, help="Current root fingerprint from the device binding")
    for kind in ("keyset", "policy", "recovery", "command"):
        anchor.add_argument(f"--{kind}-floor", type=int, required=True)
    anchor.add_argument("--keyset-envelope", type=Path, help="Issued key set envelope at --keyset-floor")
    anchor.add_argument("--policy-envelope", type=Path,
                        help="Issued policy envelope at --policy-floor (requires --keyset-envelope)")
    anchor.set_defaults(run=reanchor)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        args.run(args)
    except (FleetError, attestation.AttestationError, publish_update.PublishError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except FileExistsError:
        print("error: output already exists", file=sys.stderr)
        return 2
    except (OSError, ValueError, RecursionError):
        print("error: could not read or write the requested files, or an input is malformed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
