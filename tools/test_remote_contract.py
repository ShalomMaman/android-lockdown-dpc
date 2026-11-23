"""Offline conformance checks for the public Device Guard v1 fixtures."""

import hashlib
import os
import re
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from remote_contract import (
    CONTRACT,
    FIELD_INVALID,
    MAX_WIRE_INTEGER,
    PAYLOAD_TYPES,
    PROTOCOL,
    SCHEMA,
    P,
    b64url,
    canonical,
    decode,
    envelope_error,
    hash_hex,
    load,
    parse_wire,
    payload_error,
    schema_error,
    spki_point,
    write_private_bundle,
)


def vectors(name):
    return load(CONTRACT / "vectors" / (name + ".json"))


DOC_ORDER = PROTOCOL["sync"]["order"]
REANCHOR_TYPE = PROTOCOL["reanchor"]["type"]
NONCE_LIMIT = PROTOCOL["sync"]["nonce"]["maxAgeMsExclusive"]
STORES = PROTOCOL["journal"]["projectionWrites"]
SIGNED = vectors("signed-documents")
KEYS = SIGNED["keys"]
ENVELOPES = {name: case["envelope"] for name, case in SIGNED["documents"].items()}
PAYLOADS = {name: decode(envelope["payload"]) for name, envelope in ENVELOPES.items()}
DOCS = {name: parse_wire(payload) for name, payload in PAYLOADS.items()}
GENERATIONS = vectors("hashes")["generations"]

ROLLBACK = "doc-version-rollback"
FOREIGN_FLEET = PROTOCOL["sync"]["foreignFleetFailureCode"]


def result(outcome, failure_code=None, **evidence):
    return {"outcome": outcome, "failureCode": failure_code, **evidence}


def validation_result(error):
    if error is None:
        return result("valid")
    return result("refused", error[0], path=error[1])


# Public fixture verification only. The app will use its platform provider.
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
def add(left, right):
    if left is None or right is None:
        return right if left is None else left
    x, y = left
    u, v = right
    if x == u and (y + v) % P == 0:
        return None
    slope = ((3 * x * x - 3) * pow(2 * y, -1, P) if left == right
             else (v - y) * pow(u - x, -1, P)) % P
    w = (slope * slope - x - u) % P
    return w, (slope * (x - w) - y) % P


def multiply(scalar, point):
    total = None
    while scalar:
        if scalar & 1:
            total = add(total, point)
        point = add(point, point)
        scalar >>= 1
    return total


def signature_valid(spki, payload, signature):
    # A DER P-256 signature fits in short-form TLV lengths.
    if not 8 <= len(signature) <= 72 or signature[:2] != bytes([48, len(signature) - 2]):
        return False
    remaining = signature[2:]
    integers = []
    for _ in range(2):
        if len(remaining) < 3 or remaining[0] != 2 or not 1 <= remaining[1] <= 33:
            return False
        size = remaining[1]
        raw = remaining[2:2 + size]
        if len(raw) != size or raw[0] & 0x80 or (size > 1 and raw[0] == 0 and raw[1] < 128):
            return False
        integers.append(int.from_bytes(raw, "big"))
        remaining = remaining[2 + size:]
    r, s = integers
    point = spki_point(spki)
    if remaining or point is None or not (1 <= r < N and 1 <= s < N):
        return False
    inverse = pow(s, -1, N)
    digest = int.from_bytes(hashlib.sha256(payload).digest(), "big")
    check = add(multiply(digest * inverse % N, G), multiply(r * inverse % N, point))
    return check is not None and check[0] % N == r


def edited_payload(case):
    document = deepcopy(DOCS[case["document"]])
    path = case["path"].split("/")[1:]
    parent = document
    for part in path[:-1]:
        parent = parent[int(part)] if isinstance(parent, list) else parent[part]
    key = int(path[-1]) if isinstance(parent, list) else path[-1]
    if case["op"] == "remove":
        del parent[key]
    elif case["op"] == "device-id-range":
        parent[key] = [b64url(index.to_bytes(32, "big")) for index in range(case["value"])]
    else:
        assert case["op"] == "set", case
        parent[key] = case["value"]
    return document


def generation_hash(committed, overrides):
    prefix = b"dg-gen/1\x00" + bytes.fromhex(committed) + bytes([len(overrides)])
    codes = [code.encode("ascii") for code in sorted(overrides)]
    return hash_hex(prefix + b"".join(bytes([len(code)]) + code for code in codes))


def sync_generation_error(body):
    fields = ("fleetPolicyVersion", "committedSha256", "generationSha256")
    current = {field: body[field] for field in (*fields, "overrides")}
    previous = body["verifiedGeneration"]
    if any(current[field] is None for field in fields):
        awaiting = (all(current[field] is None for field in fields)
                    and previous is None and current["overrides"] == [])
        return None if awaiting else FIELD_INVALID
    error = schema_error({"$ref": "#/$defs/generation"}, current)
    if error is None and previous is not None:
        error = schema_error({"$ref": "#/$defs/verifiedGeneration"}, previous)
    return error[0] if error else None


def keyset_role_error(document, trusted_roots):
    roots = set(trusted_roots)
    if "successorRoot" in document:
        roots.add(document["successorRoot"])
    policy_keys = set(document["fleetPolicyKeys"])
    server_key = document["serverKey"]
    if server_key in roots or server_key in policy_keys or roots & policy_keys:
        return FIELD_INVALID
    return None


def authenticate_fixture(entry, allowed):
    name = entry["document"]
    envelope = ENVELOPES[name]
    signer = next((key for key in allowed
                   if b64url(hashlib.sha256(decode(key)).digest()) == envelope["keyId"]), None)
    if signer is None:
        return None, "doc-key-unknown"
    signature = decode(envelope["signature"])
    if entry.get("tamper") == "signature":
        signature = signature[:-1] + bytes([signature[-1] ^ 1])
    if not signature_valid(signer, PAYLOADS[name], signature):
        return None, "doc-signature-invalid"
    return signer, None


def check_batch(case, sync, request_nonce=None):
    current = case["initial"].copy()
    device = KEYS[sync["deviceKey"]]["keyId"]
    request_nonce = request_nonce or sync["nonces"]["a"]
    refs = [entry if isinstance(entry, dict) else {"document": entry} for entry in case["documents"]]
    processed = []
    for kind in DOC_ORDER:
        field = PROTOCOL["documents"][kind]["strictlyIncreasingField"]
        matching = [entry for entry in refs if DOCS[entry["document"]]["type"] == kind]
        active = DOCS[current["keyset"]]
        root_keys = [KEYS[current["root"]]["spki"]]
        if "successorRoot" in active:
            root_keys.append(active["successorRoot"])
        allowed = {"keyset": root_keys, "fleet-policy": active["fleetPolicyKeys"],
                   "recovery": active["fleetPolicyKeys"], "command": [active["serverKey"]]}[kind]

        candidates = []
        for entry in matching:
            name = entry["document"]
            signer, code = authenticate_fixture(entry, allowed)
            doc = DOCS[name]
            if code is None:
                error = payload_error(doc)
                if error:
                    code = error[0]
                elif doc["fleetId"] != sync["fleetId"]:
                    code = FOREIGN_FLEET
                elif kind == "keyset":
                    code = keyset_role_error(doc, root_keys)
            if code:
                processed.append({"document": name, **result("refused", code)})
            else:
                candidates.append((name, signer))

        # Only authenticated, schema-valid candidates participate in version ordering.
        if kind in {"keyset", "fleet-policy"}:
            candidates.sort(key=lambda candidate: DOCS[candidate[0]][field], reverse=True)
        for name, signer in candidates:
            doc = DOCS[name]
            active = DOCS[current["keyset"]]
            state_field = {"fleet-policy": "policyVersion", "recovery": "recoveryVersion",
                           "command": "commandFloor"}.get(kind)
            floor = current[state_field] if state_field else active["keySetVersion"]
            if doc[field] <= floor or doc["keySetVersion"] < active["keySetVersion"]:
                code = ROLLBACK
            elif kind != "keyset" and device not in doc.get("deviceIds", [doc.get("deviceId")]):
                code = "doc-device-not-listed"
            elif kind == "command" and doc["nonce"] != request_nonce:
                code = "command-nonce-mismatch"
            else:
                code = None
                if kind == "keyset":
                    if signer == active.get("successorRoot"):
                        current["root"] = next(role for role, key in KEYS.items() if key["spki"] == signer)
                    current["keyset"] = name
                else:
                    current[state_field] = doc[field]
            processed.append({"document": name, **result("refused" if code else "accepted", code)})
    return {"processed": processed, "final": current}


def check_nonce_events(case, sync):
    outstanding = None
    results = []
    current = {"keyset": "keyset-1", "root": "root", "policyVersion": 0,
               "recoveryVersion": 0, "commandFloor": 0}
    for item in case["events"]:
        event = item["event"]
        nonce = sync["nonces"][item["nonce"]] if "nonce" in item else None
        if event == "send":
            if outstanding is None:
                outstanding = {**item, "nonce": nonce}
                results.append(result("sent"))
            else:
                results.append(result("not-sent"))
        elif event == "response":
            owns_exchange = outstanding is not None and item["exchange"] == outstanding["exchange"]
            matches = (owns_exchange and nonce == outstanding["nonce"] and item["boot"] == outstanding["boot"]
                       and 0 <= item["elapsedMs"] - outstanding["elapsedMs"] < NONCE_LIMIT)
            if owns_exchange:
                outstanding = None
            if matches:
                answer = result("processed")
                if "documents" in item:
                    batch = check_batch({"initial": current, "documents": item["documents"]}, sync, nonce)
                    answer["processedDocuments"] = batch["processed"]
                    current = batch["final"]
            else:
                answer = result("dropped", "sync-response-stale")
                if "documents" in item:
                    answer["processedDocuments"] = []
            results.append(answer)
        else:
            assert event in {"timeout", "process-death"}, event
            if event == "timeout":
                assert item["elapsedMs"] - outstanding["elapsedMs"] >= NONCE_LIMIT
            outstanding = None
            results.append(result("discarded"))
    return results


def check_dispatch(initial, case):
    document = DOCS[case["document"]]
    assert document["type"] == "command"
    sequence = document["sequence"]
    cutoff = initial["requestSentElapsedMs"] + NONCE_LIMIT
    fault = case.get("fault")
    old_floor = initial["sequenceFloor"]
    assert sequence > old_floor
    if "commands-off" in case.get("overrides", []):
        return result("refused", "commands-suspended-by-recovery", state=None, sequenceFloor=old_floor, calls=0)
    if fault == "accept-write":
        return result("refused", "journal-write-failed", state=None, sequenceFloor=old_floor, calls=0)
    persisted = {"sequenceFloor": sequence, "cutoffElapsed": cutoff}
    expired = result("expired", "command-expired", state="EXPIRED", calls=0, **persisted)
    if fault == "dispatch-write":
        return result("refused", "journal-write-failed", state="ACCEPTED", calls=0,
                      afterRestart=expired, **persisted)
    if fault == "crash-after-accepted":
        return expired
    if fault == "crash-before-call":
        return result("unknown", "dispatch-outcome-unknown", state="OUTCOME_UNKNOWN", calls=0, **persisted)
    if case.get("recoveryOverride"):
        assert schema_error(SCHEMA["$defs"]["overrides"], [case["recoveryOverride"]]) is None
        return result("cancelled", "cancelled-by-recovery", state="CANCELLED", calls=0, **persisted)
    dispatch_overrides = case.get("dispatchOverrides", [])
    assert schema_error(SCHEMA["$defs"]["overrides"], dispatch_overrides) is None
    if "commands-off" in dispatch_overrides:
        return result("cancelled", "cancelled-by-recovery", state="CANCELLED", calls=0, **persisted)
    if case.get("dispatchBoot", initial["boot"]) != initial["boot"] or case.get("dispatchElapsedMs", cutoff - 1) >= cutoff:
        return expired
    if fault in {"crash-after-call", "done-write"}:
        return result("unknown", "dispatch-outcome-unknown", state="OUTCOME_UNKNOWN", calls=1, **persisted)
    assert fault is None, fault
    code = None
    if document["kind"] == "lock_now":
        secure = case["secureLock"]
        evidence = {"secureLock": secure, "effect": "lockNow"}
        if case.get("recoveryAfterCall"):
            evidence["recoveryOutcome"] = "command-already-executed"
        code = None if secure else "lock-screen-off-only"
    else:
        assert case["generation"] in GENERATIONS
        verified = case.get("readBackVerified", True)
        evidence = {"effect": "ensureProjected+reconcile", "readBackVerified": verified,
                    "verifiedGeneration": case["generation"] if verified else "policy-1",
                    "syncEnqueued": True}
    return result("executed", code, state="DONE", calls=1, evidence=evidence, **persisted)


def check_journal(case):
    initial, target, phase, fault = (case[key] for key in ("initial", "target", "phase", "fault"))
    assert initial is None or initial in GENERATIONS
    assert target in GENERATIONS
    projection_steps = ["journal", *STORES, "before-stamp", "stamp", "pass", "read-back", "verified"]
    assert phase in {*projection_steps, "matching-stamp"}
    assert fault in {"crash", "write-failed", "replace-target", "premature-pass", "none"}
    committed, verified = initial, initial
    projected = dict.fromkeys(STORES, initial)
    stamp = target if phase == "matching-stamp" else case.get("initialStamp", initial)
    pass_reads = []
    read_back = False

    def start_pass(generation):
        reads = set(projected.values()) | {stamp, committed}
        if reads != {generation}:
            return False
        pass_reads.append(reads)
        return True

    premature_pass_refused = False
    for step in projection_steps:
        if step == phase and fault == "write-failed":
            break
        if step == "journal":
            committed = target
        elif step in STORES:
            projected[step] = target
        elif step == "stamp":
            stamp = target
        elif step == "pass":
            if not start_pass(target):
                break
        elif step == "read-back":
            read_back = True
        elif step == "verified" and read_back and committed == target:
            verified = target
        if step == phase and fault == "replace-target":
            committed = case["replacement"]
            assert committed in GENERATIONS and committed != target
        if step == phase and fault == "crash":
            break
        if step == phase and fault == "premature-pass" and not start_pass(target):
            premature_pass_refused = True
            break
    verified_before_retry = verified
    pass_started_before_retry = bool(pass_reads)
    # Restart, boot or same-process retry reads the durable snapshot and rewrites every store.
    for store in STORES:
        projected[store] = committed
    stamp = committed
    if start_pass(committed):
        verified = committed
    code = "journal-write-failed" if fault == "write-failed" else None
    outcome = "interrupted" if fault == "crash" else "refused" if code or premature_pass_refused else "reconciled"
    evidence = {"ranFullProjection": pass_started_before_retry} if phase == "matching-stamp" else {}
    if fault == "premature-pass":
        evidence["prematurePassRefused"] = premature_pass_refused
    trigger = "boot" if case["boot"] else "process-start" if fault == "crash" else "reconcile"
    return result(outcome, code, passStartedBeforeRetry=pass_started_before_retry, durableTargetBeforeRetry=committed,
                  verifiedBeforeRetry=verified_before_retry, durableTargetAfterRetry=committed, verifiedAfterRetry=verified,
                  retryTrigger=trigger, passReadsMixedGeneration=any(len(reads) != 1 for reads in pass_reads), **evidence)


def check_read_back(case):
    target = case.get("target", "policy-5")
    controls = DOCS[target]["policy"].get("systemControls", {})
    outcomes = case["protections"]
    for control in outcomes.keys() & controls.keys():
        assert controls[control] is True
    if "deviceSdk" in case:
        assert 26 <= case["deviceSdk"] <= 27 and "date_and_time" in outcomes
    verified = all(status == "verified" for status in outcomes.values())
    hidden = not case["wouldUnhide"] or (case["previouslyHidden"] and not verified)
    retained = {}
    if "previousCa" in case:
        assert DOCS[target]["policy"]["homeFilter"]["caCertificate"] is None
        retained["retainPreviousCa"] = outcomes["caRemoval"] != "verified"
    if "previousFilter" in case:
        assert not DOCS[target]["policy"].get("homeFilter", {}).get("enabled")
        retained["retainPreviousFilter"] = outcomes["filterRemoval"] != "verified"
    return result("verified" if verified else "unverified", packageHidden=hidden,
                  verified=target if verified else "policy-1", **retained)


def check_recovery(case, data, initial=None):
    choices, fault = case["choices"], case.get("fault")
    assert schema_error(SCHEMA["$defs"]["overrides"], choices) is None
    if initial is None:
        initial = data["initial"]
    state = deepcopy({**initial, **case.get("initial", {})})
    assert schema_error(SCHEMA["$defs"]["overrides"], state["overrides"]) is None
    # The live policy thread knows whether it made the call. A restarted
    # process cannot infer that from a stranded DISPATCHING record.
    command_states = state["commandStates"]
    calls_made = case.get("callsMadeOnPolicyThread", data["callsMadeOnPolicyThread"])
    if case.get("restarted"):
        calls_made = []
        for command, status in command_states.items():
            if status == "DISPATCHING":
                command_states[command] = "OUTCOME_UNKNOWN"
    lockout = state["lockout"]
    boot = case.get("boot", data["boot"])
    elapsed = case.get("elapsedMs", data["elapsedMs"])
    if "untilElapsedMs" in lockout:
        assert lockout["boot"] == boot  # These vectors cover the first penalty in one boot.
    locked = elapsed < lockout.get("untilElapsedMs", 0)
    extra = {}
    code = None
    if not state["verifierPresent"] or not choices or fault == "cancel-before-code":
        outcome = "unchanged"
    elif locked:
        outcome = "refused"
        extra["codeChecked"] = False
    elif case.get("codeMatches") is False:
        outcome = "refused"
        extra["codeChecked"] = True
        failures = lockout["failures"] + 1
        state["lockout"] = {"failures": failures}
        lockout_rules = PROTOCOL["recovery"]["lockout"]
        if failures == lockout_rules["firstPenaltyFailures"]:
            state["lockout"].update(boot=boot, untilElapsedMs=elapsed + lockout_rules["firstPenaltyMs"])
    elif fault == "crash-before":
        outcome = "unchanged"
    elif fault == "write-failed":
        outcome, code = "refused", "recovery-commit-failed"
    else:
        outcome = "committed"
        state.update(verifierPresent=False, uses=state["uses"] + 1, overrides=sorted(set(state["overrides"]) | set(choices)))
        state["lockout"] = {"failures": 0}
        for command, status in command_states.items():
            if status == "ACCEPTED" or (status == "DISPATCHING" and command not in calls_made):
                command_states[command] = "CANCELLED"

        pending = "pending-dispatch"
        if pending in calls_made:
            extra["pendingCallOutcomeAtRecovery"] = "command-already-executed"
        elif command_states[pending] == "CANCELLED":
            extra["pendingCallOutcomeAtRecovery"] = "cancelled-by-recovery"
        else:
            extra["pendingCallOutcomeAtRecovery"] = "dispatch-outcome-unknown"
        if fault == "crash-after":
            for command in calls_made:
                if command_states[command] == "DISPATCHING":
                    command_states[command] = "OUTCOME_UNKNOWN"
    policy = "policy-5"
    if case.get("newerPolicy") == "committed":
        state["overrides"] = []
        policy = "policy-6"
    if case.get("newerPolicy") == "write-failed":
        extra["newerPolicyFailureCode"] = "journal-write-failed"
    if fault == "retry":
        retry = check_recovery({"choices": choices}, data, state)
        assert all(retry[key] == value for key, value in state.items())
        extra["secondUse"] = result(retry["outcome"], retry["failureCode"])
    if "nextAttempt" in case:
        extra["nextAttempt"] = check_recovery({"choices": choices, **case["nextAttempt"]}, data, state)
    if "network-off" in state["overrides"]:
        extra["networkReadBackTarget"] = {"vpnLockdown": False, "proxy": None, "caCertificate": None}
    generation = next(name for name, item in GENERATIONS.items()
                      if item["source"] == policy and item["value"]["overrides"] == state["overrides"])
    return result(outcome, code, **state, generation=generation,
                  cancellationCode="cancelled-by-recovery" if outcome == "committed" else None,
                  policyFieldsChanged=["homeFilter", "homeFilterControlFloor"] if "network-off" in state["overrides"] else [],
                  rejectsNewCommands="commands-off" in state["overrides"], **extra)


class RemoteContractTest(unittest.TestCase):
    def test_reference_client_transcripts(self):
        from fleet_admin import enrolment_transcript
        from remote_contract import ticket_bytes

        vector = vectors("client-wire")
        enrol = vector["enrolment"]
        transcript = enrolment_transcript({
            "challenge": enrol["challenge"],
            "ticketSha256": hash_hex(ticket_bytes(enrol["ticket"])),
            "attestationChain": enrol["chain"],
            "facts": enrol["facts"],
        })
        self.assertEqual(enrol["transcriptUtf8"].encode(), transcript)
        self.assertTrue(signature_valid(vector["signerSpki"], transcript, decode(enrol["signature"])))
        sync = vector["sync"]
        body = canonical(sync["body"])
        self.assertEqual(sync["bodyUtf8"].encode(), body)
        transcript = canonical(["dg-sync/1", "POST", "/v1/sync", sync["timestamp"], hash_hex(body)])
        self.assertEqual(sync["transcriptUtf8"].encode(), transcript)
        self.assertTrue(signature_valid(vector["signerSpki"], transcript, decode(sync["signature"])))

    def test_awaiting_policy_sync_request(self):
        vector = vectors("client-wire")
        case = vector["awaitingPolicy"]
        body = case["body"]
        self.assertEqual(case["bodyUtf8"].encode(), canonical(body))
        self.assertIsNone(sync_generation_error(body))
        self.assertIsNone(sync_generation_error(vector["sync"]["body"]))
        for name, overrides in case["invalid"].items():
            with self.subTest(name=name):
                self.assertEqual(FIELD_INVALID, sync_generation_error(body | overrides))

    def test_bundle_preserves_directory_created_after_existence_check(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            make_temporary = tempfile.TemporaryDirectory
            existing_inode = None

            def create_competing_directory(*args, **kwargs):
                nonlocal existing_inode
                staging = make_temporary(*args, **kwargs)
                output.mkdir()
                existing_inode = output.stat().st_ino
                return staging

            with patch("remote_contract.tempfile.TemporaryDirectory", side_effect=create_competing_directory):
                with self.assertRaises(FileExistsError):
                    write_private_bundle(output, {"file.txt": b"contents"})
            self.assertEqual(output.stat().st_ino, existing_inode)
            self.assertEqual(list(output.iterdir()), [])
            self.assertEqual(list(output.parent.iterdir()), [output])

    def test_bundle_cleans_up_if_a_file_cannot_be_published(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "bundle"
            link = os.link

            def fail_second_file(source, destination):
                if destination.name == "second.txt":
                    raise OSError("publication failed")
                link(source, destination)

            with patch("remote_contract.os.link", side_effect=fail_second_file):
                with self.assertRaisesRegex(OSError, "publication failed"):
                    write_private_bundle(output, {"first.txt": b"first", "second.txt": b"second"})
            self.assertEqual(list(output.parent.iterdir()), [])

    def compare_cases(self, cases, evaluate):
        self.assertTrue(cases)
        self.assertEqual(len({case["id"] for case in cases}), len(cases))
        for case in cases:
            with self.subTest(vector=case["id"]):
                self.assertEqual(evaluate(case), case["expected"])

    def test_registry(self):
        design = (CONTRACT.parent / "remote-management.md").read_text(encoding="utf-8")
        section = design.split("### 5.6 Failure codes", 1)[1].split("## 6. Policy model", 1)[0]
        self.assertEqual(PROTOCOL["failureCodes"]["section5.6"], re.findall(r"`([a-z-]+)`", section))
        self.assertEqual(DOC_ORDER, ["keyset", "fleet-policy", "recovery", "command"])
        self.assertEqual(SCHEMA["oneOf"], [{"$ref": "#/$defs/" + kind} for kind in PAYLOAD_TYPES])
        self.assertEqual(PROTOCOL["dispatch"]["kinds"], SCHEMA["$defs"]["command"]["properties"]["kind"]["enum"])
        codes = PROTOCOL["hashes"]["generationSha256"]["overrideCodes"]
        self.assertEqual(codes, sorted(set(codes)))
        self.assertEqual(SCHEMA["$defs"]["overrides"]["enum"], [[], *([code] for code in codes), codes])
        self.assertIn(FOREIGN_FLEET, PROTOCOL["failureCodes"]["section5.6"])
        self.assertEqual(PROTOCOL["sync"]["documentValidationOrder"], [
            "signature", "closed-payload-schema", "fleet-binding", "keyset-role-separation",
            "version-order-and-floors", "device-binding", "command-nonce-binding",
        ])
        self.assertEqual(MAX_WIRE_INTEGER, PROTOCOL["semanticChecks"]["maxSafeInteger"])
        self.assertEqual(PROTOCOL["envelope"]["maxEncodedBytes"], 65536)
        self.assertEqual(NONCE_LIMIT, 120000)
        self.assertEqual(PROTOCOL["hashes"]["generationSha256"]["domainAscii"], "dg-gen/1")
        self.assertEqual(PROTOCOL["hashes"]["generationSha256"]["separatorByte"], 0)
        app_source = CONTRACT.parents[1] / "app/src/main/java/com/example/lockdowndpc"
        controls_source = (app_source / "policy/SystemPolicyControl.java").read_text(encoding="utf-8")
        controls = SCHEMA["$defs"]["policy"]["properties"]["systemControls"]["properties"]
        self.assertEqual(set(controls), set(re.findall(r'\n    [A-Z_]+\(\n\s+"([a-z_]+)"', controls_source)))
        lockout_source = (app_source / "security/PinLockoutPolicy.java").read_text(encoding="utf-8")
        lockout = PROTOCOL["recovery"]["lockout"]
        threshold, duration = re.search(r"if \(failures == (\d+)\) \{\s+return ([\d_]+)L;", lockout_source).groups()
        self.assertEqual((int(threshold), int(duration)), (lockout["firstPenaltyFailures"], lockout["firstPenaltyMs"]))

    def test_signed_documents(self):
        self.assertIn("TEST ONLY", SIGNED["notice"])
        readme = (CONTRACT / "README.md").read_text(encoding="utf-8")
        for name, key in KEYS.items():
            with self.subTest(key=name):
                self.assertIsNotNone(spki_point(key["spki"]))
                self.assertEqual(key["keyId"], b64url(hashlib.sha256(decode(key["spki"])).digest()))
                self.assertIn(f'`{key["keyId"]}`', readme)
        for name, case in SIGNED["documents"].items():
            with self.subTest(document=name):
                envelope, payload, document = ENVELOPES[name], PAYLOADS[name], DOCS[name]
                self.assertIsNone(envelope_error(canonical(envelope)))
                self.assertEqual(validation_result(payload_error(document)), case["expected"])
                self.assertEqual(schema_error(SCHEMA, document) is None, case["expected"]["outcome"] == "valid")
                key = KEYS[case["signer"]]
                self.assertEqual(envelope["keyId"], key["keyId"])
                self.assertTrue(signature_valid(key["spki"], payload, decode(envelope["signature"])))
                self.assertEqual(payload == canonical(document), case["canonicalPayload"])

    def test_reanchor_vectors(self):
        vector = vectors("re-anchor")
        envelope = vector["envelope"]
        key = KEYS[vector["signer"]]
        self.assertIsNone(envelope_error(canonical(envelope)))
        self.assertLessEqual(len(canonical(envelope)), PROTOCOL["reanchor"]["maxEncodedBytes"])
        raw = decode(envelope["payload"])
        document = parse_wire(raw)
        self.assertIsNone(payload_error(document))
        self.assertIsNone(schema_error(SCHEMA, document))
        self.assertEqual(document["type"], REANCHOR_TYPE)
        self.assertEqual(document["rootSpki"], key["spki"])
        self.assertEqual(document["rootFingerprint"], envelope["keyId"])
        self.assertEqual(envelope["keyId"], key["keyId"])
        self.assertTrue(signature_valid(key["spki"], raw, decode(envelope["signature"])))
        self.assertEqual(set(document["floors"]), set(DOC_ORDER))
        self.assertEqual(document["floorPayloadSha256"]["fleet-policy"], hash_hex(PAYLOADS["policy-6"]))
        sync = vectors("sync")
        for case in vector["cases"]:
            with self.subTest(vector=case["id"]):
                pin = KEYS[case.get("key", vector["signer"])]["keyId"]
                binding = (case.get("fleetId", sync["fleetId"]),
                           KEYS[case.get("deviceKey", sync["deviceKey"])]["keyId"])
                expected_nonce = case.get("nonce", sync["nonces"]["a"])
                failure = None
                if envelope["keyId"] != pin:
                    failure = "re-anchor-root-mismatch"
                elif (document["fleetId"], document["deviceId"]) != binding:
                    failure = "re-anchor-binding-mismatch"
                elif document["nonce"] != expected_nonce:
                    failure = "re-anchor-nonce-invalid"
                self.assertEqual(failure, case["expectedFailure"])

    def test_document_shapes(self):
        cases = vectors("document-shapes")
        self.compare_cases(cases["payloads"], lambda case: validation_result(payload_error(edited_payload(case))))

        def check_envelope(case):
            envelope = {**ENVELOPES[case["document"]], **case.get("set", {})}
            raw = canonical(envelope)
            raw = raw.ljust(case.get("wireBytes", len(raw)))
            return validation_result(envelope_error(raw))

        def check_raw_payload(case):
            raw = bytes.fromhex(case["bytesHex"]) if "bytesHex" in case else case["utf8"].encode("utf-8")
            try:
                return validation_result(payload_error(parse_wire(raw)))
            except ValueError:
                return validation_result((FIELD_INVALID, ""))

        self.compare_cases(cases["envelopes"], check_envelope)
        self.compare_cases(cases["rawPayloads"], check_raw_payload)

    def test_hash_vectors(self):
        data = vectors("hashes")
        example_bytes = data["canonicalJson"]
        self.assertEqual(canonical(example_bytes["value"]), example_bytes["canonicalUtf8"].encode("utf-8"))
        self.assertEqual(example_bytes["expected"], result("reproduced"))
        self.compare_cases(data["canonicalStrings"], lambda case: result(
            "reproduced", canonicalUtf8=canonical(case["value"]).decode("utf-8")))
        baseline = data["baseline"]
        self.assertEqual(baseline["expected"], result("reproduced"))
        self.assertIsNone(schema_error(SCHEMA["$defs"]["policy"], baseline["body"]))
        baseline_bytes = canonical(baseline["body"])
        self.assertEqual(baseline_bytes, baseline["canonicalUtf8"].encode("utf-8"))
        self.assertEqual(hash_hex(baseline_bytes), baseline["baselineSha256"])
        sources = {"baseline": ("baseline", baseline_bytes), "example": ("baseline", data["example"].encode("ascii"))}
        sources.update({name: (doc["fleetPolicyVersion"], PAYLOADS[name])
                        for name, doc in DOCS.items() if doc["type"] == "fleet-policy"})
        for name, case in {**GENERATIONS, "verifiedGeneration": data["verifiedGeneration"]}.items():
            with self.subTest(generation=name):
                version, payload = sources[case["source"]]
                value = case["value"]
                hash_field = "verifiedSha256" if name == "verifiedGeneration" else "generationSha256"
                schema_name = "verifiedGeneration" if name == "verifiedGeneration" else "generation"
                self.assertIsNone(schema_error(SCHEMA["$defs"][schema_name], value))
                self.assertEqual(version, value["fleetPolicyVersion"])
                self.assertEqual(hash_hex(payload), value["committedSha256"])
                hash_overrides = case.get("hashInputOverrides", value["overrides"])
                self.assertEqual(sorted(hash_overrides), value["overrides"])
                self.assertEqual(generation_hash(hash_hex(payload), hash_overrides), value[hash_field])
                self.assertEqual(case["expected"], result("reproduced"))
        verified = data["verifiedGeneration"]
        current = GENERATIONS[verified["current"]]["value"]
        self.assertGreater(current["fleetPolicyVersion"], verified["value"]["fleetPolicyVersion"])
        self.assertNotEqual(current["generationSha256"], verified["value"]["verifiedSha256"])
        exact = data["exactBytes"]
        left, right = exact["canonical"], exact["alternative"]
        self.assertEqual(DOCS[left], DOCS[right])
        self.assertNotEqual(hash_hex(PAYLOADS[left]), hash_hex(PAYLOADS[right]))
        self.assertEqual(exact["expected"], result("equal-json-different-committed-hashes"))
        self.compare_cases(data["invalidOverrides"], lambda case: result(
            "refused", schema_error(SCHEMA["$defs"]["overrides"], case["overrides"])[0]))
        example = GENERATIONS["example-empty"]["value"]
        design = (CONTRACT.parent / "remote-management.md").read_text(encoding="utf-8")
        section = design.split("  - Example vectors", 1)[1].split("  - `verifiedSha256`", 1)[0]
        self.assertEqual(re.findall(r"[0-9a-f]{64}", section), [
            example["committedSha256"], example["generationSha256"],
            GENERATIONS["example-network-off"]["value"]["generationSha256"]])
        self.assertEqual(GENERATIONS["example-both"]["value"]["generationSha256"],
                         GENERATIONS["example-both-reversed"]["value"]["generationSha256"])

    def test_sync(self):
        data = vectors("sync")
        self.assertEqual(len(set(data["nonces"].values())), len(data["nonces"]))
        for nonce in data["nonces"].values():
            self.assertIsNone(schema_error(SCHEMA["$defs"]["base64url32"], nonce))
            self.assertEqual(len(decode(nonce)), PROTOCOL["sync"]["nonce"]["bytes"])
        self.compare_cases(data["nonceCases"], lambda case: check_nonce_events(case, data))
        self.compare_cases(data["batches"], lambda case: check_batch(case, data))

    def test_dispatch(self):
        data = vectors("dispatch")
        self.compare_cases(data["cases"], lambda case: check_dispatch(data["initial"], case))

    def test_journal(self):
        data = vectors("journal")
        for store in STORES:
            with self.subTest(store=store):
                self.assertEqual({case["fault"] for case in data["cases"] if case["phase"] == store and not case["boot"]}
                                 & {"crash", "write-failed"}, {"crash", "write-failed"})
        self.assertEqual(sum(case["boot"] for case in data["cases"]), 4)
        self.compare_cases(data["cases"], check_journal)
        self.compare_cases(data["readBackCases"], check_read_back)

    def test_recovery(self):
        data = vectors("recovery")
        code = data["testCode"]
        self.assertIn("TEST ONLY", code["notice"])
        parameters = PROTOCOL["recovery"]
        groups = code["display"].split(" ")
        self.assertTrue(all(len(group) == parameters["displayGroupSize"] for group in groups))
        compact = "".join(groups)
        self.assertEqual(len(compact), parameters["codeCharacters"])
        self.assertLessEqual(set(compact), set(parameters["codeAlphabet"]))
        for name, document in DOCS.items():
            if document["type"] == "recovery":
                with self.subTest(document=name):
                    salt = decode(document["salt"])
                    self.assertEqual(len(salt), parameters["saltBytes"])
                    derived = hashlib.pbkdf2_hmac("sha256", compact.encode("ascii"), salt,
                                                  parameters["iterations"], parameters["derivedBytes"])
                    self.assertEqual(b64url(derived), document["verifier"])
        self.assertEqual(DOCS[code["document"]]["type"], "recovery")
        self.assertEqual(code["expected"], result("reproduced"))
        self.compare_cases(data["cases"], lambda case: check_recovery(case, data))


if __name__ == "__main__":
    unittest.main()
