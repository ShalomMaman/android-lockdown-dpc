"""Offline conformance checks for the public Device Guard v1 fixtures."""

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import unittest
from urllib.parse import unquote, urlsplit


CONTRACT = Path(__file__).resolve().parents[1] / "docs" / "remote-contract"
MAX_WIRE_INTEGER = (1 << 53) - 1


def unique_object(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate JSON member")
    return result


def reject_number(value):
    raise ValueError(f"unsupported JSON number: {value}")


def parse_wire_integer(token):
    value = int(token)
    if token == "-0" or abs(value) > MAX_WIRE_INTEGER:
        reject_number(token)
    return value


def parse_wire(raw):
    document = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_constant=reject_number, parse_float=reject_number,
                          parse_int=parse_wire_integer)
    # JSON's escape scanner can produce a lone surrogate even on valid UTF-8 input.
    canonical(document)
    return document


def load(path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)


def vectors(name):
    return load(CONTRACT / "vectors" / (name + ".json"))


def canonical(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False,
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


def b64url(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode(encoded):
    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    if b64url(raw) != encoded:
        raise ValueError("noncanonical base64url")
    return raw


def hash_hex(raw):
    return hashlib.sha256(raw).hexdigest()


SCHEMA = load(CONTRACT / "v1.schema.json")
PROTOCOL = load(CONTRACT / "protocol.json")
DOC_ORDER = PROTOCOL["sync"]["order"]
REANCHOR_TYPE = PROTOCOL["reanchor"]["type"]
PAYLOAD_TYPES = [*DOC_ORDER, REANCHOR_TYPE]
NONCE_LIMIT = PROTOCOL["sync"]["nonce"]["maxAgeMsExclusive"]
STORES = PROTOCOL["journal"]["projectionWrites"]
SIGNED = vectors("signed-documents")
KEYS = SIGNED["keys"]
ENVELOPES = {name: case["envelope"] for name, case in SIGNED["documents"].items()}
PAYLOADS = {name: decode(envelope["payload"]) for name, envelope in ENVELOPES.items()}
DOCS = {name: parse_wire(payload) for name, payload in PAYLOADS.items()}
GENERATIONS = vectors("hashes")["generations"]

FIELD_INVALID = "doc-field-invalid"
FIELD_UNKNOWN = "doc-field-unknown"
ROLLBACK = "doc-version-rollback"
FOREIGN_FLEET = PROTOCOL["sync"]["foreignFleetFailureCode"]


def result(outcome, failure_code=None, **evidence):
    return {"outcome": outcome, "failureCode": failure_code, **evidence}


def pointer(path, key):
    return path + "/" + str(key).replace("~", "~0").replace("/", "~1")


def typed_equal(left, right):
    return type(left) is type(right) and left == right


# Test-only validation of the small, local schema subset in v1.schema.json.
# Fail on unfamiliar keywords so schema edits cannot silently weaken a check.
ANNOTATIONS = {"$schema", "$defs", "title", "default"}
KEYWORDS = ANNOTATIONS | {
    "$ref", "type", "oneOf", "const", "enum", "minimum", "maximum",
    "properties", "required", "additionalProperties", "maxProperties", "items",
    "minItems", "maxItems", "uniqueItems", "pattern", "minLength", "maxLength",
}
TYPES = {"object": dict, "array": list, "string": str, "integer": int,
         "boolean": bool, "null": type(None)}


def schema_error(schema, value, path=""):
    assert schema.keys() <= KEYWORDS, schema.keys() - KEYWORDS
    invalid = (FIELD_INVALID, path)
    if "$ref" in schema:
        prefix = "#/$defs/"
        assert schema["$ref"].startswith(prefix)
        name = schema["$ref"][len(prefix):]
        error = schema_error(SCHEMA["$defs"][name], value, path)
        if error:
            return error
        if name in {"httpsUrl", "pacUrl", "serverUrl", "kioskUrl"}:
            try:
                url = urlsplit(value)
                if url.port == 0 or not url.hostname:
                    return invalid
            except ValueError:
                return invalid
            if name == "kioskUrl":
                if not ("." in url.hostname or ":" in url.hostname):
                    return invalid
                if any(unquote(segment) in {".", ".."} for segment in url.path.split("/")):
                    return invalid
        if name == "p256Spki" and spki_point(value) is None:
            return invalid
    if "type" in schema and type(value) is not TYPES[schema["type"]]:
        return invalid
    if "const" in schema and not typed_equal(value, schema["const"]):
        return invalid
    if "enum" in schema and not any(typed_equal(value, item) for item in schema["enum"]):
        code = "command-unknown" if path == "/kind" and isinstance(value, str) else FIELD_INVALID
        return code, path
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        unknown = value.keys() - properties.keys()
        if unknown and schema.get("additionalProperties") is False:
            return FIELD_UNKNOWN, pointer(path, min(unknown))
        for key in schema.get("required", ()):
            if key not in value:
                return FIELD_INVALID, pointer(path, key)
        if len(value) > schema.get("maxProperties", len(value)):
            return invalid
        for key, child_schema in properties.items():
            if key in value:
                error = schema_error(child_schema, value[key], pointer(path, key))
                if error:
                    return error
    if isinstance(value, list):
        if not schema.get("minItems", 0) <= len(value) <= schema.get("maxItems", len(value)):
            return invalid
        if schema.get("uniqueItems") and len({canonical(item) for item in value}) != len(value):
            return invalid
        if "items" in schema:
            for index, item in enumerate(value):
                error = schema_error(schema["items"], item, pointer(path, index))
                if error:
                    return error
        if path.endswith("/apps/systemSelection") and len({item["package"] for item in value}) != len(value):
            return invalid
    if isinstance(value, str):
        if not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", len(value)):
            return invalid
        if "pattern" in schema and not re.search(schema["pattern"], value):
            return invalid
        if path.endswith("/canary/expectedBody") and len(value.encode("utf-8")) > 1024:
            return invalid
    if type(value) is int and not schema.get("minimum", value) <= value <= schema.get("maximum", value):
        return invalid
    if "oneOf" in schema and sum(schema_error(branch, value, path) is None for branch in schema["oneOf"]) != 1:
        return invalid
    return None


def payload_error(document):
    kind = document.get("type") if isinstance(document, dict) else None
    if isinstance(kind, str) and kind not in PAYLOAD_TYPES:
        return "doc-type-unexpected", "/type"
    if not isinstance(kind, str):
        return FIELD_INVALID, "/type"
    return schema_error(SCHEMA["$defs"][kind], document)


def envelope_error(raw):
    if len(raw) > PROTOCOL["envelope"]["maxEncodedBytes"]:
        return FIELD_INVALID, ""
    try:
        envelope = parse_wire(raw)
    except ValueError:
        return FIELD_INVALID, ""
    return schema_error(SCHEMA["$defs"]["envelope"], envelope)


def validation_result(error):
    if error is None:
        return result("valid")
    return result("refused", error[0], path=error[1])


# Public fixture verification only. The app will use its platform provider.
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")


def spki_point(encoded):
    raw = decode(encoded)
    if not raw.startswith(SPKI_PREFIX) or len(raw) != len(SPKI_PREFIX) + 64:
        return None
    x, y = (int.from_bytes(raw[start:end], "big") for start, end in ((-64, -32), (-32, None)))
    if x < P and y < P and (y * y - (x * x * x - 3 * x + B)) % P == 0:
        return x, y
    return None


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
