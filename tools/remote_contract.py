"""Strict JSON encoding and validation for the Device Guard remote v1 contract."""

import base64
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlsplit

CONTRACT = Path(__file__).resolve().parents[1] / "docs" / "remote-contract"
MAX_WIRE_INTEGER = (1 << 53) - 1
TICKET_BYTES = 24
FIELD_INVALID = "doc-field-invalid"
FIELD_UNKNOWN = "doc-field-unknown"


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
def pointer(path, key):
    return path + "/" + str(key).replace("~", "~0").replace("/", "~1")


def typed_equal(left, right):
    return type(left) is type(right) and left == right


# Validation of the closed subset used by v1.schema.json.
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


PAYLOAD_TYPES = [*PROTOCOL["sync"]["order"], PROTOCOL["reanchor"]["type"]]


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
    except (ValueError, RecursionError):
        return FIELD_INVALID, ""
    return schema_error(SCHEMA["$defs"]["envelope"], envelope)


P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")


def spki_point(encoded):
    if not isinstance(encoded, str):
        return None
    try:
        raw = decode(encoded)
    except ValueError:
        return None
    if not raw.startswith(SPKI_PREFIX) or len(raw) != len(SPKI_PREFIX) + 64:
        return None
    x, y = (int.from_bytes(raw[start:end], "big") for start, end in ((-64, -32), (-32, None)))
    if x < P and y < P and (y * y - (x * x * x - 3 * x + B)) % P == 0:
        return x, y
    return None


def ticket_bytes(value: str) -> bytes:
    if len(value) != 32:
        raise ValueError("invalid enrolment ticket")
    raw = decode(value)
    if len(raw) != TICKET_BYTES:
        raise ValueError("invalid enrolment ticket")
    return raw


def write_private_bundle(output: Path, files: dict[str, bytes]) -> None:
    """Publish a complete owner-only directory without updating an existing bundle."""
    if output.exists():
        raise FileExistsError("bundle output directory already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{output.name}.", dir=output.parent) as temporary:
        directory = Path(temporary)
        for name, content in files.items():
            fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as file:
                file.write(content)
                file.flush()
                os.fchmod(file.fileno(), 0o600)
                os.fsync(file.fileno())
        directory.rename(output)
