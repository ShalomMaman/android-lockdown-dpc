#!/usr/bin/env python3
"""Rehearse the offline half of a Device Guard signed self-update drill and record the evidence.

The acceptance gate for removing ADB as the normal recovery path is a real signed
self-update from an installed version to a higher version. This tool rehearses and
records everything that can be proven without a device: that the two APKs form a
legal in-place update pair, and that the published envelope satisfies exactly the
rules `UpdateEnvelopeVerifier` and `SecureUpdateManager` apply on the device.

It never contacts the network and never proves the on-device half of the drill.
Checks that cannot be performed in this environment are reported as SKIP and are
never counted as passing. See `docs/update-drill.md` for the full runbook.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit, urlunsplit

import publish_update
import verify_pilot_apk


RECORD_SCHEMA_VERSION = 1
UPDATE_SCHEMA_VERSION = 1
MAX_ENVELOPE_BYTES = 64 * 1024
MAX_APK_BYTES = 100 * 1024 * 1024
MAX_VALIDITY_SECONDS = 91 * 24 * 60 * 60
MAX_CLOCK_SKEW_SECONDS = 5 * 60
MAX_APK_URL_QUERY_LENGTH = 2_048
MAX_VERSION_NAME_LENGTH = 64
BASE64URL_ALPHABET = re.compile(r"^[A-Za-z0-9_-]+$")
LOWER_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")

STATUS_PASS = "pass"
STATUS_FAIL = "fail"
STATUS_SKIPPED = "skipped"
STATUS_LABEL = {STATUS_PASS: "PASS", STATUS_FAIL: "FAIL", STATUS_SKIPPED: "SKIP"}

VERDICT_PASS = "pass"
VERDICT_FAIL = "fail"
VERDICT_INCOMPLETE = "incomplete"
VERDICT_EXIT_CODE = {VERDICT_PASS: 0, VERDICT_INCOMPLETE: 1, VERDICT_FAIL: 2}
USAGE_EXIT_CODE = 3


class DrillError(Exception):
    """A safe, operator-facing input failure that stops the drill before any check runs."""


class EnvelopeStructureError(Exception):
    """The envelope could not be decoded far enough for its contents to be checked."""


# --------------------------------------------------------------------------- #
# Check recording
# --------------------------------------------------------------------------- #


class DrillRecorder:
    """Ordered log of drill checks. A skipped check is never reported as passing."""

    def __init__(self) -> None:
        self._checks: list[dict[str, object]] = []

    def record(
        self,
        identifier: str,
        description: str,
        status: str,
        detail: str,
        unrecoverable: bool = False,
    ) -> None:
        self._checks.append(
            {
                "id": identifier,
                "description": description,
                "status": status,
                "detail": detail,
                "unrecoverable": bool(unrecoverable and status == STATUS_FAIL),
            }
        )

    def passed(self, identifier: str, description: str, detail: str) -> None:
        self.record(identifier, description, STATUS_PASS, detail)

    def failed(
        self,
        identifier: str,
        description: str,
        detail: str,
        unrecoverable: bool = False,
    ) -> None:
        self.record(identifier, description, STATUS_FAIL, detail, unrecoverable)

    def skipped(self, identifier: str, description: str, reason: str) -> None:
        self.record(identifier, description, STATUS_SKIPPED, reason)

    def result(
        self,
        identifier: str,
        description: str,
        ok: bool,
        pass_detail: str,
        fail_detail: str,
        unrecoverable: bool = False,
    ) -> None:
        if ok:
            self.passed(identifier, description, pass_detail)
        else:
            self.failed(identifier, description, fail_detail, unrecoverable)

    @property
    def checks(self) -> list[dict[str, object]]:
        return list(self._checks)

    def counts(self) -> dict[str, int]:
        return {
            "total": len(self._checks),
            "passed": sum(1 for check in self._checks if check["status"] == STATUS_PASS),
            "failed": sum(1 for check in self._checks if check["status"] == STATUS_FAIL),
            "skipped": sum(1 for check in self._checks if check["status"] == STATUS_SKIPPED),
        }

    def verdict(self) -> str:
        counts = self.counts()
        if counts["failed"]:
            return VERDICT_FAIL
        if counts["skipped"] or not counts["total"]:
            return VERDICT_INCOMPLETE
        return VERDICT_PASS

    def unrecoverable_failures(self) -> list[dict[str, object]]:
        return [check for check in self._checks if check["unrecoverable"]]


# --------------------------------------------------------------------------- #
# APK facts
# --------------------------------------------------------------------------- #


class ApkFacts:
    """What is actually known about one side of the update pair, and how it is known."""

    FIELDS = ("packageName", "versionCode", "versionName", "signerSha256", "apkSha256", "apkSize")

    def __init__(self, label: str) -> None:
        self.label = label
        self.path: str | None = None
        self.values: dict[str, object] = {field: None for field in self.FIELDS}
        self.sources: dict[str, str] = {}
        self.unavailable: dict[str, str] = {}

    def set(self, field: str, measured: object, declared: object, missing_reason: str) -> None:
        if measured is not None:
            self.values[field] = measured
            self.sources[field] = "measured"
        elif declared is not None:
            self.values[field] = declared
            self.sources[field] = "declared"
        else:
            self.unavailable[field] = missing_reason

    def get(self, field: str) -> object:
        return self.values[field]

    def reason(self, field: str) -> str:
        return self.unavailable.get(field, f"{self.label} {field} is unavailable")

    def to_json(self) -> dict[str, object]:
        return {
            "apk": self.path,
            "values": {field: self.values[field] for field in self.FIELDS},
            "sources": dict(self.sources),
            "unavailable": dict(self.unavailable),
        }


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def sha256_and_size(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def normalize_declared_digest(value: str | None, option_name: str) -> str | None:
    if value is None:
        return None
    try:
        return publish_update.normalize_certificate_sha256(value, option_name)
    except publish_update.PublishError as exc:
        raise DrillError(str(exc)) from exc


def locate_tool(name: str, explicit: Path | None) -> Path | None:
    """Resolve an external binary. An explicit bad path is an error; an absent one is a skip."""
    if explicit is not None:
        candidate = explicit.expanduser().resolve()
        if not (candidate.is_file() and os.access(candidate, os.X_OK)):
            raise DrillError(f"--{name} is not executable: {candidate}")
        return candidate
    if name == "openssl":
        found = shutil.which("openssl")
        return Path(found).resolve() if found else None
    try:
        return publish_update.find_android_build_tool(name, None)
    except publish_update.PublishError:
        return None


def clean_https_url_problem(value: object) -> str | None:
    """Mirror `UpdateEnvelopeVerifier.requireCleanHttpsUrl`; return a reason or None."""
    if not isinstance(value, str) or not value:
        return "apkUrl is missing or not a string"
    parsed = urlsplit(value)
    if parsed.scheme.lower() != "https":
        return "apkUrl is not HTTPS"
    if not parsed.hostname:
        return "apkUrl has no host"
    if parsed.username is not None or parsed.password is not None:
        return "apkUrl embeds credentials"
    if parsed.fragment:
        return "apkUrl contains a fragment"
    if len(parsed.query) > MAX_APK_URL_QUERY_LENGTH:
        return "apkUrl query exceeds the client limit"
    try:
        parsed.port
    except ValueError:
        return "apkUrl contains an invalid port"
    return None


def decode_base64url(value: object, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise EnvelopeStructureError(f"envelope {field} is missing")
    if len(value) > MAX_ENVELOPE_BYTES * 2 or not BASE64URL_ALPHABET.match(value):
        raise EnvelopeStructureError(f"envelope {field} is not unpadded URL-safe Base64")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise EnvelopeStructureError(f"envelope {field} could not be decoded") from exc


def parse_envelope(path: Path) -> tuple[bytes, bytes, dict[str, object]]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise EnvelopeStructureError(f"envelope could not be read: {exc.strerror or exc}") from exc
    if not raw or len(raw) > MAX_ENVELOPE_BYTES:
        raise EnvelopeStructureError(
            f"envelope size {len(raw)} bytes is outside the client limit of 1-{MAX_ENVELOPE_BYTES}"
        )
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise EnvelopeStructureError("envelope is not UTF-8 JSON") from exc
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
        raise EnvelopeStructureError('envelope must contain exactly "payload" and "signature"')
    payload_bytes = decode_base64url(envelope.get("payload"), "payload")
    signature_bytes = decode_base64url(envelope.get("signature"), "signature")
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise EnvelopeStructureError("envelope payload is not UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise EnvelopeStructureError("envelope payload is not a JSON object")
    return payload_bytes, signature_bytes, payload


def openssl_signature_is_valid(
    openssl: Path,
    public_key: Path,
    payload_bytes: bytes,
    signature_bytes: bytes,
) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory(prefix="device-guard-drill-") as directory:
        payload_path = Path(directory) / "payload.json"
        signature_path = Path(directory) / "signature.der"
        payload_path.write_bytes(payload_bytes)
        signature_path.write_bytes(signature_bytes)
        result = subprocess.run(
            [
                str(openssl),
                "dgst",
                "-sha256",
                "-verify",
                str(public_key),
                "-signature",
                str(signature_path),
                str(payload_path),
            ],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    if result.returncode == 0 and result.stdout.strip() == "Verified OK":
        return True, "OpenSSL reported Verified OK for SHA256withECDSA over the canonical payload"
    return False, "OpenSSL did not report Verified OK for the canonical payload"


def iso_utc(epoch_seconds: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch_seconds))


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Rehearse the offline half of a signed Device Guard self-update: prove the APK pair "
            "is a legal in-place update and that the envelope satisfies the on-device rules."
        ),
    )
    parser.add_argument("--envelope", required=True, type=Path, help="Signed update envelope JSON")
    parser.add_argument(
        "--metadata-public-key",
        required=True,
        type=Path,
        help="PEM P-256 metadata public key the devices trust (never the private key)",
    )
    parser.add_argument(
        "--expected-metadata-key-sha256",
        required=True,
        help="Approved SHA-256 of the metadata public-key DER",
    )

    parser.add_argument("--from-apk", type=Path, help="Currently installed APK")
    parser.add_argument("--from-package", help="Installed application ID, when no APK is available")
    parser.add_argument("--from-version-code", type=int, help="Installed versionCode")
    parser.add_argument("--from-version-name", help="Installed versionName")
    parser.add_argument("--from-signer-sha256", help="Installed APK signing-certificate SHA-256")

    parser.add_argument("--to-apk", type=Path, help="Candidate APK the envelope points at")
    parser.add_argument("--to-package", help="Candidate application ID, when no APK is available")
    parser.add_argument("--to-version-code", type=int, help="Candidate versionCode")
    parser.add_argument("--to-version-name", help="Candidate versionName")
    parser.add_argument("--to-signer-sha256", help="Candidate APK signing-certificate SHA-256")
    parser.add_argument("--to-apk-sha256", help="Candidate APK SHA-256, when no APK is available")
    parser.add_argument("--to-apk-size", type=int, help="Candidate APK size in bytes")

    parser.add_argument("--expected-package", help="Application ID both APKs and the envelope must use")
    parser.add_argument(
        "--expected-signer-sha256",
        help="Approved APK signing-certificate SHA-256 for this channel",
    )
    parser.add_argument("--expected-apk-url", help="Immutable HTTPS asset URL the envelope must name")
    parser.add_argument(
        "--highest-authorized-version-code",
        type=int,
        help="Replay floor already recorded on the device (defaults to the installed versionCode)",
    )
    parser.add_argument(
        "--now-epoch-seconds",
        type=int,
        help="Evaluate envelope validity at this instant instead of the current clock",
    )
    parser.add_argument("--record", type=Path, help="Write the machine-readable drill record here")
    parser.add_argument("--force", action="store_true", help="Replace an existing --record file")
    parser.add_argument("--aapt2", type=Path, help="Explicit aapt2 binary")
    parser.add_argument("--apksigner", type=Path, help="Explicit apksigner binary")
    parser.add_argument("--openssl", type=Path, help="Explicit openssl binary")
    return parser.parse_args(argv)


# --------------------------------------------------------------------------- #
# Fact collection
# --------------------------------------------------------------------------- #


def collect_apk_facts(
    label: str,
    apk: Path | None,
    declared: dict[str, object],
    tools: dict[str, Path | None],
    recorder: DrillRecorder,
) -> ApkFacts:
    facts = ApkFacts(label)
    measured: dict[str, object] = {}
    identity_reason = f"--{label}-apk was not supplied and the identity was not declared"
    signer_reason = f"--{label}-apk was not supplied and --{label}-signer-sha256 was not declared"
    digest_reason = f"--{label}-apk was not supplied and its SHA-256 was not declared"
    size_reason = f"--{label}-apk was not supplied and its size was not declared"

    if apk is not None:
        resolved = apk.expanduser().resolve()
        if not resolved.is_file():
            raise DrillError(f"--{label}-apk does not exist: {resolved}")
        facts.path = str(resolved)
        digest, size = sha256_and_size(resolved)
        measured["apkSha256"] = digest
        measured["apkSize"] = size
        inspected: list[str] = []
        failures: list[str] = []
        if tools["aapt2"] is None:
            identity_reason = "aapt2 is not available in this environment and the identity was not declared"
        else:
            try:
                package_name, version_code, version_name = publish_update.read_apk_identity(
                    resolved, tools["aapt2"]
                )
                measured["packageName"] = package_name
                measured["versionCode"] = version_code
                measured["versionName"] = version_name
                inspected.append("aapt2")
            except publish_update.PublishError as exc:
                failures.append(f"aapt2: {exc}")
        if tools["apksigner"] is None:
            signer_reason = (
                f"apksigner is not available in this environment and --{label}-signer-sha256 "
                "was not declared"
            )
        else:
            try:
                measured["signerSha256"] = verify_pilot_apk.verify_apk_has_single_signer(
                    resolved, tools["apksigner"]
                ).lower()
                inspected.append("apksigner")
            except (verify_pilot_apk.VerificationError, publish_update.PublishError) as exc:
                failures.append(f"apksigner: {exc}")
        if failures:
            recorder.failed(
                f"{label}/apk-inspectable",
                f"the {label} APK can be parsed by the Android SDK tools",
                "; ".join(failures),
            )
        elif inspected:
            recorder.passed(
                f"{label}/apk-inspectable",
                f"the {label} APK can be parsed by the Android SDK tools",
                f"parsed with {' and '.join(inspected)}",
            )
        else:
            recorder.skipped(
                f"{label}/apk-inspectable",
                f"the {label} APK can be parsed by the Android SDK tools",
                "neither aapt2 nor apksigner is available in this environment",
            )

    facts.set("packageName", measured.get("packageName"), declared.get("packageName"), identity_reason)
    facts.set("versionCode", measured.get("versionCode"), declared.get("versionCode"), identity_reason)
    facts.set("versionName", measured.get("versionName"), declared.get("versionName"), identity_reason)
    facts.set("signerSha256", measured.get("signerSha256"), declared.get("signerSha256"), signer_reason)
    facts.set("apkSha256", measured.get("apkSha256"), declared.get("apkSha256"), digest_reason)
    facts.set("apkSize", measured.get("apkSize"), declared.get("apkSize"), size_reason)

    comparable = [
        field
        for field in ApkFacts.FIELDS
        if declared.get(field) is not None and measured.get(field) is not None
    ]
    if comparable:
        disagreements = [
            f"{field}: measured {measured[field]!r} but {label} was declared as {declared[field]!r}"
            for field in comparable
            if measured[field] != declared[field]
        ]
        recorder.result(
            f"{label}/declared-metadata-agreement",
            f"declared {label} metadata matches the {label} APK on disk",
            not disagreements,
            f"declared and measured values agree for {', '.join(comparable)}",
            "; ".join(disagreements),
        )
    return facts


# --------------------------------------------------------------------------- #
# Pair checks
# --------------------------------------------------------------------------- #


def check_update_pair(
    from_facts: ApkFacts,
    to_facts: ApkFacts,
    expected_package: str | None,
    expected_signer: str | None,
    recorder: DrillRecorder,
) -> None:
    from_package = from_facts.get("packageName")
    to_package = to_facts.get("packageName")
    if from_package is None or to_package is None:
        recorder.skipped(
            "pair/application-id",
            "the installed and candidate APKs declare the same application ID",
            from_facts.reason("packageName") if from_package is None else to_facts.reason("packageName"),
        )
    else:
        recorder.result(
            "pair/application-id",
            "the installed and candidate APKs declare the same application ID",
            from_package == to_package,
            f"both sides declare {to_package}",
            (
                f"application ID changed from {from_package} to {to_package}; Android cannot "
                "replace an installed package with a different application ID"
            ),
            unrecoverable=True,
        )

    if expected_package is None:
        pass
    elif to_package is None:
        recorder.skipped(
            "pair/expected-application-id",
            "the candidate APK uses the expected application ID",
            to_facts.reason("packageName"),
        )
    else:
        recorder.result(
            "pair/expected-application-id",
            "the candidate APK uses the expected application ID",
            to_package == expected_package,
            f"candidate application ID is {expected_package}",
            f"expected {expected_package} but the candidate declares {to_package}",
            unrecoverable=True,
        )

    from_version = from_facts.get("versionCode")
    to_version = to_facts.get("versionCode")
    if from_version is None or to_version is None:
        recorder.skipped(
            "pair/version-code-increase",
            "the candidate versionCode is strictly higher than the installed versionCode",
            from_facts.reason("versionCode") if from_version is None else to_facts.reason("versionCode"),
        )
    else:
        recorder.result(
            "pair/version-code-increase",
            "the candidate versionCode is strictly higher than the installed versionCode",
            to_version > from_version,
            f"versionCode {from_version} -> {to_version}",
            (
                f"refused: versionCode {from_version} -> {to_version} is not an increase; Android "
                "installs a corrective release only as a higher versionCode, never as a downgrade"
            ),
        )

    from_signer = from_facts.get("signerSha256")
    to_signer = to_facts.get("signerSha256")
    if from_signer is None or to_signer is None:
        recorder.skipped(
            "pair/signing-certificate-identity",
            "both APKs carry the same signing certificate",
            from_facts.reason("signerSha256") if from_signer is None else to_facts.reason("signerSha256"),
        )
    else:
        recorder.result(
            "pair/signing-certificate-identity",
            "both APKs carry the same signing certificate",
            from_signer == to_signer,
            f"single signing certificate {to_signer} on both sides",
            (
                f"signer changed from {from_signer} to {to_signer}; an in-place update cannot "
                "recover from this and the drill must stop"
            ),
            unrecoverable=True,
        )

    if expected_signer is None:
        return
    known = [
        (side, digest)
        for side, digest in (("installed", from_signer), ("candidate", to_signer))
        if digest is not None
    ]
    if not known:
        recorder.skipped(
            "pair/approved-signing-certificate",
            "the APKs are signed by the approved channel certificate",
            "no signing certificate could be read or was declared for either side",
        )
        return
    wrong = [f"{side} {digest}" for side, digest in known if digest != expected_signer]
    checked = " and ".join(side for side, _ in known)
    recorder.result(
        "pair/approved-signing-certificate",
        "the APKs are signed by the approved channel certificate",
        not wrong,
        f"the {checked} APK is signed by the approved certificate {expected_signer}",
        f"expected the approved certificate {expected_signer} but found {', '.join(wrong)}",
        unrecoverable=True,
    )


# --------------------------------------------------------------------------- #
# Metadata key checks
# --------------------------------------------------------------------------- #


def check_metadata_key(
    public_key: Path,
    expected_fingerprint: str,
    openssl: Path | None,
    recorder: DrillRecorder,
) -> None:
    try:
        _, der = verify_pilot_apk.read_pem_public_key(public_key)
    except (verify_pilot_apk.VerificationError, OSError, UnicodeError) as exc:
        recorder.failed(
            "metadata-key/fingerprint",
            "the metadata public key matches the approved fingerprint",
            f"metadata public key could not be read: {exc}",
        )
        recorder.skipped(
            "metadata-key/curve",
            "the metadata public key is an EC P-256 key",
            "the metadata public key could not be read",
        )
        return
    actual = hashlib.sha256(der).hexdigest()
    recorder.result(
        "metadata-key/fingerprint",
        "the metadata public key matches the approved fingerprint",
        actual == expected_fingerprint,
        f"public-key DER SHA-256 is the approved {actual}",
        f"expected approved public-key DER SHA-256 {expected_fingerprint} but found {actual}",
    )
    if openssl is None:
        recorder.skipped(
            "metadata-key/curve",
            "the metadata public key is an EC P-256 key",
            "openssl is not available in this environment",
        )
        return
    try:
        verify_pilot_apk.require_p256_public_key(public_key, openssl)
    except verify_pilot_apk.VerificationError as exc:
        recorder.failed(
            "metadata-key/curve",
            "the metadata public key is an EC P-256 key",
            str(exc),
        )
        return
    recorder.passed(
        "metadata-key/curve",
        "the metadata public key is an EC P-256 key",
        "openssl reports secp256r1 (P-256), the only curve the client accepts",
    )


# --------------------------------------------------------------------------- #
# Envelope checks
# --------------------------------------------------------------------------- #

ENVELOPE_CHECKS = (
    ("envelope/signature", "the envelope carries a valid ECDSA P-256 signature over the payload"),
    ("envelope/schema-version", "the payload declares the supported schema version"),
    ("envelope/device-field-limits", "every payload field is within the limits the client enforces"),
    ("envelope/package-identity", "the payload names the expected application ID"),
    ("envelope/version-binding", "the payload names exactly the candidate version"),
    ("envelope/apk-digest", "the payload SHA-256 matches the candidate APK"),
    ("envelope/apk-size", "the payload size matches the candidate APK"),
    ("envelope/apk-url", "the payload names a clean HTTPS APK URL"),
    ("envelope/validity-window", "the payload is currently valid and not over-long"),
    ("envelope/advances-installed-version", "the payload version is higher than the installed version"),
    ("envelope/not-replayed", "the payload is not a replay of an older authorized version"),
)


def skip_all_envelope_checks(recorder: DrillRecorder, reason: str) -> None:
    for identifier, description in ENVELOPE_CHECKS:
        recorder.skipped(identifier, description, reason)


def check_envelope_signature(
    openssl: Path | None,
    public_key: Path,
    payload_bytes: bytes,
    signature_bytes: bytes,
    recorder: DrillRecorder,
) -> None:
    identifier, description = ENVELOPE_CHECKS[0]
    if openssl is None:
        recorder.skipped(identifier, description, "openssl is not available in this environment")
        return
    if not public_key.is_file():
        recorder.skipped(identifier, description, "the metadata public key could not be read")
        return
    valid, detail = openssl_signature_is_valid(openssl, public_key, payload_bytes, signature_bytes)
    recorder.result(identifier, description, valid, detail, detail)


def check_envelope_fields(
    payload: dict[str, object],
    to_facts: ApkFacts,
    expected_package: str | None,
    expected_apk_url: str | None,
    now_epoch_seconds: int,
    recorder: DrillRecorder,
) -> None:
    recorder.result(
        "envelope/schema-version",
        "the payload declares the supported schema version",
        payload.get("schemaVersion") == UPDATE_SCHEMA_VERSION,
        f"schemaVersion is {UPDATE_SCHEMA_VERSION}",
        f"expected schemaVersion {UPDATE_SCHEMA_VERSION} but found {payload.get('schemaVersion')!r}",
    )

    version_code = payload.get("versionCode")
    version_name = payload.get("versionName")
    apk_size = payload.get("apkSize")
    apk_sha256 = payload.get("apkSha256")
    limit_failures: list[str] = []
    if not isinstance(version_code, int) or isinstance(version_code, bool) or version_code <= 0:
        limit_failures.append("versionCode must be a positive integer")
    if not isinstance(version_name, str) or not version_name.strip():
        limit_failures.append("versionName must be a non-empty string")
    elif len(version_name) > MAX_VERSION_NAME_LENGTH:
        limit_failures.append(f"versionName exceeds {MAX_VERSION_NAME_LENGTH} characters")
    if not isinstance(apk_size, int) or isinstance(apk_size, bool) or apk_size <= 0:
        limit_failures.append("apkSize must be a positive integer")
    elif apk_size > MAX_APK_BYTES:
        limit_failures.append("apkSize exceeds the 100 MiB client limit")
    if not isinstance(apk_sha256, str) or not LOWER_HEX_SHA256.match(apk_sha256):
        limit_failures.append("apkSha256 must be 64 lower-case hexadecimal characters")
    recorder.result(
        "envelope/device-field-limits",
        "every payload field is within the limits the client enforces",
        not limit_failures,
        "versionCode, versionName, apkSize and apkSha256 are all within the client limits",
        "; ".join(limit_failures),
    )

    if expected_package is None:
        recorder.skipped(
            "envelope/package-identity",
            "the payload names the expected application ID",
            "no application ID could be measured or declared for the candidate APK",
        )
    else:
        recorder.result(
            "envelope/package-identity",
            "the payload names the expected application ID",
            payload.get("packageName") == expected_package,
            f"packageName is {expected_package}",
            (
                f"expected packageName {expected_package} but the envelope names "
                f"{payload.get('packageName')!r}"
            ),
        )

    candidate_code = to_facts.get("versionCode")
    candidate_name = to_facts.get("versionName")
    if candidate_code is None or candidate_name is None:
        recorder.skipped(
            "envelope/version-binding",
            "the payload names exactly the candidate version",
            to_facts.reason("versionCode" if candidate_code is None else "versionName"),
        )
    else:
        mismatches = []
        if version_code != candidate_code:
            mismatches.append(f"versionCode {version_code!r} but the APK is {candidate_code}")
        if version_name != candidate_name:
            mismatches.append(f"versionName {version_name!r} but the APK is {candidate_name!r}")
        recorder.result(
            "envelope/version-binding",
            "the payload names exactly the candidate version",
            not mismatches,
            f"envelope and APK agree on versionCode {candidate_code} / versionName {candidate_name}",
            "envelope declares " + "; ".join(mismatches),
        )

    candidate_digest = to_facts.get("apkSha256")
    if candidate_digest is None:
        recorder.skipped(
            "envelope/apk-digest",
            "the payload SHA-256 matches the candidate APK",
            to_facts.reason("apkSha256"),
        )
    else:
        recorder.result(
            "envelope/apk-digest",
            "the payload SHA-256 matches the candidate APK",
            isinstance(apk_sha256, str) and apk_sha256.lower() == candidate_digest,
            f"apkSha256 matches the candidate APK ({candidate_digest})",
            (
                f"apkSha256 {apk_sha256!r} does not match the candidate APK {candidate_digest}; "
                "the envelope does not describe the artifact it points at"
            ),
        )

    candidate_size = to_facts.get("apkSize")
    if candidate_size is None:
        recorder.skipped(
            "envelope/apk-size",
            "the payload size matches the candidate APK",
            to_facts.reason("apkSize"),
        )
    else:
        recorder.result(
            "envelope/apk-size",
            "the payload size matches the candidate APK",
            apk_size == candidate_size,
            f"apkSize matches the candidate APK ({candidate_size} bytes)",
            f"apkSize {apk_size!r} does not match the candidate APK size {candidate_size}",
        )

    url_problem = clean_https_url_problem(payload.get("apkUrl"))
    if url_problem is not None:
        recorder.failed("envelope/apk-url", "the payload names a clean HTTPS APK URL", url_problem)
    elif expected_apk_url is not None and payload.get("apkUrl") != expected_apk_url:
        recorder.failed(
            "envelope/apk-url",
            "the payload names a clean HTTPS APK URL",
            f"expected the immutable asset URL {expected_apk_url} but the envelope names another URL",
        )
    else:
        bound = " and matches the expected immutable asset URL" if expected_apk_url else ""
        recorder.passed(
            "envelope/apk-url",
            "the payload names a clean HTTPS APK URL",
            f"apkUrl is clean HTTPS without credentials or a fragment{bound}",
        )

    issued_at = payload.get("issuedAt")
    expires_at = payload.get("expiresAt")
    validity_failures: list[str] = []
    if not isinstance(issued_at, int) or isinstance(issued_at, bool) or issued_at <= 0:
        validity_failures.append("issuedAt must be a positive integer")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool) or expires_at <= 0:
        validity_failures.append("expiresAt must be a positive integer")
    if not validity_failures:
        if issued_at > now_epoch_seconds + MAX_CLOCK_SKEW_SECONDS:
            validity_failures.append("issuedAt is in the future beyond the accepted clock skew")
        if expires_at <= now_epoch_seconds:
            validity_failures.append("the envelope has already expired")
        if expires_at <= issued_at:
            validity_failures.append("expiresAt is not after issuedAt")
        if expires_at - issued_at > MAX_VALIDITY_SECONDS:
            validity_failures.append("the validity window exceeds the 91-day client limit")
    recorder.result(
        "envelope/validity-window",
        "the payload is currently valid and not over-long",
        not validity_failures,
        (
            f"valid from {iso_utc(issued_at)} to {iso_utc(expires_at)} at the evaluated instant "
            f"{iso_utc(now_epoch_seconds)}"
            if not validity_failures
            else ""
        ),
        "; ".join(validity_failures),
    )


def check_envelope_progress(
    payload: dict[str, object],
    installed_version_code: object,
    installed_reason: str,
    replay_floor: int | None,
    replay_floor_source: str,
    recorder: DrillRecorder,
) -> None:
    version_code = payload.get("versionCode")
    if not isinstance(version_code, int) or isinstance(version_code, bool):
        recorder.skipped(
            "envelope/advances-installed-version",
            "the payload version is higher than the installed version",
            "the envelope does not carry an integer versionCode",
        )
        recorder.skipped(
            "envelope/not-replayed",
            "the payload is not a replay of an older authorized version",
            "the envelope does not carry an integer versionCode",
        )
        return
    if installed_version_code is None:
        recorder.skipped(
            "envelope/advances-installed-version",
            "the payload version is higher than the installed version",
            installed_reason,
        )
    else:
        recorder.result(
            "envelope/advances-installed-version",
            "the payload version is higher than the installed version",
            version_code > installed_version_code,
            f"the envelope authorizes versionCode {version_code} over installed {installed_version_code}",
            (
                f"the client treats versionCode {version_code} against installed "
                f"{installed_version_code} as up to date and installs nothing"
            ),
        )
    if replay_floor is None:
        recorder.skipped(
            "envelope/not-replayed",
            "the payload is not a replay of an older authorized version",
            replay_floor_source,
        )
        return
    recorder.result(
        "envelope/not-replayed",
        "the payload is not a replay of an older authorized version",
        version_code >= replay_floor,
        (
            f"versionCode {version_code} is at or above the replay floor {replay_floor} "
            f"({replay_floor_source})"
        ),
        (
            f"refused: versionCode {version_code} is below the replay floor {replay_floor} "
            f"({replay_floor_source}); the client rejects it as a rollback"
        ),
    )


# --------------------------------------------------------------------------- #
# Drill
# --------------------------------------------------------------------------- #


def run_drill(args: argparse.Namespace) -> dict[str, object]:
    recorder = DrillRecorder()
    tools = {
        "aapt2": locate_tool("aapt2", args.aapt2),
        "apksigner": locate_tool("apksigner", args.apksigner),
        "openssl": locate_tool("openssl", args.openssl),
    }
    expected_metadata_key = normalize_declared_digest(
        args.expected_metadata_key_sha256, "--expected-metadata-key-sha256"
    )
    expected_signer = normalize_declared_digest(
        args.expected_signer_sha256, "--expected-signer-sha256"
    )
    if args.expected_apk_url is not None:
        problem = clean_https_url_problem(args.expected_apk_url)
        if problem is not None:
            raise DrillError(f"--expected-apk-url is not a clean HTTPS URL: {problem}")

    from_facts = collect_apk_facts(
        "from",
        args.from_apk,
        {
            "packageName": args.from_package,
            "versionCode": args.from_version_code,
            "versionName": args.from_version_name,
            "signerSha256": normalize_declared_digest(
                args.from_signer_sha256, "--from-signer-sha256"
            ),
            "apkSha256": None,
            "apkSize": None,
        },
        tools,
        recorder,
    )
    to_facts = collect_apk_facts(
        "to",
        args.to_apk,
        {
            "packageName": args.to_package,
            "versionCode": args.to_version_code,
            "versionName": args.to_version_name,
            "signerSha256": normalize_declared_digest(args.to_signer_sha256, "--to-signer-sha256"),
            "apkSha256": (args.to_apk_sha256 or "").lower() or None,
            "apkSize": args.to_apk_size,
        },
        tools,
        recorder,
    )

    check_update_pair(from_facts, to_facts, args.expected_package, expected_signer, recorder)
    check_metadata_key(
        args.metadata_public_key.expanduser().resolve(),
        expected_metadata_key,
        tools["openssl"],
        recorder,
    )

    now_epoch_seconds = (
        int(time.time()) if args.now_epoch_seconds is None else args.now_epoch_seconds
    )
    payload_json: dict[str, object] | None = None
    envelope_path = args.envelope.expanduser().resolve()
    try:
        payload_bytes, signature_bytes, payload = parse_envelope(envelope_path)
    except EnvelopeStructureError as exc:
        recorder.failed(
            "envelope/structure",
            "the envelope decodes into a payload and a signature",
            str(exc),
        )
        skip_all_envelope_checks(recorder, "the envelope could not be decoded")
    else:
        payload_json = payload
        recorder.passed(
            "envelope/structure",
            "the envelope decodes into a payload and a signature",
            "exactly payload and signature, both unpadded URL-safe Base64 over UTF-8 JSON",
        )
        check_envelope_signature(
            tools["openssl"],
            args.metadata_public_key.expanduser().resolve(),
            payload_bytes,
            signature_bytes,
            recorder,
        )
        expected_package = (
            args.expected_package or to_facts.get("packageName") or from_facts.get("packageName")
        )
        check_envelope_fields(
            payload,
            to_facts,
            expected_package,
            args.expected_apk_url,
            now_epoch_seconds,
            recorder,
        )
        installed_version_code = from_facts.get("versionCode")
        if args.highest_authorized_version_code is not None:
            replay_floor = args.highest_authorized_version_code
            replay_floor_source = "supplied with --highest-authorized-version-code"
        elif isinstance(installed_version_code, int):
            replay_floor = installed_version_code
            replay_floor_source = "assumed equal to the installed versionCode"
        else:
            replay_floor = None
            replay_floor_source = (
                "no replay floor was supplied and the installed versionCode is unavailable"
            )
        check_envelope_progress(
            payload,
            installed_version_code,
            from_facts.reason("versionCode"),
            replay_floor,
            replay_floor_source,
            recorder,
        )

    counts = recorder.counts()
    verdict = recorder.verdict()
    return {
        "recordSchemaVersion": RECORD_SCHEMA_VERSION,
        "tool": "tools/update_drill.py",
        "scope": "offline-half-only",
        "generatedAtEpochSeconds": now_epoch_seconds,
        "generatedAt": iso_utc(now_epoch_seconds),
        "verdict": verdict,
        "unrecoverable": bool(recorder.unrecoverable_failures()),
        "counts": counts,
        "environment": {
            name: ("available" if path is not None else "unavailable")
            for name, path in sorted(tools.items())
        },
        "from": from_facts.to_json(),
        "to": to_facts.to_json(),
        "envelope": {
            "path": str(envelope_path),
            "payload": redacted_payload(payload_json),
        },
        "checks": recorder.checks,
        "onDeviceHalf": "not-performed",
    }



def redacted_payload(payload: object) -> object:
    """The payload as it may safely be written to an evidence file.

    A drill record is meant to be attached to an issue or committed next to a
    release, and ``apkUrl`` may legitimately carry a query string of up to 2048
    characters -- which is exactly the shape of a pre-signed object-storage URL
    whose query *is* the download credential. Recording it verbatim would turn
    an evidence file into a live credential.

    The query and fragment are therefore dropped and the fact is stated, in the
    same refuse-don't-repair spirit as the client's own URL rules: scheme, host,
    port and path are what identify the artefact, and nothing is silently
    rewritten to look clean when it was not.
    """
    if not isinstance(payload, dict):
        # A structurally broken envelope has no payload to redact, and the drill
        # still has to record that fact rather than crash on it.
        return payload
    redacted = dict(payload)
    raw = redacted.get("apkUrl")
    if not isinstance(raw, str):
        return redacted
    split = urlsplit(raw)
    if not split.query and not split.fragment:
        return redacted
    redacted["apkUrl"] = urlunsplit((split.scheme, split.netloc, split.path, "", ""))
    redacted["apkUrlRedacted"] = "query-and-fragment-removed"
    return redacted


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def render_summary(record: dict[str, object]) -> str:
    checks = record["checks"]
    counts = record["counts"]
    width = max((len(str(check["id"])) for check in checks), default=0)
    lines = [
        "Device Guard signed self-update drill - offline half",
        "=" * 51,
        f"evaluated at: {record['generatedAt']}",
        "environment:  "
        + ", ".join(f"{name} {state}" for name, state in sorted(record["environment"].items())),
        "",
    ]
    for check in checks:
        label = STATUS_LABEL[check["status"]]
        lines.append(f"{label}  {str(check['id']).ljust(width)}  {check['description']}")
        if check["detail"]:
            lines.append(f"      {' ' * width}  {check['detail']}")
    lines.append("")
    lines.append(
        f"{counts['total']} checks: {counts['passed']} passed, {counts['failed']} failed, "
        f"{counts['skipped']} could not be performed in this environment"
    )
    verdict = record["verdict"]
    if verdict == VERDICT_PASS:
        lines.append("VERDICT: PASS - every offline check ran and passed.")
    elif verdict == VERDICT_INCOMPLETE:
        lines.append(
            "VERDICT: INCOMPLETE - no check failed, but the checks marked SKIP could not be "
            "performed here and must not be recorded as passing."
        )
    else:
        lines.append("VERDICT: FAIL - do not publish this update.")
    if record["unrecoverable"]:
        lines.extend(
            [
                "",
                "!! UNRECOVERABLE FAILURE",
                "!! The application ID or signing certificate is not the one already installed.",
                "!! Android cannot replace an installed package across an identity or signer",
                "!! change, so no envelope can repair this. Rebuild the candidate APK with the",
                "!! enrolled identity and signer, or re-provision the device.",
            ]
        )
        for check in checks:
            if check["unrecoverable"]:
                lines.append(f"!! {check['id']}: {check['detail']}")
    lines.extend(
        [
            "",
            "This tool proves the offline half only. Installing the candidate on hardware,",
            "observing the scheduled check, and confirming the device returned with policy",
            "verified remain unproven until the on-device half in docs/update-drill.md runs.",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    try:
        args = parse_args(argv)
        record = run_drill(args)
    except (DrillError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return USAGE_EXIT_CODE
    encoded = json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    print(render_summary(record))
    if args.record is not None:
        try:
            publish_update.write_atomic(args.record, encoded.encode("utf-8"), args.force)
        except (publish_update.PublishError, OSError) as exc:
            print(f"error: drill record could not be written: {exc}", file=sys.stderr)
            return USAGE_EXIT_CODE
    else:
        print()
        print("--- drill record (JSON) ---")
        print(encoded, end="")
    return VERDICT_EXIT_CODE[record["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
