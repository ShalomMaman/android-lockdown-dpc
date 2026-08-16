#!/usr/bin/env python3
"""Create a signed Device Guard update envelope without handling key material in-process."""

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
from urllib.parse import urlsplit


MAX_APK_BYTES = 100 * 1024 * 1024
MAX_VALIDITY_SECONDS = 90 * 24 * 60 * 60
PACKAGE_LINE = re.compile(
    r"^package: name='(?P<package>[^']+)' versionCode='(?P<code>[0-9]+)' "
    r"versionName='(?P<name>[^']+)'"
)
CERTIFICATE_BEGIN = "-----BEGIN CERTIFICATE-----"
CERTIFICATE_END = "-----END CERTIFICATE-----"


class PublishError(Exception):
    """A safe, operator-facing publishing failure."""


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Hash an APK, sign its canonical update metadata, and write an envelope.",
    )
    parser.add_argument("--apk", required=True, type=Path, help="Release APK to publish")
    parser.add_argument("--apk-url", required=True, help="Final HTTPS download URL for this APK")
    parser.add_argument(
        "--expected-package",
        required=True,
        help="Application ID that must be present in the APK",
    )
    parser.add_argument(
        "--expected-signer-sha256",
        required=True,
        help="Expected APK signing-certificate SHA-256 (hex, colons optional)",
    )
    parser.add_argument(
        "--private-key",
        required=True,
        type=Path,
        help="External PEM EC private key (never copied into the output)",
    )
    parser.add_argument(
        "--expected-metadata-key-sha256",
        required=True,
        help="Expected SHA-256 of the embedded metadata public-key DER",
    )
    parser.add_argument(
        "--key-passphrase-env",
        metavar="ENV_NAME",
        help="Environment variable OpenSSL may read for an encrypted key passphrase",
    )
    parser.add_argument("--output", required=True, type=Path, help="Envelope JSON output path")
    parser.add_argument(
        "--valid-for-hours",
        type=int,
        default=720,
        help="Envelope lifetime from now (default: 720; maximum: 2160)",
    )
    parser.add_argument("--aapt2", type=Path, help="Explicit aapt2 binary")
    parser.add_argument("--apksigner", type=Path, help="Explicit apksigner binary")
    parser.add_argument("--force", action="store_true", help="Atomically replace an existing output")
    return parser.parse_args(argv)


def validate_https_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise PublishError("--apk-url must be a clean HTTPS URL without credentials or a fragment")
    try:
        parsed.port
    except ValueError as exc:
        raise PublishError("--apk-url contains an invalid port") from exc
    return value


def find_android_build_tool(name: str, explicit: Path | None) -> Path:
    if explicit is not None:
        candidate = explicit.expanduser().resolve()
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
        raise PublishError(f"{name} is not executable: {candidate}")

    from_path = shutil.which(name)
    if from_path:
        return Path(from_path).resolve()

    candidates: list[Path] = []
    for variable in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        sdk_value = os.environ.get(variable)
        if sdk_value:
            candidates.extend(Path(sdk_value).expanduser().glob(f"build-tools/*/{name}"))
    candidates.extend(Path.home().glob(f"Library/Android/sdk/build-tools/*/{name}"))
    executable = [path for path in candidates if path.is_file() and os.access(path, os.X_OK)]
    if not executable:
        raise PublishError(f"{name} was not found; pass --{name} or configure ANDROID_SDK_ROOT")
    return max(
        executable,
        key=lambda path: tuple(int(part) for part in re.findall(r"[0-9]+", path.parent.name)),
    )


def normalize_certificate_sha256(
    value: str,
    option_name: str = "--expected-signer-sha256",
) -> str:
    normalized = value.replace(":", "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", normalized):
        raise PublishError(f"{option_name} must be exactly 32 bytes of hexadecimal")
    return normalized


def read_apk_identity(apk: Path, aapt2: Path) -> tuple[str, int, str]:
    result = subprocess.run(
        [str(aapt2), "dump", "badging", str(apk)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        detail = result.stderr.strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise PublishError(f"aapt2 could not inspect the APK{suffix}")
    first_line = result.stdout.splitlines()[0] if result.stdout else ""
    match = PACKAGE_LINE.match(first_line)
    if not match:
        raise PublishError("aapt2 returned an unrecognized package identity")
    version_name = match.group("name")
    if not version_name or len(version_name) > 64:
        raise PublishError("APK versionName must contain 1-64 characters")
    return match.group("package"), int(match.group("code")), version_name


def read_apk_signer_sha256(apk: Path, apksigner: Path) -> str:
    result = subprocess.run(
        [str(apksigner), "verify", "--print-certs-pem", str(apk)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        detail = result.stderr.strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise PublishError(f"apksigner rejected the APK{suffix}")
    certificates: list[bytes] = []
    remainder = result.stdout
    while CERTIFICATE_BEGIN in remainder:
        _, encoded_tail = remainder.split(CERTIFICATE_BEGIN, 1)
        if CERTIFICATE_END not in encoded_tail:
            raise PublishError("apksigner returned a malformed signing certificate")
        encoded, remainder = encoded_tail.split(CERTIFICATE_END, 1)
        try:
            certificates.append(base64.b64decode("".join(encoded.split()), validate=True))
        except ValueError as exc:
            raise PublishError("apksigner returned an invalid signing certificate") from exc
    if len(certificates) != 1:
        raise PublishError("APK must have exactly one signing certificate")
    return hashlib.sha256(certificates[0]).hexdigest()


def verify_apk_signer(apk: Path, apksigner: Path, expected_sha256: str) -> None:
    observed = read_apk_signer_sha256(apk, apksigner)
    if observed != expected_sha256:
        raise PublishError(
            "APK signing certificate does not exactly match the expected SHA-256: "
            f"expected {expected_sha256}, observed {observed}"
        )


def sha256_and_size(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as apk_file:
        while chunk := apk_file.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_APK_BYTES:
                raise PublishError("APK exceeds the 100 MiB client limit")
            digest.update(chunk)
    if size <= 0:
        raise PublishError("APK is empty")
    return digest.hexdigest(), size


def canonical_payload(
    package_name: str,
    version_code: int,
    version_name: str,
    apk_url: str,
    apk_sha256: str,
    apk_size: int,
    issued_at: int,
    expires_at: int,
) -> bytes:
    payload = {
        "apkSha256": apk_sha256,
        "apkSize": apk_size,
        "apkUrl": apk_url,
        "expiresAt": expires_at,
        "issuedAt": issued_at,
        "packageName": package_name,
        "schemaVersion": 1,
        "versionCode": version_code,
        "versionName": version_name,
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def openssl_passin(environment_name: str | None) -> str:
    if environment_name is None:
        return "pass:"
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", environment_name):
        raise PublishError("--key-passphrase-env must be a valid environment-variable name")
    if environment_name not in os.environ:
        raise PublishError(f"passphrase environment variable is not set: {environment_name}")
    return f"env:{environment_name}"


def sign_payload(
    payload: bytes,
    private_key: Path,
    key_passphrase_environment: str | None,
) -> bytes:
    passin = openssl_passin(key_passphrase_environment)
    key_check = subprocess.run(
        ["openssl", "ec", "-in", str(private_key), "-passin", passin, "-check", "-text", "-noout"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if key_check.returncode != 0 or b"ASN1 OID: prime256v1" not in key_check.stdout:
        raise PublishError("private key must be a valid EC P-256 key")
    with tempfile.NamedTemporaryFile(prefix="device-guard-payload-", delete=False) as payload_file:
        payload_file.write(payload)
        payload_path = Path(payload_file.name)
    try:
        result = subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-passin",
                passin,
                "-sign",
                str(private_key),
                str(payload_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
        )
    finally:
        payload_path.unlink(missing_ok=True)
    if result.returncode != 0 or not result.stdout:
        raise PublishError("OpenSSL could not create an ECDSA signature")
    return result.stdout


def metadata_public_key_sha256(
    private_key: Path,
    key_passphrase_environment: str | None,
) -> str:
    passin = openssl_passin(key_passphrase_environment)
    result = subprocess.run(
        [
            "openssl",
            "pkey",
            "-in",
            str(private_key),
            "-passin",
            passin,
            "-pubout",
            "-outform",
            "DER",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if result.returncode != 0 or not result.stdout:
        raise PublishError("OpenSSL could not derive the metadata public key")
    return hashlib.sha256(result.stdout).hexdigest()


def base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def write_atomic(output: Path, content: bytes, force: bool) -> None:
    output = output.expanduser().resolve()
    if output.exists() and not force:
        raise PublishError(f"output already exists (use --force to replace it): {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output_file:
            output_file.write(content)
            output_file.flush()
            os.fsync(output_file.fileno())
        os.chmod(temporary, 0o644)
        if force:
            os.replace(temporary, output)
        else:
            try:
                os.link(temporary, output)
            except FileExistsError as exc:
                raise PublishError(f"output already exists: {output}") from exc
            temporary.unlink()
    finally:
        temporary.unlink(missing_ok=True)


def publish(args: argparse.Namespace, now_epoch_seconds: int | None = None) -> dict[str, object]:
    apk = args.apk.expanduser().resolve()
    private_key = args.private_key.expanduser().resolve()
    output = args.output.expanduser().resolve()
    if not apk.is_file():
        raise PublishError(f"APK does not exist: {apk}")
    if not private_key.is_file():
        raise PublishError(f"private key does not exist: {private_key}")
    if output in (apk, private_key):
        raise PublishError("output must not overwrite the APK or private key")
    validity_seconds = args.valid_for_hours * 60 * 60
    if validity_seconds <= 0 or validity_seconds > MAX_VALIDITY_SECONDS:
        raise PublishError("--valid-for-hours must be between 1 and 2160")

    apk_url = validate_https_url(args.apk_url)
    expected_package = args.expected_package.strip()
    if not expected_package or any(character.isspace() for character in expected_package):
        raise PublishError("--expected-package must be a non-empty application ID")
    expected_signer_sha256 = normalize_certificate_sha256(args.expected_signer_sha256)
    expected_metadata_key_sha256 = normalize_certificate_sha256(
        args.expected_metadata_key_sha256,
        "--expected-metadata-key-sha256",
    )
    package_name, version_code, version_name = read_apk_identity(
        apk,
        find_android_build_tool("aapt2", args.aapt2),
    )
    if package_name != expected_package:
        raise PublishError(
            f"APK package mismatch: expected {expected_package}, found {package_name}",
        )
    if version_code <= 0:
        raise PublishError("APK versionCode must be positive")
    verify_apk_signer(
        apk,
        find_android_build_tool("apksigner", args.apksigner),
        expected_signer_sha256,
    )
    actual_metadata_key_sha256 = metadata_public_key_sha256(
        private_key,
        args.key_passphrase_env,
    )
    if actual_metadata_key_sha256 != expected_metadata_key_sha256:
        raise PublishError("metadata private key does not match the approved public-key SHA-256")
    apk_sha256, apk_size = sha256_and_size(apk)
    now = int(time.time()) if now_epoch_seconds is None else now_epoch_seconds
    payload = canonical_payload(
        package_name,
        version_code,
        version_name,
        apk_url,
        apk_sha256,
        apk_size,
        now,
        now + validity_seconds,
    )
    signature = sign_payload(payload, private_key, args.key_passphrase_env)
    envelope = {
        "payload": base64url(payload),
        "signature": base64url(signature),
    }
    encoded_envelope = (json.dumps(envelope, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    write_atomic(output, encoded_envelope, args.force)
    return {
        "apk": str(apk),
        "apkSha256": apk_sha256,
        "apkSize": apk_size,
        "expiresAt": now + validity_seconds,
        "output": str(output),
        "packageName": package_name,
        "metadataKeySha256": actual_metadata_key_sha256,
        "signerSha256": expected_signer_sha256,
        "versionCode": version_code,
        "versionName": version_name,
    }


def main(argv: list[str]) -> int:
    try:
        summary = publish(parse_args(argv))
    except (PublishError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
