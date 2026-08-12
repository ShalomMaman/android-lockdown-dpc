#!/usr/bin/env python3
"""Fail-closed verification for a Device Guard pilot-channel APK."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

import publish_update


BUILD_CONFIG_DESCRIPTOR = "Lcom/example/lockdowndpc/BuildConfig;"


class VerificationError(Exception):
    """A safe, operator-facing pilot artifact verification failure."""


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--expected-package", required=True)
    parser.add_argument("--expected-version-code", required=True, type=int)
    parser.add_argument("--expected-version-name", required=True)
    parser.add_argument("--expected-signer-sha256", required=True)
    parser.add_argument("--expected-manifest-url")
    parser.add_argument("--expected-public-key-file", type=Path)
    parser.add_argument("--expected-public-key-sha256")
    parser.add_argument("--expect-channel-disabled", action="store_true")
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--expected-apk-url")
    parser.add_argument("--minimum-version-code", type=int, default=9)
    parser.add_argument("--aapt2", type=Path)
    parser.add_argument("--apksigner", type=Path)
    parser.add_argument("--dexdump", type=Path)
    return parser.parse_args(argv)


def validate_clean_https_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise VerificationError("pilot URL must be clean HTTPS")
    try:
        parsed.port
    except ValueError as exc:
        raise VerificationError("pilot URL contains an invalid port") from exc
    return value


def read_pem_public_key(path: Path) -> tuple[str, bytes]:
    if not path.is_file():
        raise VerificationError("pilot metadata public-key file is missing")
    text = path.read_text(encoding="ascii")
    if text.count("-----BEGIN PUBLIC KEY-----") != 1 or text.count("-----END PUBLIC KEY-----") != 1:
        raise VerificationError("pilot metadata public key must be one PUBLIC KEY PEM block")
    encoded = "".join(
        line.strip() for line in text.splitlines() if line.strip() and not line.startswith("-----")
    )
    try:
        der = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise VerificationError("pilot metadata public key has invalid Base64") from exc
    if not der:
        raise VerificationError("pilot metadata public key is empty")
    return encoded, der


def read_compiled_build_config(apk: Path, dexdump: Path) -> dict[str, str]:
    result = subprocess.run(
        [str(dexdump), "-d", str(apk)],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        detail = result.stderr.strip().splitlines()
        suffix = f": {detail[-1]}" if detail else ""
        raise VerificationError(f"dexdump could not inspect the compiled APK{suffix}")
    lines = result.stdout.splitlines()
    class_start = next(
        (i for i, line in enumerate(lines) if line.strip() == f"Class descriptor  : '{BUILD_CONFIG_DESCRIPTOR}'"),
        None,
    )
    if class_start is None:
        raise VerificationError("compiled APK does not retain the verifiable BuildConfig class")
    class_end = next(
        (i for i in range(class_start + 1, len(lines)) if lines[i].startswith("Class #")),
        len(lines),
    )
    fields: dict[str, str] = {}
    current_name: str | None = None
    for line in lines[class_start:class_end]:
        stripped = line.strip()
        if stripped.startswith("name") and ":" in stripped:
            current_name = stripped.split(":", 1)[1].strip(" '")
        elif current_name and stripped.startswith("value") and ":" in stripped:
            fields[current_name] = stripped.split(":", 1)[1].strip(" '\"")
            current_name = None
    return fields


def verify_signed_manifest(
    manifest: Path,
    apk: Path,
    public_key_file: Path,
    expected_package: str,
    expected_version_code: int,
    expected_version_name: str,
    expected_apk_url: str,
    minimum_version_code: int,
) -> None:
    expected_apk_url = validate_clean_https_url(expected_apk_url)
    if "/releases/download/" not in expected_apk_url:
        raise VerificationError("pilot APK URL must be an immutable GitHub release asset URL")
    try:
        envelope = json.loads(manifest.read_text(encoding="utf-8"))
        if set(envelope) != {"payload", "signature"}:
            raise ValueError("unexpected envelope fields")
        payload = base64.urlsafe_b64decode(envelope["payload"] + "=" * (-len(envelope["payload"]) % 4))
        signature = base64.urlsafe_b64decode(
            envelope["signature"] + "=" * (-len(envelope["signature"]) % 4)
        )
        authorized = json.loads(payload)
    except (OSError, UnicodeError, ValueError, TypeError, KeyError) as exc:
        raise VerificationError("pilot update manifest is malformed") from exc
    with tempfile.TemporaryDirectory() as directory:
        payload_path = Path(directory) / "payload.json"
        signature_path = Path(directory) / "signature.der"
        payload_path.write_bytes(payload)
        signature_path.write_bytes(signature)
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(public_key_file),
             "-signature", str(signature_path), str(payload_path)],
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    if result.returncode != 0 or result.stdout.strip() != "Verified OK":
        raise VerificationError("pilot update manifest signature is invalid")
    digest = hashlib.sha256()
    size = 0
    with apk.open("rb") as apk_file:
        while chunk := apk_file.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    expected = {
        "schemaVersion": 1,
        "packageName": expected_package,
        "versionCode": expected_version_code,
        "versionName": expected_version_name,
        "apkUrl": expected_apk_url,
        "apkSha256": digest.hexdigest(),
        "apkSize": size,
    }
    for key, value in expected.items():
        if authorized.get(key) != value:
            raise VerificationError(f"pilot manifest {key} does not match the exact APK/release")
    if expected_version_code <= minimum_version_code:
        raise VerificationError("pilot release version must be newer than the prior/current version")
    issued_at = authorized.get("issuedAt")
    expires_at = authorized.get("expiresAt")
    now = int(time.time())
    if not isinstance(issued_at, int) or not isinstance(expires_at, int):
        raise VerificationError("pilot manifest validity timestamps are invalid")
    if issued_at > now + 300 or expires_at <= now or expires_at <= issued_at:
        raise VerificationError("pilot update manifest is not currently valid")
    if expires_at - issued_at > 91 * 24 * 60 * 60:
        raise VerificationError("pilot update manifest validity is too long")


def verify(args: argparse.Namespace) -> dict[str, str | int]:
    apk = args.apk.expanduser().resolve()
    if not apk.is_file():
        raise VerificationError(f"pilot APK does not exist: {apk}")
    if args.expected_version_code <= 0 or not args.expected_version_name:
        raise VerificationError("expected pilot version is invalid")
    expected_signer = publish_update.normalize_certificate_sha256(args.expected_signer_sha256)
    try:
        aapt2 = publish_update.find_android_build_tool("aapt2", args.aapt2)
        apksigner = publish_update.find_android_build_tool("apksigner", args.apksigner)
        dexdump = publish_update.find_android_build_tool("dexdump", args.dexdump)
        package_name, version_code, version_name = publish_update.read_apk_identity(apk, aapt2)
        publish_update.verify_apk_signer(apk, apksigner, expected_signer)
    except publish_update.PublishError as exc:
        raise VerificationError(str(exc)) from exc
    actual_identity = (package_name, version_code, version_name)
    expected_identity = (args.expected_package, args.expected_version_code, args.expected_version_name)
    if actual_identity != expected_identity:
        raise VerificationError(
            f"pilot APK identity/version mismatch: expected {expected_identity}, found {actual_identity}"
        )
    build_config = read_compiled_build_config(apk, dexdump)
    if args.expect_channel_disabled:
        if args.expected_manifest_url or args.expected_public_key_file or args.expected_public_key_sha256:
            raise VerificationError("disabled-channel verification cannot accept channel trust inputs")
        if build_config.get("UPDATE_MANIFEST_URL") != "" or build_config.get("UPDATE_PUBLIC_KEY") != "":
            raise VerificationError("ordinary compiled BuildConfig unexpectedly embeds an update channel")
        if args.manifest is not None or args.expected_apk_url is not None:
            raise VerificationError("disabled-channel verification cannot bind a release manifest")
        return {
            "apk": str(apk), "packageName": package_name, "versionCode": version_code,
            "versionName": version_name, "signerSha256": expected_signer,
            "channel": "disabled",
        }
    if not args.expected_manifest_url or not args.expected_public_key_file or not args.expected_public_key_sha256:
        raise VerificationError("configured-channel verification requires URL, public key, and fingerprint")
    manifest_url = validate_clean_https_url(args.expected_manifest_url)
    expected_key_fingerprint = publish_update.normalize_certificate_sha256(
        args.expected_public_key_sha256, "--expected-public-key-sha256"
    )
    public_key_base64, public_key_der = read_pem_public_key(args.expected_public_key_file)
    actual_key_fingerprint = hashlib.sha256(public_key_der).hexdigest()
    if actual_key_fingerprint != expected_key_fingerprint:
        raise VerificationError("pilot metadata public-key SHA-256 does not match")
    if build_config.get("UPDATE_MANIFEST_URL") != manifest_url:
        raise VerificationError("compiled BuildConfig has the wrong pilot manifest URL")
    if build_config.get("UPDATE_PUBLIC_KEY") != public_key_base64:
        raise VerificationError("compiled BuildConfig has the wrong pilot metadata public key")
    if (args.manifest is None) != (args.expected_apk_url is None):
        raise VerificationError("--manifest and --expected-apk-url must be supplied together")
    if args.manifest is not None:
        verify_signed_manifest(
            args.manifest, apk, args.expected_public_key_file, args.expected_package,
            args.expected_version_code, args.expected_version_name, args.expected_apk_url,
            args.minimum_version_code,
        )
    return {
        "apk": str(apk), "packageName": package_name, "versionCode": version_code,
        "versionName": version_name, "signerSha256": expected_signer,
        "manifestUrl": manifest_url, "metadataKeySha256": actual_key_fingerprint,
    }


def main(argv: list[str]) -> int:
    try:
        summary = verify(parse_args(argv))
    except (OSError, UnicodeError, VerificationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for key, value in summary.items():
        print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
