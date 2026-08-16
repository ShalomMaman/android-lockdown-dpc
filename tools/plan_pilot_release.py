#!/usr/bin/env python3
"""Create a fail-closed publication plan for one Device Guard pilot APK."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

import publish_update
import verify_pilot_apk


CHANNEL_FIELDS = {
    "schemaVersion",
    "packageName",
    "manifestUrl",
    "metadataPublicKeyFile",
    "metadataPublicKeySha256",
    "apkSignerSha256",
}
PAYLOAD_FIELDS = {
    "schemaVersion",
    "packageName",
    "versionCode",
    "versionName",
    "apkUrl",
    "apkSha256",
    "apkSize",
    "issuedAt",
    "expiresAt",
}
SAFE_VERSION_NAME = re.compile(r"[0-9A-Za-z][0-9A-Za-z._-]{0,63}")


class ReleasePlanError(Exception):
    """A safe, operator-facing release-plan failure."""


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--channel", required=True, type=Path)
    parser.add_argument("--current-manifest", required=True, type=Path)
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--aapt2", type=Path)
    parser.add_argument("--apksigner", type=Path)
    return parser.parse_args(argv)


def require_text(mapping: dict[str, object], field: str) -> str:
    value = mapping.get(field)
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ReleasePlanError(f"pilot channel {field} must be a non-empty trimmed string")
    return value


def load_channel(channel_file: Path) -> tuple[dict[str, object], Path]:
    try:
        channel = json.loads(channel_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ReleasePlanError("pilot channel configuration is unreadable") from exc
    if not isinstance(channel, dict) or set(channel) != CHANNEL_FIELDS or channel.get("schemaVersion") != 1:
        raise ReleasePlanError("pilot channel configuration has an unsupported schema")
    package_name = require_text(channel, "packageName")
    if any(character.isspace() for character in package_name):
        raise ReleasePlanError("pilot package name must not contain whitespace")
    verify_pilot_apk.validate_clean_https_url(require_text(channel, "manifestUrl"))
    public_key_name = require_text(channel, "metadataPublicKeyFile")
    if Path(public_key_name).name != public_key_name or "/" in public_key_name or "\\" in public_key_name:
        raise ReleasePlanError("pilot public-key file must be a simple file name")
    try:
        channel["metadataPublicKeySha256"] = publish_update.normalize_certificate_sha256(
            require_text(channel, "metadataPublicKeySha256"),
            "metadataPublicKeySha256",
        )
        channel["apkSignerSha256"] = publish_update.normalize_certificate_sha256(
            require_text(channel, "apkSignerSha256"),
            "apkSignerSha256",
        )
    except publish_update.PublishError as exc:
        raise ReleasePlanError(str(exc)) from exc
    public_key_file = channel_file.parent / public_key_name
    try:
        _, public_key_der = verify_pilot_apk.read_pem_public_key(public_key_file)
        verify_pilot_apk.require_p256_public_key(public_key_file)
    except verify_pilot_apk.VerificationError as exc:
        raise ReleasePlanError(str(exc)) from exc
    if hashlib.sha256(public_key_der).hexdigest() != channel["metadataPublicKeySha256"]:
        raise ReleasePlanError("pilot metadata public key does not match the approved fingerprint")
    return channel, public_key_file


def plan(args: argparse.Namespace) -> dict[str, str | int]:
    apk = args.apk.expanduser().resolve()
    channel_file = args.channel.expanduser().resolve()
    manifest = args.current_manifest.expanduser().resolve()
    if not apk.is_file():
        raise ReleasePlanError("pilot APK does not exist")
    channel, public_key_file = load_channel(channel_file)
    try:
        aapt2 = publish_update.find_android_build_tool("aapt2", args.aapt2)
        apksigner = publish_update.find_android_build_tool("apksigner", args.apksigner)
        package_name, version_code, version_name = publish_update.read_apk_identity(apk, aapt2)
        publish_update.verify_apk_signer(apk, apksigner, str(channel["apkSignerSha256"]))
        current = verify_pilot_apk.read_signed_manifest(manifest, public_key_file)
    except (publish_update.PublishError, verify_pilot_apk.VerificationError) as exc:
        raise ReleasePlanError(str(exc)) from exc
    if set(current) != PAYLOAD_FIELDS or current.get("schemaVersion") != 1:
        raise ReleasePlanError("current signed pilot payload has an unsupported schema")
    if package_name != channel["packageName"] or current.get("packageName") != package_name:
        raise ReleasePlanError("pilot package identity does not match the configured channel")
    current_version_code = current.get("versionCode")
    if not isinstance(current_version_code, int) or current_version_code <= 0:
        raise ReleasePlanError("current signed pilot versionCode is invalid")
    if version_code <= current_version_code:
        raise ReleasePlanError("candidate versionCode must be newer than the signed pilot release")
    if not SAFE_VERSION_NAME.fullmatch(version_name):
        raise ReleasePlanError("candidate versionName is not safe for a release tag and asset name")
    current_apk_url = current.get("apkUrl")
    if not isinstance(current_apk_url, str):
        raise ReleasePlanError("current signed pilot APK URL is invalid")
    verify_pilot_apk.validate_clean_https_url(current_apk_url)
    if "/releases/download/" not in current_apk_url:
        raise ReleasePlanError("current signed pilot APK is not an immutable release asset")
    current_apk_sha256 = current.get("apkSha256")
    current_apk_size = current.get("apkSize")
    if not isinstance(current_apk_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", current_apk_sha256):
        raise ReleasePlanError("current signed pilot APK SHA-256 is invalid")
    if not isinstance(current_apk_size, int) or current_apk_size <= 0:
        raise ReleasePlanError("current signed pilot APK size is invalid")
    tag = f"pilot-v{version_name}"
    asset_name = f"device-guard-pilot-v{version_name}.apk"
    release_url = (
        "https://github.com/ShalomMaman/android-lockdown-dpc/releases/download/"
        f"{tag}/{asset_name}"
    )
    return {
        "package_name": package_name,
        "version_code": version_code,
        "version_name": version_name,
        "current_version_code": current_version_code,
        "current_apk_url": current_apk_url,
        "current_apk_sha256": current_apk_sha256,
        "current_apk_size": current_apk_size,
        "tag": tag,
        "asset_name": asset_name,
        "release_name": f"Device Guard Pilot {version_name}",
        "release_url": release_url,
        "metadata_key_sha256": str(channel["metadataPublicKeySha256"]),
        "signer_sha256": str(channel["apkSignerSha256"]),
        "manifest_url": str(channel["manifestUrl"]),
        "metadata_public_key": str(public_key_file),
        "metadata_branch": f"automation/{tag}-metadata",
    }


def write_github_output(path: Path, values: dict[str, str | int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as output:
        for key, value in values.items():
            text = str(value)
            if "\n" in text or "\r" in text:
                raise ReleasePlanError("release-plan output contains a line break")
            output.write(f"{key}={text}\n")


def main(argv: list[str]) -> int:
    try:
        args = parse_args(argv)
        result = plan(args)
        if args.github_output is not None:
            write_github_output(args.github_output, result)
    except (OSError, UnicodeError, ReleasePlanError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
