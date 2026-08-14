#!/usr/bin/env python3
"""Build and validate an Android Device Owner provisioning payload for QR or NFC enrolment."""

from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from urllib.parse import urlsplit

import publish_update


EXTRA_COMPONENT = "android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME"
EXTRA_DOWNLOAD_LOCATION = (
    "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION"
)
EXTRA_SIGNATURE_CHECKSUM = (
    "android.app.extra.PROVISIONING_DEVICE_ADMIN_SIGNATURE_CHECKSUM"
)
EXTRA_LEAVE_SYSTEM_APPS = "android.app.extra.PROVISIONING_LEAVE_ALL_SYSTEM_APPS_ENABLED"
EXTRA_SKIP_ENCRYPTION = "android.app.extra.PROVISIONING_SKIP_ENCRYPTION"
EXTRA_WIFI_SSID = "android.app.extra.PROVISIONING_WIFI_SSID"
EXTRA_WIFI_SECURITY_TYPE = "android.app.extra.PROVISIONING_WIFI_SECURITY_TYPE"
EXTRA_WIFI_PASSWORD = "android.app.extra.PROVISIONING_WIFI_PASSWORD"
EXTRA_WIFI_HIDDEN = "android.app.extra.PROVISIONING_WIFI_HIDDEN"
EXTRA_LOCALE = "android.app.extra.PROVISIONING_LOCALE"
EXTRA_TIME_ZONE = "android.app.extra.PROVISIONING_TIME_ZONE"
EXTRA_ADMIN_EXTRAS_BUNDLE = "android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE"

# A version-40 byte-mode QR code holds 2331 bytes at error-correction level M.
# Refuse anything close to that: a maximal symbol is unreliable to scan from a
# printed sheet on a setup-wizard camera.
MAX_PAYLOAD_BYTES = 1800
MAX_ADMIN_EXTRA_VALUE_CHARACTERS = 512

SUPPORTED_WIFI_SECURITY_TYPES = ("NONE", "WPA")
ENVIRONMENT_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
JAVA_IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
LOCALE = re.compile(r"[a-z]{2,3}(_[A-Z]{2})?")
TIME_ZONE = re.compile(r"(UTC|[A-Za-z][A-Za-z0-9+_-]*(/[A-Za-z0-9+_.-]+){1,2})")
ADMIN_EXTRA_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,63}")
HEX_PSK = re.compile(r"[0-9a-fA-F]{64}")
# Keys whose value would put a device credential into a printable QR code.
FORBIDDEN_ADMIN_EXTRA_FRAGMENTS = (
    "credential",
    "passcode",
    "passphrase",
    "password",
    "pin",
    "recovery",
    "secret",
    "token",
)


class ProvisioningError(Exception):
    """A safe, operator-facing provisioning-payload failure."""


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build the JSON provisioning payload that enrols a factory-reset device "
            "as a Device Owner, verified against the real APK where possible."
        ),
    )
    parser.add_argument(
        "--admin-component",
        required=True,
        help="Fully qualified package/class of the device admin receiver",
    )
    parser.add_argument(
        "--download-location",
        required=True,
        help="HTTPS URL the setup wizard downloads the DPC APK from",
    )
    parser.add_argument(
        "--signer-sha256",
        required=True,
        help="Expected APK signing-certificate SHA-256 (hex, colons optional, or Base64)",
    )
    parser.add_argument(
        "--apk",
        type=Path,
        help="Release APK the payload is built for; its package and signer are verified",
    )
    parser.add_argument(
        "--skip-apk-verification",
        action="store_true",
        help="Emit an explicitly unverified payload when the APK is not at hand",
    )
    parser.add_argument("--wifi-ssid", help="Optional provisioning Wi-Fi network name")
    parser.add_argument(
        "--wifi-security-type",
        choices=SUPPORTED_WIFI_SECURITY_TYPES,
        help="Security of the provisioning Wi-Fi network",
    )
    parser.add_argument(
        "--wifi-password-env",
        metavar="ENV_NAME",
        help="Environment variable holding the Wi-Fi passphrase (never the value itself)",
    )
    parser.add_argument(
        "--wifi-hidden",
        action="store_true",
        help="The provisioning Wi-Fi network does not broadcast its SSID",
    )
    parser.add_argument("--locale", help="Provisioning locale, for example en_US or iw_IL")
    parser.add_argument("--time-zone", help="Provisioning time zone, for example Asia/Jerusalem")
    parser.add_argument(
        "--admin-extra",
        action="append",
        metavar="KEY=VALUE",
        default=[],
        help="Repeatable non-secret entry for the admin extras bundle",
    )
    parser.add_argument(
        "--leave-system-apps-enabled",
        choices=("true", "false"),
        default="true",
        help="Keep OEM system applications enabled after provisioning (default: true)",
    )
    parser.add_argument(
        "--skip-encryption",
        action="store_true",
        help="Ask the setup wizard to skip storage encryption (not recommended)",
    )
    parser.add_argument("--output", required=True, type=Path, help="Payload JSON output path")
    parser.add_argument("--aapt2", type=Path, help="Explicit aapt2 binary")
    parser.add_argument("--apksigner", type=Path, help="Explicit apksigner binary")
    parser.add_argument("--force", action="store_true", help="Atomically replace an existing output")
    return parser.parse_args(argv)


def validate_admin_component(value: str) -> str:
    component = value.strip()
    if not component or component.count("/") != 1:
        raise ProvisioningError(
            "--admin-component must be exactly one package/class pair, for example "
            "il.co.shalommaman.deviceguard/com.example.lockdowndpc.admin.LockdownAdminReceiver"
        )
    package_name, class_name = component.split("/", 1)
    if not is_dotted_name(package_name):
        raise ProvisioningError("--admin-component package is not a valid application ID")
    if class_name.startswith("."):
        raise ProvisioningError(
            "--admin-component must name the receiver class in full; the leading-dot form "
            "resolves against the application ID, which is not the Device Guard receiver "
            "namespace and would enrol a class that does not exist"
        )
    if not is_dotted_name(class_name):
        raise ProvisioningError("--admin-component receiver class is not a valid Java class name")
    return component


def is_dotted_name(value: str) -> bool:
    parts = value.split(".")
    return len(parts) > 1 and all(JAVA_IDENTIFIER.fullmatch(part) for part in parts)


def validate_download_location(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    ):
        raise ProvisioningError(
            "--download-location must be a clean HTTPS URL without credentials or a fragment; "
            "the setup wizard downloads it before any policy or VPN exists on the device"
        )
    try:
        parsed.port
    except ValueError as exc:
        raise ProvisioningError("--download-location contains an invalid port") from exc
    return value


def normalize_signature_digest(value: str) -> tuple[str, str]:
    """Return the (hex, web-safe Base64) forms of a 32-byte signing-certificate digest."""
    candidate = "".join(value.split())
    hexadecimal = candidate.replace(":", "").lower()
    if re.fullmatch(r"[0-9a-f]{64}", hexadecimal):
        digest = bytes.fromhex(hexadecimal)
    else:
        padded = candidate.replace("-", "+").replace("_", "/")
        padded += "=" * (-len(padded) % 4)
        try:
            digest = base64.b64decode(padded, validate=True)
        except ValueError as exc:
            raise ProvisioningError(
                "--signer-sha256 must be a SHA-256 digest as 64 hexadecimal characters "
                "or as Base64 of 32 bytes"
            ) from exc
        if len(digest) != 32:
            raise ProvisioningError(
                "--signer-sha256 must decode to exactly 32 bytes of SHA-256 digest"
            )
    return digest.hex(), base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def read_secret_from_environment(environment_name: str, option_name: str) -> str:
    if not ENVIRONMENT_NAME.fullmatch(environment_name):
        raise ProvisioningError(f"{option_name} must be a valid environment-variable name")
    value = os.environ.get(environment_name)
    if value is None:
        raise ProvisioningError(f"environment variable is not set: {environment_name}")
    if not value:
        raise ProvisioningError(f"environment variable is empty: {environment_name}")
    return value


def build_wifi_settings(
    ssid: str | None,
    security_type: str | None,
    password_environment: str | None,
    hidden: bool,
) -> dict[str, object]:
    if ssid is None:
        if security_type or password_environment or hidden:
            raise ProvisioningError("Wi-Fi options require --wifi-ssid")
        return {}
    if (
        not ssid
        or len(ssid.encode("utf-8")) > 32
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in ssid)
    ):
        raise ProvisioningError("--wifi-ssid must be 1-32 bytes of printable text")
    if security_type is None:
        raise ProvisioningError(
            "--wifi-security-type is required with --wifi-ssid; WEP and enterprise EAP "
            "networks are deliberately unsupported by this tool"
        )
    settings: dict[str, object] = {
        EXTRA_WIFI_SSID: ssid,
        EXTRA_WIFI_SECURITY_TYPE: security_type,
    }
    if hidden:
        settings[EXTRA_WIFI_HIDDEN] = True
    if security_type == "NONE":
        if password_environment:
            raise ProvisioningError("an open Wi-Fi network cannot carry a passphrase")
        return settings
    if not password_environment:
        raise ProvisioningError(
            "--wifi-password-env is required for a WPA network; the passphrase is never "
            "accepted on the command line"
        )
    passphrase = read_secret_from_environment(password_environment, "--wifi-password-env")
    if not (8 <= len(passphrase) <= 63) and not HEX_PSK.fullmatch(passphrase):
        raise ProvisioningError(
            f"the Wi-Fi passphrase in {password_environment} must be 8-63 characters "
            "or a 64-character hexadecimal PSK"
        )
    settings[EXTRA_WIFI_PASSWORD] = passphrase
    return settings


def parse_admin_extras(values: list[str]) -> dict[str, str]:
    extras: dict[str, str] = {}
    for entry in values:
        if "=" not in entry:
            raise ProvisioningError(f"--admin-extra must be KEY=VALUE: {entry}")
        key, value = entry.split("=", 1)
        if not ADMIN_EXTRA_KEY.fullmatch(key):
            raise ProvisioningError(f"--admin-extra key is not a valid bundle key: {key}")
        if key in extras:
            raise ProvisioningError(f"--admin-extra key is repeated: {key}")
        lowered = key.lower()
        if any(fragment in lowered for fragment in FORBIDDEN_ADMIN_EXTRA_FRAGMENTS):
            raise ProvisioningError(
                f"--admin-extra key looks like a credential and is refused: {key}. "
                "A provisioning QR code is printed, photographed and shared; an "
                "administrator PIN or recovery code must never travel inside it"
            )
        if len(value) > MAX_ADMIN_EXTRA_VALUE_CHARACTERS:
            raise ProvisioningError(
                f"--admin-extra value for {key} exceeds "
                f"{MAX_ADMIN_EXTRA_VALUE_CHARACTERS} characters"
            )
        extras[key] = value
    return extras


def build_payload(
    admin_component: str,
    download_location: str,
    signature_checksum: str,
    leave_system_apps_enabled: bool,
    skip_encryption: bool,
    wifi_settings: dict[str, object],
    locale: str | None,
    time_zone: str | None,
    admin_extras: dict[str, str],
) -> dict[str, object]:
    payload: dict[str, object] = {
        EXTRA_COMPONENT: admin_component,
        EXTRA_DOWNLOAD_LOCATION: download_location,
        EXTRA_SIGNATURE_CHECKSUM: signature_checksum,
        EXTRA_LEAVE_SYSTEM_APPS: leave_system_apps_enabled,
        EXTRA_SKIP_ENCRYPTION: skip_encryption,
    }
    payload.update(wifi_settings)
    if locale is not None:
        if not LOCALE.fullmatch(locale):
            raise ProvisioningError("--locale must look like en_US or iw_IL")
        payload[EXTRA_LOCALE] = locale
    if time_zone is not None:
        if not TIME_ZONE.fullmatch(time_zone):
            raise ProvisioningError("--time-zone must be an IANA identifier such as Asia/Jerusalem")
        payload[EXTRA_TIME_ZONE] = time_zone
    if admin_extras:
        payload[EXTRA_ADMIN_EXTRAS_BUNDLE] = dict(admin_extras)
    return payload


def render_payload(payload: dict[str, object]) -> bytes:
    """Encode the payload exactly as it must appear inside the QR symbol.

    The bytes are ASCII-only compact JSON with no trailing newline, so an offline
    encoder can consume the file verbatim and a decoded symbol compares equal.
    """
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    rendered = encoded.encode("ascii")
    if len(rendered) > MAX_PAYLOAD_BYTES:
        raise ProvisioningError(
            f"payload is {len(rendered)} bytes and exceeds the {MAX_PAYLOAD_BYTES}-byte "
            "limit for a reliably scannable QR code; shorten the download URL or remove "
            "admin extras"
        )
    return rendered


def repository_root() -> Path | None:
    for directory in Path(__file__).resolve().parents:
        if (directory / ".git").exists():
            return directory
    return None


def write_atomic(output: Path, content: bytes, force: bool, mode: int) -> None:
    output = output.expanduser().resolve()
    if output.exists() and not force:
        raise ProvisioningError(f"output already exists (use --force to replace it): {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output_file:
            output_file.write(content)
            output_file.flush()
            os.fsync(output_file.fileno())
        os.chmod(temporary, mode)
        if force:
            os.replace(temporary, output)
        else:
            try:
                os.link(temporary, output)
            except FileExistsError as exc:
                raise ProvisioningError(f"output already exists: {output}") from exc
            temporary.unlink()
    finally:
        temporary.unlink(missing_ok=True)


def verify_against_apk(
    apk: Path,
    package_name: str,
    signer_sha256: str,
    aapt2: Path | None,
    apksigner: Path | None,
) -> tuple[int, str]:
    try:
        found_aapt2 = publish_update.find_android_build_tool("aapt2", aapt2)
        found_apksigner = publish_update.find_android_build_tool("apksigner", apksigner)
        apk_package, version_code, version_name = publish_update.read_apk_identity(apk, found_aapt2)
        publish_update.verify_apk_signer(apk, found_apksigner, signer_sha256)
    except publish_update.PublishError as exc:
        raise ProvisioningError(
            f"{exc}. No payload was written. Install the Android SDK build tools, pass "
            "--aapt2/--apksigner explicitly, or re-run with --skip-apk-verification to "
            "accept an explicitly unverified payload"
        ) from exc
    if apk_package != package_name:
        raise ProvisioningError(
            f"APK package mismatch: --admin-component names {package_name}, "
            f"the APK is {apk_package}"
        )
    if version_code <= 0:
        raise ProvisioningError("APK versionCode must be positive")
    return version_code, version_name


def create(args: argparse.Namespace) -> dict[str, object]:
    output = args.output.expanduser().resolve()
    root = repository_root()
    if root is not None and output.is_relative_to(root):
        raise ProvisioningError(
            "output must not be written inside the Device Guard repository; a provisioning "
            "payload can carry a Wi-Fi credential and is never committed"
        )

    admin_component = validate_admin_component(args.admin_component)
    package_name = admin_component.split("/", 1)[0]
    download_location = validate_download_location(args.download_location)
    signer_sha256, signature_checksum = normalize_signature_digest(args.signer_sha256)
    admin_extras = parse_admin_extras(args.admin_extra or [])
    wifi_settings = build_wifi_settings(
        args.wifi_ssid,
        args.wifi_security_type,
        args.wifi_password_env,
        args.wifi_hidden,
    )

    apk_verification = "skipped-by-operator"
    version_code: int | None = None
    version_name: str | None = None
    if args.apk is not None:
        if args.skip_apk_verification:
            raise ProvisioningError("--apk and --skip-apk-verification are mutually exclusive")
        apk = args.apk.expanduser().resolve()
        if not apk.is_file():
            raise ProvisioningError(f"APK does not exist: {apk}")
        if output == apk:
            raise ProvisioningError("output must not overwrite the APK")
        version_code, version_name = verify_against_apk(
            apk,
            package_name,
            signer_sha256,
            args.aapt2,
            args.apksigner,
        )
        apk_verification = "verified"
    elif not args.skip_apk_verification:
        raise ProvisioningError(
            "pass --apk so the package and signing certificate are read from the real "
            "artifact, or pass --skip-apk-verification to accept an explicitly unverified "
            "payload"
        )

    payload = build_payload(
        admin_component,
        download_location,
        signature_checksum,
        args.leave_system_apps_enabled == "true",
        args.skip_encryption,
        wifi_settings,
        args.locale,
        args.time_zone,
        admin_extras,
    )
    rendered = render_payload(payload)
    embeds_wifi_password = EXTRA_WIFI_PASSWORD in payload
    write_atomic(
        output,
        rendered,
        args.force,
        stat.S_IRUSR | stat.S_IWUSR if embeds_wifi_password else 0o644,
    )

    summary: dict[str, object] = {
        "adminComponent": admin_component,
        "apkVerification": apk_verification,
        "downloadLocation": download_location,
        "leaveSystemAppsEnabled": args.leave_system_apps_enabled == "true",
        "output": str(output),
        "packageName": package_name,
        "payloadBytes": len(rendered),
        "qrEncodeCommand": f"qrencode -8 -l M -s 8 -m 4 -o {output}.png -r {output}",
        "qrVerifyCommand": f"zbarimg --raw --quiet {output}.png",
        "signatureChecksum": signature_checksum,
        "signerSha256": signer_sha256,
        "skipEncryption": bool(args.skip_encryption),
        "wifiPasswordEmbedded": embeds_wifi_password,
    }
    if version_code is not None:
        summary["versionCode"] = version_code
        summary["versionName"] = version_name
    return summary


def main(argv: list[str]) -> int:
    try:
        summary = create(parse_args(argv))
    except (ProvisioningError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if summary["apkVerification"] != "verified":
        print(
            "warning: the payload was not checked against an APK; its package and "
            "signing-certificate digest are unverified operator input",
            file=sys.stderr,
        )
    if summary["wifiPasswordEmbedded"]:
        print(
            "warning: the payload file contains a Wi-Fi passphrase; it and any QR image "
            "made from it are credentials",
            file=sys.stderr,
        )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
