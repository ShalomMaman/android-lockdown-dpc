"""Build a production candidate and witness its signed in-app update on a bench device."""

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import HTTPRedirectHandler, build_opener
from zipfile import BadZipFile

from publish_update import PublishError, find_android_build_tool, read_apk_identity, sha256_and_size
from verify_pilot_apk import VerificationError, read_signed_manifest, validate_clean_https_url, verify_apk_has_single_signer
from verify_release_apk import verify_release

ROOT = Path(__file__).resolve().parent.parent
SIGNING_SETTINGS = (
    "DEVICE_GUARD_STORE_FILE", "DEVICE_GUARD_STORE_PASSWORD",
    "DEVICE_GUARD_KEY_ALIAS", "DEVICE_GUARD_KEY_PASSWORD",
)
ADMIN_CLASS = "com.example.lockdowndpc.admin.LockdownAdminReceiver"
UPDATE_JOB = str(0x44555044)  # UpdateScheduler's persisted periodic job
MANIFEST_LIMIT = 64 * 1024  # MAX_MANIFEST_BYTES in UpdateEnvelopeVerifier.kt
DEFAULT_MAX_VERSION_JUMP = 1000


class DrillError(Exception):
    pass


class DirectHttps(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def command(*args: str, timeout: int = 30) -> str:
    return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL, timeout=timeout)


def signing_environment() -> dict[str, str]:
    signing = {name: os.environ.pop(name, "") for name in SIGNING_SETTINGS}
    if not all(value.strip() for value in signing.values()):
        raise DrillError("all four production signing environment variables are required")
    keystore = Path(signing["DEVICE_GUARD_STORE_FILE"]).expanduser().resolve()
    if not keystore.is_file() or keystore.is_relative_to(ROOT):
        raise DrillError("the signing keystore must exist outside the repository")
    signing["DEVICE_GUARD_STORE_FILE"] = str(keystore)
    return os.environ | signing


def owner(snapshot: str) -> tuple[str, int]:
    # Read the Device Owner block only. Profile owners and active admins can
    # include the same receiver class but do not establish this precondition.
    block = re.search(r"(?m)^([ \t]*)Device Owner:[ \t]*\n((?:\1[ \t]+\S[^\n]*\n?)+)", snapshot)
    if block:
        component = re.search(r"admin=ComponentInfo\{([\w.]+)/([^}]+)\}", block[2])
        user = re.search(r"(?m)^\s*User ID:\s*(\d+)\s*$", block[2])
        if component and user and component[2] == ADMIN_CLASS:
            return component[1], int(user[1])
    raise DrillError("Maakeh Device Owner and its user could not be read")


def effective_restrictions(snapshot: str, user: int) -> list[str]:
    users = re.split(r"(?m)^\s*UserInfo\{(\d+):.*$", snapshot)
    for user_id, block in zip(users[1::2], users[2::2]):
        if int(user_id) == user:
            section = re.search(r"(?m)^\s*Effective restrictions:[ \t]*\n((?:[ \t]+[a-z][a-z_0-9]*[ \t]*\n)+)", block)
            restrictions = sorted(set(section[1].split())) if section else []
            if "no_factory_reset" in restrictions:
                return restrictions
            break
    raise DrillError("effective restrictions for the owner user must include the factory-reset block")


def require_witness(prompt: str) -> None:
    # Confirmation is tied to direct observations and contains no free-text
    # fields that would enter the evidence record.
    print(prompt + " Type YES to confirm.", file=sys.stderr, flush=True)
    if sys.stdin.readline().strip() != "YES":
        raise DrillError("required witness observation was not confirmed")


def verify_staged_manifest(url: str, key: str, expected: dict, scratch: Path) -> str:
    opener = build_opener(DirectHttps())
    with opener.open(url, timeout=15) as response:
        envelope_bytes = response.read(MANIFEST_LIMIT + 1)
    if len(envelope_bytes) > MANIFEST_LIMIT:
        raise DrillError("staged update manifest exceeds the client size limit")
    envelope = scratch / "envelope.json"
    envelope.write_bytes(envelope_bytes)
    public_key = scratch / "metadata.pem"
    public_key.write_bytes(
        b"-----BEGIN PUBLIC KEY-----\n"
        + base64.encodebytes(base64.b64decode(key, validate=True))
        + b"-----END PUBLIC KEY-----\n",
    )
    payload = read_signed_manifest(envelope, public_key)
    if any(payload.get(field) != value for field, value in expected.items()):
        raise DrillError("staged signed update manifest does not identify the exact candidate")
    apk_url = payload.get("apkUrl")
    if not isinstance(apk_url, str):
        raise DrillError("staged signed update manifest is missing its APK URL")
    validate_clean_https_url(apk_url)
    now = int(time.time())
    issued, expires = payload.get("issuedAt"), payload.get("expiresAt")
    if type(issued) is not int or type(expires) is not int or not issued <= now < expires:
        raise DrillError("staged signed update manifest is outside its validity window")
    return sha256_and_size(envelope)[0]


def validate_version_jump(
    candidate_version: int,
    installed_version: int,
    max_version_jump: int = DEFAULT_MAX_VERSION_JUMP,
) -> None:
    if type(max_version_jump) is not int or max_version_jump <= 0:
        raise DrillError("--max-version-jump must be positive")
    if candidate_version <= installed_version:
        raise DrillError("candidate versionCode must be higher than the installed version")
    jump = candidate_version - installed_version
    if jump > max_version_jump:
        raise DrillError(
            f"candidate versionCode jump of {jump} exceeds max allowed jump of {max_version_jump} "
            f"(installed {installed_version}, candidate {candidate_version})"
        )


def run(args: argparse.Namespace, evidence: dict, scratch: Path) -> None:
    evidence["stage"] = "signing-inputs"
    max_version_jump = getattr(args, "max_version_jump", DEFAULT_MAX_VERSION_JUMP)
    if type(max_version_jump) is not int or max_version_jump <= 0:
        raise DrillError("--max-version-jump must be positive")
    build_env = signing_environment()
    channel_url = validate_clean_https_url(os.environ.get("DEVICE_GUARD_UPDATE_MANIFEST_URL", ""))
    channel_key = os.environ.get("DEVICE_GUARD_UPDATE_PUBLIC_KEY", "")
    if not channel_key or not os.environ.get("DEVICE_GUARD_UPDATE_PUBLIC_KEY_SHA256"):
        raise DrillError("the existing production update channel settings are required")
    if not 0 < args.version_code <= 2_100_000_000:
        raise DrillError("candidate versionCode is outside the supported range")

    evidence["stage"] = "baseline"
    connected = command("adb", "devices").splitlines()
    selection = os.environ.get("ANDROID_SERIAL")
    serials = [row.split()[0] for row in connected if re.fullmatch(r"\S+\s+device\s*", row)]
    serials = [serial for serial in serials if not selection or serial == selection]
    if len(serials) != 1 or serials[0].startswith("emulator-"):
        raise DrillError("select one authorized physical bench device")

    def adb(*argv: str, timeout: int = 30) -> str:
        return command("adb", "-s", serials[0], *argv, timeout=timeout)

    if adb("shell", "getprop", "ro.kernel.qemu").strip() == "1" or adb(
        "shell", "getprop", "ro.boot.qemu",
    ).strip() == "1":
        raise DrillError("a physical bench device is required")
    package, user = owner(adb("shell", "dumpsys", "device_policy"))
    aapt2, dexdump, apksigner = (
        find_android_build_tool(name, None) for name in ("aapt2", "dexdump", "apksigner")
    )

    def apk_path() -> str:
        output = adb("shell", "pm", "path", "--user", str(user), package).strip()
        match = re.fullmatch(r"package:(/\S+/base\.apk)", output)
        if not match:
            raise DrillError("the owner must use a single installed release APK")
        return match[1]

    installed_path = apk_path()
    baseline = scratch / "before.apk"
    adb("pull", installed_path, str(baseline), timeout=120)
    before_package, before_version, _ = read_apk_identity(baseline, aapt2)
    if before_package != package:
        raise DrillError("installed APK identity does not match the Device Owner")
    before_fields = verify_release(baseline, aapt2, dexdump)
    if (before_fields.get("UPDATE_MANIFEST_URL"), before_fields.get("UPDATE_PUBLIC_KEY")) != (
        channel_url, channel_key,
    ):
        raise DrillError("installed release does not trust the specified HTTPS channel")
    validate_version_jump(args.version_code, before_version, max_version_jump)
    signer = verify_apk_has_single_signer(baseline, apksigner)
    restrictions = effective_restrictions(adb("shell", "dumpsys", "user"), user)
    evidence["beforeVersionCode"] = before_version
    evidence["effectiveRestrictions"] = restrictions
    require_witness("Confirm this is a dedicated bench device and channel, with protection verified and ADB available.")

    evidence["stage"] = "signed-build"
    args.output_dir.mkdir(mode=0o700)
    build = subprocess.run(
        ["./gradlew", "-I", "gradle/production.init.gradle.kts", "--no-daemon",
         "--no-configuration-cache", "--no-build-cache", "--max-workers=2", "--quiet",
         f"-PdeviceGuardDrillVersionCode={args.version_code}", ":app:assembleRelease"],
        env=build_env, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1800,
    )
    if build.returncode:
        raise DrillError("production Gradle build failed; signing output is suppressed")
    candidate = args.output_dir / "candidate.apk"
    shutil.copyfile(ROOT / "app/build/outputs/apk/release/app-release.apk", candidate)
    candidate_package, candidate_version, name = read_apk_identity(candidate, aapt2)
    if (candidate_package, candidate_version) != (package, args.version_code):
        raise DrillError("candidate package or version differs from the expected release")
    fields = verify_release(candidate, aapt2, dexdump)
    if (fields.get("UPDATE_MANIFEST_URL"), fields.get("UPDATE_PUBLIC_KEY")) != (channel_url, channel_key):
        raise DrillError("candidate update channel differs from the installed release")
    if verify_apk_has_single_signer(candidate, apksigner) != signer:
        raise DrillError("candidate signer differs from the installed release signer")
    digest, size = sha256_and_size(candidate)
    evidence.update(candidateVersionCode=candidate_version, candidateSha256=digest, sameSigner=True)

    evidence["stage"] = "staged-manifest"
    require_witness(
        "Watch the device continuously. Stage candidate.apk and its separately signed manifest "
        "on the isolated channel, then confirm.",
    )
    evidence["manifestSha256"] = verify_staged_manifest(channel_url, channel_key, {
        "schemaVersion": 1, "packageName": package, "versionCode": candidate_version,
        "versionName": name, "apkSha256": digest, "apkSize": size,
    }, scratch)
    if apk_path() != installed_path:
        raise DrillError("package changed before the controlled update check")

    evidence["stage"] = "self-update"
    job = adb("shell", "cmd", "jobscheduler", "run", "-f", "-u", str(user), package, UPDATE_JOB)
    if "Running job" not in job:
        raise DrillError("Android did not start the app's existing update job")
    started = time.monotonic()
    while apk_path() == installed_path:
        if time.monotonic() - started >= args.timeout:
            raise DrillError("timed out waiting for the in-app update")
        time.sleep(2)
    updated = scratch / "after.apk"
    adb("pull", apk_path(), str(updated), timeout=120)
    if sha256_and_size(updated) != (digest, size):
        raise DrillError("installed APK does not match the exact signed candidate")
    evidence["afterVersionCode"] = candidate_version
    evidence["secondsToReplacement"] = round(time.monotonic() - started, 1)

    evidence["stage"] = "post-update-policy"
    require_witness(
        "Confirm no install prompt, approval, sideload, or interruption of protection occurred, "
        "both update audit entries are present, and the original policies still show verified and work.",
    )
    if owner(adb("shell", "dumpsys", "device_policy")) != (package, user):
        raise DrillError("Device Owner or its user changed")
    if effective_restrictions(adb("shell", "dumpsys", "user"), user) != restrictions:
        raise DrillError("effective owner-user restrictions changed")
    evidence.update(deviceOwnerRetained=True, restrictionsUnchanged=True, silentUpdateWitnessed=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version-code", type=int, required=True)
    parser.add_argument("--output-dir", type=Path, required=True, help="new directory for candidate.apk")
    parser.add_argument("--timeout", type=int, choices=range(10, 901), metavar="SECONDS", default=180)
    parser.add_argument(
        "--max-version-jump",
        type=int,
        default=DEFAULT_MAX_VERSION_JUMP,
        help=(
            "maximum allowed versionCode increase over the installed release "
            f"(default: {DEFAULT_MAX_VERSION_JUMP})"
        ),
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    evidence = {"case": "U-1", "timeUtc": datetime.now(timezone.utc).isoformat(), "verdict": "FAIL"}
    try:
        with tempfile.TemporaryDirectory(prefix="device-update-drill-") as scratch:
            run(args, evidence, Path(scratch))
    except DrillError as error:
        evidence["reason"] = str(error)
    except (PublishError, VerificationError, subprocess.SubprocessError, OSError,
            BadZipFile, ValueError, TypeError, EOFError):
        # Tool errors and raw ADB output can contain paths, identifiers or signer
        # details. Keep only the controlled stage name in shareable evidence.
        evidence["reason"] = "required tool or verification failed at this stage"
    except KeyboardInterrupt:
        evidence["reason"] = "run interrupted"
    else:
        evidence.update(stage="complete", verdict="PASS")
    print(json.dumps(evidence, sort_keys=True))
    return 0 if evidence["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
