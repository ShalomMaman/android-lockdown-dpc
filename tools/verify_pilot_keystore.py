#!/usr/bin/env python3
"""Fail-fast verification for the restored pilot APK signing keystore."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


SHA256_LINE = re.compile(r"^\s*SHA256:\s*(?P<digest>[0-9A-Fa-f:]+)\s*$")


class VerificationError(Exception):
    """A safe, operator-facing pilot keystore verification failure."""


def normalize_sha256(value: str) -> str:
    normalized = value.replace(":", "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", normalized):
        raise VerificationError("pilot signer SHA-256 is malformed")
    return normalized


def expected_signer(channel_path: Path) -> str:
    try:
        channel = json.loads(channel_path.read_text(encoding="utf-8"))
        value = channel["apkSignerSha256"]
    except (OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
        raise VerificationError("pilot channel configuration is malformed") from exc
    if not isinstance(value, str):
        raise VerificationError("pilot channel signer SHA-256 is malformed")
    return normalize_sha256(value)


def observed_signer(
    keystore: Path,
    store_password_environment: str,
    key_alias_environment: str,
    keytool: Path | None = None,
) -> str:
    if not keystore.is_file():
        raise VerificationError("restored pilot signing keystore is missing")
    if store_password_environment not in os.environ:
        raise VerificationError("pilot keystore password environment variable is missing")
    alias = os.environ.get(key_alias_environment, "").strip()
    if not alias:
        raise VerificationError("pilot signing alias environment variable is missing")
    executable = keytool or (Path(found) if (found := shutil.which("keytool")) else None)
    if executable is None:
        raise VerificationError("keytool was not found")
    result = subprocess.run(
        [
            str(executable),
            "-J-Duser.language=en",
            "-J-Duser.country=US",
            "-list",
            "-v",
            "-keystore",
            str(keystore),
            "-storepass:env",
            store_password_environment,
            "-alias",
            alias,
        ],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise VerificationError("keytool could not read the restored pilot signing identity")
    digests = [
        normalize_sha256(match.group("digest"))
        for line in result.stdout.splitlines()
        if (match := SHA256_LINE.match(line))
    ]
    if len(digests) != 1:
        raise VerificationError("keytool did not report exactly one pilot signing certificate")
    return digests[0]


def verify(
    keystore: Path,
    channel: Path,
    store_password_environment: str,
    key_alias_environment: str,
    keytool: Path | None = None,
) -> str:
    expected = expected_signer(channel)
    observed = observed_signer(
        keystore,
        store_password_environment,
        key_alias_environment,
        keytool,
    )
    if observed != expected:
        raise VerificationError(
            f"restored pilot keystore signer mismatch: expected {expected}, observed {observed}"
        )
    return observed


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keystore", required=True, type=Path)
    parser.add_argument("--channel", required=True, type=Path)
    parser.add_argument("--store-password-env", required=True)
    parser.add_argument("--key-alias-env", required=True)
    parser.add_argument("--keytool", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        signer = verify(
            args.keystore.expanduser().resolve(),
            args.channel.expanduser().resolve(),
            args.store_password_env,
            args.key_alias_env,
            args.keytool,
        )
    except (OSError, UnicodeError, VerificationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"pilotKeystoreSignerSha256: {signer}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
