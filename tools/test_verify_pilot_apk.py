#!/usr/bin/env python3

import argparse
import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import verify_pilot_apk


class VerifyPilotApkTest(unittest.TestCase):
    def test_rejects_non_https_and_credentialed_manifest_urls(self) -> None:
        invalid = (
            "http://updates.example.test/latest.json",
            "https://user@updates.example.test/latest.json",
            "https://updates.example.test/latest.json#fragment",
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(verify_pilot_apk.VerificationError):
                verify_pilot_apk.validate_clean_https_url(value)

    def test_reads_exact_public_key_der_and_rejects_malformed_pem(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "public.pem"
            der = b"public-key-der"
            encoded = base64.b64encode(der).decode("ascii")
            path.write_text(f"-----BEGIN PUBLIC KEY-----\n{encoded}\n-----END PUBLIC KEY-----\n")
            self.assertEqual((encoded, der), verify_pilot_apk.read_pem_public_key(path))

            path.write_text("not a public key")
            with self.assertRaises(verify_pilot_apk.VerificationError):
                verify_pilot_apk.read_pem_public_key(path)

    def test_verifies_identity_signer_and_compiled_channel(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk = root / "pilot.apk"
            apk.write_bytes(b"apk")
            der = b"public-key-der"
            encoded = base64.b64encode(der).decode("ascii")
            key = root / "public.pem"
            key.write_text(f"-----BEGIN PUBLIC KEY-----\n{encoded}\n-----END PUBLIC KEY-----\n")
            args = self._args(apk, key, hashlib.sha256(der).hexdigest())

            with (
                mock.patch.object(
                    verify_pilot_apk.publish_update,
                    "find_android_build_tool",
                    side_effect=lambda name, explicit: Path(f"/mock/{name}"),
                ),
                mock.patch.object(
                    verify_pilot_apk.publish_update,
                    "read_apk_identity",
                    return_value=("com.example.lockdowndpc", 10, "0.5.1"),
                ),
                mock.patch.object(verify_pilot_apk.publish_update, "verify_apk_signer"),
                mock.patch.object(verify_pilot_apk, "require_p256_public_key"),
                mock.patch.object(
                    verify_pilot_apk,
                    "read_compiled_build_config",
                    return_value={
                        "UPDATE_MANIFEST_URL": args.expected_manifest_url,
                        "UPDATE_PUBLIC_KEY": encoded,
                    },
                ),
            ):
                summary = verify_pilot_apk.verify(args)

            self.assertEqual(10, summary["versionCode"])
            self.assertEqual(args.expected_manifest_url, summary["manifestUrl"])

    def test_rejects_channel_disabled_compiled_apk(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk = root / "pilot.apk"
            apk.write_bytes(b"apk")
            der = b"public-key-der"
            encoded = base64.b64encode(der).decode("ascii")
            key = root / "public.pem"
            key.write_text(f"-----BEGIN PUBLIC KEY-----\n{encoded}\n-----END PUBLIC KEY-----\n")
            args = self._args(apk, key, hashlib.sha256(der).hexdigest())

            with (
                mock.patch.object(
                    verify_pilot_apk.publish_update,
                    "find_android_build_tool",
                    side_effect=lambda name, explicit: Path(f"/mock/{name}"),
                ),
                mock.patch.object(
                    verify_pilot_apk.publish_update,
                    "read_apk_identity",
                    return_value=("com.example.lockdowndpc", 10, "0.5.1"),
                ),
                mock.patch.object(verify_pilot_apk.publish_update, "verify_apk_signer"),
                mock.patch.object(verify_pilot_apk, "require_p256_public_key"),
                mock.patch.object(verify_pilot_apk, "read_compiled_build_config", return_value={}),
                self.assertRaises(verify_pilot_apk.VerificationError),
            ):
                verify_pilot_apk.verify(args)

    def test_accepts_exactly_empty_channel_for_ordinary_build(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "ordinary.apk"
            apk.write_bytes(b"apk")
            args = self._args(apk, Path(directory) / "unused.pem", "00" * 32)
            args.expect_channel_disabled = True
            args.expected_manifest_url = None
            args.expected_public_key_file = None
            args.expected_public_key_sha256 = None
            with (
                mock.patch.object(
                    verify_pilot_apk.publish_update,
                    "find_android_build_tool",
                    side_effect=lambda name, explicit: Path(f"/mock/{name}"),
                ),
                mock.patch.object(
                    verify_pilot_apk.publish_update,
                    "read_apk_identity",
                    return_value=("com.example.lockdowndpc", 10, "0.5.1"),
                ),
                mock.patch.object(verify_pilot_apk.publish_update, "verify_apk_signer"),
                mock.patch.object(
                    verify_pilot_apk,
                    "read_compiled_build_config",
                    return_value={"UPDATE_MANIFEST_URL": "", "UPDATE_PUBLIC_KEY": ""},
                ),
            ):
                summary = verify_pilot_apk.verify(args)
            self.assertEqual("disabled", summary["channel"])

    def test_rejects_manifest_that_does_not_bind_exact_apk(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk = root / "pilot.apk"
            apk.write_bytes(b"exact-apk")
            key = root / "public.pem"
            key.write_text("public")
            payload = {
                "schemaVersion": 1,
                "packageName": "com.example.lockdowndpc",
                "versionCode": 10,
                "versionName": "0.5.1",
                "apkUrl": "https://github.com/org/repo/releases/download/pilot-v0.5.1/app.apk",
                "apkSha256": "00" * 32,
                "apkSize": len(b"exact-apk"),
                "issuedAt": 1_800_000_000,
                "expiresAt": 1_800_003_600,
            }
            payload_bytes = json.dumps(payload).encode()
            manifest = root / "latest.json"
            manifest.write_text(json.dumps({
                "payload": base64.urlsafe_b64encode(payload_bytes).decode().rstrip("="),
                "signature": base64.urlsafe_b64encode(b"signature").decode().rstrip("="),
            }))
            openssl_ok = mock.Mock(returncode=0, stdout="Verified OK\n", stderr="")
            with (
                mock.patch.object(verify_pilot_apk.subprocess, "run", return_value=openssl_ok),
                mock.patch.object(verify_pilot_apk.time, "time", return_value=1_800_000_100),
                self.assertRaises(verify_pilot_apk.VerificationError),
            ):
                verify_pilot_apk.verify_signed_manifest(
                    manifest, apk, key, "com.example.lockdowndpc", 10, "0.5.1",
                    payload["apkUrl"], 9,
                )

    def test_accepts_manifest_bound_to_exact_apk(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk = root / "pilot.apk"
            apk.write_bytes(b"exact-apk")
            key = root / "public.pem"
            key.write_text("public")
            apk_url = "https://github.com/org/repo/releases/download/pilot-v0.5.1/app.apk"
            payload = {
                "schemaVersion": 1,
                "packageName": "com.example.lockdowndpc",
                "versionCode": 10,
                "versionName": "0.5.1",
                "apkUrl": apk_url,
                "apkSha256": hashlib.sha256(b"exact-apk").hexdigest(),
                "apkSize": len(b"exact-apk"),
                "issuedAt": 1_800_000_000,
                "expiresAt": 1_800_003_600,
            }
            payload_bytes = json.dumps(payload).encode()
            manifest = root / "latest.json"
            manifest.write_text(json.dumps({
                "payload": base64.urlsafe_b64encode(payload_bytes).decode().rstrip("="),
                "signature": base64.urlsafe_b64encode(b"signature").decode().rstrip("="),
            }))
            openssl_ok = mock.Mock(returncode=0, stdout="Verified OK\n", stderr="")
            with (
                mock.patch.object(verify_pilot_apk.subprocess, "run", return_value=openssl_ok),
                mock.patch.object(verify_pilot_apk.time, "time", return_value=1_800_000_100),
            ):
                verify_pilot_apk.verify_signed_manifest(
                    manifest, apk, key, "com.example.lockdowndpc", 10, "0.5.1", apk_url, 9,
                )

    @staticmethod
    def _args(apk: Path, key: Path, fingerprint: str) -> argparse.Namespace:
        return argparse.Namespace(
            apk=apk,
            expected_package="com.example.lockdowndpc",
            expected_version_code=10,
            expected_version_name="0.5.1",
            expected_signer_sha256="25" * 32,
            require_single_signer=False,
            expected_manifest_url="https://updates.example.test/latest.json",
            expected_public_key_file=key,
            expected_public_key_sha256=fingerprint,
            expect_channel_disabled=False,
            aapt2=None,
            apksigner=None,
            dexdump=None,
            manifest=None,
            expected_apk_url=None,
            minimum_version_code=9,
        )

    def test_metadata_key_must_be_secp256r1(self) -> None:
        accepted = mock.Mock(
            returncode=0,
            stdout="ASN1 OID: prime256v1\nNIST CURVE: P-256\n",
            stderr="",
        )
        with mock.patch.object(verify_pilot_apk.subprocess, "run", return_value=accepted):
            verify_pilot_apk.require_p256_public_key(Path("public.pem"), Path("openssl"))

        wrong_curve = mock.Mock(
            returncode=0,
            stdout="ASN1 OID: secp384r1\nNIST CURVE: P-384\n",
            stderr="",
        )
        with (
            mock.patch.object(verify_pilot_apk.subprocess, "run", return_value=wrong_curve),
            self.assertRaises(verify_pilot_apk.VerificationError),
        ):
            verify_pilot_apk.require_p256_public_key(Path("public.pem"), Path("openssl"))

    def test_ci_signer_policy_requires_exactly_one_certificate(self) -> None:
        digest = "ab" * 32
        single = mock.Mock(
            returncode=0,
            stdout=f"Signer #1 certificate SHA-256 digest: {digest}\n",
            stderr="",
        )
        with mock.patch.object(verify_pilot_apk.subprocess, "run", return_value=single):
            self.assertEqual(
                digest,
                verify_pilot_apk.verify_apk_has_single_signer(Path("app.apk"), Path("apksigner")),
            )

        multiple = mock.Mock(
            returncode=0,
            stdout=(
                f"Signer #1 certificate SHA-256 digest: {digest}\n"
                f"Signer #2 certificate SHA-256 digest: {'cd' * 32}\n"
            ),
            stderr="",
        )
        with (
            mock.patch.object(verify_pilot_apk.subprocess, "run", return_value=multiple),
            self.assertRaises(verify_pilot_apk.VerificationError),
        ):
            verify_pilot_apk.verify_apk_has_single_signer(Path("app.apk"), Path("apksigner"))


if __name__ == "__main__":
    unittest.main()
