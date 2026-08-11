#!/usr/bin/env python3

import argparse
import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import publish_update


class PublishUpdateTest(unittest.TestCase):
    def test_rejects_non_https_and_credentialed_urls(self) -> None:
        invalid = (
            "http://updates.example.test/app.apk",
            "https://user@updates.example.test/app.apk",
            "https://updates.example.test/app.apk#fragment",
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(publish_update.PublishError):
                publish_update.validate_https_url(value)

    def test_payload_is_canonical_and_contains_required_schema(self) -> None:
        payload = publish_update.canonical_payload(
            "com.example.lockdowndpc",
            9,
            "0.5.0",
            "https://updates.example.test/app.apk",
            "ab" * 32,
            1234,
            1_799_999_940,
            1_800_000_000,
        )

        self.assertEqual(payload, json.dumps(json.loads(payload), separators=(",", ":"), sort_keys=True).encode())
        self.assertEqual(1, json.loads(payload)["schemaVersion"])

    def test_signer_preflight_requires_exactly_the_expected_certificate(self) -> None:
        expected = "ab" * 32
        accepted = mock.Mock(
            returncode=0,
            stdout=f"Signer #1 certificate SHA-256 digest: {expected}\n",
            stderr="",
        )
        with mock.patch.object(publish_update.subprocess, "run", return_value=accepted):
            publish_update.verify_apk_signer(Path("app.apk"), Path("apksigner"), expected)

        rejected = mock.Mock(
            returncode=0,
            stdout=f"Signer #1 certificate SHA-256 digest: {'cd' * 32}\n",
            stderr="",
        )
        with (
            mock.patch.object(publish_update.subprocess, "run", return_value=rejected),
            self.assertRaises(publish_update.PublishError),
        ):
            publish_update.verify_apk_signer(Path("app.apk"), Path("apksigner"), expected)

    def test_signer_preflight_rejects_multiple_signers(self) -> None:
        expected = "ab" * 32
        result = mock.Mock(
            returncode=0,
            stdout=(
                f"Signer #1 certificate SHA-256 digest: {expected}\n"
                f"Signer #2 certificate SHA-256 digest: {'cd' * 32}\n"
            ),
            stderr="",
        )
        with (
            mock.patch.object(publish_update.subprocess, "run", return_value=result),
            self.assertRaises(publish_update.PublishError),
        ):
            publish_update.verify_apk_signer(Path("app.apk"), Path("apksigner"), expected)

        duplicate = mock.Mock(
            returncode=0,
            stdout=(
                f"Signer #1 certificate SHA-256 digest: {expected}\n"
                f"Signer #2 certificate SHA-256 digest: {expected}\n"
            ),
            stderr="",
        )
        with (
            mock.patch.object(publish_update.subprocess, "run", return_value=duplicate),
            self.assertRaises(publish_update.PublishError),
        ):
            publish_update.verify_apk_signer(Path("app.apk"), Path("apksigner"), expected)

    def test_refuses_to_replace_existing_output_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "manifest.json"
            output.write_bytes(b"original")

            with self.assertRaises(publish_update.PublishError):
                publish_update.write_atomic(output, b"replacement", force=False)

            self.assertEqual(b"original", output.read_bytes())

    def test_openssl_passin_is_non_interactive_and_does_not_read_the_secret(self) -> None:
        self.assertEqual("pass:", publish_update.openssl_passin(None))
        secret = "not-observed-by-the-tool"
        with mock.patch.dict("os.environ", {"UPDATE_KEY_PASSWORD": secret}, clear=False):
            self.assertEqual(
                "env:UPDATE_KEY_PASSWORD",
                publish_update.openssl_passin("UPDATE_KEY_PASSWORD"),
            )
        with self.assertRaises(publish_update.PublishError):
            publish_update.openssl_passin("INVALID-NAME")

    def test_signing_passes_only_the_environment_reference_to_openssl(self) -> None:
        key_checked = mock.Mock(
            returncode=0,
            stdout=b"ASN1 OID: prime256v1\nNIST CURVE: P-256\n",
        )
        signed = mock.Mock(returncode=0, stdout=b"der-signature")
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict("os.environ", {"UPDATE_KEY_PASSWORD": "secret"}, clear=False),
            mock.patch.object(
                publish_update.subprocess,
                "run",
                side_effect=[key_checked, signed],
            ) as runner,
        ):
            result = publish_update.sign_payload(
                b"payload",
                Path(directory) / "key.pem",
                "UPDATE_KEY_PASSWORD",
            )

        self.assertEqual(b"der-signature", result)
        self.assertEqual(2, runner.call_count)
        for call in runner.call_args_list:
            command = call.args[0]
            self.assertIn("env:UPDATE_KEY_PASSWORD", command)
            self.assertNotIn("secret", command)

    def test_signing_rejects_a_non_p256_ec_key(self) -> None:
        wrong_curve = mock.Mock(returncode=0, stdout=b"ASN1 OID: secp384r1\n")
        with (
            mock.patch.object(publish_update.subprocess, "run", return_value=wrong_curve),
            self.assertRaises(publish_update.PublishError),
        ):
            publish_update.sign_payload(b"payload", Path("key.pem"), None)

    def test_publish_builds_decodable_envelope_without_copying_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk = root / "release.apk"
            key = root / "offline.pem"
            output = root / "update.json"
            apk.write_bytes(b"signed-apk-placeholder")
            key.write_text("external key placeholder")
            args = argparse.Namespace(
                apk=apk,
                apk_url="https://updates.example.test/app.apk",
                expected_package="com.example.lockdowndpc",
                expected_signer_sha256="ab" * 32,
                expected_metadata_key_sha256="ef" * 32,
                private_key=key,
                key_passphrase_env=None,
                output=output,
                valid_for_hours=1,
                aapt2=Path("/unused/aapt2"),
                apksigner=Path("/unused/apksigner"),
                force=False,
            )

            with (
                mock.patch.object(
                    publish_update,
                    "find_android_build_tool",
                    side_effect=lambda name, explicit: Path(f"/mock/{name}"),
                ),
                mock.patch.object(
                    publish_update,
                    "read_apk_identity",
                    return_value=("com.example.lockdowndpc", 9, "0.5.0"),
                ),
                mock.patch.object(publish_update, "verify_apk_signer"),
                mock.patch.object(
                    publish_update,
                    "metadata_public_key_sha256",
                    return_value="ef" * 32,
                ),
                mock.patch.object(publish_update, "sign_payload", return_value=b"der-signature"),
            ):
                summary = publish_update.publish(args, now_epoch_seconds=1_800_000_000)

            envelope = json.loads(output.read_text())
            payload = json.loads(_decode_url_base64(envelope["payload"]))
            self.assertEqual("com.example.lockdowndpc", payload["packageName"])
            self.assertEqual(1_800_000_000, payload["issuedAt"])
            self.assertEqual(1_800_003_600, payload["expiresAt"])
            self.assertEqual(b"der-signature", _decode_url_base64(envelope["signature"]))
            self.assertEqual(9, summary["versionCode"])
            self.assertEqual("ab" * 32, summary["signerSha256"])
            self.assertEqual("ef" * 32, summary["metadataKeySha256"])
            self.assertNotIn(key.read_text(), output.read_text())

    def test_publish_rejects_an_unexpected_package_before_signing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk = root / "release.apk"
            key = root / "offline.pem"
            apk.write_bytes(b"apk")
            key.write_text("key")
            args = argparse.Namespace(
                apk=apk,
                apk_url="https://updates.example.test/app.apk",
                expected_package="com.example.lockdowndpc",
                expected_signer_sha256="ab" * 32,
                expected_metadata_key_sha256="ef" * 32,
                private_key=key,
                key_passphrase_env=None,
                output=root / "update.json",
                valid_for_hours=1,
                aapt2=None,
                apksigner=None,
                force=False,
            )
            with (
                mock.patch.object(
                    publish_update,
                    "find_android_build_tool",
                    return_value=Path("/mock/aapt2"),
                ),
                mock.patch.object(
                    publish_update,
                    "read_apk_identity",
                    return_value=("com.attacker.app", 9, "0.5.0"),
                ),
                mock.patch.object(publish_update, "sign_payload") as signer,
                self.assertRaises(publish_update.PublishError),
            ):
                publish_update.publish(args, now_epoch_seconds=1_800_000_000)
            signer.assert_not_called()


def _decode_url_base64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


if __name__ == "__main__":
    unittest.main()
