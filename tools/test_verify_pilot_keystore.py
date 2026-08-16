#!/usr/bin/env python3

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import verify_pilot_keystore


class VerifyPilotKeystoreTest(unittest.TestCase):
    def test_accepts_the_exact_channel_signer_without_putting_password_in_argv(self) -> None:
        expected = "ab" * 32
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            keystore = root / "pilot.jks"
            keystore.write_bytes(b"keystore")
            channel = root / "channel.json"
            channel.write_text(json.dumps({"apkSignerSha256": expected}), encoding="utf-8")
            completed = mock.Mock(
                returncode=0,
                stdout="Certificate fingerprints:\n\tSHA256: " + ":".join(
                    expected[index : index + 2].upper() for index in range(0, 64, 2)
                ) + "\n",
                stderr="",
            )
            with (
                mock.patch.dict(os.environ, {"STORE_PASS": "do-not-log", "KEY_ALIAS": "pilot"}),
                mock.patch.object(verify_pilot_keystore.subprocess, "run", return_value=completed) as run,
            ):
                self.assertEqual(
                    expected,
                    verify_pilot_keystore.verify(
                        keystore, channel, "STORE_PASS", "KEY_ALIAS", Path("keytool")
                    ),
                )
            command = run.call_args.args[0]
            self.assertIn("-storepass:env", command)
            self.assertIn("STORE_PASS", command)
            self.assertNotIn("do-not-log", command)

    def test_reports_expected_and_observed_fingerprints_on_mismatch(self) -> None:
        expected = "ab" * 32
        observed = "cd" * 32
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            keystore = root / "pilot.jks"
            keystore.write_bytes(b"keystore")
            channel = root / "channel.json"
            channel.write_text(json.dumps({"apkSignerSha256": expected}), encoding="utf-8")
            completed = mock.Mock(
                returncode=0,
                stdout=f"SHA256: {observed}\n",
                stderr="",
            )
            with (
                mock.patch.dict(os.environ, {"STORE_PASS": "secret", "KEY_ALIAS": "pilot"}),
                mock.patch.object(verify_pilot_keystore.subprocess, "run", return_value=completed),
                self.assertRaisesRegex(
                    verify_pilot_keystore.VerificationError,
                    f"expected {expected}, observed {observed}",
                ),
            ):
                verify_pilot_keystore.verify(
                    keystore, channel, "STORE_PASS", "KEY_ALIAS", Path("keytool")
                )

    def test_fails_closed_when_keytool_cannot_read_the_keystore(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            keystore = root / "pilot.jks"
            keystore.write_bytes(b"keystore")
            channel = root / "channel.json"
            channel.write_text(json.dumps({"apkSignerSha256": "ab" * 32}), encoding="utf-8")
            completed = mock.Mock(returncode=1, stdout="", stderr="bad password")
            with (
                mock.patch.dict(os.environ, {"STORE_PASS": "secret", "KEY_ALIAS": "pilot"}),
                mock.patch.object(verify_pilot_keystore.subprocess, "run", return_value=completed),
                self.assertRaises(verify_pilot_keystore.VerificationError),
            ):
                verify_pilot_keystore.verify(
                    keystore, channel, "STORE_PASS", "KEY_ALIAS", Path("keytool")
                )


if __name__ == "__main__":
    unittest.main()
