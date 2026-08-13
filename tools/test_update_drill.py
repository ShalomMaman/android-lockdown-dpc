#!/usr/bin/env python3

import base64
import contextlib
import hashlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import publish_update
import update_drill


PACKAGE = "com.example.lockdowndpc"
OTHER_PACKAGE = "com.attacker.app"
APK_URL = "https://example.test/releases/download/v0.6.0/device-guard.apk"
SIGNER = "ab" * 32
OTHER_SIGNER = "cd" * 32
NOW = 1_800_000_000
VALID_FOR_SECONDS = 30 * 24 * 60 * 60

HAS_OPENSSL = shutil.which("openssl") is not None


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


@unittest.skipUnless(HAS_OPENSSL, "openssl is required to generate throwaway drill keys")
class UpdateDrillTest(unittest.TestCase):
    """Every key here is generated inside the test's temporary directory and discarded."""

    def setUp(self) -> None:
        self._directory = tempfile.TemporaryDirectory(prefix="device-guard-drill-test-")
        self.addCleanup(self._directory.cleanup)
        self.root = Path(self._directory.name).resolve()
        self.openssl = Path(shutil.which("openssl")).resolve()

        self.private_key = self.root / "throwaway-metadata-key.pem"
        self.public_key = self.root / "throwaway-metadata-key.pub"
        subprocess.run(
            [
                str(self.openssl), "genpkey", "-algorithm", "EC",
                "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(self.private_key),
            ],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [str(self.openssl), "pkey", "-in", str(self.private_key), "-pubout",
             "-out", str(self.public_key)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        public_der = subprocess.run(
            [str(self.openssl), "pkey", "-in", str(self.private_key), "-pubout", "-outform", "DER"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        ).stdout
        self.metadata_key_sha256 = hashlib.sha256(public_der).hexdigest()

        self.from_apk = self.root / "installed.apk"
        self.to_apk = self.root / "candidate.apk"
        self.from_apk.write_bytes(b"installed-apk-placeholder")
        self.to_apk.write_bytes(b"candidate-apk-placeholder")
        self.to_apk_sha256, self.to_apk_size = update_drill.sha256_and_size(self.to_apk)

        self.identity = {
            str(self.from_apk): (PACKAGE, 10, "0.5.1"),
            str(self.to_apk): (PACKAGE, 11, "0.6.0"),
        }
        self.signers = {str(self.from_apk): SIGNER, str(self.to_apk): SIGNER}
        self.available_tools = {"aapt2", "apksigner", "openssl"}

    # -- helpers ---------------------------------------------------------- #

    def _sign(self, payload: bytes) -> bytes:
        return subprocess.run(
            [str(self.openssl), "dgst", "-sha256", "-sign", str(self.private_key)],
            check=True, input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        ).stdout

    def _write_envelope(self, **overrides) -> Path:
        fields = {
            "package_name": PACKAGE,
            "version_code": 11,
            "version_name": "0.6.0",
            "apk_url": APK_URL,
            "apk_sha256": self.to_apk_sha256,
            "apk_size": self.to_apk_size,
            "issued_at": NOW - 60,
            "expires_at": NOW + VALID_FOR_SECONDS,
        }
        corrupt_signature = overrides.pop("corrupt_signature", False)
        fields.update(overrides)
        payload = publish_update.canonical_payload(
            fields["package_name"], fields["version_code"], fields["version_name"],
            fields["apk_url"], fields["apk_sha256"], fields["apk_size"],
            fields["issued_at"], fields["expires_at"],
        )
        signature = bytearray(self._sign(payload))
        if corrupt_signature:
            signature[-1] ^= 0xFF
        envelope = self.root / "latest.json"
        envelope.write_text(
            json.dumps(
                {"payload": _base64url(payload), "signature": _base64url(bytes(signature))},
                separators=(",", ":"), sort_keys=True,
            ) + "\n",
            encoding="utf-8",
        )
        return envelope

    def _locate_tool(self, name, explicit):
        if name not in self.available_tools:
            return None
        return self.openssl if name == "openssl" else Path(f"/mock/{name}")

    def _run(self, envelope: Path, extra=()) -> tuple[int, str, dict]:
        record_path = self.root / "drill-record.json"
        argv = [
            "--envelope", str(envelope),
            "--metadata-public-key", str(self.public_key),
            "--expected-metadata-key-sha256", self.metadata_key_sha256,
            "--from-apk", str(self.from_apk),
            "--to-apk", str(self.to_apk),
            "--expected-package", PACKAGE,
            "--expected-signer-sha256", SIGNER,
            "--expected-apk-url", APK_URL,
            "--now-epoch-seconds", str(NOW),
            "--record", str(record_path),
            "--force",
            *extra,
        ]
        stdout = io.StringIO()
        with (
            mock.patch.object(update_drill, "locate_tool", side_effect=self._locate_tool),
            mock.patch.object(
                update_drill.publish_update, "read_apk_identity",
                side_effect=lambda apk, aapt2: self.identity[str(apk)],
            ),
            mock.patch.object(
                update_drill.verify_pilot_apk, "verify_apk_has_single_signer",
                side_effect=lambda apk, apksigner: self.signers[str(apk)],
            ),
            contextlib.redirect_stdout(stdout),
        ):
            exit_code = update_drill.main(argv)
        return exit_code, stdout.getvalue(), json.loads(record_path.read_text(encoding="utf-8"))

    def _status(self, record: dict, identifier: str) -> str:
        for check in record["checks"]:
            if check["id"] == identifier:
                return check["status"]
        self.fail(f"the drill record does not contain the check {identifier}")

    # -- tests ------------------------------------------------------------ #

    def test_matching_pair_and_envelope_pass_every_offline_check(self) -> None:
        exit_code, summary, record = self._run(self._write_envelope())

        self.assertEqual(0, exit_code, msg=summary)
        self.assertEqual("pass", record["verdict"])
        self.assertEqual(0, record["counts"]["failed"])
        self.assertEqual(0, record["counts"]["skipped"])
        self.assertFalse(record["unrecoverable"])
        self.assertEqual("not-performed", record["onDeviceHalf"])
        self.assertEqual("offline-half-only", record["scope"])
        for identifier in (
            "envelope/signature",
            "envelope/apk-digest",
            "envelope/apk-size",
            "envelope/apk-url",
            "envelope/validity-window",
            "envelope/advances-installed-version",
            "envelope/not-replayed",
            "metadata-key/fingerprint",
            "metadata-key/curve",
            "pair/application-id",
            "pair/version-code-increase",
            "pair/signing-certificate-identity",
            "pair/approved-signing-certificate",
        ):
            self.assertEqual("pass", self._status(record, identifier), msg=identifier)
        self.assertIn("VERDICT: PASS", summary)
        self.assertIn("on-device half", summary)

    def test_refuses_a_downgrade(self) -> None:
        self.identity[str(self.to_apk)] = (PACKAGE, 9, "0.4.9")
        envelope = self._write_envelope(version_code=9, version_name="0.4.9")

        exit_code, summary, record = self._run(envelope)

        self.assertEqual(2, exit_code)
        self.assertEqual("fail", record["verdict"])
        self.assertEqual("fail", self._status(record, "pair/version-code-increase"))
        self.assertEqual("fail", self._status(record, "envelope/advances-installed-version"))
        self.assertIn("VERDICT: FAIL", summary)

    def test_refuses_a_replayed_older_envelope(self) -> None:
        exit_code, summary, record = self._run(
            self._write_envelope(),
            extra=["--highest-authorized-version-code", "12"],
        )

        self.assertEqual(2, exit_code)
        self.assertEqual("fail", self._status(record, "envelope/not-replayed"))
        self.assertEqual("pass", self._status(record, "envelope/advances-installed-version"))
        self.assertIn("replay floor 12", summary)

    def test_signer_change_is_an_unrecoverable_failure(self) -> None:
        self.signers[str(self.to_apk)] = OTHER_SIGNER

        exit_code, summary, record = self._run(self._write_envelope())

        self.assertEqual(2, exit_code)
        self.assertTrue(record["unrecoverable"])
        self.assertEqual("fail", self._status(record, "pair/signing-certificate-identity"))
        self.assertEqual("fail", self._status(record, "pair/approved-signing-certificate"))
        self.assertIn("UNRECOVERABLE FAILURE", summary)
        self.assertIn("pair/signing-certificate-identity", summary)

    def test_application_id_change_is_an_unrecoverable_failure(self) -> None:
        self.identity[str(self.to_apk)] = (OTHER_PACKAGE, 11, "0.6.0")

        exit_code, _, record = self._run(self._write_envelope())

        self.assertEqual(2, exit_code)
        self.assertTrue(record["unrecoverable"])
        self.assertEqual("fail", self._status(record, "pair/application-id"))
        self.assertEqual("fail", self._status(record, "pair/expected-application-id"))

    def test_refuses_an_envelope_naming_another_package(self) -> None:
        exit_code, _, record = self._run(self._write_envelope(package_name=OTHER_PACKAGE))

        self.assertEqual(2, exit_code)
        self.assertEqual("fail", self._status(record, "envelope/package-identity"))
        self.assertEqual("pass", self._status(record, "envelope/signature"))

    def test_refuses_an_envelope_that_does_not_describe_the_apk_it_points_at(self) -> None:
        exit_code, _, record = self._run(
            self._write_envelope(apk_sha256="ff" * 32, apk_size=self.to_apk_size + 1)
        )

        self.assertEqual(2, exit_code)
        self.assertEqual("fail", self._status(record, "envelope/apk-digest"))
        self.assertEqual("fail", self._status(record, "envelope/apk-size"))

    def test_refuses_a_corrupted_signature(self) -> None:
        exit_code, summary, record = self._run(self._write_envelope(corrupt_signature=True))

        self.assertEqual(2, exit_code)
        self.assertEqual("fail", self._status(record, "envelope/signature"))
        self.assertIn("VERDICT: FAIL", summary)

    def test_refuses_an_unapproved_metadata_key(self) -> None:
        other_key = self.root / "unapproved.pem"
        subprocess.run(
            [str(self.openssl), "genpkey", "-algorithm", "EC",
             "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(other_key)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        other_public_der = subprocess.run(
            [str(self.openssl), "pkey", "-in", str(other_key), "-pubout", "-outform", "DER"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        ).stdout
        self.metadata_key_sha256 = hashlib.sha256(other_public_der).hexdigest()

        exit_code, _, record = self._run(self._write_envelope())

        self.assertEqual(2, exit_code)
        self.assertEqual("fail", self._status(record, "metadata-key/fingerprint"))

    def test_refuses_a_plain_http_apk_url(self) -> None:
        insecure = "http://example.test/releases/download/v0.6.0/device-guard.apk"

        exit_code, _, record = self._run(self._write_envelope(apk_url=insecure))

        self.assertEqual(2, exit_code)
        self.assertEqual("fail", self._status(record, "envelope/apk-url"))

    def test_an_insecure_expected_url_stops_the_drill_before_any_check(self) -> None:
        argv = [
            "--envelope", str(self._write_envelope()),
            "--metadata-public-key", str(self.public_key),
            "--expected-metadata-key-sha256", self.metadata_key_sha256,
            "--expected-apk-url", "http://example.test/app.apk",
        ]
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            exit_code = update_drill.main(argv)

        self.assertEqual(update_drill.USAGE_EXIT_CODE, exit_code)
        self.assertIn("--expected-apk-url", stderr.getvalue())

    def test_refuses_an_expired_envelope(self) -> None:
        exit_code, _, record = self._run(self._write_envelope(expires_at=NOW - 1))

        self.assertEqual(2, exit_code)
        self.assertEqual("fail", self._status(record, "envelope/validity-window"))

    def test_refuses_a_structurally_broken_envelope_without_claiming_the_rest(self) -> None:
        envelope = self.root / "latest.json"
        envelope.write_text('{"payload":"not base64!","signature":"also bad"}\n', encoding="utf-8")

        exit_code, summary, record = self._run(envelope)

        self.assertEqual(2, exit_code)
        self.assertEqual("fail", self._status(record, "envelope/structure"))
        for identifier, _ in update_drill.ENVELOPE_CHECKS:
            self.assertEqual("skipped", self._status(record, identifier), msg=identifier)
        self.assertNotIn("PASS  envelope/", summary)

    def test_checks_that_cannot_run_are_reported_as_skipped_and_never_as_pass(self) -> None:
        self.available_tools = {"aapt2", "apksigner"}

        exit_code, summary, record = self._run(self._write_envelope())

        self.assertEqual(1, exit_code)
        self.assertEqual("incomplete", record["verdict"])
        self.assertEqual(0, record["counts"]["failed"])
        self.assertEqual("skipped", self._status(record, "envelope/signature"))
        self.assertEqual("skipped", self._status(record, "metadata-key/curve"))
        self.assertEqual("unavailable", record["environment"]["openssl"])
        self.assertIn("SKIP  envelope/signature", summary)
        self.assertNotIn("PASS  envelope/signature", summary)
        self.assertNotIn("PASS  metadata-key/curve", summary)
        self.assertIn("VERDICT: INCOMPLETE", summary)
        self.assertNotIn("VERDICT: PASS", summary)

    def test_missing_android_tools_do_not_fabricate_pair_results(self) -> None:
        self.available_tools = {"openssl"}

        exit_code, summary, record = self._run(self._write_envelope())

        self.assertEqual(1, exit_code)
        self.assertEqual("incomplete", record["verdict"])
        for identifier in (
            "from/apk-inspectable",
            "pair/application-id",
            "pair/version-code-increase",
            "pair/signing-certificate-identity",
            "envelope/version-binding",
        ):
            self.assertEqual("skipped", self._status(record, identifier), msg=identifier)
        self.assertEqual("pass", self._status(record, "envelope/signature"))
        self.assertEqual("pass", self._status(record, "envelope/apk-digest"))
        self.assertNotIn("PASS  pair/", summary)

    def test_declared_metadata_that_contradicts_the_apk_is_a_failure(self) -> None:
        exit_code, _, record = self._run(
            self._write_envelope(),
            extra=["--to-version-code", "99", "--to-signer-sha256", OTHER_SIGNER],
        )

        self.assertEqual(2, exit_code)
        self.assertEqual("fail", self._status(record, "to/declared-metadata-agreement"))

    def test_generated_key_material_never_reaches_the_repository(self) -> None:
        self._run(self._write_envelope())

        tools_directory = Path(__file__).resolve().parent
        for pattern in ("*.pem", "*.pub", "*.apk", "drill-record.json"):
            self.assertEqual([], sorted(tools_directory.glob(pattern)), msg=pattern)

    def test_an_unexecutable_explicit_binary_is_an_input_error(self) -> None:
        with self.assertRaises(update_drill.DrillError):
            update_drill.locate_tool("openssl", self.root / "missing-openssl")


class UpdateDrillPureLogicTest(unittest.TestCase):
    def test_clean_https_url_problem_matches_the_client_rules(self) -> None:
        rejected = {
            "http://example.test/app.apk": "not HTTPS",
            "https://user@example.test/app.apk": "credentials",
            "https://example.test/app.apk#fragment": "fragment",
            "https:///app.apk": "no host",
        }
        for value, expected in rejected.items():
            with self.subTest(value=value):
                problem = update_drill.clean_https_url_problem(value)
                self.assertIsNotNone(problem)
                self.assertIn(expected, problem)
        self.assertIsNone(update_drill.clean_https_url_problem(APK_URL))

    def test_verdict_is_incomplete_when_any_check_is_skipped(self) -> None:
        recorder = update_drill.DrillRecorder()
        recorder.passed("a", "first", "ok")
        self.assertEqual("pass", recorder.verdict())
        recorder.skipped("b", "second", "openssl is not available in this environment")
        self.assertEqual("incomplete", recorder.verdict())
        recorder.failed("c", "third", "wrong", unrecoverable=True)
        self.assertEqual("fail", recorder.verdict())
        self.assertEqual(1, len(recorder.unrecoverable_failures()))

    def test_a_skipped_check_is_never_marked_unrecoverable(self) -> None:
        recorder = update_drill.DrillRecorder()
        recorder.record("a", "first", update_drill.STATUS_SKIPPED, "reason", unrecoverable=True)
        self.assertEqual([], recorder.unrecoverable_failures())


if __name__ == "__main__":
    unittest.main()
