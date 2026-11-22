"""CLI round trips against the public v1 contract using throwaway PEM keys."""

import base64
import hashlib
import json
import os
import secrets
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import android_attestation as attestation
import fleet_admin
from test_remote_contract import (
    DOCS,
    KEYS,
    PROTOCOL,
    b64url,
    canonical,
    decode,
    envelope_error,
    hash_hex,
    parse_wire,
    payload_error,
    signature_valid,
    vectors,
)

TOOL = Path(fleet_admin.__file__)
PACKAGE = "test.fleet.app"
SIGNER_DIGEST = hashlib.sha256(b"synthetic APK certificate").digest()


def openssl(*arguments, data=b"", env=None):
    return subprocess.run(["openssl", *map(str, arguments)], input=data, env=env,
                          capture_output=True, check=True).stdout


def der(tag, value):
    size = len(value)
    length = bytes([size]) if size < 128 else bytes([0x81, size])
    return tag + length + value


def sequence(*fields):
    return der(b"\x30", b"".join(fields))


def octets(value):
    return der(b"\x04", value)


def integer(value, tag=b"\x02"):
    return der(tag, bytes([value]))


def extension(challenge, *, locked=True, security=1, boot_state=0, signer=SIGNER_DIGEST):
    packages = der(b"\x31", sequence(octets(PACKAGE.encode()), integer(1)))
    app_id = sequence(packages, der(b"\x31", octets(signer)))
    software = sequence(der(b"\xbf\x85\x45", octets(app_id)))  # Tag 709.
    boot = sequence(octets(b"boot-key"), der(b"\x01", b"\xff" if locked else b"\x00"),
                    integer(boot_state, b"\x0a"), octets(b"boot-hash"))
    hardware = sequence(der(b"\xbf\x85\x40", boot), der(b"\xbf\x85\x49", octets(b"test-serial")))
    return sequence(integer(4), integer(security, b"\x0a"), integer(4), integer(security, b"\x0a"),
                    octets(challenge), octets(b""), software, hardware)


class FleetAdminTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.output = self.directory / "output"
        self.keys = self.directory / "keys"
        self.keys.mkdir()
        self.passphrase = secrets.token_urlsafe(32)
        self.env = {**os.environ, "TEST_FLEET_PASSPHRASE": self.passphrase}
        self.root_key = self.make_key("root", encrypted=True)
        self.policy_key = self.make_key("policy")
        self.server_key = self.make_key("server")
        self.device_key = self.make_key("device")
        self.keyset_file = self.output / "keyset.json"

    def make_key(self, label, *, encrypted=False):
        private = self.keys / (label + ".pem")
        public = self.directory / (label + ".pub")
        args = ["-aes-256-cbc", "-pass", "env:TEST_FLEET_PASSPHRASE"] if encrypted else []
        openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                *args, "-out", private, env=self.env)
        passin = ["-passin", "env:TEST_FLEET_PASSPHRASE"] if encrypted else []
        openssl("pkey", "-in", private, *passin, "-pubout", "-out", public, env=self.env)
        spki = openssl("pkey", "-pubin", "-in", public, "-outform", "DER")
        return private, public, spki

    def run_cli(self, *args, status=0, env=None):
        result = subprocess.run([sys.executable, str(TOOL), *map(str, args)], text=True,
                                capture_output=True, check=False, env=self.env if env is None else env)
        self.assertNotIn(self.passphrase, result.stdout + result.stderr)
        self.assertNotIn("PRIVATE KEY-----", result.stdout + result.stderr)
        self.assertEqual(result.returncode, status, result.stderr)
        return result

    def write_json(self, name, value):
        path = self.directory / name
        path.write_bytes(canonical(value))
        return path

    def signing_args(self, key, output, version=None):
        args = ["--fleet-id", "test-fleet", "--private-key", key[0], "--output", output]
        if key is self.root_key:
            args += ["--key-passphrase-env", "TEST_FLEET_PASSPHRASE"]
        if version is not None:
            args += ["--keyset", self.keyset_file, "--root-public-key", self.root_key[1],
                     "--key-set-version", "1", "--version", version]
        return args

    def keyset_args(self, output=None, policy_public=None):
        return [*self.signing_args(self.root_key, output or self.keyset_file), "--key-set-version", "1",
                "--server-url", "https://127.0.0.1/fleet", "--server-public-key", self.server_key[1],
                "--policy-public-key", policy_public or self.policy_key[1]]

    def assert_envelope(self, filename, signer):
        raw = filename.read_bytes()
        self.assertIsNone(envelope_error(raw))
        envelope = parse_wire(raw)
        spki = signer[2]
        payload, signature = decode(envelope["payload"]), decode(envelope["signature"])
        self.assertEqual(envelope["keyId"], b64url(hashlib.sha256(spki).digest()))
        self.assertTrue(signature_valid(b64url(spki), payload, signature))
        document = parse_wire(payload)
        self.assertEqual(payload, canonical(document))
        self.assertIsNone(payload_error(document))
        return document

    def test_keyset_uses_external_encrypted_key_and_keeps_it_out_of_outputs(self):
        before = self.root_key[0].read_bytes()
        successor = self.make_key("successor")
        self.assertTrue(self.run_cli("--help").stdout.startswith("usage:"))
        error = self.run_cli("keyset", *self.keyset_args(), status=2,
                             env={**self.env, "TEST_FLEET_PASSPHRASE": secrets.token_urlsafe(32)})
        self.assertIn("passphrase variable", error.stderr)
        self.assertFalse(self.output.exists())
        self.assertIn("Root fingerprint", self.run_cli(
            "keyset", *self.keyset_args(), "--successor-root-public-key", successor[1],
        ).stdout)
        document = self.assert_envelope(self.keyset_file, self.root_key)
        self.assertEqual(document["fleetPolicyKeys"], [b64url(self.policy_key[2])])
        self.assertEqual(document["serverKey"], b64url(self.server_key[2]))
        self.assertEqual(document["successorRoot"], b64url(successor[2]))
        self.assertEqual(list(self.output.iterdir()), [self.keyset_file])
        self.assertNotIn(before, self.keyset_file.read_bytes())
        self.assertNotIn(self.passphrase.encode(), self.keyset_file.read_bytes())
        self.run_cli("keyset", *self.keyset_args(self.root_key[0]), "--force", status=2)
        self.assertEqual(self.root_key[0].read_bytes(), before)

    def test_keyset_rejects_wrong_curve_key_roles_and_fixture_keys(self):
        policy = self.directory / "fixture.pub"
        policy.write_bytes(b"-----BEGIN PUBLIC KEY-----\n"
                           + base64.b64encode(decode(KEYS["policy"]["spki"]))
                           + b"\n-----END PUBLIC KEY-----\n")
        failure = self.run_cli("keyset", *self.keyset_args(policy_public=policy), status=2)
        self.assertIn("fixture keys", failure.stderr)
        failure = self.run_cli("keyset", *self.keyset_args(policy_public=self.server_key[1]), status=2)
        self.assertIn("must be distinct", failure.stderr)
        wrong_curve = self.keys / "wrong.pem"
        openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384", "-out", wrong_curve)
        args = self.keyset_args()
        args[args.index("--private-key") + 1] = wrong_curve
        self.assertIn("P-256", self.run_cli("keyset", *args, status=2).stderr)
        self.assertFalse(self.keyset_file.exists())

    def issue(self, command="tickets", *, identity_type="serial", identity="test-serial", **kwargs):
        devices = self.write_json("devices.json", [
            {"identityType": identity_type, "identity": identity, "firmwareFamily": "test-family"},
        ])
        bundle = self.directory / command
        result = self.run_cli(command, "--fleet-id", "test-fleet", "--devices", devices,
                              "--output", bundle, **kwargs)
        return bundle, result

    def test_ticket_and_bench_code_round_trip_without_logging_credentials(self):
        for command, hours in (("tickets", 72), ("bench-code", 1)):
            with self.subTest(command=command):
                bundle, result = self.issue(command)
                filename = "tickets.txt" if command == "tickets" else "bench-code.txt"
                code = (bundle / filename).read_text().strip()
                if command == "tickets":
                    raw = decode(code)
                    self.assertEqual(len(raw), 24)
                else:
                    self.assertRegex(code, r"^[A-Z2-7]{16}$")
                    raw = code.encode("ascii")
                self.assertNotIn(code, result.stdout + result.stderr)
                self.assertEqual(stat.S_IMODE(bundle.stat().st_mode), 0o700)
                for path in bundle.iterdir():
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                [inventory] = json.loads((bundle / "inventory.json").read_bytes())
                [server] = json.loads((bundle / "server.json").read_bytes())
                self.assertEqual(inventory["ticketSha256"], hash_hex(raw))
                self.assertEqual(server["ticketSha256"], hash_hex(raw))
                self.assertEqual(server["maxUses"], 1)
                self.assertEqual(server.get("maxAttempts"), 5 if command == "bench-code" else None)
                self.assertAlmostEqual(server["expiresAt"] - time.time(), hours * 3600, delta=5)
                self.assertNotIn("identity", server)
                self.assertNotIn(code, (bundle / "inventory.json").read_text())
        output = self.directory / "too-long"
        result = self.run_cli("tickets", "--fleet-id", "test-fleet", "--devices",
                              self.directory / "devices.json", "--valid-for-hours", 169,
                              "--output", output, status=2)
        self.assertIn("168 hours", result.stderr)
        self.assertFalse(output.exists())

    def make_attestation(self, *, expired_intermediate=False, **changes):
        root = self.directory / "attestation-root.pem"
        root_key = self.make_key("attestation-root")
        openssl("req", "-new", "-x509", "-key", root_key[0], "-days", 2,
                "-subj", "/CN=Synthetic root", "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", root)
        intermediate = self.directory / "intermediate.pem"
        intermediate_key = self.make_key("intermediate")
        request = self.directory / "intermediate.csr"
        config = self.directory / "intermediate.conf"
        config.write_text("basicConstraints=critical,CA:TRUE,pathlen:0\n"
                          "keyUsage=critical,keyCertSign,cRLSign\n")
        openssl("req", "-new", "-key", intermediate_key[0], "-subj", "/CN=Synthetic intermediate",
                "-out", request)
        if expired_intermediate:
            self.issue_expired_intermediate(root, root_key[0], request, config, intermediate)
        else:
            openssl("x509", "-req", "-in", request, "-CA", root, "-CAkey", root_key[0],
                    "-set_serial", "123", "-days", 2, "-extfile", config, "-out", intermediate)
        device = self.directory / "attested-device.pem"
        request = self.directory / "device.csr"
        config = self.directory / "device.conf"
        challenge = secrets.token_bytes(32)
        ext = extension(challenge, **changes).hex(":")
        config.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                          f"1.3.6.1.4.1.11129.2.1.17=DER:{ext}\n")
        openssl("req", "-new", "-key", self.device_key[0], "-subj", "/CN=Synthetic device", "-out", request)
        openssl("x509", "-req", "-in", request, "-CA", intermediate, "-CAkey", intermediate_key[0],
                "-set_serial", "42", "-days", 2, "-extfile", config, "-out", device)
        return root, [b64url(ssl.PEM_cert_to_DER_cert(cert.read_text()))
                      for cert in (device, intermediate)], challenge

    def issue_expired_intermediate(self, root, root_key, request, extensions, output):
        index = self.directory / "ca-index"
        index.touch()
        serial = self.directory / "ca-serial"
        serial.write_text("7B\n")
        config = self.directory / "ca.conf"
        config.write_text(
            f"[ca]\ndefault_ca = issuer\n[issuer]\ndatabase = {index}\n"
            f"new_certs_dir = {self.directory}\nserial = {serial}\n"
            "default_md = sha256\npolicy = subject_policy\n"
            "[subject_policy]\ncommonName = supplied\n"
        )
        openssl("ca", "-batch", "-notext", "-config", config, "-cert", root, "-keyfile", root_key,
                "-in", request, "-startdate", "200101000000Z", "-enddate", "210101000000Z",
                "-extfile", extensions, "-out", output)

    def enrolment(self, *, identity_type="serial", identity="test-serial", **changes):
        bundle, _ = self.issue(identity_type=identity_type, identity=identity)
        roots, chain, challenge = self.make_attestation(**changes)
        [inventory] = json.loads((bundle / "inventory.json").read_bytes())
        record = {"attestationChain": chain, "challenge": b64url(challenge),
                  "deviceId": b64url(hashlib.sha256(self.device_key[2]).digest()),
                  "facts": {"sdk": 33, "firmwareFamily": "test-family",
                            "enrollmentSpecificId": "test-enrolment-id"},
                  "fleetId": "test-fleet", "ticketSha256": inventory["ticketSha256"], "trusted": False}
        self.sign_record(record)
        revocations = self.write_json("revocations.json", {"entries": {}})
        args = ["--inventory", bundle / "inventory.json", "--attestation-roots", roots,
                "--revocation-list", revocations, "--expected-package", PACKAGE,
                "--expected-signer-sha256", SIGNER_DIGEST.hex()]
        return record, args

    def sign_record(self, record):
        transcript = canonical([
            "dg-enrol/1", record["challenge"], record["ticketSha256"],
            hash_hex(canonical(record["attestationChain"])), hash_hex(canonical(record["facts"])),
        ])
        record["transcriptSignature"] = b64url(openssl("dgst", "-sha256", "-sign",
                                                     self.device_key[0], data=transcript))

    def test_enrolment_checks_chain_revocations_challenge_signature_and_local_identity(self):
        record, trust = self.enrolment()
        path = self.write_json("record.json", record)
        args = ["verify-enrolment", "--fleet-id", "test-fleet", "--record", path, *trust]
        self.assertIn("verified", self.run_cli(*args).stdout)
        self.write_json("revocations.json", {"entries": {"007b": {"status": "SUSPENDED"}}})
        self.assertIn("revoked or suspended", self.run_cli(*args, status=2).stderr)
        self.write_json("revocations.json", {"entries": {}})
        self.write_json("record.json", {**record, "facts": {**record["facts"], "sdk": 34}, "trusted": True})
        self.assertIn("transcript signature", self.run_cli(*args, status=2).stderr)
        changed = {**record, "challenge": b64url(secrets.token_bytes(32))}
        self.sign_record(changed)
        self.write_json("record.json", changed)
        self.assertIn("challenge does not match", self.run_cli(*args, status=2).stderr)
        self.write_json("record.json", {**record, "ticketSha256": "0" * 64})
        self.assertIn("absent from", self.run_cli(*args, status=2).stderr)
        self.write_json("record.json", {**record, "deviceId": b64url(bytes(32))})
        self.assertIn("device ID does not match", self.run_cli(*args, status=2).stderr)
        self.write_json("record.json", {**record, "fleetId": "other-fleet"})
        self.assertIn("different fleet", self.run_cli(*args, status=2).stderr)
        self.write_json("record.json", record)
        inventory_path = self.directory / "tickets" / "inventory.json"
        [entry] = json.loads(inventory_path.read_bytes())
        self.write_json("tickets/inventory.json", [{**entry, "identity": "different-device"}])
        self.assertIn("identity does not match", self.run_cli(*args, status=2).stderr)
        self.write_json("tickets/inventory.json", [entry])
        foreign_root, _, _ = self.make_attestation()  # New certificate/key at the same local root path.
        self.assertEqual(foreign_root, trust[3])
        self.assertIn("does not validate", self.run_cli(*args, status=2).stderr)

    def test_enrolment_accepts_bench_recorded_enrollment_specific_id(self):
        record, trust = self.enrolment(identity_type="enrollmentSpecificId", identity="test-enrolment-id")
        path = self.write_json("record.json", record)
        self.run_cli("verify-enrolment", "--fleet-id", "test-fleet", "--record", path, *trust)

    def test_enrolment_accepts_expired_intermediate_unless_revoked(self):
        record, trust = self.enrolment(expired_intermediate=True)
        path = self.write_json("record.json", record)
        args = ["verify-enrolment", "--fleet-id", "test-fleet", "--record", path, *trust]
        self.assertIn("verified", self.run_cli(*args).stdout)
        self.write_json("revocations.json", {"entries": {"7b": {"status": "REVOKED"}}})
        self.assertIn("revoked or suspended", self.run_cli(*args, status=2).stderr)

    def test_enrolment_enforces_revocation_list_age(self):
        record, trust = self.enrolment()
        path = self.write_json("record.json", record)
        args = ["verify-enrolment", "--fleet-id", "test-fleet", "--record", path, *trust]
        revocations = self.directory / "revocations.json"
        stale = time.time() - 8 * 24 * 3600
        os.utime(revocations, (stale, stale))
        self.assertIn("older than 7 day(s)", self.run_cli(*args, status=2).stderr)
        self.assertIn("verified", self.run_cli(*args, "--revocation-max-age-days", 9).stdout)
        self.assertIn("must be positive", self.run_cli(*args, "--revocation-max-age-days", 0, status=2).stderr)
        future = time.time() + 3600
        os.utime(revocations, (future, future))
        self.assertIn("future modification time", self.run_cli(*args, status=2).stderr)

    def test_revocation_list_allows_up_to_five_minutes_of_clock_skew(self):
        revocations = self.write_json("revocations.json", {"entries": {"007b": {"status": "REVOKED"}}})
        now = int(time.time())
        with patch.object(fleet_admin.time, "time", return_value=now):
            os.utime(revocations, (now, now + 300))
            self.assertEqual(fleet_admin.load_revocations(revocations, 7), {"7b"})
            os.utime(revocations, (now, now + 301))
            with self.assertRaisesRegex(fleet_admin.FleetError, "future modification time"):
                fleet_admin.load_revocations(revocations, 7)

    def test_android_attestation_rejects_software_unlocked_unverified_or_wrong_signer(self):
        for changes, error in (({"locked": False}, "locked bootloader"),
                               ({"boot_state": 1}, "verified boot"),
                               ({"security": 0}, "hardware-backed"),
                               ({"signer": bytes(32)}, "signing certificate")):
            with self.subTest(changes=changes):
                root, chain, challenge = self.make_attestation(**changes)
                certificates = [attestation.certificate(decode(item)) for item in chain]
                attestation.verify_chain(certificates, attestation.root_certificates(root.read_text()), set())
                with self.assertRaisesRegex(attestation.AttestationError, error):
                    attestation.verify_android_fields(certificates, challenge, PACKAGE, SIGNER_DIGEST)

    def test_policy_guards_trust_diff_and_signature(self):
        self.run_cli("keyset", *self.keyset_args())
        record, trust = self.enrolment()
        enrolment = self.write_json("record.json", record)
        body = {"managementMode": "REMOTE", "protection": {"state": "ON"},
                "apps": {"mode": "BLOCK_SELECTED", "allowed": []},
                "systemControls": {"developer_options_and_adb": False, "app_stores_and_installers": True}}
        body_path = self.write_json("body.json", body)
        first = self.output / "policy-1.json"
        second = self.output / "policy-2.json"
        options = ["--body", body_path, "--device-id", record["deviceId"]]
        first_args = ["policy", *self.signing_args(self.policy_key, first, 1), *options]
        second_args = ["policy", *self.signing_args(self.policy_key, second, 2), *options,
                       "--previous", first, "--enrolment-record", enrolment, *trust]
        self.assertIn("untrusted device", self.run_cli(*first_args, status=2).stderr)
        self.assertFalse(first.exists())
        self.run_cli(*first_args, "--allow-untrusted")
        initial = self.assert_envelope(first, self.policy_key)
        self.assertIn("--allow-untrusted", initial["auditNote"])
        for controls in (None, {"app_stores_and_installers": False}):
            with self.subTest(system_controls=controls):
                inherited_body = {field: value for field, value in body.items() if field != "systemControls"}
                if controls is not None:
                    inherited_body["systemControls"] = controls
                self.write_json("body.json", inherited_body)
                error = self.run_cli(*second_args, status=2).stderr
                self.assertIn("ADB guard", error)
                self.assertIn("locally recorded self-update drill PASS", error)
        body["systemControls"] = {"developer_options_and_adb": True, "app_stores_and_installers": False}
        self.write_json("body.json", body)
        self.assertIn("ADB guard", self.run_cli(*second_args, status=2).stderr)
        drill = {"firmwareFamily": "test-family", "offline": {"tool": "tools/update_drill.py",
                 "scope": "offline-half-only", "verdict": "PASS"}}
        evidence = self.write_json("drill.json", [drill])
        self.assertIn("ADB guard", self.run_cli(*second_args, "--drill-evidence", evidence, status=2).stderr)
        drill.update(onDevice="PASS", onDeviceEvidence="synthetic steps 0–5")
        self.write_json("drill.json", [{**drill, "firmwareFamily": "another-family"}])
        self.assertIn("ADB guard", self.run_cli(*second_args, "--drill-evidence", evidence, status=2).stderr)
        self.write_json("drill.json", [drill])
        self.assertFalse(second.exists())
        result = self.run_cli(*second_args, "--drill-evidence", evidence)
        self.assertIn("GLOBAL INSTALL EXPOSURE", result.stdout)
        self.assertIn("app_stores_and_installers: true -> false", result.stdout)
        self.assertIn("developer_options_and_adb: false -> true", result.stdout)
        document = self.assert_envelope(second, self.policy_key)
        self.assertEqual(document["policy"], body)
        self.assertNotIn("auditNote", document)
        self.write_json("record.json", {**record, "trusted": True, "transcriptSignature": b64url(b"bad")})
        self.assertIn("untrusted device", self.run_cli(*second_args, "--force", status=2).stderr)
        self.assertIn("ADB guard", self.run_cli(*second_args, "--force", "--allow-untrusted",
                                               "--drill-evidence", evidence, status=2).stderr)
        self.write_json("body.json", {**body, "systemUpdates": True})
        result = self.run_cli(*second_args, "--force", status=2)
        self.assertIn("doc-field-unknown at /policy/systemUpdates", result.stderr)
        self.assertEqual(self.assert_envelope(second, self.policy_key), document)
        self.write_json("record.json", record)
        del body["systemControls"]["developer_options_and_adb"]
        self.write_json("body.json", body)
        self.run_cli(*second_args, "--force", "--drill-evidence", evidence)
        self.assertEqual(self.assert_envelope(second, self.policy_key)["policy"], body)

    def test_recovery_publishes_private_bundle_without_logging_code(self):
        self.run_cli("keyset", *self.keyset_args())
        output = self.output / "recovery"
        code_path = output / "recovery-code.txt"
        verifier_path = output / "recovery.json"
        device_id = b64url(hashlib.sha256(self.device_key[2]).digest())
        args = ["recovery", *self.signing_args(self.policy_key, output, 1), "--device-id", device_id]
        result = self.run_cli(*args)
        code_contents = code_path.read_text()
        code = code_contents.strip()
        self.assertRegex(code, r"^[A-Z2-7]{4}(?: [A-Z2-7]{4}){4}$")
        self.assertEqual(result.stdout, f"{code_path.resolve()}\n")
        self.assertEqual(result.stderr, "")
        self.assertNotIn(code, result.stdout + result.stderr)
        self.assertNotIn(code.replace(" ", ""), result.stdout + result.stderr)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        for path in (code_path, verifier_path):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        document = self.assert_envelope(verifier_path, self.policy_key)
        spec = PROTOCOL["recovery"]
        self.assertEqual(decode(document["verifier"]), hashlib.pbkdf2_hmac(
            "sha256", code.replace(" ", "").encode("ascii"), decode(document["salt"]),
            spec["iterations"], dklen=spec["derivedBytes"],
        ))
        self.assertNotIn(code.replace(" ", ""), canonical(document).decode())
        original_verifier = verifier_path.read_bytes()
        existing = self.run_cli(*args, status=2)
        self.assertEqual(existing.stdout, "")
        self.assertEqual(existing.stderr, "error: output already exists\n")
        self.assertEqual(code_path.read_text(), code_contents)
        self.assertEqual(verifier_path.read_bytes(), original_verifier)
        wrong_output = self.output / "wrong"
        wrong = ["recovery", *self.signing_args(self.server_key, wrong_output, 1), "--device-id", device_id]
        self.assertIn("not a fleet policy key", self.run_cli(*wrong, status=2).stderr)
        self.assertFalse(wrong_output.exists())

    def test_reanchor_matches_vector_shape_and_requires_current_root(self):
        reference = parse_wire(decode(vectors("re-anchor")["envelope"]["payload"]))
        device_id = b64url(hashlib.sha256(self.device_key[2]).digest())
        root_id = b64url(hashlib.sha256(self.root_key[2]).digest())
        output = self.output / "anchor.json"
        self.run_cli("keyset", *self.keyset_args())
        keyset_payload = decode(parse_wire(self.keyset_file.read_bytes())["payload"])
        # The hash must use the exact accepted bytes, even for noncanonical JSON.
        policy_payload = b"\n" + canonical({**DOCS["policy-6"], "fleetId": "test-fleet",
                                             "deviceIds": [device_id]}) + b"\n"
        policy_envelope = {
            "format": "dg-signed/1",
            "keyId": b64url(hashlib.sha256(self.policy_key[2]).digest()),
            "payload": b64url(policy_payload),
            "signature": b64url(openssl("dgst", "-sha256", "-sign", self.policy_key[0], data=policy_payload)),
        }
        policy = self.write_json("issued-policy.json", policy_envelope)
        args = ["reanchor", *self.signing_args(self.root_key, output),
                "--device-id", device_id, "--nonce", reference["nonce"],
                "--root-fingerprint", root_id,
                "--keyset-floor", 1, "--policy-floor", 6, "--recovery-floor", 2, "--command-floor", 0]
        self.run_cli(*args, "--keyset-envelope", self.keyset_file, "--policy-envelope", policy)
        document = self.assert_envelope(output, self.root_key)
        self.assertEqual(set(reference), set(document))
        self.assertEqual(document["floors"], {"keyset": 1, "fleet-policy": 6, "recovery": 2, "command": 0})
        self.assertEqual(document["floorPayloadSha256"], {
            "keyset": hash_hex(keyset_payload), "fleet-policy": hash_hex(policy_payload),
        })
        self.assertEqual(document["deviceId"], device_id)
        self.assertEqual(document["nonce"], reference["nonce"])
        self.assertEqual(document["rootFingerprint"], root_id)
        self.assertEqual(document["rootSpki"], b64url(self.root_key[2]))
        self.assertIn("--policy-envelope requires --keyset-envelope", self.run_cli(
            *args, "--force", "--policy-envelope", policy, status=2,
        ).stderr)
        keyset_args = ["--keyset-envelope", self.keyset_file]
        self.assertIn("expected a fleet-policy document", self.run_cli(
            *args, "--force", *keyset_args, "--policy-envelope", self.keyset_file, status=2,
        ).stderr)
        self.assertIn("must match the re-anchor fleet and floor version", self.run_cli(
            *args, "--force", *keyset_args, "--policy-floor", 7, "--policy-envelope", policy, status=2,
        ).stderr)

        keyset_envelope = parse_wire(self.keyset_file.read_bytes())
        wrong_signature = b64url(openssl("dgst", "-sha256", "-sign", self.server_key[0], data=keyset_payload))
        wrong_keyset = self.write_json("wrong-keyset.json", {**keyset_envelope, "signature": wrong_signature})
        self.assertIn("keyset envelope signature is invalid", self.run_cli(
            *args, "--force", "--keyset-envelope", wrong_keyset, status=2,
        ).stderr)
        wrong_signature = b64url(openssl("dgst", "-sha256", "-sign", self.server_key[0], data=policy_payload))
        wrong_policy = self.write_json("wrong-policy.json", {**policy_envelope, "signature": wrong_signature})
        self.assertIn("fleet-policy envelope signature is invalid", self.run_cli(
            *args, "--force", *keyset_args, "--policy-envelope", wrong_policy, status=2,
        ).stderr)
        wrong_policy = self.write_json("wrong-policy.json", {
            **policy_envelope, "signature": wrong_signature, "keyId": fleet_admin.key_id(self.server_key[2]),
        })
        self.assertIn("fleet-policy envelope signer is not trusted", self.run_cli(
            *args, "--force", *keyset_args, "--policy-envelope", wrong_policy, status=2,
        ).stderr)
        self.assertEqual(self.assert_envelope(output, self.root_key), document)
        args[args.index("--root-fingerprint") + 1] = device_id
        self.assertIn("current root fingerprint", self.run_cli(*args, "--force", status=2).stderr)


if __name__ == "__main__":
    unittest.main()
