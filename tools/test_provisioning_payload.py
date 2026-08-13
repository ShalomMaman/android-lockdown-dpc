#!/usr/bin/env python3

import argparse
import base64
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import provisioning_payload


COMPONENT = "il.co.shalommaman.deviceguard/com.example.lockdowndpc.admin.LockdownAdminReceiver"
SIGNER_HEX = "25507e47f49cbacc8cad66ee4967b2bae3f22bbd26fbb4587e9326626669014b"
DOWNLOAD_LOCATION = "https://updates.example.test/device-guard.apk"


def _namespace(**overrides: object) -> argparse.Namespace:
    defaults = {
        "admin_component": COMPONENT,
        "download_location": DOWNLOAD_LOCATION,
        "signer_sha256": SIGNER_HEX,
        "apk": None,
        "skip_apk_verification": True,
        "wifi_ssid": None,
        "wifi_security_type": None,
        "wifi_password_env": None,
        "wifi_hidden": False,
        "locale": None,
        "time_zone": None,
        "admin_extra": [],
        "leave_system_apps_enabled": "true",
        "skip_encryption": False,
        "output": None,
        "aapt2": None,
        "apksigner": None,
        "force": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class ProvisioningPayloadTest(unittest.TestCase):
    def test_builds_a_payload_verified_against_the_apk(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk = root / "device-guard.apk"
            apk.write_bytes(b"signed-apk-placeholder")
            output = root / "provisioning-payload.json"
            args = _namespace(
                apk=apk,
                skip_apk_verification=False,
                output=output,
                locale="iw_IL",
                time_zone="Asia/Jerusalem",
                admin_extra=["enrolment_site=north-branch"],
            )

            with (
                mock.patch.object(
                    provisioning_payload.publish_update,
                    "find_android_build_tool",
                    side_effect=lambda name, explicit: Path(f"/mock/{name}"),
                ),
                mock.patch.object(
                    provisioning_payload.publish_update,
                    "read_apk_identity",
                    return_value=("il.co.shalommaman.deviceguard", 11, "0.5.2"),
                ),
                mock.patch.object(
                    provisioning_payload.publish_update, "verify_apk_signer"
                ) as signer_check,
            ):
                summary = provisioning_payload.create(args)

            signer_check.assert_called_once()
            payload = json.loads(output.read_bytes())
            self.assertEqual(
                COMPONENT,
                payload["android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME"],
            )
            self.assertEqual(
                DOWNLOAD_LOCATION,
                payload[
                    "android.app.extra.PROVISIONING_DEVICE_ADMIN_PACKAGE_DOWNLOAD_LOCATION"
                ],
            )
            self.assertTrue(
                payload["android.app.extra.PROVISIONING_LEAVE_ALL_SYSTEM_APPS_ENABLED"]
            )
            self.assertFalse(payload["android.app.extra.PROVISIONING_SKIP_ENCRYPTION"])
            self.assertEqual("Asia/Jerusalem", payload["android.app.extra.PROVISIONING_TIME_ZONE"])
            self.assertEqual("iw_IL", payload["android.app.extra.PROVISIONING_LOCALE"])
            self.assertEqual(
                {"enrolment_site": "north-branch"},
                payload["android.app.extra.PROVISIONING_ADMIN_EXTRAS_BUNDLE"],
            )
            self.assertEqual("verified", summary["apkVerification"])
            self.assertEqual(11, summary["versionCode"])
            self.assertFalse(summary["wifiPasswordEmbedded"])

    def test_checksum_is_the_web_safe_base64_of_the_certificate_digest(self) -> None:
        _, checksum = provisioning_payload.normalize_signature_digest(SIGNER_HEX)
        decoded = base64.urlsafe_b64decode(checksum + "=" * (-len(checksum) % 4))

        self.assertEqual(bytes.fromhex(SIGNER_HEX), decoded)
        self.assertNotIn("=", checksum)
        self.assertNotIn("+", checksum)
        self.assertNotIn("/", checksum)

    def test_digest_normalisation_accepts_hex_colons_and_base64_forms(self) -> None:
        raw = bytes.fromhex(SIGNER_HEX)
        colonized = ":".join(SIGNER_HEX[index : index + 2] for index in range(0, 64, 2))
        equivalent = (
            SIGNER_HEX.upper(),
            colonized,
            base64.b64encode(raw).decode("ascii"),
            base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii"),
        )
        for value in equivalent:
            with self.subTest(value=value):
                self.assertEqual(
                    provisioning_payload.normalize_signature_digest(SIGNER_HEX),
                    provisioning_payload.normalize_signature_digest(value),
                )

    def test_digest_normalisation_refuses_values_that_are_not_sha256(self) -> None:
        invalid = (
            "",
            "not-a-digest",
            SIGNER_HEX[:-1],
            SIGNER_HEX + "ab",
            base64.b64encode(b"\x01" * 20).decode("ascii"),
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(provisioning_payload.ProvisioningError):
                provisioning_payload.normalize_signature_digest(value)

    def test_refuses_a_download_location_that_is_not_clean_https(self) -> None:
        invalid = (
            "http://updates.example.test/device-guard.apk",
            "ftp://updates.example.test/device-guard.apk",
            "https://operator:secret@updates.example.test/device-guard.apk",
            "https://updates.example.test/device-guard.apk#fragment",
            "https:///device-guard.apk",
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(provisioning_payload.ProvisioningError):
                provisioning_payload.validate_download_location(value)

    def test_refuses_an_empty_or_malformed_admin_component(self) -> None:
        invalid = (
            "",
            "   ",
            "il.co.shalommaman.deviceguard",
            "il.co.shalommaman.deviceguard/",
            "/com.example.lockdowndpc.admin.LockdownAdminReceiver",
            "il.co.shalommaman.deviceguard/a/b",
            "deviceguard/com.example.lockdowndpc.admin.LockdownAdminReceiver",
            "il.co.shalommaman.deviceguard/.admin.LockdownAdminReceiver",
            "il.co.shalommaman.deviceguard/com.example.lockdowndpc.admin.Lockdown Receiver",
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(provisioning_payload.ProvisioningError):
                provisioning_payload.validate_admin_component(value)

        self.assertEqual(COMPONENT, provisioning_payload.validate_admin_component(f" {COMPONENT} "))

    def test_refuses_a_payload_whose_apk_package_differs_from_the_component(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk = root / "device-guard.apk"
            apk.write_bytes(b"apk")
            output = root / "payload.json"
            args = _namespace(apk=apk, skip_apk_verification=False, output=output)

            with (
                mock.patch.object(
                    provisioning_payload.publish_update,
                    "find_android_build_tool",
                    side_effect=lambda name, explicit: Path(f"/mock/{name}"),
                ),
                mock.patch.object(
                    provisioning_payload.publish_update,
                    "read_apk_identity",
                    return_value=("com.attacker.app", 11, "0.5.2"),
                ),
                mock.patch.object(provisioning_payload.publish_update, "verify_apk_signer"),
                self.assertRaises(provisioning_payload.ProvisioningError),
            ):
                provisioning_payload.create(args)

            self.assertFalse(output.exists())

    def test_missing_sdk_tools_refuse_the_payload_and_name_the_degraded_option(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk = root / "device-guard.apk"
            apk.write_bytes(b"apk")
            output = root / "payload.json"
            args = _namespace(apk=apk, skip_apk_verification=False, output=output)

            with (
                mock.patch.object(
                    provisioning_payload.publish_update,
                    "find_android_build_tool",
                    side_effect=provisioning_payload.publish_update.PublishError(
                        "apksigner was not found"
                    ),
                ),
                self.assertRaises(provisioning_payload.ProvisioningError) as raised,
            ):
                provisioning_payload.create(args)

            self.assertIn("--skip-apk-verification", str(raised.exception))
            self.assertFalse(output.exists())

    def test_requires_an_explicit_choice_between_verification_and_degradation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "payload.json"
            with self.assertRaises(provisioning_payload.ProvisioningError):
                provisioning_payload.create(
                    _namespace(apk=None, skip_apk_verification=False, output=output)
                )

            apk = Path(directory) / "device-guard.apk"
            apk.write_bytes(b"apk")
            with self.assertRaises(provisioning_payload.ProvisioningError):
                provisioning_payload.create(
                    _namespace(apk=apk, skip_apk_verification=True, output=output)
                )

            self.assertFalse(output.exists())

    def test_unverified_payload_is_recorded_as_unverified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "payload.json"
            summary = provisioning_payload.create(_namespace(output=output))

            self.assertEqual("skipped-by-operator", summary["apkVerification"])
            self.assertNotIn("versionCode", summary)

    def test_wifi_passphrase_is_read_only_from_the_named_environment_variable(self) -> None:
        secret = "provisioning-network-passphrase"
        with mock.patch.dict(os.environ, {"DEVICE_GUARD_WIFI_PASSWORD": secret}, clear=False):
            settings = provisioning_payload.build_wifi_settings(
                "DeviceGuard-Enrolment",
                "WPA",
                "DEVICE_GUARD_WIFI_PASSWORD",
                hidden=True,
            )

        self.assertEqual(secret, settings["android.app.extra.PROVISIONING_WIFI_PASSWORD"])
        self.assertTrue(settings["android.app.extra.PROVISIONING_WIFI_HIDDEN"])
        self.assertEqual("WPA", settings["android.app.extra.PROVISIONING_WIFI_SECURITY_TYPE"])

    def test_wifi_environment_handling_refuses_unusable_references(self) -> None:
        with self.assertRaises(provisioning_payload.ProvisioningError):
            provisioning_payload.build_wifi_settings("ssid", "WPA", "INVALID-NAME", hidden=False)
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(provisioning_payload.ProvisioningError):
                provisioning_payload.build_wifi_settings("ssid", "WPA", "ABSENT_VAR", hidden=False)
        with mock.patch.dict(os.environ, {"EMPTY_VAR": ""}, clear=False):
            with self.assertRaises(provisioning_payload.ProvisioningError):
                provisioning_payload.build_wifi_settings("ssid", "WPA", "EMPTY_VAR", hidden=False)
        with mock.patch.dict(os.environ, {"SHORT_VAR": "1234567"}, clear=False):
            with self.assertRaises(provisioning_payload.ProvisioningError) as raised:
                provisioning_payload.build_wifi_settings("ssid", "WPA", "SHORT_VAR", hidden=False)
        self.assertNotIn("1234567", str(raised.exception))

    def test_wifi_options_are_internally_consistent(self) -> None:
        with self.assertRaises(provisioning_payload.ProvisioningError):
            provisioning_payload.build_wifi_settings(None, None, "SOME_VAR", hidden=False)
        with self.assertRaises(provisioning_payload.ProvisioningError):
            provisioning_payload.build_wifi_settings("ssid", None, None, hidden=False)
        with self.assertRaises(provisioning_payload.ProvisioningError):
            provisioning_payload.build_wifi_settings("ssid", "WPA", None, hidden=False)
        with mock.patch.dict(os.environ, {"OPEN_VAR": "unused-value"}, clear=False):
            with self.assertRaises(provisioning_payload.ProvisioningError):
                provisioning_payload.build_wifi_settings("ssid", "NONE", "OPEN_VAR", hidden=False)
        with self.assertRaises(provisioning_payload.ProvisioningError):
            provisioning_payload.build_wifi_settings("x" * 33, "NONE", None, hidden=False)

        self.assertEqual({}, provisioning_payload.build_wifi_settings(None, None, None, False))

    def test_embedded_wifi_passphrase_restricts_the_output_file_mode(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict(os.environ, {"WIFI_PASSPHRASE": "correct-horse"}, clear=False),
        ):
            output = Path(directory) / "payload.json"
            summary = provisioning_payload.create(
                _namespace(
                    output=output,
                    wifi_ssid="DeviceGuard-Enrolment",
                    wifi_security_type="WPA",
                    wifi_password_env="WIFI_PASSPHRASE",
                )
            )

            self.assertTrue(summary["wifiPasswordEmbedded"])
            self.assertNotIn("correct-horse", json.dumps(summary))
            self.assertEqual(0o600, stat.S_IMODE(output.stat().st_mode))
            self.assertIn("correct-horse", output.read_text(encoding="ascii"))

    def test_admin_extras_refuse_credential_shaped_keys_and_malformed_entries(self) -> None:
        invalid = (
            ["no_equals_sign"],
            ["bad key=value"],
            ["=value"],
            ["site=north", "site=south"],
            ["admin_pin=1234"],
            ["recoveryCode=abcd"],
            ["kiosk_password=hunter2"],
            [f"note={'x' * 513}"],
        )
        for entry in invalid:
            with self.subTest(entry=entry), self.assertRaises(provisioning_payload.ProvisioningError):
                provisioning_payload.parse_admin_extras(entry)

        self.assertEqual(
            {"enrolment_site": "north-branch", "fleet.id": "il-01"},
            provisioning_payload.parse_admin_extras(
                ["enrolment_site=north-branch", "fleet.id=il-01"]
            ),
        )

    def test_rendered_payload_is_ascii_compact_json_without_a_trailing_newline(self) -> None:
        payload = provisioning_payload.build_payload(
            COMPONENT,
            DOWNLOAD_LOCATION,
            provisioning_payload.normalize_signature_digest(SIGNER_HEX)[1],
            leave_system_apps_enabled=True,
            skip_encryption=False,
            wifi_settings={"android.app.extra.PROVISIONING_WIFI_SSID": "מכשיר-רשת"},
            locale=None,
            time_zone=None,
            admin_extras={},
        )
        rendered = provisioning_payload.render_payload(payload)

        self.assertEqual(rendered, rendered.decode("ascii").encode("ascii"))
        self.assertFalse(rendered.endswith(b"\n"))
        self.assertNotIn(b", ", rendered)
        self.assertEqual(payload, json.loads(rendered))

    def test_refuses_a_payload_too_large_for_a_scannable_qr_code(self) -> None:
        payload = provisioning_payload.build_payload(
            COMPONENT,
            DOWNLOAD_LOCATION,
            provisioning_payload.normalize_signature_digest(SIGNER_HEX)[1],
            leave_system_apps_enabled=True,
            skip_encryption=False,
            wifi_settings={},
            locale=None,
            time_zone=None,
            admin_extras={f"note{index}": "x" * 400 for index in range(6)},
        )
        with self.assertRaises(provisioning_payload.ProvisioningError):
            provisioning_payload.render_payload(payload)

    def test_refuses_invalid_locale_and_time_zone(self) -> None:
        checksum = provisioning_payload.normalize_signature_digest(SIGNER_HEX)[1]
        for locale, time_zone in (("english", None), (None, "Mars/Olympus Mons"), ("EN-us", None)):
            with self.subTest(locale=locale, time_zone=time_zone):
                with self.assertRaises(provisioning_payload.ProvisioningError):
                    provisioning_payload.build_payload(
                        COMPONENT,
                        DOWNLOAD_LOCATION,
                        checksum,
                        leave_system_apps_enabled=True,
                        skip_encryption=False,
                        wifi_settings={},
                        locale=locale,
                        time_zone=time_zone,
                        admin_extras={},
                    )

    def test_refuses_to_replace_an_existing_payload_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "payload.json"
            output.write_bytes(b"original")

            with self.assertRaises(provisioning_payload.ProvisioningError):
                provisioning_payload.create(_namespace(output=output))

            self.assertEqual(b"original", output.read_bytes())
            provisioning_payload.create(_namespace(output=output, force=True))
            self.assertNotEqual(b"original", output.read_bytes())

    def test_refuses_to_write_the_payload_into_the_repository(self) -> None:
        root = provisioning_payload.repository_root()
        if root is None:
            self.skipTest("the guard only applies inside a repository checkout")
        with self.assertRaises(provisioning_payload.ProvisioningError):
            provisioning_payload.create(_namespace(output=root / "provisioning-payload.json"))

    def test_cli_exits_non_zero_on_a_validation_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "payload.json"
            exit_code = provisioning_payload.main(
                [
                    "--admin-component",
                    COMPONENT,
                    "--download-location",
                    "http://updates.example.test/device-guard.apk",
                    "--signer-sha256",
                    SIGNER_HEX,
                    "--skip-apk-verification",
                    "--output",
                    str(output),
                ]
            )

            self.assertEqual(2, exit_code)
            self.assertFalse(output.exists())

    def test_cli_writes_a_payload_and_reports_the_offline_qr_commands(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "payload.json"
            exit_code = provisioning_payload.main(
                [
                    "--admin-component",
                    COMPONENT,
                    "--download-location",
                    DOWNLOAD_LOCATION,
                    "--signer-sha256",
                    SIGNER_HEX,
                    "--skip-apk-verification",
                    "--output",
                    str(output),
                ]
            )

            self.assertEqual(0, exit_code)
            payload = json.loads(output.read_bytes())
            self.assertEqual(
                COMPONENT,
                payload["android.app.extra.PROVISIONING_DEVICE_ADMIN_COMPONENT_NAME"],
            )

    def test_payload_never_carries_the_skip_user_consent_extra(self) -> None:
        payload = provisioning_payload.build_payload(
            COMPONENT,
            DOWNLOAD_LOCATION,
            provisioning_payload.normalize_signature_digest(SIGNER_HEX)[1],
            leave_system_apps_enabled=True,
            skip_encryption=False,
            wifi_settings={},
            locale=None,
            time_zone=None,
            admin_extras={},
        )

        self.assertNotIn("android.app.extra.PROVISIONING_SKIP_USER_CONSENT", payload)
        self.assertTrue(all(key.startswith("android.app.extra.PROVISIONING_") for key in payload))


if __name__ == "__main__":
    unittest.main()
