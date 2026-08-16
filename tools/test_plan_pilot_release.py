import argparse
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import plan_pilot_release


ROOT = Path(__file__).resolve().parents[1]
CHANNEL = ROOT / "updates" / "pilot" / "channel.json"


def current_payload(**overrides):
    payload = {
        "schemaVersion": 1,
        "packageName": "com.example.lockdowndpc",
        "versionCode": 12,
        "versionName": "0.5.2",
        "apkUrl": (
            "https://github.com/ShalomMaman/android-lockdown-dpc/releases/download/"
            "pilot-v0.5.2/device-guard-pilot-v0.5.2.apk"
        ),
        "apkSha256": "a" * 64,
        "apkSize": 123,
        "issuedAt": 1,
        "expiresAt": 2,
    }
    payload.update(overrides)
    return payload


class PlanPilotReleaseTest(unittest.TestCase):
    def test_repository_channel_configuration_is_valid(self):
        channel, public_key = plan_pilot_release.load_channel(CHANNEL)
        self.assertEqual("com.example.lockdowndpc", channel["packageName"])
        self.assertTrue(public_key.is_file())

    def test_channel_rejects_extra_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "channel.json"
            data = json.loads(CHANNEL.read_text(encoding="utf-8"))
            data["unexpected"] = True
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(plan_pilot_release.ReleasePlanError, "unsupported schema"):
                plan_pilot_release.load_channel(path)

    def run_plan(self, identity=("com.example.lockdowndpc", 13, "0.5.3"), payload=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        apk = Path(temporary.name) / "candidate.apk"
        apk.write_bytes(b"apk")
        manifest = Path(temporary.name) / "latest.json"
        args = argparse.Namespace(
            apk=apk,
            channel=CHANNEL,
            current_manifest=manifest,
            github_output=None,
            aapt2=None,
            apksigner=None,
        )
        patches = (
            mock.patch("plan_pilot_release.publish_update.find_android_build_tool", return_value=Path("tool")),
            mock.patch("plan_pilot_release.publish_update.read_apk_identity", return_value=identity),
            mock.patch("plan_pilot_release.publish_update.verify_apk_signer"),
            mock.patch(
                "plan_pilot_release.verify_pilot_apk.read_signed_manifest",
                return_value=payload or current_payload(),
            ),
        )
        with patches[0], patches[1], patches[2], patches[3]:
            return plan_pilot_release.plan(args)

    def test_plan_derives_safe_release_names_and_requires_progress(self):
        result = self.run_plan()
        self.assertEqual(13, result["version_code"])
        self.assertEqual("pilot-v0.5.3", result["tag"])
        self.assertEqual("device-guard-pilot-v0.5.3.apk", result["asset_name"])
        self.assertEqual(12, result["current_version_code"])

    def test_plan_rejects_reused_version_code(self):
        with self.assertRaisesRegex(plan_pilot_release.ReleasePlanError, "must be newer"):
            self.run_plan(identity=("com.example.lockdowndpc", 12, "0.5.3"))

    def test_plan_rejects_unsafe_version_name(self):
        with self.assertRaisesRegex(plan_pilot_release.ReleasePlanError, "not safe"):
            self.run_plan(identity=("com.example.lockdowndpc", 13, "../escape"))

    def test_plan_rejects_package_drift(self):
        with self.assertRaisesRegex(plan_pilot_release.ReleasePlanError, "package identity"):
            self.run_plan(identity=("example.other", 13, "0.5.3"))

    def test_plan_rejects_unknown_signed_payload_fields(self):
        payload = current_payload(unexpected=True)
        with self.assertRaisesRegex(plan_pilot_release.ReleasePlanError, "unsupported schema"):
            self.run_plan(payload=payload)

    def test_github_output_rejects_line_breaks(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            with self.assertRaisesRegex(plan_pilot_release.ReleasePlanError, "line break"):
                plan_pilot_release.write_github_output(output, {"tag": "bad\nvalue"})


if __name__ == "__main__":
    unittest.main()
