import io
import json
import os
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import device_update_drill as drill


class _ReachedWitness(Exception):
    pass


class DeviceUpdateDrillTest(unittest.TestCase):
    def test_requires_every_signing_setting_before_gradle_or_adb(self):
        for missing in drill.SIGNING_SETTINGS:
            supplied = {name: "unprinted-fixture" for name in drill.SIGNING_SETTINGS if name != missing}
            with (
                self.subTest(missing=missing),
                patch.dict(os.environ, supplied, clear=True),
                patch.object(drill, "command") as command,
                patch.object(drill.subprocess, "run") as gradle,
                self.assertRaisesRegex(drill.DrillError, "four production signing"),
            ):
                drill.run(Namespace(), {}, Path("."))
            command.assert_not_called()
            gradle.assert_not_called()

    def test_missing_signing_prints_sanitized_failure_record(self):
        output = io.StringIO()
        with (
            patch.dict(os.environ, {drill.SIGNING_SETTINGS[1]: "unprinted-fixture"}, clear=True),
            patch("sys.argv", ["device_update_drill.py", "--version-code", "15", "--output-dir", "unused"]),
            redirect_stdout(output),
        ):
            self.assertEqual(1, drill.main())
        self.assertIn('"verdict": "FAIL"', output.getvalue())
        self.assertIn('"stage": "signing-inputs"', output.getvalue())
        self.assertNotIn("unprinted-fixture", output.getvalue())

    def test_reads_device_owner_and_rejects_profile_owner(self):
        dump = (
            "  Device Owner: \n"
            f"    admin=ComponentInfo{{org.example.device/{drill.ADMIN_CLASS}}}\n"
            "    package=org.example.device\n"
            "    User ID: 11\n"
            "\n  Profile Owner (User 12):\n"
            f"    admin=ComponentInfo{{org.example.profile/{drill.ADMIN_CLASS}}}\n"
        )
        self.assertEqual(("org.example.device", 11), drill.owner(dump))
        with self.assertRaisesRegex(drill.DrillError, "Device Owner"):
            drill.owner(dump.replace("Device Owner:", "Profile Owner:"))

    def test_uses_effective_restrictions_for_the_owner_user_only(self):
        dump = (
            "Users:\n  UserInfo{0:bench:800}\n"
            "    Effective restrictions:\n     no_debugging_features\n"
            "  UserInfo{11:bench:400}\n"
            "    Device policy restrictions:\n     no_remove_user\n"
            "    Effective restrictions:\n     no_factory_reset\n     no_add_user\n"
            "    State: RUNNING_UNLOCKED\n"
        )
        self.assertEqual(["no_add_user", "no_factory_reset"], drill.effective_restrictions(dump, 11))
        with self.assertRaisesRegex(drill.DrillError, "factory-reset block"):
            drill.effective_restrictions(dump, 0)

    def _run_baseline_version_check(
        self,
        *,
        version_code: int,
        installed_version: int,
        max_version_jump: int | None = None,
    ) -> None:
        env = {
            "DEVICE_GUARD_UPDATE_MANIFEST_URL": "https://updates.example.test/manifest.json",
            "DEVICE_GUARD_UPDATE_PUBLIC_KEY": "dGVzdC1rZXk=",
            "DEVICE_GUARD_UPDATE_PUBLIC_KEY_SHA256": "0" * 64,
        }
        args_kwargs = {"version_code": version_code, "output_dir": Path("unused"), "timeout": 180}
        if max_version_jump is not None:
            args_kwargs["max_version_jump"] = max_version_jump
        args = Namespace(**args_kwargs)
        evidence: dict = {}

        def fake_command(*argv, timeout=30):
            if argv == ("adb", "devices"):
                return "List of devices attached\nBENCH123\tdevice\n"
            if argv[:3] == ("adb", "-s", "BENCH123"):
                sub = argv[3:]
                if sub in (
                    ("shell", "getprop", "ro.kernel.qemu"),
                    ("shell", "getprop", "ro.boot.qemu"),
                ):
                    return "0\n"
                if sub == ("shell", "dumpsys", "device_policy"):
                    return (
                        "  Device Owner:\n"
                        f"    admin=ComponentInfo{{org.example.device/{drill.ADMIN_CLASS}}}\n"
                        "    User ID: 0\n"
                    )
                if sub == ("shell", "pm", "path", "--user", "0", "org.example.device"):
                    return "package:/data/app/org.example.device/base.apk\n"
                if sub[:2] == ("pull", "/data/app/org.example.device/base.apk"):
                    return ""
                if sub == ("shell", "dumpsys", "user"):
                    return (
                        "Users:\n  UserInfo{0:bench:800}\n"
                        "    Effective restrictions:\n     no_factory_reset\n"
                    )
            raise AssertionError(f"unexpected command: {argv!r}")

        with (
            patch.dict(os.environ, env, clear=True),
            patch.object(drill, "signing_environment", return_value={}),
            patch.object(drill, "command", side_effect=fake_command),
            patch.object(drill, "find_android_build_tool", side_effect=lambda name, _: Path(f"/fake/{name}")),
            patch.object(drill, "read_apk_identity", return_value=("org.example.device", installed_version, "1.0")),
            patch.object(
                drill,
                "verify_release",
                return_value={
                    "UPDATE_MANIFEST_URL": env["DEVICE_GUARD_UPDATE_MANIFEST_URL"],
                    "UPDATE_PUBLIC_KEY": env["DEVICE_GUARD_UPDATE_PUBLIC_KEY"],
                },
            ),
            patch.object(drill, "verify_apk_has_single_signer", return_value="a" * 64),
            patch.object(drill, "require_witness", side_effect=_ReachedWitness()) as witness,
            patch.object(drill.subprocess, "run") as gradle,
        ):
            try:
                drill.run(args, evidence, Path("."))
            except drill.DrillError:
                witness.assert_not_called()
                gradle.assert_not_called()
                self.assertEqual("baseline", evidence.get("stage"))
                raise
            except _ReachedWitness:
                witness.assert_called_once()
                gradle.assert_not_called()
                self.assertEqual(installed_version, evidence.get("beforeVersionCode"))
                raise
        raise AssertionError("expected baseline check to stop before or at witness confirmation")

    def test_validate_version_jump_enforces_positive_limit_and_ceiling(self):
        drill.validate_version_jump(1010, 10)
        drill.validate_version_jump(11, 10, 1)
        for bad_limit in (0, -1, False, True):
            with (
                self.subTest(max_version_jump=bad_limit),
                self.assertRaisesRegex(drill.DrillError, "positive"),
            ):
                drill.validate_version_jump(15, 10, bad_limit)
        with self.assertRaisesRegex(drill.DrillError, r"jump of 1001 exceeds max allowed jump of 1000"):
            drill.validate_version_jump(1011, 10)

    def test_parser_defaults_and_overrides_max_version_jump(self):
        default_args = drill.build_parser().parse_args(
            ["--version-code", "15", "--output-dir", "unused"]
        )
        self.assertEqual(1000, default_args.max_version_jump)
        custom_args = drill.build_parser().parse_args(
            ["--version-code", "15", "--output-dir", "unused", "--max-version-jump", "250"]
        )
        self.assertEqual(250, custom_args.max_version_jump)

    def test_rejects_non_positive_max_version_jump_before_adb_or_gradle(self):
        for bad_limit in (0, -1, -1000):
            with (
                self.subTest(max_version_jump=bad_limit),
                patch.object(drill, "command") as command,
                patch.object(drill.subprocess, "run") as gradle,
                self.assertRaisesRegex(drill.DrillError, "positive"),
            ):
                drill.run(Namespace(version_code=15, max_version_jump=bad_limit), {}, Path("."))
            command.assert_not_called()
            gradle.assert_not_called()

    def test_main_rejects_non_positive_max_version_jump(self):
        for raw_limit in ("0", "-5"):
            output = io.StringIO()
            with (
                self.subTest(max_version_jump=raw_limit),
                patch.dict(os.environ, {}, clear=True),
                patch.object(drill, "command") as command,
                patch.object(drill.subprocess, "run") as gradle,
                patch(
                    "sys.argv",
                    [
                        "device_update_drill.py",
                        "--version-code", "15",
                        "--output-dir", "unused",
                        "--max-version-jump", raw_limit,
                    ],
                ),
                redirect_stdout(output),
            ):
                self.assertEqual(1, drill.main())
            record = json.loads(output.getvalue())
            self.assertEqual("FAIL", record["verdict"])
            self.assertEqual("signing-inputs", record["stage"])
            self.assertIn("positive", record["reason"])
            command.assert_not_called()
            gradle.assert_not_called()

    def test_rejects_version_jump_exceeding_default_limit(self):
        with self.assertRaisesRegex(drill.DrillError, r"jump of 1001 exceeds max allowed jump of 1000"):
            self._run_baseline_version_check(version_code=1011, installed_version=10)

    def test_allows_version_jump_equal_to_default_limit(self):
        with self.assertRaises(_ReachedWitness):
            self._run_baseline_version_check(version_code=1010, installed_version=10)

    def test_respects_custom_max_version_jump_override(self):
        with self.assertRaises(_ReachedWitness):
            self._run_baseline_version_check(
                version_code=2510,
                installed_version=10,
                max_version_jump=2500,
            )
        with self.assertRaisesRegex(drill.DrillError, r"jump of 11 exceeds max allowed jump of 10"):
            self._run_baseline_version_check(
                version_code=21,
                installed_version=10,
                max_version_jump=10,
            )

    def test_rejects_non_increasing_version_code(self):
        for candidate_version in (10, 9):
            with (
                self.subTest(candidate_version=candidate_version),
                self.assertRaisesRegex(drill.DrillError, "higher than the installed version"),
            ):
                self._run_baseline_version_check(version_code=candidate_version, installed_version=10)
