import io
import os
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import device_update_drill as drill


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
