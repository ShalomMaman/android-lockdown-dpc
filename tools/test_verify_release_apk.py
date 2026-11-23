import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from zipfile import ZipFile

from verify_release_apk import VerificationError, verify_manifest, verify_release


MANIFEST = """
  E: manifest (line=1)
      E: application (line=2)
        A: http://schemas.android.com/apk/res/android:usesCleartextTraffic(0x010104ec)=false
          E: activity (line=3)
            A: android:name(0x01010003)=".ui.MainActivity" (Raw: ".ui.MainActivity")
            A: android:exported(0x01010010)=true
          E: service (line=4)
            A: android:name(0x01010003)=".updates.UpdateCheckJobService"
            A: android:exported(0x01010010)=true
            A: android:permission(0x01010006)="android.permission.BIND_JOB_SERVICE"
"""


class VerifyReleaseApkTest(unittest.TestCase):
    package = "com.example.lockdowndpc"

    def verify(self, gate="false", secondary_dex=b""):
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "app.apk"
            with ZipFile(apk, "w") as archive:
                archive.writestr("classes.dex", b"")
                archive.writestr("classes2.dex", secondary_dex)
            with (
                patch("verify_release_apk.read_apk_identity", return_value=(self.package, 14, "1.0")),
                patch("verify_release_apk.subprocess.check_output", return_value=MANIFEST),
                patch("verify_release_apk.read_compiled_build_config",
                      return_value={} if gate is None else {"REMOTE_ENROLMENT_ENABLED": gate}),
            ):
                verify_release(apk, Path("aapt2"), Path("dexdump"))

    def test_release_boundary_accepts_disabled_gate_and_expected_exports(self):
        self.verify()

    def test_rejects_enabled_or_missing_compiled_gate(self):
        for value in ("true", None):
            with self.subTest(value=value), self.assertRaisesRegex(VerificationError, "must be false"):
                self.verify(gate=value)

    def test_rejects_lab_code_in_secondary_dex(self):
        for marker in (b"remote_test_client", b"openedByTest", b"RemoteTestJobService;"):
            with self.subTest(marker=marker), self.assertRaisesRegex(VerificationError, "lab-only code"):
                self.verify(secondary_dex=marker)

    def test_rejects_non_exported_lab_component(self):
        manifest = MANIFEST + """
          E: receiver (line=5)
            A: android:name(0x01010003)=".policy.RemoteTestLifecycleReceiver"
            A: android:exported(0x01010010)=false
"""
        with self.assertRaisesRegex(VerificationError, "lab-only component"):
            verify_manifest(manifest, self.package)

    def test_rejects_debug_test_cleartext_and_network_config(self):
        for field in ("debuggable", "testOnly", "usesCleartextTraffic", "networkSecurityConfig"):
            manifest = MANIFEST.replace(
                "usesCleartextTraffic(0x010104ec)=false",
                f"usesCleartextTraffic(0x010104ec)={'true' if field == 'usesCleartextTraffic' else 'false'}",
            )
            if field != "usesCleartextTraffic":
                manifest = manifest.replace("          E: activity", f"        A: android:{field}=true\n          E: activity")
            with self.subTest(field=field), self.assertRaises(VerificationError):
                verify_manifest(manifest, self.package)

    def test_rejects_unexpected_export_or_missing_platform_permission(self):
        for manifest in (
            MANIFEST.replace(".ui.MainActivity", ".ui.UnexpectedActivity"),
            MANIFEST.replace("android.permission.BIND_JOB_SERVICE", "android.permission.INTERNET"),
        ):
            with self.assertRaisesRegex(VerificationError, "unexpected release export"):
                verify_manifest(manifest, self.package)
