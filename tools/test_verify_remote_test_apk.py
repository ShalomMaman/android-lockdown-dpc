import unittest
from pathlib import Path
from unittest.mock import patch

import verify_remote_test_apk as verifier


class VerifyRemoteTestApkTest(unittest.TestCase):
    RELEASE = Path("release.apk")
    REMOTE = Path("remoteTest.apk")
    SERVICE = "RemoteTestJobService"
    RECEIVER = "RemoteTestLifecycleReceiver"

    def verify(self, release_components, remote_components):
        def manifest(command, *, text):
            apk = Path(command[3])
            components = release_components if apk == self.RELEASE else remote_components
            return "".join(
                f'      A: android:name(0x01010003)="com.example.lockdowndpc.policy.{component}"\n'
                for component in components
            )

        with (
            patch.object(verifier, "find_android_build_tool", return_value=Path("/mock/tool")),
            patch.object(verifier, "read_apk_identity", side_effect=[
                ("com.example.lockdowndpc", 1, "1"),
                ("com.example.lockdowndpc.remotetest", 1, "1"),
            ]),
            patch.object(verifier, "verify_apk_has_single_signer", side_effect=["release", "test"]),
            patch.object(verifier.subprocess, "check_output", side_effect=manifest),
        ):
            verifier.verify(self.RELEASE, self.REMOTE)

    def test_accepts_both_components_only_in_remote_test(self):
        self.verify([], [self.SERVICE, self.RECEIVER])

    def test_rejects_receiver_in_release(self):
        with self.assertRaisesRegex(verifier.VerificationError, self.RECEIVER):
            self.verify([self.RECEIVER], [self.SERVICE, self.RECEIVER])

    def test_rejects_missing_receiver_in_remote_test(self):
        with self.assertRaisesRegex(verifier.VerificationError, self.RECEIVER):
            self.verify([], [self.SERVICE, self.RECEIVER + "Other"])


if __name__ == "__main__":
    unittest.main()
