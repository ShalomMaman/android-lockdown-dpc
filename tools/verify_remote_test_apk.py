"""Check isolation using the two compiled and signed APKs."""

import re
import subprocess
import sys
from pathlib import Path

from publish_update import PublishError, find_android_build_tool, read_apk_identity
from verify_pilot_apk import VerificationError, verify_apk_has_single_signer


def verify(release: Path, remote_test: Path) -> None:
    aapt2 = find_android_build_tool("aapt2", None)
    apksigner = find_android_build_tool("apksigner", None)
    release_package, _, _ = read_apk_identity(release, aapt2)
    test_package, _, _ = read_apk_identity(remote_test, aapt2)
    if test_package != release_package + ".remotetest":
        raise VerificationError("remote-test package must be distinct from release")
    release_signer = verify_apk_has_single_signer(release, apksigner)
    remote_signer = verify_apk_has_single_signer(remote_test, apksigner)
    if release_signer == remote_signer:
        raise VerificationError("remote-test APK shares the release signer")

    def manifest(apk: Path) -> str:
        return subprocess.check_output(
            [str(aapt2), "dump", "xmltree", str(apk), "--file", "AndroidManifest.xml"],
            text=True,
        )

    test_manifest = manifest(remote_test)
    android = r"(?:android:|http://schemas\.android\.com/apk/res/android:)"
    name = re.compile(rf'{android}name\([^)]*\)="([^"]+)"')
    release_names = set(name.findall(manifest(release)))
    test_names = set(name.findall(test_manifest))
    for component in ("RemoteTestJobService", "RemoteTestLifecycleReceiver"):
        qualified = f"com.example.lockdowndpc.policy.{component}"
        if qualified in release_names or qualified not in test_names:
            raise VerificationError(f"{component} has the wrong manifest scope")
    for attribute in ("debuggable", "testOnly"):
        match = re.search(rf"{android}{attribute}\([^)]*\)=(.+)", test_manifest)
        if match and not re.fullmatch(r"false|\(type 0x12\)0x0+", match[1].strip()):
            raise VerificationError(f"remote-test APK enables {attribute}")


if __name__ == "__main__":
    try:
        verify(*(Path(argument) for argument in sys.argv[1:]))
    except (VerificationError, PublishError, subprocess.SubprocessError, OSError, TypeError) as error:
        sys.exit(f"Remote-test APK verification failed: {error}")
