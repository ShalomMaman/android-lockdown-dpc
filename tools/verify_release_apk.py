"""Verify the merged manifest and remote-enrolment boundary of a release APK."""

import re
import subprocess
import sys
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from publish_update import PublishError, find_android_build_tool, read_apk_identity
from verify_pilot_apk import VerificationError, read_compiled_build_config

NAMESPACE = "com.example.lockdowndpc"
COMPONENTS = {"activity", "activity-alias", "provider", "receiver", "service"}
EXPORTED = {
    ("activity", NAMESPACE + ".ui.MainActivity"): None,
    ("activity", NAMESPACE + ".kiosk.KioskHostActivity"): None,
    ("activity", NAMESPACE + ".ui.BlockedBrowserActivity"): None,
    ("activity", NAMESPACE + ".admin.ProvisioningModeActivity"): "android.permission.BIND_DEVICE_ADMIN",
    ("activity", NAMESPACE + ".admin.PolicyComplianceActivity"): "android.permission.BIND_DEVICE_ADMIN",
    ("receiver", NAMESPACE + ".admin.LockdownAdminReceiver"): "android.permission.BIND_DEVICE_ADMIN",
    ("receiver", NAMESPACE + ".receivers.PolicyUpdateAuditReceiver"): "android.permission.BIND_DEVICE_ADMIN",
    ("service", NAMESPACE + ".admin.LockdownDeviceAdminService"): "android.permission.BIND_DEVICE_ADMIN",
    ("service", NAMESPACE + ".updates.UpdateCheckJobService"): "android.permission.BIND_JOB_SERVICE",
    ("service", NAMESPACE + ".maintenance.MaintenanceGuardJobService"): "android.permission.BIND_JOB_SERVICE",
    ("service", NAMESPACE + ".policy.ScheduleSweepJobService"): "android.permission.BIND_JOB_SERVICE",
    ("receiver", "androidx.profileinstaller.ProfileInstallReceiver"): "android.permission.DUMP",
}
DISABLED_SURFACES = {NAMESPACE + ".kiosk.KioskHostActivity", NAMESPACE + ".ui.BlockedBrowserActivity"}
LAB_MARKERS = (
    b"openedByTest", b"remote_test_client", b"device-guard-remote-test",
    b"RemoteTestJobService;", b"RemoteTestLifecycleReceiver;", b"RemoteTestClient;",
    # Literal provisioning keys survive R8 renaming; main carries only the "dg.remote." prefix.
    b"dg.remote.ticket", b"dg.remote.fleet",
)
ANDROID_ATTRIBUTE = re.compile(
    r"A: (?:android:|http://schemas\.android\.com/apk/res/android:)(\w+)(?:\(0x[0-9a-f]+\))?=(.*)"
)


def manifest_elements(xmltree: str):
    """Yield (depth, element, attributes) from aapt2's binary XML dump."""
    element = None
    for line in xmltree.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("E: "):
            if element is not None:
                yield element
            element = (len(line) - len(stripped), stripped[3:].split()[0], {})
        elif element is not None and (attribute := ANDROID_ATTRIBUTE.fullmatch(stripped)):
            name, value = attribute.groups()
            if value.startswith('"'):
                value = value.split('"', 2)[1]
            element[2][name] = value
    if element is not None:
        yield element


def is_false(value: str | None) -> bool:
    return value == "false" or bool(value and re.fullmatch(r"\(type 0x12\)0x0+", value))


def verify_manifest(xmltree: str, package: str) -> None:
    application_depth = None
    for depth, tag, attrs in manifest_elements(xmltree):
        if tag == "application":
            application_depth = depth
            for name in ("debuggable", "testOnly"):
                if name in attrs and not is_false(attrs[name]):
                    raise VerificationError(f"release enables {name}")
            if not is_false(attrs.get("usesCleartextTraffic")) or "networkSecurityConfig" in attrs:
                raise VerificationError("release must explicitly deny cleartext traffic without an override")
        elif application_depth is not None and depth > application_depth and tag in COMPONENTS:
            name = attrs.get("name", "")
            if name.startswith("."):
                name = package + name
            elif "." not in name:
                name = package + "." + name
            if any(name.endswith(marker) for marker in (".RemoteTestJobService", ".RemoteTestLifecycleReceiver")):
                raise VerificationError("release declares a lab-only component")
            if name in DISABLED_SURFACES and not is_false(attrs.get("enabled")):
                raise VerificationError(f"release enables {name} at install time")
            exported = attrs.get("exported")
            # Providers default to private at this application's minimum SDK.
            # All activities, receivers and services must declare their scope.
            if is_false(exported) or (tag == "provider" and exported is None):
                continue
            # Require an explicit scope for each merged declaration.
            if (tag, name) not in EXPORTED or not (
                exported == "true" or exported == "(type 0x12)0xffffffff"
            ) or attrs.get("permission") != EXPORTED[(tag, name)]:
                raise VerificationError(f"unexpected release export or permission: {tag} {name}")
    if application_depth is None:
        raise VerificationError("release manifest has no application")


def verify_release(apk: Path, aapt2: Path, dexdump: Path) -> dict[str, str]:
    package, _, _ = read_apk_identity(apk, aapt2)
    if package.endswith(".remotetest"):
        raise VerificationError("release uses the lab package identity")
    xmltree = subprocess.check_output(
        [str(aapt2), "dump", "xmltree", str(apk), "--file", "AndroidManifest.xml"], text=True,
    )
    verify_manifest(xmltree, package)
    fields = read_compiled_build_config(apk, dexdump)
    if fields.get("REMOTE_ENROLMENT_ENABLED") != "false":
        raise VerificationError("compiled REMOTE_ENROLMENT_ENABLED must be false")
    with ZipFile(apk) as archive:
        for entry in archive.namelist():
            if re.fullmatch(r"classes\d*\.dex", entry):
                dex = archive.read(entry)
                if any(marker in dex for marker in LAB_MARKERS):
                    raise VerificationError("release DEX contains lab-only code")
    return fields


def main() -> int:
    if len(sys.argv) != 2:
        sys.exit("Usage: verify_release_apk.py RELEASE_APK")
    try:
        verify_release(
            Path(sys.argv[1]),
            find_android_build_tool("aapt2", None),
            find_android_build_tool("dexdump", None),
        )
    except (VerificationError, PublishError, subprocess.SubprocessError, OSError, BadZipFile) as error:
        sys.exit(f"Release hardening verification failed: {error}")
    print("Release hardening verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
