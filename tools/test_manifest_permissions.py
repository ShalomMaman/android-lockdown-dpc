import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ANDROID = "{http://schemas.android.com/apk/res/android}"
ANDROID_NAME = f"{ANDROID}name"


class ManifestPermissionsTest(unittest.TestCase):
    def test_network_constrained_update_jobs_have_network_state_permission(self):
        manifest = ET.parse(ROOT / "app/src/main/AndroidManifest.xml").getroot()
        permissions = {
            element.attrib[ANDROID_NAME]
            for element in manifest.findall("uses-permission")
        }

        self.assertIn("android.permission.ACCESS_NETWORK_STATE", permissions)

    def test_schedule_boundaries_use_the_grantable_exact_alarm_permission_only(self):
        manifest = ET.parse(ROOT / "app/src/main/AndroidManifest.xml").getroot()
        permissions = {
            element.attrib[ANDROID_NAME]
            for element in manifest.findall("uses-permission")
        }

        self.assertIn("android.permission.SCHEDULE_EXACT_ALARM", permissions)
        # Reserved for alarm clock and calendar apps; the boundary alarm falls
        # back to an inexact window instead.
        self.assertNotIn("android.permission.USE_EXACT_ALARM", permissions)

    def test_clock_and_timezone_changes_reach_the_unexported_policy_receiver(self):
        manifest = ET.parse(ROOT / "app/src/main/AndroidManifest.xml").getroot()
        receivers = [
            receiver
            for receiver in manifest.findall("application/receiver")
            if receiver.get(ANDROID_NAME) == ".receivers.PolicyRefreshReceiver"
        ]
        self.assertEqual(1, len(receivers))
        receiver = receivers[0]
        self.assertEqual("false", receiver.get(f"{ANDROID}exported"))
        actions = {
            item.get(ANDROID_NAME) for item in receiver.findall("intent-filter/action")
        }
        for action in (
            "android.intent.action.BOOT_COMPLETED",
            "android.intent.action.TIME_SET",
            "android.intent.action.TIMEZONE_CHANGED",
            "android.app.action.SCHEDULE_EXACT_ALARM_PERMISSION_STATE_CHANGED",
        ):
            self.assertIn(action, actions)

    def test_provisioning_mode_activity_is_protected(self):
        self.assert_provisioning_activity(
            ".admin.ProvisioningModeActivity", "android.app.action.GET_PROVISIONING_MODE"
        )

    def test_policy_compliance_activity_is_protected(self):
        self.assert_provisioning_activity(
            ".admin.PolicyComplianceActivity", "android.app.action.ADMIN_POLICY_COMPLIANCE"
        )

    def test_shell_pin_provider_uses_application_id_authority_and_is_exported(self):
        manifest = ET.parse(ROOT / "app/src/main/AndroidManifest.xml").getroot()
        providers = [
            provider
            for provider in manifest.findall("application/provider")
            if provider.get(ANDROID_NAME) == ".security.ShellPinProvider"
        ]
        self.assertEqual(1, len(providers))
        provider = providers[0]
        self.assertEqual("true", provider.get(f"{ANDROID}exported"))
        self.assertEqual("${applicationId}.shellpin", provider.get(f"{ANDROID}authorities"))
        self.assertEqual("false", provider.get(f"{ANDROID}directBootAware"))
        self.assertIsNone(provider.get(f"{ANDROID}permission"))

    def assert_provisioning_activity(self, name, action):
        manifest = ET.parse(ROOT / "app/src/main/AndroidManifest.xml").getroot()
        handlers = [
            activity
            for activity in manifest.findall("application/activity")
            if any(
                item.get(ANDROID_NAME) == action
                for item in activity.findall("intent-filter/action")
            )
        ]
        self.assertEqual([name], [activity.get(ANDROID_NAME) for activity in handlers])
        activity = handlers[0]
        self.assertEqual("true", activity.get(f"{ANDROID}exported"))
        self.assertEqual("android.permission.BIND_DEVICE_ADMIN", activity.get(f"{ANDROID}permission"))
        self.assertTrue(any(
            intent_filter.find(f"action[@{ANDROID_NAME}='{action}']") is not None
            and intent_filter.find(
                f"category[@{ANDROID_NAME}='android.intent.category.DEFAULT']"
            ) is not None
            for intent_filter in activity.findall("intent-filter")
        ))


if __name__ == "__main__":
    unittest.main()
