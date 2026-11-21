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

    def test_provisioning_mode_activity_is_protected(self):
        self.assert_provisioning_activity(
            ".admin.ProvisioningModeActivity", "android.app.action.GET_PROVISIONING_MODE"
        )

    def test_policy_compliance_activity_is_protected(self):
        self.assert_provisioning_activity(
            ".admin.PolicyComplianceActivity", "android.app.action.ADMIN_POLICY_COMPLIANCE"
        )

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
