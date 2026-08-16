import unittest
import xml.etree.ElementTree as ET
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ANDROID_NAME = "{http://schemas.android.com/apk/res/android}name"


class ManifestPermissionsTest(unittest.TestCase):
    def test_network_constrained_update_jobs_have_network_state_permission(self):
        manifest = ET.parse(ROOT / "app/src/main/AndroidManifest.xml").getroot()
        permissions = {
            element.attrib[ANDROID_NAME]
            for element in manifest.findall("uses-permission")
        }

        self.assertIn("android.permission.ACCESS_NETWORK_STATE", permissions)


if __name__ == "__main__":
    unittest.main()
