from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "publish-pilot-release.yml"
ANDROID_CI = ROOT / ".github" / "workflows" / "android-ci.yml"
PILOT_INIT = ROOT / "gradle" / "pilot-update.init.gradle.kts"
PILOT_SIGNING = ROOT / "gradle" / "pilot-signing.gradle"
PILOT_CHANNEL = ROOT / "gradle" / "pilot-update.gradle"


class PilotReleaseWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_release_is_manual_serialized_and_environment_scoped(self):
        self.assertIn("workflow_dispatch:", self.workflow)
        self.assertNotIn("pull_request:", self.workflow)
        self.assertIn("group: publish-pilot-release", self.workflow)
        self.assertIn("cancel-in-progress: false", self.workflow)
        self.assertIn("environment: pilot-release", self.workflow)
        self.assertIn('"$GITHUB_REF" != "refs/heads/main"', self.workflow)

    def test_every_release_secret_is_environment_referenced(self):
        for name in (
            "PILOT_SIGNING_KEYSTORE_B64",
            "PILOT_SIGNING_STORE_PASSWORD",
            "PILOT_SIGNING_KEY_ALIAS",
            "PILOT_SIGNING_KEY_PASSWORD",
            "PILOT_UPDATE_PRIVATE_KEY_B64",
            "PILOT_UPDATE_KEY_PASSWORD",
        ):
            self.assertIn(f"secrets.{name}", self.workflow)
        self.assertNotIn("BEGIN PRIVATE KEY", self.workflow)

    def test_artifact_is_published_before_metadata_is_merged(self):
        publish = self.workflow.index("gh release edit")
        merge = self.workflow.index("gh pr merge")
        public_readback = self.workflow.index("Verify the active public metadata")
        self.assertLess(publish, merge)
        self.assertLess(merge, public_readback)

    def test_generated_metadata_receives_an_explicit_ci_run(self):
        self.assertIn("gh workflow run android-ci.yml", self.workflow)
        self.assertIn("gh run watch", self.workflow)
        android_ci = ANDROID_CI.read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", android_ci)

    def test_ephemeral_keys_have_unconditional_cleanup(self):
        cleanup = self.workflow.index("Remove ephemeral key material")
        self.assertIn("if: always()", self.workflow[cleanup : cleanup + 300])
        self.assertIn("$RUNNER_TEMP/device-guard-pilot.keystore", self.workflow[cleanup:])
        self.assertIn("$RUNNER_TEMP/device-guard-pilot-update.pem", self.workflow[cleanup:])

    def test_every_action_is_pinned_to_an_immutable_commit(self):
        action_ref = re.compile(r"^\s*uses:\s+[^#\s]+@([^\s#]+)", re.MULTILINE)
        for workflow_path in (WORKFLOW, ANDROID_CI):
            workflow = workflow_path.read_text(encoding="utf-8")
            refs = action_ref.findall(workflow)
            self.assertTrue(refs, f"no action references found in {workflow_path}")
            for ref in refs:
                self.assertRegex(
                    ref,
                    r"^[0-9a-f]{40}$",
                    f"{workflow_path} contains a mutable action reference: {ref}",
                )

    def test_external_pilot_signing_is_configured_before_app_evaluation(self):
        init_script = PILOT_INIT.read_text(encoding="utf-8")
        early_signing = 'apply(from = rootProject.file("gradle/pilot-signing.gradle"))'
        late_channel = 'apply(from = rootProject.file("gradle/pilot-update.gradle"))'
        self.assertIn(early_signing, init_script)
        self.assertIn(late_channel, init_script)
        self.assertLess(init_script.index(early_signing), init_script.index("afterEvaluate"))
        self.assertGreater(init_script.index(late_channel), init_script.index("afterEvaluate"))

        signing_script = PILOT_SIGNING.read_text(encoding="utf-8")
        self.assertIn("plugins.withId('com.android.application')", signing_script)
        self.assertIn("debugSigning.storeFile = externalStoreFile", signing_script)
        self.assertNotIn("DEVICE_GUARD_PILOT_STORE_FILE", PILOT_CHANNEL.read_text(encoding="utf-8"))

    def test_restored_keystore_identity_is_verified_before_the_expensive_build(self):
        preflight = self.workflow.index("Verify the restored pilot signing identity")
        build = self.workflow.index("Build and verify the enrolled pilot APK")
        self.assertLess(preflight, build)
        self.assertIn("tools/verify_pilot_keystore.py", self.workflow[preflight:build])
        self.assertIn("--store-password-env", self.workflow[preflight:build])


if __name__ == "__main__":
    unittest.main()
