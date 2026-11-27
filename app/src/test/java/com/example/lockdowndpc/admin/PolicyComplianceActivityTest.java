package com.example.lockdowndpc.admin;

import static android.app.Activity.RESULT_CANCELED;
import static android.app.Activity.RESULT_OK;
import static android.app.admin.DevicePolicyManager.ACTION_ADMIN_POLICY_COMPLIANCE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.robolectric.Shadows.shadowOf;

import android.app.Application;
import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Looper;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.example.lockdowndpc.R;
import com.example.lockdowndpc.policy.PolicyReconciliationCoordinator;
import com.example.lockdowndpc.policy.PolicyReconciliationCoordinator.ProvisioningResult;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;
import org.robolectric.annotation.Implementation;
import org.robolectric.annotation.Implements;
import org.robolectric.shadows.ShadowLog;

import java.util.List;
import java.util.function.Consumer;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 32, qualifiers = "iw-rIL-ldrtl", shadows = PolicyComplianceActivityTest.PolicyPass.class)
public final class PolicyComplianceActivityTest {
    @Before
    public void setUp() {
        PolicyPass.completion = null;
        PolicyPass.failToStart = false;
        PolicyPass.starts = 0;
        Context context = RuntimeEnvironment.getApplication();
        DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
        assertTrue(shadowOf(dpm).setDeviceOwner(LockdownAdminReceiver.componentName(context)));
    }

    @Test
    public void failedPassShowsAllDistinctCodesAndWaitsForFinish() {
        try (var controller = Robolectric.buildActivity(PolicyComplianceActivity.class, request()).setup()) {
            var activity = controller.get();
            List<String> errors = List.of(
                    "link-filter-target-unverified:https",
                    "system-policy:private_dns:failed:not-in-force",
                    "browser-suspension-unverified",
                    "package-policy-state-mismatch:com.example.browser",
                    "kiosk-lock-task-release-unverified",
                    "system-policy:factory_reset:failed:not-in-force",
                    "link-filter-target-unverified:http",
                    "system-policy:private_dns:failed:read-denied");
            PolicyPass.completion.accept(new ProvisioningResult(false, errors));
            shadowOf(Looper.getMainLooper()).idle();

            assertFalse(activity.isFinishing());
            assertFalse(PolicyComplianceActivity.isComplianceDone(activity));
            assertEquals(View.LAYOUT_DIRECTION_RTL,
                    activity.findViewById(R.id.provisioning_failure_root).getLayoutDirection());
            activity.getOnBackPressedDispatcher().onBackPressed();
            assertFalse(activity.isFinishing());
            assertEquals(String.join("\n",
                    "link-filter-target-unverified:https",
                    "system-policy:private_dns",
                    "browser-suspension-unverified",
                    "package-policy-state-mismatch:com.example.browser",
                    "kiosk-lock-task-release-unverified",
                    "system-policy:factory_reset",
                    "link-filter-target-unverified:http"),
                    text(activity, R.id.provisioning_failure_steps));
            assertEquals("קוד תקלה", text(activity, R.id.provisioning_failure_reference_label));
            String reference = text(activity, R.id.provisioning_failure_reference);
            assertTrue(reference.matches("MQ-[0-9A-F]{8}"));
            assertEquals(View.TEXT_DIRECTION_LTR,
                    activity.findViewById(R.id.provisioning_failure_reference).getTextDirection());
            var logs = ShadowLog.getLogsForTag("MaakehProvisioning");
            assertEquals(errors.size(), logs.size());
            for (int i = 0; i < errors.size(); i++) {
                var log = logs.get(i);
                assertEquals(Log.ERROR, log.type);
                assertTrue(log.msg.endsWith(" " + errors.get(i)));
                assertEquals(reference, log.msg.split(" ", 2)[0]);
            }

            controller.recreate();
            activity = controller.get();
            assertEquals(reference, text(activity, R.id.provisioning_failure_reference));
            assertEquals(1, PolicyPass.starts);
            assertFalse(activity.isFinishing());
            Button finish = activity.findViewById(R.id.provisioning_failure_finish);
            assertSame(activity.findViewById(R.id.provisioning_failure_scroll).getParent(),
                    finish.getParent());
            assertEquals("סיום", finish.getText().toString());
            finish.performClick();

            assertTrue(activity.isFinishing());
            assertEquals(RESULT_CANCELED, shadowOf(activity).getResultCode());
        }
    }

    @Test
    public void verifiedPassReturnsOkImmediatelyWithoutFailureScreen() {
        try (var controller = Robolectric.buildActivity(PolicyComplianceActivity.class, request()).setup()) {
            var activity = controller.get();
            assertNotNull(PolicyPass.completion);
            PolicyPass.completion.accept(new ProvisioningResult(true, List.of()));
            shadowOf(Looper.getMainLooper()).idle();

            assertTrue(activity.isFinishing());
            assertTrue(PolicyComplianceActivity.isComplianceDone(activity));
            assertEquals(RESULT_OK, shadowOf(activity).getResultCode());
            assertNull(activity.findViewById(R.id.provisioning_failure_root));
        }
    }

    @Test
    public void passThatThrowsShowsCrashCodeAndWaitsForFinish() {
        PolicyPass.failToStart = true;
        try (var controller = Robolectric.buildActivity(PolicyComplianceActivity.class, request()).setup()) {
            var activity = controller.get();
            shadowOf(Looper.getMainLooper()).idle();

            assertEquals("policy-pass-crashed:IllegalStateException",
                    text(activity, R.id.provisioning_failure_steps));
            assertFalse(activity.isFinishing());
            activity.findViewById(R.id.provisioning_failure_finish).performClick();
            assertTrue(activity.isFinishing());
            assertEquals(RESULT_CANCELED, shadowOf(activity).getResultCode());
        }
    }

    @Test
    @Config(application = FailingProvisioningPreferences.class)
    public void markComplianceDoneThrowShowsFailureAndReturnsCanceled() {
        try (var controller = Robolectric.buildActivity(PolicyComplianceActivity.class, request()).setup()) {
            var activity = controller.get();
            var app = (FailingProvisioningPreferences) activity.getApplication();
            assertNotNull(PolicyPass.completion);
            app.failProvisioningPreferences = true;
            try {
                PolicyPass.completion.accept(new ProvisioningResult(true, List.of()));
            } finally {
                app.failProvisioningPreferences = false;
            }
            shadowOf(Looper.getMainLooper()).idle();

            assertEquals("policy-pass-crashed:SecurityException",
                    text(activity, R.id.provisioning_failure_steps));
            assertFalse(PolicyComplianceActivity.isComplianceDone(activity));
            assertFalse(activity.isFinishing());
            assertEquals(RESULT_CANCELED, shadowOf(activity).getResultCode());
            activity.findViewById(R.id.provisioning_failure_finish).performClick();
            assertTrue(activity.isFinishing());
            assertEquals(RESULT_CANCELED, shadowOf(activity).getResultCode());
        }
    }

    private static Intent request() {
        return new Intent(RuntimeEnvironment.getApplication(), PolicyComplianceActivity.class)
                .setAction(ACTION_ADMIN_POLICY_COMPLIANCE);
    }

    private static String text(PolicyComplianceActivity activity, int id) {
        TextView view = activity.findViewById(id);
        return view.getText().toString();
    }

    public static class FailingProvisioningPreferences extends Application {
        boolean failProvisioningPreferences;

        @Override
        public SharedPreferences getSharedPreferences(String name, int mode) {
            if (failProvisioningPreferences && "provisioning".equals(name)) {
                throw new SecurityException("Provisioning preferences unavailable");
            }
            return super.getSharedPreferences(name, mode);
        }
    }

    @Implements(PolicyReconciliationCoordinator.class)
    public static class PolicyPass {
        static Consumer<ProvisioningResult> completion;
        static boolean failToStart;
        static int starts;

        @Implementation
        protected static void reconcileForProvisioningWithDiagnostics(
                Context context, Consumer<ProvisioningResult> callback
        ) {
            starts++;
            if (failToStart) {
                throw new IllegalStateException("Policy queue unavailable");
            }
            completion = callback;
        }
    }
}
