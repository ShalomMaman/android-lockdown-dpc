package com.example.lockdowndpc.admin;

import static android.app.admin.DevicePolicyManager.ACTION_ADMIN_POLICY_COMPLIANCE;

import android.app.Activity;
import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.os.Bundle;
import android.util.Log;

import com.example.lockdowndpc.policy.LockdownPolicyController;
import com.example.lockdowndpc.policy.PolicyReconciliationCoordinator;

import java.util.concurrent.CompletableFuture;

/** Applies the local Device Owner baseline before returning to the setup wizard. */
public final class PolicyComplianceActivity extends Activity {
    private static final String TAG = "PolicyCompliance";

    private record ComplianceRun(CompletableFuture<Integer> result) {}

    private ComplianceRun run;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setResult(RESULT_CANCELED);
        DevicePolicyManager dpm = getSystemService(DevicePolicyManager.class);
        if (!ACTION_ADMIN_POLICY_COMPLIANCE.equals(getIntent().getAction())
                || dpm == null || !dpm.isDeviceOwnerApp(getPackageName())) {
            finish();
            return;
        }

        if (getLastNonConfigurationInstance() instanceof ComplianceRun previousRun) {
            run = previousRun;
        } else {
            Context appContext = getApplicationContext();
            run = new ComplianceRun(CompletableFuture.supplyAsync(
                    () -> ProvisioningFlow.completeCompliance(
                            () -> LockdownPolicyController.apply(appContext)),
                    PolicyReconciliationCoordinator::runOnPolicyThread));
        }
        run.result().whenComplete((result, error) -> runOnUiThread(() -> {
            if (isDestroyed() || isFinishing()) {
                return;
            }
            if (error == null) {
                setResult(result);
            } else {
                Log.e(TAG, "Baseline policy could not complete", error);
            }
            finish();
        }));
    }

    @Override
    public Object onRetainNonConfigurationInstance() {
        // A recreated activity waits for the same policy pass and delivers its result.
        return run;
    }
}
