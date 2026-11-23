package com.example.lockdowndpc.admin;

import static android.app.admin.DevicePolicyManager.ACTION_ADMIN_POLICY_COMPLIANCE;

import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.util.Log;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.activity.OnBackPressedCallback;
import androidx.appcompat.app.AppCompatActivity;

import com.example.lockdowndpc.R;
import com.example.lockdowndpc.policy.AllowedAppsStore;
import com.example.lockdowndpc.policy.ManagementModeStore;
import com.example.lockdowndpc.policy.RemoteEnrolmentGate;
import com.example.lockdowndpc.policy.RemoteProvisioning;
import com.example.lockdowndpc.policy.RemoteTestScheduler;
import com.example.lockdowndpc.policy.PolicyReconciliationCoordinator;

import java.util.function.IntConsumer;

/**
 * Applies the local Device Owner baseline before returning to the setup wizard.
 *
 * <p>The pass runs through {@link PolicyReconciliationCoordinator#reconcileForProvisioning},
 * so it shares the policy thread, the reconciliation record and the failure
 * handling of every other pass. The wizard receives {@code RESULT_OK} when the
 * pass is verified or the request meets the baseline skip criteria.
 */
public final class PolicyComplianceActivity extends AppCompatActivity {
    private static final String TAG = "PolicyCompliance";
    private static final String PREFS = "provisioning";
    private static final String KEY_COMPLIANCE_DONE = "compliance_done";
    /** {@code Settings.Secure.USER_SETUP_COMPLETE}, which the SDK does not expose. */
    private static final String USER_SETUP_COMPLETE = "user_setup_complete";
    private static final Handler MAIN = new Handler(Looper.getMainLooper());

    /**
     * The pass in flight, shared by every instance of this activity. Read and
     * written on the main thread only. It survives recreation, so a rotated or
     * relaunched activity waits for the same pass instead of starting a second
     * one.
     */
    private static final ProvisioningFlow.PendingCompliance PENDING =
            new ProvisioningFlow.PendingCompliance(MAIN::post);

    private final IntConsumer deliverResult = this::deliver;

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
        if (!RemoteEnrolmentGate.permitsLocalProvisioning(getIntent())) {
            if (!RemoteProvisioning.store(this, getIntent())) {
                Log.w(TAG, "remote-enrolment-config-refused");
                finish();
                return;
            }
            Context appContext = getApplicationContext();
            PENDING.request(() -> true, this::showProgress,
                    report -> PolicyReconciliationCoordinator.reconcileForProvisioning(appContext, verified -> {
                        if (Boolean.TRUE.equals(verified)) {
                            markComplianceDone(appContext);
                            RemoteTestScheduler.schedule(appContext);
                        }
                        report.accept(verified);
                    }), deliverResult);
            return;
        }
        if (!ManagementModeStore.selectLocal(this)) {
            if (!ManagementModeStore.read(this).usesLocalPolicy()) {
                finish();
                return;
            }
            Log.w(TAG, "Local mode could not be saved; continuing with baseline verification");
        }

        Context appContext = getApplicationContext();
        PENDING.request(
                () -> ProvisioningFlow.shouldApplyBaseline(
                        isUserSetupComplete(appContext), isComplianceDone(appContext),
                        AllowedAppsStore.getPolicyState(appContext)
                                == AllowedAppsStore.PolicyState.ACTIVE),
                this::showProgress,
                report -> PolicyReconciliationCoordinator.reconcileForProvisioning(
                        appContext,
                        verified -> {
                            if (Boolean.TRUE.equals(verified)) {
                                markComplianceDone(appContext);
                            } else {
                                Log.e(TAG, "Baseline policy was not verified");
                            }
                            report.accept(verified);
                        }),
                deliverResult);
    }

    @Override
    protected void onDestroy() {
        PENDING.detach(deliverResult);
        super.onDestroy();
    }

    private void deliver(int resultCode) {
        if (isFinishing() || isDestroyed()) {
            return;
        }
        setResult(resultCode);
        finish();
    }

    private void showProgress() {
        // Back would hand the wizard a cancelled result while the baseline is
        // still being applied, so it is ignored until the pass reports.
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                // This screen closes itself when the pass completes.
            }
        });

        int padding = Math.round(TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_DIP, 24, getResources().getDisplayMetrics()));
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER);
        root.setPadding(padding, padding, padding, padding);

        ProgressBar progress = new ProgressBar(this);
        progress.setIndeterminate(true);
        root.addView(progress, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        TextView message = new TextView(this);
        message.setText(R.string.provisioning_compliance_progress);
        message.setGravity(Gravity.CENTER);
        message.setTextAlignment(TextView.TEXT_ALIGNMENT_CENTER);
        message.setPaddingRelative(0, padding, 0, 0);
        root.addView(message, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        setContentView(root, new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
    }

    private static boolean isUserSetupComplete(Context context) {
        try {
            return Settings.Secure.getInt(context.getContentResolver(), USER_SETUP_COMPLETE, 0) == 1;
        } catch (SecurityException exception) {
            // An unreadable setup state leaves the stored compliance flag as
            // the only reason to skip the baseline.
            Log.w(TAG, "Setup state is not readable", exception);
            return false;
        }
    }

    static boolean isComplianceDone(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .getBoolean(KEY_COMPLIANCE_DONE, false);
    }

    private static void markComplianceDone(Context context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putBoolean(KEY_COMPLIANCE_DONE, true)
                .commit();
    }
}
