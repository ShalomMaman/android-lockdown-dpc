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
import com.example.lockdowndpc.policy.PolicyReconciliationCoordinator;

/**
 * Applies the local Device Owner baseline before returning to the setup wizard.
 *
 * <p>The pass runs through {@link PolicyReconciliationCoordinator#reconcileForProvisioning},
 * so it shares the policy thread, the reconciliation record and the failure
 * handling of every other pass. The wizard receives {@code RESULT_OK} only for a
 * verified pass.
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
    private static PendingCompliance pending;

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

        showProgress();
        // Back would hand the wizard a cancelled result while the baseline is
        // still being applied, so it is ignored until the pass reports.
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                // Swallowed: this screen closes itself when the pass completes.
            }
        });

        if (pending == null) {
            pending = new PendingCompliance();
            Context appContext = getApplicationContext();
            boolean applyBaseline = ProvisioningFlow.shouldApplyBaseline(
                    isUserSetupComplete(appContext), isComplianceDone(appContext));
            PendingCompliance started = pending;
            ProvisioningFlow.completeCompliance(
                    applyBaseline,
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
                    resultCode -> MAIN.post(() -> started.complete(resultCode)));
        }
        pending.attach(this);
    }

    @Override
    protected void onDestroy() {
        if (pending != null) {
            pending.detach(this);
        }
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
            // Unreadable: rely on the stored flag, and apply the baseline when
            // neither says setup is over. Applying is the protective default.
            Log.w(TAG, "Setup state is not readable", exception);
            return false;
        }
    }

    private static boolean isComplianceDone(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .getBoolean(KEY_COMPLIANCE_DONE, false);
    }

    private static void markComplianceDone(Context context) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putBoolean(KEY_COMPLIANCE_DONE, true)
                .commit();
    }

    /** One compliance pass and the activity, if any, waiting for its result. Main thread only. */
    private static final class PendingCompliance {
        private PolicyComplianceActivity host;

        void attach(PolicyComplianceActivity activity) {
            host = activity;
        }

        void detach(PolicyComplianceActivity activity) {
            if (host == activity) {
                host = null;
            }
        }

        void complete(int code) {
            if (host == null) {
                // Nobody is waiting: the wizard abandoned this request. Drop the
                // result so a later request decides afresh rather than receiving
                // a stale answer. A verified pass is remembered by the stored
                // flag, so that request still succeeds without re-applying.
                if (pending == this) {
                    pending = null;
                }
                return;
            }
            PolicyComplianceActivity activity = host;
            // The pass is over: the next request decides afresh.
            if (pending == this) {
                pending = null;
            }
            host = null;
            activity.deliver(code);
        }
    }
}
