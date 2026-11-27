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
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.activity.OnBackPressedCallback;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.example.lockdowndpc.R;
import com.example.lockdowndpc.policy.AllowedAppsStore;
import com.example.lockdowndpc.policy.ManagementModeStore;
import com.example.lockdowndpc.policy.PolicyReconciliationCoordinator;
import com.example.lockdowndpc.policy.PolicyReconciliationCoordinator.ProvisioningResult;
import com.example.lockdowndpc.policy.RemoteEnrolmentGate;
import com.example.lockdowndpc.policy.RemoteTransport;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.zip.CRC32;

/**
 * Applies the local Device Owner baseline before returning to the setup wizard.
 *
 * <p>The pass runs through
 * {@link PolicyReconciliationCoordinator#reconcileForProvisioningWithDiagnostics},
 * so it shares the policy thread, the reconciliation record and the failure
 * handling of every other pass. The wizard receives {@code RESULT_OK} when the
 * pass is verified or the request meets the baseline skip criteria.
 */
public final class PolicyComplianceActivity extends AppCompatActivity {
    private static final String TAG = "PolicyCompliance";
    private static final String DIAGNOSTIC_TAG = "MaakehProvisioning";
    private static final String STATE_FAILURE = "compliance_failure";
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
            new ProvisioningFlow.PendingCompliance(MAIN::post, PolicyComplianceActivity::logResult);

    private final Consumer<ProvisioningResult> deliverResult = this::deliver;
    private Bundle failureState;

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

        // The wizard must wait for verification or for the owner to acknowledge a failure.
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {}
        });
        if (savedInstanceState != null) {
            Bundle savedFailure = savedInstanceState.getBundle(STATE_FAILURE);
            if (savedFailure != null) {
                showFailure(savedFailure);
                return;
            }
        }

        if (!RemoteEnrolmentGate.permitsLocalProvisioning(getIntent())) {
            if (!RemoteTransport.store(this, getIntent())) {
                Log.w(TAG, "remote-enrolment-config-refused");
                finish();
                return;
            }
            Context appContext = getApplicationContext();
            PENDING.request(() -> true, this::showProgress,
                    report -> runCompliance(appContext, true, report), deliverResult);
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
                report -> runCompliance(appContext, false, report),
                deliverResult);
    }

    private static void runCompliance(
            Context context, boolean remote, Consumer<ProvisioningResult> report
    ) {
        PolicyReconciliationCoordinator.reconcileForProvisioningWithDiagnostics(context, result -> {
            try {
                if (result.verified()) {
                    markComplianceDone(context);
                    if (remote) {
                        RemoteTransport.schedule(context);
                    }
                }
            } catch (RuntimeException exception) {
                report.accept(ProvisioningResult.crashed(exception));
                return;
            }
            report.accept(result);
        });
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        if (failureState != null) {
            outState.putBundle(STATE_FAILURE, failureState);
        }
    }

    @Override
    protected void onDestroy() {
        PENDING.detach(deliverResult);
        super.onDestroy();
    }

    private void deliver(ProvisioningResult result) {
        if (isFinishing() || isDestroyed()) {
            return;
        }
        if (result.verified()) {
            setResult(RESULT_OK);
            finish();
        } else {
            List<String> codes = diagnosticCodes(result);
            Bundle state = new Bundle();
            state.putString("steps", String.join("\n", codes));
            state.putString("reference", referenceCode(codes));
            showFailure(state);
        }
    }

    private void showFailure(Bundle state) {
        failureState = state;
        setContentView(R.layout.provisioning_compliance_failure);
        View root = findViewById(R.id.provisioning_failure_root);
        int top = root.getPaddingTop();
        int bottom = root.getPaddingBottom();
        int start = root.getPaddingStart();
        int end = root.getPaddingEnd();
        ViewCompat.setOnApplyWindowInsetsListener(root, (view, insets) -> {
            var safe = insets.getInsets(WindowInsetsCompat.Type.systemBars()
                    | WindowInsetsCompat.Type.displayCutout());
            boolean rtl = view.getLayoutDirection() == View.LAYOUT_DIRECTION_RTL;
            view.setPaddingRelative(start + (rtl ? safe.right : safe.left), top + safe.top,
                    end + (rtl ? safe.left : safe.right), bottom + safe.bottom);
            return insets;
        });
        ViewCompat.requestApplyInsets(root);

        TextView steps = findViewById(R.id.provisioning_failure_steps);
        steps.setText(state.getString("steps"));
        TextView reference = findViewById(R.id.provisioning_failure_reference);
        reference.setText(state.getString("reference"));
        findViewById(R.id.provisioning_failure_finish).setOnClickListener(view -> {
            setResult(RESULT_CANCELED);
            finish();
        });
    }

    private static void logResult(ProvisioningResult result) {
        if (!result.verified()) {
            String reference = referenceCode(diagnosticCodes(result));
            for (String error : result.errors()) {
                String detail = error.matches("[A-Za-z0-9][A-Za-z0-9_./:,-]{0,199}")
                        ? error : shortCode(error);
                Log.e(DIAGNOSTIC_TAG, reference + " " + detail);
            }
        }
    }

    private static List<String> diagnosticCodes(ProvisioningResult result) {
        return result.errors().stream().map(PolicyComplianceActivity::shortCode)
                .distinct().collect(Collectors.toList());
    }

    private static String shortCode(String error) {
        // Keep the step and its qualifier (e.g. the scheme or control ID).
        String[] parts = error.split(":", 3);
        if (!parts[0].matches("[a-z0-9][a-z0-9_-]{0,63}")) {
            return "policy-step-unclassified";
        }
        if (parts.length > 1 && parts[1].matches("[A-Za-z0-9_.-]{1,48}")) {
            return parts[0] + ":" + parts[1];
        }
        return parts[0];
    }

    private static String referenceCode(List<String> codes) {
        String sorted = codes.stream().sorted().collect(Collectors.joining("\n"));
        CRC32 hash = new CRC32();
        hash.update(sorted.getBytes(StandardCharsets.UTF_8));
        return String.format(Locale.ROOT, "MQ-%08X", hash.getValue());
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
