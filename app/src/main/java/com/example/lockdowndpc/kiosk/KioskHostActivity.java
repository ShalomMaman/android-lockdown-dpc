package com.example.lockdowndpc.kiosk;

import android.app.ActivityManager;
import android.app.ActivityOptions;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.graphics.Color;
import android.net.http.SslError;
import android.os.Build;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Log;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.CookieManager;
import android.webkit.SslErrorHandler;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.RenderProcessGoneDetail;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.activity.OnBackPressedCallback;
import androidx.appcompat.app.AppCompatActivity;

import com.example.lockdowndpc.R;
import com.example.lockdowndpc.kiosk.KioskStateMachine.KioskState;
import com.example.lockdowndpc.policy.AuditLog;

/**
 * The controlled HOME/launcher surface, active only while kiosk is enabled.
 *
 * <p>Responsibilities, in order of importance:
 *
 * <ol>
 *   <li>Never fall through to another launcher or browser. Anything that is not
 *       a healthy kiosk target renders the safe error state below.</li>
 *   <li>Hold lock task for the session, including after a reboot, because the
 *       system launches HOME and the kiosk HOME preference points here.</li>
 *   <li>For single-site, host a WebView whose navigation is confined to the
 *       configured origin by {@link KioskNavigationGuard}.</li>
 *   <li>For single-app, launch exactly the configured, validated package.</li>
 * </ol>
 *
 * <p>The component is disabled in the manifest and enabled by
 * {@link KioskController} only while kiosk is active.
 *
 * <p>The base class is {@code AppCompatActivity} for the same reason as the
 * console: below API 33 that is what applies the administrator's chosen display
 * language to this activity's resources. A school that runs the console in
 * Hebrew must not get an English kiosk error screen, and the choice itself is
 * only reachable from the authenticated console, never from here.
 */
public final class KioskHostActivity extends AppCompatActivity {

    private static final String TAG = "KioskHost";
    private static final long RELAUNCH_COOLDOWN_MILLIS = 1_500L;
    private static final long NOTICE_MILLIS = 4_000L;

    private final AdminEntryGesture adminEntryGesture = new AdminEntryGesture();

    private FrameLayout root;
    private WebView webView;
    private LinearLayout errorView;
    private TextView errorMessage;
    private TextView notice;

    private KioskOrigin origin;
    private String siteUrl = "";
    private long lastTargetLaunchAt;
    private boolean lockTaskRequested;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        buildViews();
        // Back is handled through the dispatcher rather than by overriding
        // onBackPressed: at targetSdk 33+ that override is no longer invoked for
        // a back *gesture*, only for the legacy button, so a kiosk that relied on
        // it would let a swipe reach behaviour this activity never sanctioned.
        // The callback is permanently enabled, so back is always consumed here.
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                if (webView != null
                        && webView.getVisibility() == View.VISIBLE
                        && webView.canGoBack()) {
                    webView.goBack();
                }
                // Otherwise the gesture is swallowed. Back never leaves the host.
            }
        });
        // After a reboot the system starts HOME, which is this activity while
        // kiosk is active. Re-asserting here is what returns the device to its
        // configured target without any administrator interaction.
        KioskController.restoreAfterBootOnce(this);
    }

    @Override
    protected void onResume() {
        super.onResume();
        render();
    }

    /** Re-derives the whole screen from stored kiosk state. Safe to call again. */
    private void render() {
        KioskConfigStore.Settings settings = KioskConfigStore.read(this);
        if (settings.state() == KioskState.OFF || settings.state() == KioskState.ARMED) {
            // Kiosk was turned off by an authenticated administrator while this
            // screen was in the background. Release and step aside.
            releaseLockTask();
            finish();
            return;
        }

        enterLockTask();

        KioskConfigValidator.Validation validation =
                KioskConfigValidator.validate(settings.config(), KioskController.resolveTarget(
                        this, settings.config().targetPackage()));
        if (!validation.valid()) {
            // Record the fault so the stored state matches what is on screen and
            // an administrator sees why in the audit log.
            KioskController.reportFault(this, String.join(", ", validation.errors()));
        }
        if (settings.state() == KioskState.FAULT || !validation.valid()) {
            showError(settings.config().mode() == KioskMode.SINGLE_SITE
                    ? getString(R.string.kiosk_host_site_unavailable)
                    : getString(R.string.kiosk_host_target_unavailable));
            return;
        }

        switch (settings.config().mode()) {
            case SINGLE_SITE -> showSite(validation);
            case SINGLE_APP -> launchTarget(settings.config().targetPackage());
            default -> showError(getString(R.string.kiosk_host_not_configured));
        }
    }

    @Override
    protected void onDestroy() {
        if (webView != null) {
            root.removeView(webView);
            webView.destroy();
            webView = null;
        }
        super.onDestroy();
    }

    // ------------------------------------------------------------------ views

    private void buildViews() {
        root = new FrameLayout(this);
        root.setBackgroundColor(Color.parseColor("#F6F8FC"));
        setContentView(root, new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        errorView = new LinearLayout(this);
        errorView.setOrientation(LinearLayout.VERTICAL);
        errorView.setGravity(Gravity.CENTER);
        int padding = dp(24);
        errorView.setPadding(padding, padding, padding, padding);

        TextView title = new TextView(this);
        title.setText(R.string.kiosk_host_error_title);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 22f);
        title.setGravity(Gravity.CENTER);
        errorView.addView(title);

        errorMessage = new TextView(this);
        errorMessage.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f);
        errorMessage.setGravity(Gravity.CENTER);
        errorMessage.setPadding(0, dp(12), 0, dp(20));
        errorView.addView(errorMessage);

        Button retry = new Button(this);
        retry.setText(R.string.kiosk_host_retry);
        retry.setOnClickListener(view -> render());
        errorView.addView(retry);

        root.addView(errorView, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        notice = new TextView(this);
        notice.setVisibility(View.GONE);
        notice.setGravity(Gravity.CENTER);
        notice.setBackgroundColor(Color.parseColor("#174EA6"));
        notice.setTextColor(Color.WHITE);
        notice.setPadding(padding, dp(12), padding, dp(12));
        root.addView(notice, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM));

        root.addView(adminEntryTarget(), new FrameLayout.LayoutParams(
                dp(56), dp(56), Gravity.TOP | Gravity.START));
    }

    /**
     * The deliberate local admin-entry affordance: an unlabeled corner target that
     * only opens the existing console. See {@link KioskAdminEntry}.
     */
    private View adminEntryTarget() {
        View target = new View(this);
        target.setBackgroundColor(Color.TRANSPARENT);
        target.setContentDescription(null);
        target.setOnClickListener(view -> {
            if (adminEntryGesture.onTap(SystemClock.elapsedRealtime())) {
                AuditLog.append(this, getString(R.string.audit_kiosk_admin_entry));
                startActivity(KioskAdminEntry.consoleIntent(
                        this, KioskAdminEntry.SOURCE_KIOSK_GESTURE));
            }
        });
        return target;
    }

    /** Terminal state for this render pass: no target, no site, no fallback. */
    private void showError(String message) {
        if (webView != null) {
            webView.setVisibility(View.GONE);
        }
        notice.setVisibility(View.GONE);
        errorMessage.setText(message);
        errorView.setVisibility(View.VISIBLE);
    }

    /**
     * Non-destructive refusal. A blocked link or download must not throw away the
     * page the user is legitimately working in.
     */
    private void showNotice(String message) {
        notice.setText(message);
        notice.setVisibility(View.VISIBLE);
        notice.removeCallbacks(hideNotice);
        notice.postDelayed(hideNotice, NOTICE_MILLIS);
    }

    private final Runnable hideNotice = () -> notice.setVisibility(View.GONE);

    // ------------------------------------------------------------ single site

    private void showSite(KioskConfigValidator.Validation validation) {
        origin = validation.origin();
        String target = validation.normalizedSiteUrl();
        errorView.setVisibility(View.GONE);
        if (webView == null) {
            webView = createHardenedWebView();
            root.addView(webView, 0, new FrameLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        }
        webView.setVisibility(View.VISIBLE);
        if (!target.equals(siteUrl) || webView.getUrl() == null) {
            siteUrl = target;
            webView.loadUrl(target);
        }
    }

    private WebView createHardenedWebView() {
        WebView view = new WebView(this);
        WebSettings settings = view.getSettings();
        // JavaScript is on because real school portals require it. No
        // JavascriptInterface bridge is ever added, so page script has no path
        // into the DPC.
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setJavaScriptCanOpenWindowsAutomatically(false);
        settings.setSupportMultipleWindows(false);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setAllowFileAccessFromFileURLs(false);
        settings.setAllowUniversalAccessFromFileURLs(false);
        settings.setGeolocationEnabled(false);
        settings.setMediaPlaybackRequiresUserGesture(true);
        settings.setSaveFormData(false);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        settings.setSafeBrowsingEnabled(true);
        settings.setBuiltInZoomControls(false);
        settings.setDisplayZoomControls(false);

        boolean debuggable = (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        WebView.setWebContentsDebuggingEnabled(debuggable);

        CookieManager cookies = CookieManager.getInstance();
        cookies.setAcceptCookie(true);
        cookies.setAcceptThirdPartyCookies(view, false);

        view.setWebViewClient(new ContainedWebViewClient());
        view.setWebChromeClient(new WebChromeClient() {
            @Override
            public boolean onCreateWindow(WebView host, boolean dialog, boolean gesture,
                    android.os.Message resultMsg) {
                // Popups and target=_blank would escape the containment check.
                return false;
            }
        });
        view.setDownloadListener((url, agent, disposition, mime, length) ->
                showNotice(getString(R.string.kiosk_host_download_blocked)));
        view.setLongClickable(false);
        view.setOnLongClickListener(v -> true);
        return view;
    }

    private final class ContainedWebViewClient extends WebViewClient {
        @Override
        public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
            return blockIfOutsideOrigin(request.getUrl() == null ? "" : request.getUrl().toString());
        }

        @Override
        @SuppressWarnings("deprecation")
        public boolean shouldOverrideUrlLoading(WebView view, String url) {
            return blockIfOutsideOrigin(url);
        }

        @Override
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
            // Fail closed: never proceed through a TLS error.
            handler.cancel();
            showError(getString(R.string.kiosk_host_tls));
        }

        @Override
        public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
            if (request != null && request.isForMainFrame()) {
                showError(getString(R.string.kiosk_host_site_unavailable));
            }
        }

        @Override
        public boolean onRenderProcessGone(WebView view, RenderProcessGoneDetail detail) {
            // Without this the renderer taking itself down kills the whole
            // process — and this process is HOME while kiosk holds, so the
            // device would sit in a crash loop with no launcher behind it.
            // Detach and destroy the dead WebView, then show the safe error
            // state with a retry that builds a fresh one.
            Log.e(TAG, "Kiosk WebView renderer gone; crashed="
                    + (detail != null && detail.didCrash()));
            if (webView == view) {
                root.removeView(webView);
                webView.destroy();
                webView = null;
                siteUrl = "";
            } else if (view != null) {
                view.destroy();
            }
            showError(getString(R.string.kiosk_host_renderer_gone));
            return true;
        }

        private boolean blockIfOutsideOrigin(String url) {
            KioskNavigationGuard.Verdict verdict = KioskNavigationGuard.evaluate(origin, url);
            if (verdict.allowed()) {
                return false;
            }
            Log.i(TAG, "Blocked kiosk navigation: " + verdict.reason());
            showNotice(getString(R.string.kiosk_host_blocked_navigation));
            return true;
        }
    }

    // ------------------------------------------------------------- single app

    private void launchTarget(String packageName) {
        long now = SystemClock.elapsedRealtime();
        if (now - lastTargetLaunchAt < RELAUNCH_COOLDOWN_MILLIS) {
            // The target came straight back to us: treat it as unavailable rather
            // than spinning in a relaunch loop.
            showError(getString(R.string.kiosk_host_target_unavailable));
            return;
        }
        Intent launch = getPackageManager().getLaunchIntentForPackage(packageName);
        if (launch == null) {
            showError(getString(R.string.kiosk_host_target_unavailable));
            return;
        }
        launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        lastTargetLaunchAt = now;
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                // API 28+ starts the target directly into lock task.
                ActivityOptions options = ActivityOptions.makeBasic();
                options.setLockTaskEnabled(true);
                startActivity(launch, options.toBundle());
            } else {
                // On Android 8.0/8.1 the host holds lock task and the allowlisted
                // target inherits it.
                startActivity(launch);
            }
            errorView.setVisibility(View.GONE);
        } catch (RuntimeException exception) {
            Log.e(TAG, "Kiosk target launch failed", exception);
            showError(getString(R.string.kiosk_host_target_unavailable));
        }
    }

    // --------------------------------------------------------------- lockTask

    private void enterLockTask() {
        if (lockTaskRequested && isInLockTask()) {
            return;
        }
        try {
            startLockTask();
            lockTaskRequested = true;
        } catch (RuntimeException exception) {
            // Not allowlisted yet (policy apply still in flight) or unsupported.
            Log.e(TAG, "startLockTask failed", exception);
        }
    }

    private void releaseLockTask() {
        if (!isInLockTask()) {
            return;
        }
        try {
            stopLockTask();
        } catch (RuntimeException exception) {
            Log.e(TAG, "stopLockTask failed", exception);
        } finally {
            lockTaskRequested = false;
        }
    }

    private boolean isInLockTask() {
        ActivityManager manager = getSystemService(ActivityManager.class);
        return manager != null
                && manager.getLockTaskModeState() != ActivityManager.LOCK_TASK_MODE_NONE;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
