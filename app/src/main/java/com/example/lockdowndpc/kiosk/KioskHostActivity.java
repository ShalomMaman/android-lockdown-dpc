package com.example.lockdowndpc.kiosk;

import android.app.ActivityManager;
import android.app.ActivityOptions;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Bitmap;
import android.net.http.SslError;
import android.os.Build;
import android.os.Bundle;
import android.os.SystemClock;
import android.util.Log;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.CookieManager;
import android.webkit.SslErrorHandler;
import android.webkit.WebChromeClient;
import android.webkit.WebBackForwardList;
import android.webkit.WebHistoryItem;
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
import com.example.lockdowndpc.security.AppLabelSanitizer;

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
 *   <li>For single-app, launch exactly the configured, validated package, and
 *       stay reachable afterwards: the HOME key comes back here (see
 *       {@link KioskRecoveryPolicy}) and lands on the contained kiosk home, which
 *       is where the administrator gesture lives. Coming back is not leaving —
 *       nothing here unlocks anything, and the PIN remains the only authority
 *       that changes or exits kiosk.</li>
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
    private static final long NOTICE_MILLIS = 4_000L;

    private final AdminEntryGesture adminEntryGesture = new AdminEntryGesture();
    private final int[] rootLocation = new int[2];

    private FrameLayout root;
    private WebView webView;
    private LinearLayout errorView;
    private TextView errorMessage;
    private LinearLayout homeView;
    private TextView homeMessage;
    private TextView notice;

    private KioskOrigin origin;
    private String siteUrl = "";
    /**
     * Whether this host instance has already started its single-app target. It is
     * what turns every later resume — the HOME key, or a target that closed
     * itself — into the contained kiosk home instead of an immediate relaunch.
     * Per instance on purpose: a reboot or a process restart builds a fresh host,
     * which is the pass that must go straight back to the configured target.
     */
    private boolean targetLaunched;
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
                    goBackWithinOrigin();
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
        boolean usable = validation.valid() && settings.state() != KioskState.FAULT;
        KioskMode mode = settings.config().mode();
        switch (KioskRecoveryPolicy.surfaceFor(mode, usable, targetLaunched)) {
            case SITE -> showSite(validation);
            case LAUNCH_TARGET -> launchTarget(settings.config().targetPackage());
            case RECOVERY_HOME -> showKioskHome(settings.config().targetPackage());
            default -> showError(errorTextFor(mode, usable));
        }
    }

    private String errorTextFor(KioskMode mode, boolean usable) {
        if (usable) {
            // A valid configuration that resolves to no surface at all can only be
            // a mode this build does not render.
            return getString(R.string.kiosk_host_not_configured);
        }
        return mode == KioskMode.SINGLE_SITE
                ? getString(R.string.kiosk_host_site_unavailable)
                : getString(R.string.kiosk_host_target_unavailable);
    }

    /**
     * Counts administrator corner taps without consuming them.
     *
     * <p>0.5.0 laid an invisible, click-consuming 56 dp view over the top of the
     * leading edge, which is exactly where a school portal puts its logo or its
     * hamburger menu — in either direction, because the target mirrors with the
     * layout. Observing the dispatch and forwarding the event leaves the page's
     * own controls working and the gesture unchanged.
     */
    @Override
    public boolean dispatchTouchEvent(MotionEvent event) {
        if (event.getActionMasked() == MotionEvent.ACTION_DOWN && root != null) {
            root.getLocationInWindow(rootLocation);
            boolean rightToLeft = root.getLayoutDirection() == View.LAYOUT_DIRECTION_RTL;
            if (AdminEntryCorner.contains(
                    event.getX() - rootLocation[0],
                    event.getY() - rootLocation[1],
                    root.getWidth(),
                    dp(AdminEntryCorner.SIZE_DP),
                    rightToLeft)) {
                onAdminCornerTap();
            }
        }
        return super.dispatchTouchEvent(event);
    }

    /**
     * The deliberate local admin-entry affordance. Completing the gesture only
     * starts the existing console, which begins on its locked PIN screen. See
     * {@link KioskAdminEntry}.
     */
    private void onAdminCornerTap() {
        if (!adminEntryGesture.onTap(SystemClock.elapsedRealtime())) {
            return;
        }
        AuditLog.append(this, getString(R.string.audit_kiosk_admin_entry));
        startActivity(KioskAdminEntry.consoleIntent(this, KioskAdminEntry.SOURCE_KIOSK_GESTURE));
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
        // The direction follows the *resolved* strings, not the system locale. On
        // a device set to another right-to-left language with the display
        // language left on "System default", resources fall back to English while
        // the configuration still reports RTL; mirroring an English kiosk screen
        // would also move the administrator corner away from "the side the text
        // starts from", which is how both languages describe it.
        root.setLayoutDirection(getResources().getBoolean(R.bool.use_rtl_layout)
                ? View.LAYOUT_DIRECTION_RTL
                : View.LAYOUT_DIRECTION_LTR);
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

        homeView = new LinearLayout(this);
        homeView.setOrientation(LinearLayout.VERTICAL);
        homeView.setGravity(Gravity.CENTER);
        homeView.setPadding(padding, padding, padding, padding);
        homeView.setVisibility(View.GONE);

        TextView homeTitle = new TextView(this);
        homeTitle.setText(R.string.kiosk_home_title);
        homeTitle.setTextSize(TypedValue.COMPLEX_UNIT_SP, 22f);
        homeTitle.setGravity(Gravity.CENTER);
        homeView.addView(homeTitle);

        homeMessage = new TextView(this);
        homeMessage.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f);
        homeMessage.setGravity(Gravity.CENTER);
        homeMessage.setPadding(0, dp(12), 0, dp(20));
        homeView.addView(homeMessage);

        Button resume = new Button(this);
        resume.setText(R.string.kiosk_home_resume);
        resume.setOnClickListener(view -> {
            targetLaunched = false;
            render();
        });
        homeView.addView(resume);

        root.addView(homeView, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        notice = new TextView(this);
        notice.setVisibility(View.GONE);
        notice.setGravity(Gravity.CENTER);
        notice.setBackgroundColor(Color.parseColor("#174EA6"));
        notice.setTextColor(Color.WHITE);
        notice.setPadding(padding, dp(12), padding, dp(12));
        // A blocked link or download appears in place with no focus change, so a
        // screen reader is told to read it rather than being left silent.
        notice.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        errorMessage.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        root.addView(notice, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
                Gravity.BOTTOM));
    }

    /** Terminal state for this render pass: no target, no site, no fallback. */
    private void showError(String message) {
        if (webView != null) {
            webView.setVisibility(View.GONE);
        }
        notice.setVisibility(View.GONE);
        homeView.setVisibility(View.GONE);
        errorMessage.setText(message);
        errorView.setVisibility(View.VISIBLE);
    }

    /**
     * The contained kiosk home of a single-app kiosk.
     *
     * <p>What the HOME key lands on once the target has been started. It offers
     * exactly two things: a way back into the pinned application, and the
     * administrator corner gesture that every surface of this activity carries.
     * It grants nothing — the console it can reach still opens on its PIN screen.
     */
    private void showKioskHome(String packageName) {
        if (webView != null) {
            webView.setVisibility(View.GONE);
        }
        notice.setVisibility(View.GONE);
        errorView.setVisibility(View.GONE);
        // The label comes from the target's own manifest, so its language is
        // unknown here and it is isolated without a forced direction.
        homeMessage.setText(getString(
                R.string.kiosk_home_body, BidiText.bidiIsolated(targetLabel(packageName))));
        homeView.setVisibility(View.VISIBLE);
    }

    /** Best-effort display name for the pinned target; the package name otherwise. */
    private String targetLabel(String packageName) {
        try {
            PackageManager pm = getPackageManager();
            CharSequence label = pm.getApplicationLabel(pm.getApplicationInfo(packageName, 0));
            String sanitized = AppLabelSanitizer.sanitize(label == null ? null : label.toString());
            return sanitized == null || sanitized.isBlank() ? packageName : sanitized;
        } catch (PackageManager.NameNotFoundException | RuntimeException exception) {
            return packageName;
        }
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
        homeView.setVisibility(View.GONE);
        if (webView == null) {
            webView = createHardenedWebView();
            root.addView(webView, 0, new FrameLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        }
        webView.setVisibility(View.VISIBLE);
        String current = webView.getUrl();
        if (!target.equals(siteUrl)
                || current == null
                || !KioskNavigationGuard.evaluate(origin, current).allowed()) {
            siteUrl = target;
            resetToConfiguredSite(webView, false);
        }
    }

    /** Back may only select the immediately preceding same-origin history item. */
    private void goBackWithinOrigin() {
        WebBackForwardList history = webView.copyBackForwardList();
        int previousIndex = history == null ? -1 : history.getCurrentIndex() - 1;
        WebHistoryItem previous = previousIndex < 0 ? null : history.getItemAtIndex(previousIndex);
        String previousUrl = previous == null ? null : previous.getUrl();
        if (KioskNavigationGuard.evaluate(origin, previousUrl).allowed()) {
            webView.goBack();
            return;
        }
        Log.i(TAG, "Discarded unsafe kiosk history entry");
        resetToConfiguredSite(webView, true);
    }

    /** Stops an escaped navigation, removes its history, and reasserts the configured site. */
    private void resetToConfiguredSite(WebView view, boolean notify) {
        if (view == null || siteUrl.isEmpty()) {
            return;
        }
        view.stopLoading();
        view.clearHistory();
        view.loadUrl(siteUrl);
        if (notify) {
            showNotice(getString(R.string.kiosk_host_blocked_navigation));
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
        public void onPageStarted(WebView view, String url, Bitmap favicon) {
            enforcePostNavigation(view, url);
        }

        @Override
        public void doUpdateVisitedHistory(WebView view, String url, boolean isReload) {
            // Covers same-document History API changes, which do not pass
            // through shouldOverrideUrlLoading.
            enforcePostNavigation(view, url);
        }

        @Override
        public void onPageCommitVisible(WebView view, String url) {
            enforcePostNavigation(view, url);
        }

        @Override
        public void onPageFinished(WebView view, String url) {
            enforcePostNavigation(view, url);
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

        /**
         * Re-checks the URL after WebView has accepted a navigation. Android does
         * not promise shouldOverrideUrlLoading for POST requests, server
         * redirects, script assignment, or every history mutation.
         */
        private void enforcePostNavigation(WebView view, String url) {
            KioskNavigationGuard.Verdict verdict = KioskNavigationGuard.evaluate(origin, url);
            if (verdict.allowed()) {
                return;
            }
            Log.i(TAG, "Reasserting kiosk site after navigation: " + verdict.reason());
            resetToConfiguredSite(view, true);
        }
    }

    // ------------------------------------------------------------- single app

    /**
     * Starts the pinned target exactly once per host instance.
     *
     * <p>There is no relaunch cooldown any more, because there is no relaunch: a
     * target that comes straight back leaves {@link #targetLaunched} set, so the
     * next render lands on the contained kiosk home rather than trying again. That
     * removes the loop the cooldown existed to break, and replaces an error screen
     * claiming the app is unavailable with a screen that says what is true.
     */
    private void launchTarget(String packageName) {
        Intent launch = getPackageManager().getLaunchIntentForPackage(packageName);
        if (launch == null) {
            showError(getString(R.string.kiosk_host_target_unavailable));
            return;
        }
        launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        targetLaunched = true;
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
            homeView.setVisibility(View.GONE);
        } catch (RuntimeException exception) {
            Log.e(TAG, "Kiosk target launch failed", exception);
            targetLaunched = false;
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
