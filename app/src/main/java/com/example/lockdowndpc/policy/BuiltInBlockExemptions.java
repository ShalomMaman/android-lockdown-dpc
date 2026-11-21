package com.example.lockdowndpc.policy;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Administrator-approved exemptions from the built-in block catalogues.
 *
 * <p>With protection active, Device Guard hides every package in
 * {@link LockdownPackages#ALWAYS_BLOCKED} and
 * {@link LockdownPackages#KNOWN_BROWSER_AND_SOCIAL}, and the ordinary allowlist
 * never reaches them. Two narrow, explicit exceptions exist, both off by
 * default:
 *
 * <ol>
 *   <li><b>One browser through the home filter.</b> The administrator may name
 *       exactly one package from {@link #FILTERABLE_BROWSERS}. It is available
 *       only while the home filter's Android settings were read back as
 *       confirmed in this pass and, when a canary is configured, the most recent
 *       canary check for that exact canary passed. Anything less resolves to a
 *       blocked browser, so a filter that turns off or fails read-back blocks the
 *       browser again on the next pass. While the browser is available, link
 *       routing goes to it instead of the blocked-browser screen, which is also
 *       what lets a Trusted Web Activity backed by that browser open.</li>
 *   <li><b>Approved social and messaging applications.</b> An explicit list of
 *       packages from {@link #EXEMPTABLE_SOCIAL}. A listed package is kept
 *       available instead of being hidden by the built-in catalogue. Application stores and browsers can
 *       never be listed: a store would reopen installation, and a browser is
 *       governed by rule 1 alone.</li>
 * </ol>
 *
 * <p>Both are loosening changes. Callers own authentication and the audit line;
 * this class owns the rules, holds no Android type and is tested on the JVM.
 * Removing an exemption takes effect on the very next evaluation: nothing here
 * remembers that a package was once exempt.
 */
public final class BuiltInBlockExemptions {

    private BuiltInBlockExemptions() {}

    /** The error a pass records when a chosen browser had to be blocked again. */
    public static final String BROWSER_FILTER_UNVERIFIED_ERROR = "browser-filter-unverified";

    /** The error a pass records when the chosen browser has no link handler. */
    public static final String BROWSER_ROUTE_UNRESOLVED_ERROR = "browser-route-unresolved";

    /** Built-in application stores. Never exemptable by either rule. */
    public static final Set<String> APP_STORES = immutableSet(
            "com.android.vending",
            "com.sec.android.app.samsungapps",
            "com.xiaomi.mipicks",
            "com.huawei.appmarket",
            "com.oppo.market",
            "com.bbk.appstore",
            "com.amazon.venezia"
    );

    /**
     * Browsers that may be routed through the home filter.
     *
     * <p>The browser half of both built-in catalogues. The search application
     * ({@code com.google.android.googlequicksearchbox}) is deliberately absent:
     * it is a search surface, not a browser an administrator chooses.
     */
    public static final Set<String> FILTERABLE_BROWSERS = immutableSet(
            "com.android.chrome",
            "com.sec.android.app.sbrowser",
            "com.android.browser",
            "com.mi.globalbrowser",
            "com.heytap.browser",
            "com.oppo.browser",
            "com.vivo.browser",
            "com.huawei.browser",
            "org.mozilla.firefox",
            "com.microsoft.emmx",
            "com.opera.browser",
            "com.opera.mini.native",
            "com.brave.browser",
            "com.duckduckgo.mobile.android",
            "com.vivaldi.browser",
            "com.kiwibrowser.browser",
            "com.UCMobile.intl"
    );

    /** Social and messaging applications an administrator may approve one by one. */
    public static final Set<String> EXEMPTABLE_SOCIAL;

    static {
        LinkedHashSet<String> social = new LinkedHashSet<>(LockdownPackages.KNOWN_BROWSER_AND_SOCIAL);
        social.removeAll(FILTERABLE_BROWSERS);
        social.removeAll(APP_STORES);
        EXEMPTABLE_SOCIAL = Collections.unmodifiableSet(social);
    }

    public static boolean isFilterableBrowser(String packageName) {
        return packageName != null && FILTERABLE_BROWSERS.contains(packageName);
    }

    public static boolean isAppStore(String packageName) {
        return packageName != null && APP_STORES.contains(packageName);
    }

    public static boolean isExemptableSocial(String packageName) {
        return packageName != null && EXEMPTABLE_SOCIAL.contains(packageName);
    }

    /**
     * The administrator's stored decision.
     *
     * @param browserPackage   the one browser to route through the filter, or
     *                         {@code null} for none
     * @param socialExemptions approved social and messaging packages
     */
    public record Settings(String browserPackage, Set<String> socialExemptions) {
        public static final Settings NONE = new Settings(null, Set.of());

        public Settings {
            if (browserPackage != null && browserPackage.isEmpty()) {
                browserPackage = null;
            }
            if (browserPackage != null && !isFilterableBrowser(browserPackage)) {
                throw new IllegalArgumentException("browser-not-filterable");
            }
            LinkedHashSet<String> social = new LinkedHashSet<>();
            if (socialExemptions != null) {
                for (String packageName : socialExemptions) {
                    if (!isExemptableSocial(packageName)) {
                        throw new IllegalArgumentException("package-not-exemptable");
                    }
                    social.add(packageName);
                }
            }
            socialExemptions = Collections.unmodifiableSet(social);
        }

        public boolean any() {
            return browserPackage != null || !socialExemptions.isEmpty();
        }

        public Settings withBrowser(String packageName) {
            return new Settings(packageName, socialExemptions);
        }

        public Settings withSocial(String packageName, boolean exempt) {
            LinkedHashSet<String> social = new LinkedHashSet<>(socialExemptions);
            if (exempt) {
                social.add(packageName);
            } else {
                social.remove(packageName);
            }
            return new Settings(browserPackage, social);
        }

        /**
         * Whether moving from {@code this} to {@code next} makes anything newly
         * available. Only such changes need the administrator session; a pure
         * removal tightens the device and can always be applied immediately.
         */
        public boolean loosensTo(Settings next) {
            if (next.browserPackage != null && !next.browserPackage.equals(browserPackage)) {
                return true;
            }
            return !socialExemptions.containsAll(next.socialExemptions);
        }
    }

    /** What the home filter has proven in the current pass. */
    public record FilterEvidence(
            boolean androidSettingsConfirmed,
            boolean canaryConfigured,
            boolean canaryPassed
    ) {
        public static final FilterEvidence NONE = new FilterEvidence(false, false, false);

        /** Android settings confirmed and, when a canary exists, the canary passed. */
        public boolean verified() {
            return androidSettingsConfirmed && (!canaryConfigured || canaryPassed);
        }
    }

    /** What the browser exemption resolves to for one pass. */
    public enum BrowserState {
        /** No browser chosen. Every browser stays blocked, as before this feature. */
        OFF(false),
        /** Chosen, and the home filter is verified: the browser is available. */
        ACTIVE(true),
        /** Chosen, but the home filter is not verified: the browser stays blocked. */
        FILTER_UNVERIFIED(false),
        /** Chosen, but the canary has not passed for the current configuration. */
        CANARY_UNVERIFIED(false),
        /** Chosen, but the package is not installed on this device. */
        NOT_INSTALLED(false),
        /**
         * Chosen and the filter verified, but links could not be routed to the
         * browser and read back, so it was blocked again.
         */
        LINK_ROUTE_UNVERIFIED(false);

        private final boolean available;

        BrowserState(boolean available) {
            this.available = available;
        }

        public boolean browserAvailable() {
            return available;
        }
    }

    /** Resolves the browser exemption from the stored choice and this pass's evidence. */
    public static BrowserState browserState(
            Settings settings,
            boolean browserInstalled,
            FilterEvidence evidence
    ) {
        if (settings == null || settings.browserPackage() == null) {
            return BrowserState.OFF;
        }
        if (!browserInstalled) {
            return BrowserState.NOT_INSTALLED;
        }
        if (evidence == null || !evidence.androidSettingsConfirmed()) {
            return BrowserState.FILTER_UNVERIFIED;
        }
        if (!evidence.verified()) {
            return BrowserState.CANARY_UNVERIFIED;
        }
        return BrowserState.ACTIVE;
    }

    /** The browser this pass may leave available, or {@code null}. */
    public static String exemptBrowser(Settings settings, BrowserState state) {
        return state != null && state.browserAvailable() && settings != null
                ? settings.browserPackage()
                : null;
    }

    /**
     * Whether the policy pass must leave {@code packageName} available.
     *
     * <p>An exemption is an explicit administrator approval, so like the Google
     * Play compatibility exception it wins over the built-in catalogue and the
     * ordinary allow/block list. Management, essential-package and kiosk rules
     * are applied after it and are unaffected.
     *
     * @param exemptBrowser the result of {@link #exemptBrowser} for this pass
     */
    public static boolean keepsAvailable(
            String packageName,
            Settings settings,
            String exemptBrowser
    ) {
        if (packageName == null || settings == null || isAppStore(packageName)) {
            return false;
        }
        if (isFilterableBrowser(packageName)) {
            return packageName.equals(exemptBrowser);
        }
        return isExemptableSocial(packageName)
                && settings.socialExemptions().contains(packageName);
    }

    /**
     * Whether the browser-backed WebView provider must stay unsuspended because
     * it is the browser the administrator routed through the filter.
     */
    public static boolean keepsWebViewProviderUnsuspended(String provider, String exemptBrowser) {
        return provider != null && provider.equals(exemptBrowser);
    }

    /** Where an {@code http} or {@code https} view intent is routed. */
    public enum LinkRoute {
        /** Device Guard's blocked-browser screen. */
        BLOCKED_BROWSER,
        /** The administrator's exempt browser. */
        EXEMPT_BROWSER
    }

    /**
     * Routing for a link.
     *
     * <p>{@code requestedBrowser} is the browser a Trusted Web Activity bound to,
     * or {@code null} for an ordinary link. An ordinary link goes to the exempt
     * browser when there is one. A Trusted Web Activity goes there only when it
     * runs in that same browser; one bound to any other browser stays on the
     * blocked screen, because every other browser is still hidden.
     */
    public static LinkRoute route(String requestedBrowser, String exemptBrowser) {
        if (exemptBrowser == null) {
            return LinkRoute.BLOCKED_BROWSER;
        }
        if (requestedBrowser == null || requestedBrowser.equals(exemptBrowser)) {
            return LinkRoute.EXEMPT_BROWSER;
        }
        return LinkRoute.BLOCKED_BROWSER;
    }

    private static Set<String> immutableSet(String... values) {
        LinkedHashSet<String> result = new LinkedHashSet<>();
        Collections.addAll(result, values);
        return Collections.unmodifiableSet(result);
    }
}
