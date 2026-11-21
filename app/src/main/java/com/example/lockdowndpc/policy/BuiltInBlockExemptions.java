package com.example.lockdowndpc.policy;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Administrator-approved exemptions from the built-in block catalogues.
 *
 * <p>With protection active, Device Guard hides every package in
 * {@link LockdownPackages#ALWAYS_BLOCKED} and
 * {@link LockdownPackages#KNOWN_BROWSER_AND_SOCIAL}. Two narrow exceptions exist,
 * both off by default, and both bound to a signing identity rather than to a
 * package name:
 *
 * <ol>
 *   <li><b>Chrome through the home filter.</b> Only {@link #CHROME}, only when
 *       its current signer is {@link #CHROME_RELEASE_SIGNER_SHA256}, and only
 *       while every condition Device Guard itself enforces and reads back on
 *       each pass holds: the home filter's always-on VPN in lockdown on the
 *       approved, signer-verified VPN package; the global PAC proxy; the
 *       filter CA where the profile carries one; and Chrome's managed
 *       configuration ({@link #chromeRestrictions}). Nothing is time-based and
 *       no free-standing network check is consulted, so the decision is the
 *       same on every pass, including the first one after boot.</li>
 *   <li><b>Approved social and messaging applications</b> from the positive
 *       catalogue {@link #EXEMPTABLE_SOCIAL}, each pinned at approval time to
 *       the signer digest it had then. A different signer under the same name
 *       is not the approved application and stays blocked.</li>
 * </ol>
 *
 * <p>No Android type and no resource identifier appears here, so every rule is
 * an ordinary JVM test. {@link ChromeFilterExemption} owns the ordering of
 * grant and revocation; the controller supplies the Android gateway.
 */
public final class BuiltInBlockExemptions {

    private BuiltInBlockExemptions() {}

    /** The only browser that may be exempted. */
    public static final String CHROME = "com.android.chrome";

    /**
     * SHA-256 of Google's release signing certificate for {@link #CHROME},
     * lower-case hex. A Chrome package signed by anything else is never
     * exempted.
     */
    public static final String CHROME_RELEASE_SIGNER_SHA256 =
            "f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83";

    public static final String BROWSER_FILTER_UNVERIFIED_ERROR = "browser-filter-unverified";
    public static final String BROWSER_ROUTE_UNRESOLVED_ERROR = "browser-route-unresolved";
    public static final String CHROME_REVOCATION_UNVERIFIED_ERROR = "chrome-exemption-revocation-unverified";
    public static final String SOCIAL_REVOCATION_UNVERIFIED_ERROR = "social-exemption-revocation-unverified";

    /** Built-in application stores. Never exemptable. */
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
     * Social and messaging applications an administrator may approve one by
     * one. A positive list: a package added to a built-in catalogue later is
     * not exemptable until it is reviewed and added here.
     */
    public static final Set<String> EXEMPTABLE_SOCIAL = immutableSet(
            "com.facebook.katana",
            "com.facebook.lite",
            "com.instagram.android",
            "com.zhiliaoapp.musically",
            "com.ss.android.ugc.trill",
            "com.twitter.android",
            "com.snapchat.android",
            "com.reddit.frontpage",
            "com.pinterest",
            "com.linkedin.android",
            "com.discord",
            "org.telegram.messenger",
            "com.telegram.messenger",
            "com.whatsapp",
            "com.google.android.youtube",
            "com.google.android.apps.youtube.music"
    );

    public static boolean isAppStore(String packageName) {
        return packageName != null && APP_STORES.contains(packageName);
    }

    public static boolean isExemptableSocial(String packageName) {
        return packageName != null && EXEMPTABLE_SOCIAL.contains(packageName);
    }

    /**
     * Whether {@code packageName} is in any built-in block catalogue. Such a
     * package may not serve as the home filter's VPN either: a catalogue
     * browser entered as the VPN package would otherwise inherit the VPN's
     * visibility override.
     */
    public static boolean isBuiltInBlocked(String packageName) {
        return packageName != null
                && (LockdownPackages.ALWAYS_BLOCKED.contains(packageName)
                    || LockdownPackages.KNOWN_BROWSER_AND_SOCIAL.contains(packageName));
    }

    /** Lower-cases hex digests and drops separators; blank stays blank. */
    public static String normalizeDigest(String digest) {
        return LockdownPackages.normalizeDigest(digest);
    }

    /**
     * The administrator's stored decision.
     *
     * @param chromeThroughFilter whether Chrome may be exempted while the
     *                            filter conditions hold
     * @param socialPins          approved social package to the signer digest
     *                            recorded at approval
     */
    public record Settings(boolean chromeThroughFilter, Map<String, String> socialPins) {
        public static final Settings NONE = new Settings(false, Map.of());

        public Settings {
            LinkedHashMap<String, String> pins = new LinkedHashMap<>();
            if (socialPins != null) {
                for (Map.Entry<String, String> entry : socialPins.entrySet()) {
                    String packageName = entry.getKey();
                    String digest = normalizeDigest(entry.getValue());
                    if (!isExemptableSocial(packageName)) {
                        throw new IllegalArgumentException("package-not-exemptable");
                    }
                    if (digest.isEmpty()) {
                        throw new IllegalArgumentException("signer-required");
                    }
                    pins.put(packageName, digest);
                }
            }
            socialPins = Collections.unmodifiableMap(pins);
        }

        public boolean any() {
            return chromeThroughFilter || !socialPins.isEmpty();
        }

        public Settings withChrome(boolean enabled) {
            return new Settings(enabled, socialPins);
        }

        /** Approves {@code packageName} pinned to {@code signerSha256}. */
        public Settings withSocial(String packageName, String signerSha256) {
            LinkedHashMap<String, String> pins = new LinkedHashMap<>(socialPins);
            pins.put(packageName, signerSha256);
            return new Settings(chromeThroughFilter, pins);
        }

        public Settings withoutSocial(String packageName) {
            LinkedHashMap<String, String> pins = new LinkedHashMap<>(socialPins);
            pins.remove(packageName);
            return new Settings(chromeThroughFilter, pins);
        }

        /**
         * Whether moving to {@code next} makes anything newly available,
         * including re-pinning an approved application to a different signer.
         * Only such a change needs the administrator session.
         */
        public boolean loosensTo(Settings next) {
            if (next.chromeThroughFilter && !chromeThroughFilter) {
                return true;
            }
            for (Map.Entry<String, String> entry : next.socialPins.entrySet()) {
                if (!entry.getValue().equals(socialPins.get(entry.getKey()))) {
                    return true;
                }
            }
            return false;
        }

        /** Packages whose exemption {@code next} withdraws. */
        public Set<String> revokedBy(Settings next) {
            LinkedHashSet<String> revoked = new LinkedHashSet<>();
            if (chromeThroughFilter && !next.chromeThroughFilter) {
                revoked.add(CHROME);
            }
            for (Map.Entry<String, String> entry : socialPins.entrySet()) {
                if (!entry.getValue().equals(next.socialPins.get(entry.getKey()))) {
                    revoked.add(entry.getKey());
                }
            }
            return Collections.unmodifiableSet(revoked);
        }

        /** A stable, non-secret text form for audit entries. */
        public String auditText() {
            StringBuilder text = new StringBuilder("chrome=").append(chromeThroughFilter);
            for (Map.Entry<String, String> entry : socialPins.entrySet()) {
                text.append(",").append(entry.getKey()).append("@")
                        .append(entry.getValue(), 0, Math.min(12, entry.getValue().length()));
            }
            return text.toString();
        }
    }

    /**
     * Whether a social package may stay available this pass: it is approved and
     * its current signer is the one pinned at approval.
     *
     * @param currentSignerSha256 the installed package's single current signer,
     *                            or {@code ""} when none could be read
     */
    public static boolean keepsSocialAvailable(
            String packageName,
            Settings settings,
            String currentSignerSha256
    ) {
        if (settings == null || !isExemptableSocial(packageName)) {
            return false;
        }
        String pinned = settings.socialPins().get(packageName);
        String observed = normalizeDigest(currentSignerSha256);
        return pinned != null && !observed.isEmpty() && pinned.equals(observed);
    }

    /** Whether the installed Chrome is Google's release build. */
    public static boolean chromeSignerVerified(String currentSignerSha256) {
        return CHROME_RELEASE_SIGNER_SHA256.equals(normalizeDigest(currentSignerSha256));
    }

    /**
     * What the home filter has proven on this pass, from Android read-back only.
     *
     * @param androidSettingsConfirmed the always-on VPN in lockdown on the
     *                                 approved, signer-verified VPN package
     *                                 with no exemptions; the global PAC proxy;
     *                                 the profile restrictions; private DNS
     * @param caSatisfied              the profile carries no CA, or it carries
     *                                 one that is installed and not being removed
     * @param vpnPackageAllowed        the VPN package is not a built-in blocked
     *                                 browser, store or social application
     */
    public record FilterEvidence(
            boolean androidSettingsConfirmed,
            boolean caSatisfied,
            boolean vpnPackageAllowed
    ) {
        public static final FilterEvidence NONE = new FilterEvidence(false, false, false);

        public boolean verified() {
            return androidSettingsConfirmed && caSatisfied && vpnPackageAllowed;
        }
    }

    /** The CA condition, from the stored profile and the CA read-back. */
    public static boolean caSatisfied(boolean profileHasCa, boolean removalPending, boolean caConfirmed) {
        if (!profileHasCa) {
            return true;
        }
        return !removalPending && caConfirmed;
    }

    /** Key names of Chrome's managed configuration (Chrome Enterprise policies). */
    public static final String PROXY_MODE = "ProxyMode";
    public static final String PROXY_PAC_URL = "ProxyPacUrl";
    public static final String QUIC_ALLOWED = "QuicAllowed";
    public static final String DNS_OVER_HTTPS_MODE = "DnsOverHttpsMode";
    public static final String INCOGNITO_MODE_AVAILABILITY = "IncognitoModeAvailability";
    public static final String FORCE_GOOGLE_SAFE_SEARCH = "ForceGoogleSafeSearch";
    public static final String FORCE_YOUTUBE_RESTRICT = "ForceYouTubeRestrict";
    public static final String BROWSER_SIGNIN = "BrowserSignin";
    public static final String DEVELOPER_TOOLS_AVAILABILITY = "DeveloperToolsAvailability";
    public static final String URL_BLOCKLIST = "URLBlocklist";

    /** Internal Chrome pages that could inspect or bypass the proxy settings. */
    public static final String[] BLOCKED_CHROME_URLS = {
            "chrome://flags",
            "chrome://net-internals",
            "chrome://proxy"
    };

    /**
     * Chrome's required managed configuration for the given PAC URL.
     *
     * <p>Values use the types Chrome's Android policy reader accepts: strings,
     * booleans, integers and a string array for list policies. Custom Tabs and
     * Trusted Web Activities run inside the Chrome package, so this
     * configuration governs them too.
     */
    public static Map<String, Object> chromeRestrictions(String pacUrl) {
        if (pacUrl == null || pacUrl.isBlank()) {
            throw new IllegalArgumentException("pac-url-required");
        }
        LinkedHashMap<String, Object> values = new LinkedHashMap<>();
        values.put(PROXY_MODE, "pac_script");
        values.put(PROXY_PAC_URL, pacUrl);
        values.put(QUIC_ALLOWED, Boolean.FALSE);
        values.put(DNS_OVER_HTTPS_MODE, "off");
        values.put(INCOGNITO_MODE_AVAILABILITY, 1);
        values.put(FORCE_GOOGLE_SAFE_SEARCH, Boolean.TRUE);
        values.put(FORCE_YOUTUBE_RESTRICT, 2);
        values.put(BROWSER_SIGNIN, 0);
        values.put(DEVELOPER_TOOLS_AVAILABILITY, 2);
        values.put(URL_BLOCKLIST, BLOCKED_CHROME_URLS.clone());
        return Collections.unmodifiableMap(values);
    }

    /**
     * Whether a read-back configuration carries every required value with the
     * same type. Extra keys are allowed: an administrator may restrict Chrome
     * further.
     */
    public static boolean restrictionsSatisfied(Map<String, Object> readBack, Map<String, Object> required) {
        if (readBack == null) {
            return false;
        }
        for (Map.Entry<String, Object> entry : required.entrySet()) {
            Object actual = readBack.get(entry.getKey());
            Object expected = entry.getValue();
            if (expected instanceof String[] expectedList) {
                if (!(actual instanceof String[] actualList)
                        || !new LinkedHashSet<>(Arrays.asList(actualList))
                            .containsAll(Arrays.asList(expectedList))) {
                    return false;
                }
            } else if (!Objects.equals(expected, actual)) {
                return false;
            }
        }
        return true;
    }

    /**
     * The configuration to write: what is there now with every required value
     * laid over it. A required list keeps any extra entries already present.
     */
    public static Map<String, Object> mergeRestrictions(Map<String, Object> current, Map<String, Object> required) {
        LinkedHashMap<String, Object> merged = new LinkedHashMap<>();
        if (current != null) {
            merged.putAll(current);
        }
        for (Map.Entry<String, Object> entry : required.entrySet()) {
            Object expected = entry.getValue();
            Object existing = merged.get(entry.getKey());
            if (expected instanceof String[] expectedList && existing instanceof String[] existingList) {
                LinkedHashSet<String> union = new LinkedHashSet<>(Arrays.asList(existingList));
                union.addAll(Arrays.asList(expectedList));
                merged.put(entry.getKey(), union.toArray(new String[0]));
            } else {
                merged.put(entry.getKey(), expected);
            }
        }
        return merged;
    }

    private static Set<String> immutableSet(String... values) {
        LinkedHashSet<String> result = new LinkedHashSet<>();
        Collections.addAll(result, values);
        return Collections.unmodifiableSet(result);
    }
}
