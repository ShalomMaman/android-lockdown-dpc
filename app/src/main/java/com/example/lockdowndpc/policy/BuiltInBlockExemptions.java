package com.example.lockdowndpc.policy;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Administrator-approved exemptions from the built-in block catalogues.
 *
 * <p>With protection active, Device Guard hides every package in
 * {@link LockdownPackages#ALWAYS_BLOCKED} and
 * {@link LockdownPackages#KNOWN_BROWSER_AND_SOCIAL}. Two narrow exceptions
 * exist, both off by default:
 *
 * <ol>
 *   <li><b>Chrome.</b> {@link #CHROME} is shown only when an administrator
 *       exempted it, the home filter is enabled, protection is active, the
 *       installed Chrome is Google's release build, and Chrome's managed
 *       configuration ({@link #chromeRestrictions}) was written and read back.
 *       That configuration makes Chrome itself fail closed: a mandatory PAC
 *       script, so Chrome never falls back to a direct connection. Network
 *       enforcement for every application remains the home filter's always-on
 *       VPN in lockdown; Chrome does not re-prove it.</li>
 *   <li><b>Approved social and messaging applications</b> from the positive
 *       catalogue {@link #EXEMPTABLE_SOCIAL}, each pinned at approval to its
 *       single current signer. Any other signer, or a signer that cannot be
 *       read, keeps the package hidden.</li>
 * </ol>
 *
 * <p>No Android type appears here, so every rule is an ordinary JVM test.
 */
public final class BuiltInBlockExemptions {

    private BuiltInBlockExemptions() {}

    /** The only browser that may be exempted. */
    public static final String CHROME = "com.android.chrome";

    /** SHA-256 of Google's release signing certificate for {@link #CHROME}, lower-case hex. */
    public static final String CHROME_RELEASE_SIGNER_SHA256 =
            "f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83";

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

    /** What Android reports for a package. {@link #UNKNOWN} when a read threw. */
    public enum Observed { VISIBLE, HIDDEN, SUSPENDED, DISABLED, NOT_INSTALLED, UNKNOWN }

    public static boolean isAppStore(String packageName) {
        return packageName != null && APP_STORES.contains(packageName);
    }

    public static boolean isExemptableSocial(String packageName) {
        return packageName != null && EXEMPTABLE_SOCIAL.contains(packageName);
    }

    /**
     * Whether {@code packageName} is in a built-in block catalogue. Such a
     * package may not serve as the home filter's VPN: it would inherit the VPN's
     * visibility override.
     */
    public static boolean isBuiltInBlocked(String packageName) {
        return packageName != null
                && (LockdownPackages.ALWAYS_BLOCKED.contains(packageName)
                    || LockdownPackages.KNOWN_BROWSER_AND_SOCIAL.contains(packageName));
    }

    /**
     * The administrator's stored decision.
     *
     * @param chrome     whether Chrome is exempted
     * @param socialPins approved social package to the signer digest recorded at approval
     */
    public record Settings(boolean chrome, Map<String, String> socialPins) {
        public static final Settings NONE = new Settings(false, Map.of());

        public Settings {
            LinkedHashMap<String, String> pins = new LinkedHashMap<>();
            if (socialPins != null) {
                for (Map.Entry<String, String> entry : socialPins.entrySet()) {
                    String digest = LockdownPackages.normalizeDigest(entry.getValue());
                    if (!isExemptableSocial(entry.getKey())) {
                        throw new IllegalArgumentException("package-not-exemptable");
                    }
                    if (digest.isEmpty()) {
                        throw new IllegalArgumentException("signer-required");
                    }
                    pins.put(entry.getKey(), digest);
                }
            }
            socialPins = Collections.unmodifiableMap(pins);
        }

        public Settings withChrome(boolean exempted) {
            return new Settings(exempted, socialPins);
        }

        /** Approves {@code packageName} pinned to {@code signerSha256}. */
        public Settings withSocial(String packageName, String signerSha256) {
            LinkedHashMap<String, String> pins = new LinkedHashMap<>(socialPins);
            pins.put(packageName, signerSha256);
            return new Settings(chrome, pins);
        }

        public Settings withoutSocial(String packageName) {
            LinkedHashMap<String, String> pins = new LinkedHashMap<>(socialPins);
            pins.remove(packageName);
            return new Settings(chrome, pins);
        }

        /**
         * Whether moving to {@code next} makes anything newly available,
         * re-pinning to another signer included. Only such a change needs the
         * administrator session; a removal is accepted without it.
         */
        public boolean loosensTo(Settings next) {
            if (next.chrome && !chrome) {
                return true;
            }
            for (Map.Entry<String, String> entry : next.socialPins.entrySet()) {
                if (!entry.getValue().equals(socialPins.get(entry.getKey()))) {
                    return true;
                }
            }
            return false;
        }

        /** A stable, non-secret text form for audit entries and read-back binding. */
        public String auditText() {
            StringBuilder text = new StringBuilder("chrome=").append(chrome);
            for (Map.Entry<String, String> entry : socialPins.entrySet()) {
                text.append(",").append(entry.getKey()).append("@")
                        .append(entry.getValue(), 0, Math.min(12, entry.getValue().length()));
            }
            return text.toString();
        }
    }

    /**
     * Whether a social package may be shown: approved, and its single current
     * signer is the one pinned at approval. An unreadable signer ({@code ""})
     * never matches.
     */
    public static boolean socialVisible(String packageName, Settings settings, String currentSignerSha256) {
        if (settings == null || !isExemptableSocial(packageName)) {
            return false;
        }
        String pinned = settings.socialPins().get(packageName);
        String observed = LockdownPackages.normalizeDigest(currentSignerSha256);
        return pinned != null && !observed.isEmpty() && pinned.equals(observed);
    }

    public static boolean chromeSignerVerified(String currentSignerSha256) {
        return CHROME_RELEASE_SIGNER_SHA256.equals(LockdownPackages.normalizeDigest(currentSignerSha256));
    }

    // --- Chrome managed configuration (Chrome Enterprise policy names) ----------------
    //
    // ProxyPacMandatory exists only as a field of the ProxySettings dictionary,
    // and Chrome reads it from nowhere else (Chromium
    // components/policy/resources/templates/policy_definitions/Miscellaneous/ProxySettings.yaml,
    // supported_on android:30-; components/proxy_config/proxy_policy_handler.cc).
    // On Android a dictionary policy is delivered as one JSON-encoded string
    // (components/policy/tools/generate_policy_source.py, TYPE_MAP 'dict' ->
    // restriction type 'string'), and the separate, deprecated proxy policies
    // are not part of Chrome's Android schema at all.

    public static final String PROXY_SETTINGS = "ProxySettings";

    /** Separate proxy policies, removed so ProxySettings is the only proxy source. */
    public static final List<String> SEPARATE_PROXY_POLICIES = List.of(
            "ProxyMode", "ProxyServerMode", "ProxyServer", "ProxyPacUrl", "ProxyBypassList");

    public static final String INCOGNITO_MODE_AVAILABILITY = "IncognitoModeAvailability";
    public static final String DNS_OVER_HTTPS_MODE = "DnsOverHttpsMode";
    public static final String DEVELOPER_TOOLS_AVAILABILITY = "DeveloperToolsAvailability";
    public static final String BROWSER_SIGNIN = "BrowserSignin";

    /**
     * The ProxySettings dictionary as Chrome's Android JSON string: a PAC script
     * that is mandatory, so Chrome never falls back to a direct connection when
     * the script is unavailable or invalid.
     */
    public static String proxySettingsJson(String pacUrl) {
        if (pacUrl == null || pacUrl.isBlank()) {
            throw new IllegalArgumentException("pac-url-required");
        }
        return "{\"ProxyMode\":\"pac_script\",\"ProxyPacUrl\":\"" + jsonEscape(pacUrl)
                + "\",\"ProxyPacMandatory\":true}";
    }

    /** Chrome's required managed configuration for the given PAC URL. */
    public static Map<String, Object> chromeRestrictions(String pacUrl) {
        LinkedHashMap<String, Object> values = new LinkedHashMap<>();
        values.put(PROXY_SETTINGS, proxySettingsJson(pacUrl));
        values.put(INCOGNITO_MODE_AVAILABILITY, 1);
        values.put(DNS_OVER_HTTPS_MODE, "off");
        values.put(DEVELOPER_TOOLS_AVAILABILITY, 2);
        values.put(BROWSER_SIGNIN, 0);
        return Collections.unmodifiableMap(values);
    }

    /**
     * Whether a read-back configuration carries every required value, with the
     * same type, and no separate proxy policy. Other keys are allowed: an
     * administrator may restrict Chrome further.
     */
    public static boolean restrictionsSatisfied(Map<String, Object> readBack, String pacUrl) {
        if (readBack == null) {
            return false;
        }
        for (String separate : SEPARATE_PROXY_POLICIES) {
            if (readBack.containsKey(separate)) {
                return false;
            }
        }
        for (Map.Entry<String, Object> entry : chromeRestrictions(pacUrl).entrySet()) {
            if (!Objects.equals(entry.getValue(), readBack.get(entry.getKey()))) {
                return false;
            }
        }
        return true;
    }

    /** What to write: the current configuration, required values laid over it, separate proxy keys removed. */
    public static Map<String, Object> mergeRestrictions(Map<String, Object> current, String pacUrl) {
        LinkedHashMap<String, Object> merged = new LinkedHashMap<>();
        if (current != null) {
            merged.putAll(current);
        }
        SEPARATE_PROXY_POLICIES.forEach(merged::remove);
        merged.putAll(chromeRestrictions(pacUrl));
        return merged;
    }

    private static String jsonEscape(String value) {
        StringBuilder escaped = new StringBuilder(value.length());
        for (char c : value.toCharArray()) {
            if (c == '"' || c == '\\') {
                escaped.append('\\').append(c);
            } else if (c < 0x20) {
                escaped.append(String.format(java.util.Locale.ROOT, "\\u%04x", (int) c));
            } else {
                escaped.append(c);
            }
        }
        return escaped.toString();
    }

    private static Set<String> immutableSet(String... values) {
        LinkedHashSet<String> result = new LinkedHashSet<>();
        Collections.addAll(result, values);
        return Collections.unmodifiableSet(result);
    }
}
