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

    /** The stored Chrome approval flag as found on disk, read on its own. */
    public enum ChromeFlag { ABSENT, PRESENT, UNREADABLE }

    /**
     * Classifies the raw stored record for the teardown guard. Any malformed
     * part of the record — the Chrome flag or any social pin — is
     * {@link ChromeFlag#UNREADABLE}, which the guard treats like a saved
     * approval. A pass, by contrast, withholds every exemption on such a record.
     */
    public static ChromeFlag chromeFlag(Object rawChrome, Object rawSocialPins) {
        if (rawChrome != null && !(rawChrome instanceof Boolean)) {
            return ChromeFlag.UNREADABLE;
        }
        if (rawSocialPins != null) {
            if (!(rawSocialPins instanceof Set<?> pins)) {
                return ChromeFlag.UNREADABLE;
            }
            LinkedHashMap<String, String> parsed = new LinkedHashMap<>();
            for (Object entry : pins) {
                if (!(entry instanceof String text) || text.indexOf('=') <= 0) {
                    return ChromeFlag.UNREADABLE;
                }
                parsed.put(text.substring(0, text.indexOf('=')), text.substring(text.indexOf('=') + 1));
            }
            try {
                new Settings(false, parsed);
            } catch (IllegalArgumentException exception) {
                return ChromeFlag.UNREADABLE;
            }
        }
        return Boolean.TRUE.equals(rawChrome) ? ChromeFlag.PRESENT : ChromeFlag.ABSENT;
    }

    /** Whether a home filter change turns the filter off or removes its CA. */
    public static boolean isFilterTeardown(HomeFilterPolicy.Settings before, HomeFilterPolicy.Settings after) {
        if (before == null || after == null || !before.configured()) {
            return false;
        }
        return (before.enabled() && !after.enabled()) || (!before.removeCa() && after.removeCa());
    }

    /** Whether stored settings still carry a teardown Android has not finished. */
    public static boolean hasPendingTeardown(HomeFilterPolicy.Settings settings) {
        return settings != null && settings.configured() && (!settings.enabled() || settings.removeCa());
    }

    /** The answer to "may the home filter be turned off or its CA removed now?". */
    public enum TeardownVerdict {
        ALLOWED,
        /** A Chrome approval is saved; remove it first. */
        CHROME_APPROVED,
        /** The stored approval record could not be read; treated as approved. */
        APPROVAL_UNREADABLE,
        /** Android does not report Chrome hidden, suspended or uninstalled right now. */
        CHROME_NOT_CONTAINED
    }

    /**
     * The teardown guard, from live facts only and failing closed. While
     * protection is on, Chrome must be observed hidden, suspended (the existing
     * WebView-provider containment) or not installed; an unreadable observation
     * refuses. While protection is paused every app is shown by design, so only
     * the approval itself is checked then.
     */
    public static TeardownVerdict teardownVerdict(
            ChromeFlag flag,
            Observed chromeObserved,
            boolean protectionActive
    ) {
        if (flag == ChromeFlag.PRESENT) {
            return TeardownVerdict.CHROME_APPROVED;
        }
        if (flag != ChromeFlag.ABSENT) {
            return TeardownVerdict.APPROVAL_UNREADABLE;
        }
        if (!protectionActive) {
            return TeardownVerdict.ALLOWED;
        }
        return chromeObserved == Observed.HIDDEN
                || chromeObserved == Observed.SUSPENDED
                || chromeObserved == Observed.NOT_INSTALLED
                ? TeardownVerdict.ALLOWED
                : TeardownVerdict.CHROME_NOT_CONTAINED;
    }

    /**
     * The settings reconciliation enforces while a pending teardown is held:
     * the filter stays on with its CA, and the stored request is left pending.
     */
    public static HomeFilterPolicy.Settings withTeardownHeld(HomeFilterPolicy.Settings settings) {
        return new HomeFilterPolicy.Settings(settings.config(), true, settings.ca(), false);
    }

    /**
     * Whether Chrome may be approved now: the home filter is on, nothing is
     * pending, and a CA the profile carries is installed. Approving over a
     * pending teardown would let that teardown finish under the approval.
     */
    public static boolean filterSteadyForChrome(
            HomeFilterPolicy.Settings settings,
            HomeFilterPolicy.State caState
    ) {
        return settings != null && settings.configured() && settings.enabled() && !settings.removeCa()
                && (settings.ca() == null || caState == HomeFilterPolicy.State.CONFIRMED);
    }

    /**
     * What the credentials lock must be. It follows the saved approval, not the
     * pass: on while Chrome is approved (or the record is unreadable); released
     * only when the teardown guard itself would allow a teardown; otherwise —
     * for example after a refused hide — left exactly as it is.
     *
     * @return {@code TRUE} to set, {@code FALSE} to release, {@code null} to leave
     */
    public static Boolean credentialsLockTarget(ChromeFlag flag, TeardownVerdict verdict) {
        if (flag != ChromeFlag.ABSENT) {
            return Boolean.TRUE;
        }
        return verdict == TeardownVerdict.ALLOWED ? Boolean.FALSE : null;
    }

    /**
     * The home filter settings one pass enforces, computed once and handed to
     * every step that depends on them — system policy, packages and the
     * filter's own reconciliation — so a held teardown looks "enabled" to all.
     *
     * @param stored    what is stored
     * @param effective what the pass enforces: the stored settings, or the
     *                  stored settings with a pending teardown held
     * @param hold      why a pending teardown is held, or {@code null}
     */
    public record PassFilter(
            HomeFilterPolicy.Settings stored,
            HomeFilterPolicy.Settings effective,
            TeardownVerdict hold
    ) {
        public boolean held() {
            return hold != null;
        }

        /**
         * Whether the home filter counts as on for system policy — the one
         * answer every policy writer uses, in a pass or outside one
         * (maintenance open and restore, pause). A held teardown is on;
         * settings that could not be read ({@code null}) are on too, failing
         * closed exactly like {@code HomeFilterController.isEnabled}.
         */
        public static boolean enforcedEnabled(PassFilter filter) {
            return filter == null || filter.stored() == null || filter.effective().enabled();
        }

        /** Holds a pending teardown unless the guard allows it now. */
        public static PassFilter forPass(
                HomeFilterPolicy.Settings stored,
                java.util.function.Supplier<TeardownVerdict> guard
        ) {
            if (hasPendingTeardown(stored)) {
                TeardownVerdict verdict = guard.get();
                if (verdict != TeardownVerdict.ALLOWED) {
                    return new PassFilter(stored, withTeardownHeld(stored), verdict);
                }
            }
            return new PassFilter(stored, stored, null);
        }
    }

    /** The credentials lock as Android reports it. Any call may throw. */
    public interface CredentialsLock {
        boolean isSet();

        void set(boolean locked);
    }

    /** Brings the lock to {@code required} and reads it back; {@code false} on a mismatch. */
    public static boolean reconcileCredentialsLock(boolean required, CredentialsLock lock, List<String> errors) {
        try {
            if (lock.isSet() != required) {
                lock.set(required);
            }
            if (lock.isSet() == required) {
                return true;
            }
            errors.add("credentials-lock-unverified:" + required);
        } catch (RuntimeException exception) {
            errors.add("credentials-lock:" + exception.getClass().getSimpleName());
        }
        return false;
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
