package com.example.lockdowndpc.kiosk;

import java.util.Set;

/**
 * The single decision point for "may the kiosk WebView navigate here?".
 *
 * <p>Pure, so the containment rules are proven off-device. The Android side
 * ({@code KioskHostActivity}) only forwards URLs into {@link #evaluate} and
 * renders the verdict.
 *
 * <p>Scope note: this guards <em>top-level navigation</em>. Sub-resource loads
 * (scripts, fonts, XHR to a CDN) are not restricted here, because real school
 * portals are cross-origin by construction. Single-site kiosk is navigation
 * containment, not a network firewall.
 */
public final class KioskNavigationGuard {

    /** Schemes that always get an explicit, named refusal. */
    private static final Set<String> ESCAPE_SCHEMES = Set.of(
            "intent",
            "android-app",
            "javascript",
            "data",
            "blob",
            "file",
            "content",
            "about",
            "market",
            "tel",
            "sms",
            "smsto",
            "mailto",
            "geo",
            "ftp",
            "ws",
            "wss"
    );

    private KioskNavigationGuard() {}

    public enum Decision {
        ALLOW,
        BLOCK
    }

    public record Verdict(Decision decision, String reason) {
        public boolean allowed() {
            return decision == Decision.ALLOW;
        }

        static Verdict allow() {
            return new Verdict(Decision.ALLOW, "same-origin");
        }

        static Verdict block(String reason) {
            return new Verdict(Decision.BLOCK, reason);
        }
    }

    public static Verdict evaluate(KioskOrigin origin, String url) {
        if (origin == null) {
            return Verdict.block("no-origin-configured");
        }
        String scheme = KioskUrl.schemeOf(url);
        if (ESCAPE_SCHEMES.contains(scheme)) {
            return Verdict.block("blocked-scheme:" + scheme);
        }
        if ("http".equals(scheme)) {
            return Verdict.block("insecure-scheme:http");
        }
        KioskUrl.Result normalized = KioskUrl.normalize(url);
        if (!normalized.ok()) {
            return Verdict.block(normalized.error());
        }
        if (!origin.matches(normalized.value())) {
            return Verdict.block("external-origin");
        }
        return Verdict.allow();
    }
}
