package com.example.lockdowndpc.policy;

import java.util.List;
import java.util.Map;

/**
 * The Chrome half of the exemptions, run at the start of every protected pass.
 *
 * <p>Order is the whole point:
 * <ul>
 *   <li>When Chrome may be shown, its managed configuration is written and read
 *       back <em>here</em>, before the package pass can unhide it.</li>
 *   <li>When it may not, it is hidden <em>here</em>, before anything else in the
 *       pass. The one exception is Chrome acting as the WebView provider: it
 *       keeps the existing behaviour (never hidden, suspended by the pass).</li>
 *   <li>Any exception is a "not shown" decision.</li>
 * </ul>
 *
 * <p>No state is kept between passes: each pass decides from the stored
 * administrator choice and what Android reads back now.
 */
public final class ChromeFilterExemption {

    private ChromeFilterExemption() {}

    public static final String CONFIG_UNVERIFIED_ERROR = "chrome-exemption-config-unverified";
    public static final String HIDE_UNVERIFIED_ERROR = "chrome-exemption-hide-unverified";

    /** Why Chrome is, or is not, shown on this pass. */
    public enum Decision {
        NOT_EXEMPTED(false),
        PROTECTION_PAUSED(false),
        FILTER_DISABLED(false),
        NOT_INSTALLED(false),
        SIGNER_UNVERIFIED(false),
        CONFIG_UNVERIFIED(false),
        ERROR(false),
        SHOWN(true);

        private final boolean shown;

        Decision(boolean shown) {
            this.shown = shown;
        }

        public boolean shown() {
            return shown;
        }
    }

    /** Android, as seen by this decision. Any call may throw. */
    public interface Gateway {
        boolean installed();

        /** Chrome's single current signer, lower-case hex, or {@code ""}. */
        String currentSignerSha256();

        Map<String, Object> restrictions();

        void setRestrictions(Map<String, Object> values);

        boolean webViewProvider();

        void setHidden(boolean hidden);

        boolean hidden();
    }

    /**
     * Decides, and performs the step that must come first.
     *
     * @param exempted         the administrator exempted Chrome
     * @param protectionActive protection is on (not paused)
     * @param filterEnabled    the home filter is enabled in its store
     * @param pacUrl           the home filter's PAC URL, or {@code null}
     */
    public static Decision prepare(
            boolean exempted,
            boolean protectionActive,
            boolean filterEnabled,
            String pacUrl,
            Gateway gateway,
            List<String> errors
    ) {
        Decision decision;
        try {
            decision = decide(exempted, protectionActive, filterEnabled, pacUrl, gateway);
        } catch (RuntimeException exception) {
            errors.add("chrome-exemption:" + exception.getClass().getSimpleName());
            decision = Decision.ERROR;
        }
        if (decision == Decision.CONFIG_UNVERIFIED) {
            errors.add(CONFIG_UNVERIFIED_ERROR);
        }
        if (!decision.shown()) {
            hideFirst(gateway, errors);
        }
        return decision;
    }

    private static Decision decide(
            boolean exempted,
            boolean protectionActive,
            boolean filterEnabled,
            String pacUrl,
            Gateway gateway
    ) {
        if (!exempted) {
            return Decision.NOT_EXEMPTED;
        }
        if (!protectionActive) {
            return Decision.PROTECTION_PAUSED;
        }
        if (!filterEnabled || pacUrl == null || pacUrl.isBlank()) {
            return Decision.FILTER_DISABLED;
        }
        if (!gateway.installed()) {
            return Decision.NOT_INSTALLED;
        }
        if (!BuiltInBlockExemptions.chromeSignerVerified(gateway.currentSignerSha256())) {
            return Decision.SIGNER_UNVERIFIED;
        }
        Map<String, Object> current = gateway.restrictions();
        if (!BuiltInBlockExemptions.restrictionsSatisfied(current, pacUrl)) {
            gateway.setRestrictions(BuiltInBlockExemptions.mergeRestrictions(current, pacUrl));
        }
        return BuiltInBlockExemptions.restrictionsSatisfied(gateway.restrictions(), pacUrl)
                ? Decision.SHOWN
                : Decision.CONFIG_UNVERIFIED;
    }

    private static void hideFirst(Gateway gateway, List<String> errors) {
        try {
            if (!gateway.installed() || gateway.webViewProvider()) {
                return;
            }
            gateway.setHidden(true);
            if (!gateway.hidden()) {
                errors.add(HIDE_UNVERIFIED_ERROR);
            }
        } catch (RuntimeException exception) {
            errors.add(HIDE_UNVERIFIED_ERROR + ":" + exception.getClass().getSimpleName());
        }
    }
}
