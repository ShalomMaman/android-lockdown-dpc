package com.example.lockdowndpc.policy;

import java.util.List;
import java.util.Map;

/**
 * Chrome's visibility, owned end to end by this class on every protected pass.
 * The generic package sweep and the WebView suspension pass leave Chrome alone.
 *
 * <p>Two calls, in this order:
 * <ol>
 *   <li>{@link #prepare} at the very start of the pass (and before any early
 *       return). Unless Chrome is already allowed — every precondition holds
 *       and its managed configuration already reads back as required — Chrome
 *       is contained <em>first</em>: hidden, or suspended when it is the WebView
 *       provider (which is never hidden). Only then is the configuration
 *       written and read back. A refused containment is an error, so the pass
 *       is reported unverified rather than contained.</li>
 *   <li>{@link #applyVisibility} in the package sweep's place: shows Chrome only
 *       for a {@link Decision#SHOWN} decision, otherwise checks it is still
 *       contained. It never shows Chrome on any other decision.</li>
 * </ol>
 *
 * <p>No state is kept between passes. Any exception is a "not shown" decision.
 */
public final class ChromeFilterExemption {

    private ChromeFilterExemption() {}

    public static final String CONFIG_UNVERIFIED_ERROR = "chrome-exemption-config-unverified";
    public static final String CONTAIN_UNVERIFIED_ERROR = "chrome-exemption-contain-unverified";
    public static final String SHOW_UNVERIFIED_ERROR = "chrome-exemption-show-unverified";

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

    /** What Android reports for Chrome. {@link #UNKNOWN} when a read threw. */
    public enum Observed { VISIBLE, HIDDEN, SUSPENDED, NOT_INSTALLED, UNKNOWN }

    /** Android, as seen by this class. Any call may throw. */
    public interface Gateway {
        boolean installed();

        /** Chrome's single current signer, lower-case hex, or {@code ""}. */
        String currentSignerSha256();

        Map<String, Object> restrictions();

        void setRestrictions(Map<String, Object> values);

        boolean webViewProvider();

        void setHidden(boolean hidden);

        boolean hidden();

        /** Throws when Android refuses. */
        void setSuspended(boolean suspended);

        boolean suspended();
    }

    /**
     * Decides, containing Chrome first unless it is already allowed.
     *
     * @param exempted         the administrator exempted Chrome
     * @param protectionActive protection is on (not paused)
     * @param filterEnabled    the home filter is enabled and its settings are readable
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
            decision = preconditions(exempted, protectionActive, filterEnabled, pacUrl, gateway);
            boolean alreadyAllowed = decision == null
                    && BuiltInBlockExemptions.restrictionsSatisfied(gateway.restrictions(), pacUrl);
            if (!alreadyAllowed) {
                contain(gateway, errors);
            }
            if (decision == null) {
                Map<String, Object> current = gateway.restrictions();
                if (!BuiltInBlockExemptions.restrictionsSatisfied(current, pacUrl)) {
                    gateway.setRestrictions(BuiltInBlockExemptions.mergeRestrictions(current, pacUrl));
                }
                decision = BuiltInBlockExemptions.restrictionsSatisfied(gateway.restrictions(), pacUrl)
                        ? Decision.SHOWN
                        : Decision.CONFIG_UNVERIFIED;
            }
        } catch (RuntimeException exception) {
            errors.add("chrome-exemption:" + exception.getClass().getSimpleName());
            decision = Decision.ERROR;
            contain(gateway, errors);
        }
        if (decision == Decision.CONFIG_UNVERIFIED) {
            errors.add(CONFIG_UNVERIFIED_ERROR);
        }
        return decision;
    }

    /**
     * Chrome's part of the package sweep: show it only on {@link Decision#SHOWN},
     * reading the result back; otherwise confirm it is still contained.
     */
    public static void applyVisibility(Decision decision, Gateway gateway, List<String> errors) {
        if (!decision.shown()) {
            Observed observed = observe(gateway);
            if (observed == Observed.VISIBLE || observed == Observed.UNKNOWN) {
                errors.add(CONTAIN_UNVERIFIED_ERROR);
            }
            return;
        }
        try {
            gateway.setHidden(false);
            gateway.setSuspended(false);
        } catch (RuntimeException exception) {
            errors.add(SHOW_UNVERIFIED_ERROR + ":" + exception.getClass().getSimpleName());
            return;
        }
        if (observe(gateway) != Observed.VISIBLE) {
            errors.add(SHOW_UNVERIFIED_ERROR);
        }
    }

    /** What Android reports now, never guessed: a failed read is {@link Observed#UNKNOWN}. */
    public static Observed observe(Gateway gateway) {
        try {
            if (!gateway.installed()) {
                return Observed.NOT_INSTALLED;
            }
            if (gateway.hidden()) {
                return Observed.HIDDEN;
            }
            return gateway.suspended() ? Observed.SUSPENDED : Observed.VISIBLE;
        } catch (RuntimeException exception) {
            return Observed.UNKNOWN;
        }
    }

    /** {@code null} when every precondition holds; otherwise the reason. */
    private static Decision preconditions(
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
        return null;
    }

    /** Hidden, or suspended when Chrome is the WebView provider; read back. */
    private static void contain(Gateway gateway, List<String> errors) {
        try {
            if (!gateway.installed()) {
                return;
            }
            if (gateway.webViewProvider()) {
                gateway.setSuspended(true);
                if (!gateway.suspended()) {
                    errors.add(CONTAIN_UNVERIFIED_ERROR);
                }
            } else {
                gateway.setHidden(true);
                if (!gateway.hidden()) {
                    errors.add(CONTAIN_UNVERIFIED_ERROR);
                }
            }
        } catch (RuntimeException exception) {
            errors.add(CONTAIN_UNVERIFIED_ERROR + ":" + exception.getClass().getSimpleName());
        }
    }
}
