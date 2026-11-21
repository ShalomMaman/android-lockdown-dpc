package com.example.lockdowndpc.policy;

import java.util.List;
import java.util.Map;

/**
 * The Chrome exemption.
 *
 * <p><b>Scope.</b> It applies only on Android 10 and later and only while
 * Chrome is not the WebView provider ({@link #inScope}). Otherwise the
 * exemption is inert ({@link Decision#NOT_AVAILABLE}) and Chrome is handled
 * by the existing package sweep and WebView suspension, unchanged.
 *
 * <p><b>Order</b> within a protected pass:
 * <ol>
 *   <li>{@link #contain} runs in the pass's single containment step, before
 *       any early return: unless Chrome is already allowed, it is hidden and
 *       the hide is read back.</li>
 *   <li>{@link #decide} writes and reads back the managed configuration —
 *       never when containment was refused — and returns the decision.</li>
 *   <li>{@link #release}, after the home filter's own reconciliation in the
 *       same pass, is the only step that shows Chrome: only for
 *       {@link Decision#SHOWN} and only when that reconciliation reported no
 *       error. A show Android does not confirm is undone. Its result, not the
 *       earlier decision, decides link routing.</li>
 * </ol>
 * No state is kept between passes. Any exception is a "not shown" decision.
 */
public final class ChromeFilterExemption {

    private ChromeFilterExemption() {}

    /** First Android release on which the exemption may apply (Android 10). */
    public static final int MIN_SDK = 29;

    public static final String CONFIG_UNVERIFIED_ERROR = "chrome-exemption-config-unverified";
    public static final String CONTAIN_UNVERIFIED_ERROR = "chrome-exemption-contain-unverified";
    public static final String SHOW_UNVERIFIED_ERROR = "chrome-exemption-show-unverified";
    public static final String FILTER_UNCONFIRMED_ERROR = "chrome-exemption-filter-unconfirmed";

    /** Why Chrome is, or is not, shown on this pass. */
    public enum Decision {
        /** Chrome is or may be the WebView provider, or Android is too old: inert. */
        NOT_AVAILABLE(false),
        NOT_EXEMPTED(false),
        PROTECTION_PAUSED(false),
        FILTER_DISABLED(false),
        NOT_INSTALLED(false),
        /**
         * Chrome is disabled in Android. It is never shown: showing it would
         * only be undone again, and every show is a package event that starts
         * another pass.
         */
        DISABLED(false),
        SIGNER_UNVERIFIED(false),
        CONTAIN_UNVERIFIED(false),
        CONFIG_UNVERIFIED(false),
        /** Everything held, but the home filter's reconciliation in this pass failed. */
        FILTER_UNCONFIRMED(false),
        /** Shown, but Android did not confirm it, so Chrome was hidden again. */
        SHOW_UNVERIFIED(false),
        /** Chrome had to be hidden after the decision and Android did not confirm the hide. */
        HIDE_REFUSED(false),
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

    /** The outcome of the containment step. */
    public enum Containment {
        /** Every condition already holds; Chrome was left as it is. */
        ALREADY_ALLOWED,
        /** Android confirmed Chrome hidden. */
        CONTAINED,
        /** Android did not confirm the hide. */
        REFUSED,
        NOT_INSTALLED
    }

    /** Android, as seen by this class. Any call may throw. */
    public interface Gateway {
        boolean installed();

        /** Chrome's single current signer, lower-case hex, or {@code ""}. */
        String currentSignerSha256();

        Map<String, Object> restrictions();

        void setRestrictions(Map<String, Object> values);

        void setHidden(boolean hidden);

        boolean hidden();

        void setSuspended(boolean suspended);

        boolean suspended();

        /** Whether the package is enabled (an app disabled in Settings cannot launch). */
        boolean enabled();
    }

    /**
     * Whether the exemption may act at all. Chrome as the WebView provider is
     * never hidden by Device Guard, so it stays with the existing code path.
     */
    public static boolean inScope(int sdk, String webViewProvider) {
        return sdk >= MIN_SDK && !BuiltInBlockExemptions.CHROME.equals(webViewProvider);
    }

    /**
     * The containment step: hide Chrome and read it back, unless every
     * condition already holds and its configuration already reads back.
     */
    public static Containment contain(
            boolean exempted,
            boolean filterEnabled,
            String pacUrl,
            Gateway gateway,
            List<String> errors
    ) {
        try {
            if (!gateway.installed()) {
                return Containment.NOT_INSTALLED;
            }
            if (exempted && filterEnabled && pacUrl != null && !pacUrl.isBlank()
                    && gateway.enabled()
                    && BuiltInBlockExemptions.chromeSignerVerified(gateway.currentSignerSha256())
                    && BuiltInBlockExemptions.restrictionsSatisfied(gateway.restrictions(), pacUrl)) {
                return Containment.ALREADY_ALLOWED;
            }
        } catch (RuntimeException exception) {
            errors.add("chrome-exemption:" + exception.getClass().getSimpleName());
        }
        return hide(gateway, errors);
    }

    /**
     * Decides after the pass has started. Writes the configuration only when
     * Chrome was confirmed contained or was already allowed.
     *
     * @param protectionActive read after the pass recorded that it started
     */
    public static Decision decide(
            Containment containment,
            boolean exempted,
            boolean protectionActive,
            boolean filterEnabled,
            String pacUrl,
            Gateway gateway,
            List<String> errors
    ) {
        Decision decision;
        try {
            decision = preconditions(containment, exempted, protectionActive, filterEnabled, pacUrl, gateway);
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
        }
        if (decision == Decision.CONFIG_UNVERIFIED) {
            errors.add(CONFIG_UNVERIFIED_ERROR);
        }
        if (!decision.shown() && containment == Containment.ALREADY_ALLOWED) {
            // Allowed at the start of the pass, not any more: contain now.
            hide(gateway, errors);
        }
        return decision;
    }

    /**
     * The only step that shows Chrome, run after the home filter's own
     * reconciliation. Shows it only for {@link Decision#SHOWN} and only when
     * that reconciliation reported no error; a show Android does not confirm
     * visible is undone. In every other case Chrome is hidden if Android does
     * not already report it hidden or suspended. Every hide is read back, and a
     * hide Android does not confirm is reported as {@link Decision#HIDE_REFUSED}
     * rather than as a hidden Chrome.
     *
     * @param filterConfirmed the home filter's reconciliation in this pass
     *                        reported no error
     * @return the final decision; only {@link Decision#SHOWN} may route links
     */
    public static Decision release(
            Decision decision,
            boolean filterConfirmed,
            Gateway gateway,
            List<String> errors
    ) {
        if (decision.shown() && filterConfirmed) {
            try {
                gateway.setHidden(false);
                gateway.setSuspended(false);
                if (observe(gateway) == BuiltInBlockExemptions.Observed.VISIBLE) {
                    return Decision.SHOWN;
                }
                errors.add(SHOW_UNVERIFIED_ERROR);
            } catch (RuntimeException exception) {
                errors.add(SHOW_UNVERIFIED_ERROR + ":" + exception.getClass().getSimpleName());
            }
            return hide(gateway, errors) == Containment.CONTAINED
                    ? Decision.SHOW_UNVERIFIED
                    : Decision.HIDE_REFUSED;
        }
        Decision result = decision;
        if (decision.shown()) {
            errors.add(FILTER_UNCONFIRMED_ERROR);
            result = Decision.FILTER_UNCONFIRMED;
        }
        BuiltInBlockExemptions.Observed observed = observe(gateway);
        if ((observed == BuiltInBlockExemptions.Observed.VISIBLE
                || observed == BuiltInBlockExemptions.Observed.DISABLED
                || observed == BuiltInBlockExemptions.Observed.UNKNOWN)
                && hide(gateway, errors) != Containment.CONTAINED) {
            // CONTAIN_UNVERIFIED already says the hide was refused, and that
            // the configuration was therefore left alone; keep it.
            return decision == Decision.CONTAIN_UNVERIFIED ? decision : Decision.HIDE_REFUSED;
        }
        return result;
    }

    /** What Android reports now; a failed read is {@code UNKNOWN}, never guessed. */
    public static BuiltInBlockExemptions.Observed observe(Gateway gateway) {
        try {
            if (!gateway.installed()) {
                return BuiltInBlockExemptions.Observed.NOT_INSTALLED;
            }
            if (gateway.hidden()) {
                return BuiltInBlockExemptions.Observed.HIDDEN;
            }
            if (gateway.suspended()) {
                return BuiltInBlockExemptions.Observed.SUSPENDED;
            }
            return gateway.enabled()
                    ? BuiltInBlockExemptions.Observed.VISIBLE
                    : BuiltInBlockExemptions.Observed.DISABLED;
        } catch (RuntimeException exception) {
            return BuiltInBlockExemptions.Observed.UNKNOWN;
        }
    }

    /** {@code null} when the configuration may be written; otherwise the reason. */
    private static Decision preconditions(
            Containment containment,
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
        if (containment == Containment.NOT_INSTALLED || !gateway.installed()) {
            return Decision.NOT_INSTALLED;
        }
        if (!gateway.enabled()) {
            return Decision.DISABLED;
        }
        if (!BuiltInBlockExemptions.chromeSignerVerified(gateway.currentSignerSha256())) {
            return Decision.SIGNER_UNVERIFIED;
        }
        if (containment == Containment.REFUSED) {
            // No configuration write without a confirmed containment.
            return Decision.CONTAIN_UNVERIFIED;
        }
        return null;
    }

    private static Containment hide(Gateway gateway, List<String> errors) {
        try {
            gateway.setHidden(true);
            if (gateway.hidden()) {
                return Containment.CONTAINED;
            }
            errors.add(CONTAIN_UNVERIFIED_ERROR);
        } catch (RuntimeException exception) {
            errors.add(CONTAIN_UNVERIFIED_ERROR + ":" + exception.getClass().getSimpleName());
        }
        return Containment.REFUSED;
    }
}
