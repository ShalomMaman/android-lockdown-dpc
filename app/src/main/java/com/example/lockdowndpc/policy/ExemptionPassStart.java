package com.example.lockdowndpc.policy;

import java.util.List;

/**
 * The start of a protected pass, in the one order that is allowed:
 *
 * <ol>
 *   <li>the single containment step — every built-in blocked social package
 *       without a verified exemption is hidden, a browser-backed WebView
 *       provider is suspended by the existing routine (an earlier call of the
 *       same code the pass runs again later), and Chrome (when in scope)
 *       unless it is already allowed — before any early return;</li>
 *   <li>the early returns (unreadable home filter settings, no device owner);
 *       on unreadable settings the Android state the containment step left is
 *       recorded first, so the console never keeps an older result;</li>
 *   <li>the pass records that it started;</li>
 *   <li>Chrome's decision, made with the protection state read <em>after</em>
 *       that record, which is the state the pass actually runs under.</li>
 * </ol>
 *
 * <p>When Android did not confirm Chrome's hide and the home filter is being
 * turned off (or its CA removed), the start says to hold that teardown: the
 * VPN lockdown, the PAC and the CA stay until a later pass confirms Chrome is
 * contained.
 *
 * <p>Later steps may only show a package through the verified path. The
 * Android side is the {@link Steps} the controller supplies, so the order is a
 * JVM test.
 */
final class ExemptionPassStart {

    private ExemptionPassStart() {}

    enum Stop { NONE, CORRUPT_HOME_FILTER, NOT_DEVICE_OWNER }

    /**
     * Where the pass stopped, Chrome's decision when it did not, and whether
     * the home filter's teardown must wait for a confirmed Chrome containment.
     */
    record Start(Stop stop, ChromeFilterExemption.Decision chrome, boolean holdFilterTeardown) {}

    interface Steps {
        boolean deviceOwner();

        boolean homeFilterReadable();

        /** The stored filter asks Android to remove its VPN, PAC or CA on this pass. */
        boolean filterTeardownRequested();

        /** Hides every catalogue social package without a verified exemption. */
        void containSocial(List<String> errors);

        /** The existing WebView-provider suspension routine, called early. */
        void containWebViewProvider(List<String> errors);

        /** {@code null} when the Chrome exemption is not in scope on this pass. */
        ChromeFilterExemption.Containment containChrome(List<String> errors);

        /** Records what Android reports now, for a pass that stops early. */
        void recordEarlyReadback(List<String> errors);

        void markApplyStarted();

        boolean protectionActive();

        ChromeFilterExemption.Decision decideChrome(
                ChromeFilterExemption.Containment containment,
                boolean protectionActive,
                List<String> errors);
    }

    static Start begin(Steps steps, List<String> errors) {
        boolean deviceOwner = steps.deviceOwner();
        ChromeFilterExemption.Containment chrome = null;
        if (deviceOwner) {
            steps.containSocial(errors);
            steps.containWebViewProvider(errors);
            chrome = steps.containChrome(errors);
        }
        if (!steps.homeFilterReadable()) {
            if (deviceOwner) {
                steps.recordEarlyReadback(errors);
            }
            return new Start(Stop.CORRUPT_HOME_FILTER, null, false);
        }
        steps.markApplyStarted();
        if (!deviceOwner) {
            return new Start(Stop.NOT_DEVICE_OWNER, null, false);
        }
        ChromeFilterExemption.Decision decision = chrome == null
                ? ChromeFilterExemption.Decision.NOT_AVAILABLE
                : steps.decideChrome(chrome, steps.protectionActive(), errors);
        boolean holdFilterTeardown = chrome == ChromeFilterExemption.Containment.REFUSED
                && steps.filterTeardownRequested();
        return new Start(Stop.NONE, decision, holdFilterTeardown);
    }
}
