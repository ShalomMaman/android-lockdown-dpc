package com.example.lockdowndpc.policy;

import java.util.List;

/**
 * The start of a protected pass, in the one order that is allowed:
 *
 * <ol>
 *   <li>the single containment step — every built-in blocked social package
 *       without a verified exemption is hidden, and Chrome (when in scope)
 *       unless it is already allowed — before any early return;</li>
 *   <li>the early returns (unreadable home filter settings, no device owner);</li>
 *   <li>the pass records that it started;</li>
 *   <li>Chrome's decision, made with the protection state read <em>after</em>
 *       that record, which is the state the pass actually runs under.</li>
 * </ol>
 *
 * <p>Later steps may only show a package through the verified path. The
 * Android side is the {@link Steps} the controller supplies, so the order is a
 * JVM test.
 */
final class ExemptionPassStart {

    private ExemptionPassStart() {}

    enum Stop { NONE, CORRUPT_HOME_FILTER, NOT_DEVICE_OWNER }

    /** Where the pass stopped, and Chrome's decision when it did not. */
    record Start(Stop stop, ChromeFilterExemption.Decision chrome) {}

    interface Steps {
        boolean deviceOwner();

        boolean homeFilterReadable();

        /** Hides every catalogue social package without a verified exemption. */
        void containSocial(List<String> errors);

        /** {@code null} when the Chrome exemption is not in scope on this pass. */
        ChromeFilterExemption.Containment containChrome(List<String> errors);

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
            chrome = steps.containChrome(errors);
        }
        if (!steps.homeFilterReadable()) {
            return new Start(Stop.CORRUPT_HOME_FILTER, null);
        }
        steps.markApplyStarted();
        if (!deviceOwner) {
            return new Start(Stop.NOT_DEVICE_OWNER, null);
        }
        ChromeFilterExemption.Decision decision = chrome == null
                ? ChromeFilterExemption.Decision.NOT_AVAILABLE
                : steps.decideChrome(chrome, steps.protectionActive(), errors);
        return new Start(Stop.NONE, decision);
    }
}
