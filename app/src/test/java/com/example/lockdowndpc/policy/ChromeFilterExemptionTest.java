package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.policy.BuiltInBlockExemptions.Observed;
import com.example.lockdowndpc.policy.ChromeFilterExemption.Containment;
import com.example.lockdowndpc.policy.ChromeFilterExemption.Decision;

import org.junit.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Chrome's containment, decision and visibility, driven through the production
 * calls in the order the pass makes them ({@code contain}, {@code decide},
 * then {@code release} after the home filter's reconciliation) against a fake Android
 * layer that records every call. Visibility only ever changes through those
 * calls. These tests make no claim about what Chrome or Android does with the
 * values.
 */
public final class ChromeFilterExemptionTest {

    private static final String PAC = "https://filter.example.org/proxy.pac";

    private static class FakeChrome implements ChromeFilterExemption.Gateway {
        final List<String> calls = new ArrayList<>();
        boolean installed = true;
        String signer = BuiltInBlockExemptions.CHROME_RELEASE_SIGNER_SHA256;
        Map<String, Object> restrictions = new LinkedHashMap<>();
        boolean keepRestrictions = true;
        boolean hidden;
        boolean suspended;
        boolean enabled = true;
        boolean refuseHide;
        RuntimeException throwOnRead;
        RuntimeException throwOnObserve;
        boolean observeFailsAfterShow;

        @Override public boolean installed() { return installed; }
        @Override public String currentSignerSha256() { return signer; }

        @Override
        public Map<String, Object> restrictions() {
            calls.add("read-config");
            if (throwOnRead != null) {
                throw throwOnRead;
            }
            return new LinkedHashMap<>(restrictions);
        }

        @Override
        public void setRestrictions(Map<String, Object> values) {
            calls.add("write-config");
            if (keepRestrictions) {
                restrictions = new LinkedHashMap<>(values);
            }
        }

        @Override
        public void setHidden(boolean value) {
            calls.add("hide=" + value);
            if (!(refuseHide && value)) {
                hidden = value;
            }
            if (!value && observeFailsAfterShow) {
                throwOnObserve = new IllegalStateException("binder");
            }
            if (value) {
                throwOnObserve = null;
            }
        }

        @Override
        public boolean hidden() {
            if (throwOnObserve != null) {
                throw throwOnObserve;
            }
            return hidden;
        }

        @Override
        public void setSuspended(boolean value) {
            calls.add("suspend=" + value);
            suspended = value;
        }

        @Override public boolean suspended() { return suspended; }
        @Override public boolean enabled() { return enabled; }
    }

    /**
     * One protected pass's Chrome steps, in production order.
     *
     * @param filterConfirmed the home filter's reconciliation in this pass reported no error
     */
    private static Decision pass(FakeChrome chrome, boolean exempted, boolean protectionActive,
                                 boolean filterEnabled, boolean filterConfirmed, List<String> errors) {
        String pac = filterEnabled ? PAC : null;
        Containment containment = ChromeFilterExemption.contain(exempted, filterEnabled, pac, chrome, errors);
        Decision decision = ChromeFilterExemption.decide(
                containment, exempted, protectionActive, filterEnabled, pac, chrome, errors);
        return ChromeFilterExemption.release(decision, filterConfirmed, chrome, errors);
    }

    private static Decision pass(FakeChrome chrome, boolean exempted, boolean protectionActive,
                                 boolean filterEnabled, List<String> errors) {
        return pass(chrome, exempted, protectionActive, filterEnabled, filterEnabled, errors);
    }

    private static FakeChrome visibleChrome() {
        FakeChrome chrome = new FakeChrome();
        chrome.hidden = false;
        return chrome;
    }

    // --- Scope ----------------------------------------------------------------------

    @Test
    public void theExemptionIsInertWhileChromeIsTheWebViewProviderOrBeforeAndroid10() {
        assertFalse(ChromeFilterExemption.inScope(33, BuiltInBlockExemptions.CHROME));
        assertFalse(ChromeFilterExemption.inScope(28, "com.google.android.webview"));
        assertTrue(ChromeFilterExemption.inScope(29, "com.google.android.webview"));
        assertTrue(ChromeFilterExemption.inScope(34, null));
    }

    @Test
    public void onResumeWithAReplacementProfileAndAMissingVpnChromeIsHiddenThroughoutAndNeverReleased() {
        // Paused with Chrome visible and approved, its managed configuration
        // already matching; a replacement profile keeps the same PAC URL but its
        // VPN package is missing. Resume is not a continuation, so Chrome is
        // contained before the pass starts, and the filter's reconciliation in
        // the same pass reports the missing VPN, so it is never released.
        FakeChrome chrome = visibleChrome();
        chrome.restrictions = new LinkedHashMap<>(BuiltInBlockExemptions.chromeRestrictions(PAC));
        List<String> errors = new ArrayList<>();
        Containment containment = ChromeFilterExemption.contain(true, true, PAC, false, chrome, errors);
        assertEquals(Containment.CONTAINED, containment);
        assertEquals(Observed.HIDDEN, ChromeFilterExemption.observe(chrome));
        Decision decision = ChromeFilterExemption.decide(containment, true, true, true, PAC, chrome, errors);
        assertEquals(Observed.HIDDEN, ChromeFilterExemption.observe(chrome));
        boolean missingVpnConfirmed = false;
        Decision released = ChromeFilterExemption.release(decision, missingVpnConfirmed, chrome, errors);
        assertEquals(Decision.FILTER_UNCONFIRMED, released);
        assertFalse("never released", chrome.calls.contains("hide=false"));
        assertEquals(Observed.HIDDEN, ChromeFilterExemption.observe(chrome));
    }

    @Test
    public void anUnreadableChromeSignerIsReportedAsUnreadableNotAsNotGoogles() {
        FakeChrome chrome = visibleChrome();
        chrome.signer = "";
        assertEquals(Decision.SIGNER_UNREADABLE, pass(chrome, true, true, true, new ArrayList<>()));
        assertEquals(Observed.HIDDEN, ChromeFilterExemption.observe(chrome));
    }

    @Test
    public void theNotAvailableReasonClaimsOnlyWhatTheProviderCheckFound() {
        assertEquals(Decision.NOT_AVAILABLE_WEBVIEW_PROVIDER,
                ChromeFilterExemption.unavailableReason(28, BuiltInBlockExemptions.CHROME));
        assertEquals(Decision.NOT_AVAILABLE_WEBVIEW_PROVIDER,
                ChromeFilterExemption.unavailableReason(33, BuiltInBlockExemptions.CHROME));
        assertEquals(Decision.NOT_AVAILABLE_ANDROID_VERSION,
                ChromeFilterExemption.unavailableReason(28, "com.google.android.webview"));
        assertEquals(Decision.NOT_AVAILABLE_ANDROID_VERSION, ChromeFilterExemption.unavailableReason(26, null));
        assertEquals(Decision.NOT_AVAILABLE_WEBVIEW_UNCONFIRMED, ChromeFilterExemption.unavailableReason(33, null));
    }

    // --- Contained unless every condition holds --------------------------------------

    @Test
    public void containedWithoutAnExemption() {
        FakeChrome chrome = visibleChrome();
        List<String> errors = new ArrayList<>();
        assertEquals(Decision.NOT_EXEMPTED, pass(chrome, false, true, true, errors));
        assertEquals(Observed.HIDDEN, ChromeFilterExemption.observe(chrome));
        assertFalse(chrome.calls.contains("write-config"));
        assertTrue(errors.isEmpty());
    }

    @Test
    public void containedWhileProtectionIsPaused() {
        FakeChrome chrome = visibleChrome();
        assertEquals(Decision.PROTECTION_PAUSED, pass(chrome, true, false, true, new ArrayList<>()));
        assertEquals(Observed.HIDDEN, ChromeFilterExemption.observe(chrome));
    }

    @Test
    public void containedWhenTheHomeFilterIsDisabledOrItsSettingsAreUnreadable() {
        FakeChrome chrome = visibleChrome();
        assertEquals(Decision.FILTER_DISABLED, pass(chrome, true, true, false, new ArrayList<>()));
        assertEquals(Observed.HIDDEN, ChromeFilterExemption.observe(chrome));
    }

    @Test
    public void containedWhenTheSignerIsNotGoogles() {
        FakeChrome chrome = visibleChrome();
        chrome.signer = "ab".repeat(32);
        assertEquals(Decision.SIGNER_UNVERIFIED, pass(chrome, true, true, true, new ArrayList<>()));
        assertEquals(Observed.HIDDEN, ChromeFilterExemption.observe(chrome));
        assertFalse(chrome.calls.contains("write-config"));
    }

    @Test
    public void containedWhenTheConfigurationReadBackDoesNotMatch() {
        FakeChrome chrome = visibleChrome();
        chrome.keepRestrictions = false;
        List<String> errors = new ArrayList<>();
        assertEquals(Decision.CONFIG_UNVERIFIED, pass(chrome, true, true, true, errors));
        assertEquals(Observed.HIDDEN, ChromeFilterExemption.observe(chrome));
        assertTrue(errors.contains(ChromeFilterExemption.CONFIG_UNVERIFIED_ERROR));
    }

    @Test
    public void anExceptionIsANotShownDecisionAndContains() {
        FakeChrome chrome = visibleChrome();
        chrome.throwOnRead = new IllegalStateException("binder");
        List<String> errors = new ArrayList<>();
        assertEquals(Decision.ERROR, pass(chrome, true, true, true, errors));
        assertEquals(Observed.HIDDEN, ChromeFilterExemption.observe(chrome));
    }

    // --- Refused containment ------------------------------------------------------------

    @Test
    public void aRefusedHideStopsTheConfigurationWriteAndLeavesThePassUnverified() {
        FakeChrome chrome = visibleChrome();
        chrome.refuseHide = true;
        List<String> errors = new ArrayList<>();
        assertEquals(Decision.CONTAIN_UNVERIFIED, pass(chrome, true, true, true, errors));
        assertFalse("no configuration write without a confirmed containment",
                chrome.calls.contains("write-config"));
        assertTrue(errors.contains(ChromeFilterExemption.CONTAIN_UNVERIFIED_ERROR));
        assertFalse(chrome.calls.contains("hide=false"));
    }

    @Test
    public void theReleaseStepNeverShowsChromeForANotShownDecision() {
        for (Decision decision : Decision.values()) {
            if (decision.shown()) {
                continue;
            }
            for (boolean filterConfirmed : new boolean[]{true, false}) {
                FakeChrome chrome = new FakeChrome();
                chrome.hidden = true;
                ChromeFilterExemption.release(decision, filterConfirmed, chrome, new ArrayList<>());
                assertFalse(decision.name(), chrome.calls.contains("hide=false"));
                assertFalse(decision.name(), chrome.calls.contains("suspend=false"));
            }
        }
    }

    // --- Release after the home filter's reconciliation --------------------------------

    @Test
    public void firstFilterEnableWithAMissingVpnKeepsChromeContained() {
        // The filter was off; the administrator enables it, but the configured
        // VPN app is missing, so this pass's reconciliation reports an error.
        FakeChrome chrome = new FakeChrome();
        chrome.hidden = true;
        List<String> errors = new ArrayList<>();
        Decision decision = pass(chrome, true, true, true, false, errors);
        assertEquals(Decision.FILTER_UNCONFIRMED, decision);
        assertFalse(chrome.calls.contains("hide=false"));
        assertEquals(Observed.HIDDEN, ChromeFilterExemption.observe(chrome));
        assertTrue(errors.contains(ChromeFilterExemption.FILTER_UNCONFIRMED_ERROR));
    }

    @Test
    public void anAllowedChromeIsHiddenWhenThisPassesReconciliationFails() {
        FakeChrome chrome = visibleChrome();
        chrome.restrictions = new LinkedHashMap<>(BuiltInBlockExemptions.chromeRestrictions(PAC));
        assertEquals(Decision.FILTER_UNCONFIRMED, pass(chrome, true, true, true, false, new ArrayList<>()));
        assertEquals(Observed.HIDDEN, ChromeFilterExemption.observe(chrome));
    }

    @Test
    public void aVisibilityReadFailureAfterShowingHidesChromeAgainAndBlocksRouting() {
        FakeChrome chrome = new FakeChrome();
        chrome.hidden = true;
        chrome.observeFailsAfterShow = true;
        List<String> errors = new ArrayList<>();
        Decision decision = pass(chrome, true, true, true, true, errors);
        assertEquals(Decision.SHOW_UNVERIFIED, decision);
        assertFalse("only SHOWN routes links", decision.shown());
        assertEquals("hide=true", chrome.calls.get(chrome.calls.size() - 1));
        assertEquals(Observed.HIDDEN, ChromeFilterExemption.observe(chrome));
    }

    // --- Ordering ------------------------------------------------------------------------

    @Test
    public void chromeIsContainedBeforeTheConfigurationIsWrittenAndShownOnlyAfterReadBack() {
        FakeChrome chrome = visibleChrome();
        assertEquals(Decision.SHOWN, pass(chrome, true, true, true, new ArrayList<>()));
        int contain = chrome.calls.indexOf("hide=true");
        int write = chrome.calls.indexOf("write-config");
        int readBack = chrome.calls.lastIndexOf("read-config");
        int show = chrome.calls.indexOf("hide=false");
        assertTrue(chrome.calls.toString(), contain >= 0 && contain < write);
        assertTrue(chrome.calls.toString(), write < readBack && readBack < show);
        assertEquals(Observed.VISIBLE, ChromeFilterExemption.observe(chrome));
    }

    @Test
    public void anAlreadyAllowedChromeIsNotContainedOrRewritten() {
        FakeChrome chrome = visibleChrome();
        chrome.restrictions = new LinkedHashMap<>(BuiltInBlockExemptions.chromeRestrictions(PAC));
        assertEquals(Decision.SHOWN, pass(chrome, true, true, true, new ArrayList<>()));
        assertFalse(chrome.calls.contains("hide=true"));
        assertFalse(chrome.calls.contains("write-config"));
    }

    @Test
    public void allowedAtTheStartButNotAtTheDecisionIsContained() {
        // Configured and exempted, but the pass then runs paused.
        FakeChrome chrome = visibleChrome();
        chrome.restrictions = new LinkedHashMap<>(BuiltInBlockExemptions.chromeRestrictions(PAC));
        assertEquals(Decision.PROTECTION_PAUSED, pass(chrome, true, false, true, new ArrayList<>()));
        assertEquals(Observed.HIDDEN, ChromeFilterExemption.observe(chrome));
    }

    @Test
    public void theWritePutsAMandatoryPacInProxySettingsAndDropsSeparateProxyKeys() {
        FakeChrome chrome = new FakeChrome();
        chrome.restrictions.put("ProxyMode", "direct");
        chrome.restrictions.put("ProxyPacUrl", "https://other.example/p.pac");
        assertEquals(Decision.SHOWN, pass(chrome, true, true, true, new ArrayList<>()));
        assertFalse(chrome.restrictions.containsKey("ProxyMode"));
        assertFalse(chrome.restrictions.containsKey("ProxyPacUrl"));
        assertTrue(((String) chrome.restrictions.get("ProxySettings"))
                .contains("\"ProxyPacMandatory\":true"));
    }

    // --- Observation -------------------------------------------------------------------

    @Test
    public void anObservationThatThrowsIsUnknownAndNotTakenAsContained() {
        FakeChrome chrome = visibleChrome();
        chrome.throwOnObserve = new IllegalStateException("binder");
        assertEquals(Observed.UNKNOWN, ChromeFilterExemption.observe(chrome));
        List<String> errors = new ArrayList<>();
        ChromeFilterExemption.release(Decision.NOT_EXEMPTED, true, chrome, errors);
        assertTrue("an unknown state is contained again",
                chrome.calls.contains("hide=true"));
    }

    @Test
    public void aRefusedRecoveryHideIsReportedAsRefusedNotAsHidden() {
        FakeChrome chrome = new FakeChrome();
        chrome.hidden = true;
        chrome.observeFailsAfterShow = true;
        // The opening hide works; the recovery hide after the failed show does not.
        List<String> errors = new ArrayList<>();
        String pac = PAC;
        Containment containment = ChromeFilterExemption.contain(true, true, pac, chrome, errors);
        Decision decision = ChromeFilterExemption.decide(containment, true, true, true, pac, chrome, errors);
        chrome.refuseHide = true;
        Decision released = ChromeFilterExemption.release(decision, true, chrome, errors);
        assertEquals(Decision.HIDE_REFUSED, released);
        assertFalse(released.shown());
        assertTrue(errors.stream().anyMatch(e -> e.startsWith(ChromeFilterExemption.CONTAIN_UNVERIFIED_ERROR)));
    }

    @Test
    public void aRefusedHideInTheReleaseStepIsReportedAsRefused() {
        FakeChrome chrome = visibleChrome();
        chrome.refuseHide = true;
        assertEquals(Decision.HIDE_REFUSED,
                ChromeFilterExemption.release(Decision.NOT_EXEMPTED, true, chrome, new ArrayList<>()));
    }

    @Test
    public void aDisabledChromeIsNeverShownAndTheReleaseStepMakesNoVisibilityCall() {
        FakeChrome chrome = visibleChrome();
        chrome.enabled = false;
        chrome.restrictions = new LinkedHashMap<>(BuiltInBlockExemptions.chromeRestrictions(PAC));
        List<String> errors = new ArrayList<>();
        Containment containment = ChromeFilterExemption.contain(true, true, PAC, chrome, errors);
        Decision decision = ChromeFilterExemption.decide(containment, true, true, true, PAC, chrome, errors);
        assertEquals(Decision.DISABLED, decision);
        assertFalse("no configuration write for a disabled Chrome", chrome.calls.contains("write-config"));
        int callsBeforeRelease = chrome.calls.size();
        assertEquals(Decision.DISABLED, ChromeFilterExemption.release(decision, true, chrome, errors));
        assertEquals("release leaves an already hidden, disabled Chrome alone",
                callsBeforeRelease, chrome.calls.size());
        assertFalse(chrome.calls.contains("hide=false"));
    }

    @Test
    public void afterARemovedApprovalWhoseHideAndroidRefusedTurningOffTheFilterIsRefused() {
        // The approval is removed (flag absent), but Android refuses to hide
        // Chrome on the pass that follows. The live guard then refuses to turn
        // the filter off: Chrome is not observed contained.
        FakeChrome chrome = visibleChrome();
        chrome.refuseHide = true;
        Decision decision = pass(chrome, false, true, true, new ArrayList<>());
        assertFalse(decision.shown());
        assertEquals(Observed.VISIBLE, ChromeFilterExemption.observe(chrome));
        assertEquals(BuiltInBlockExemptions.TeardownVerdict.CHROME_NOT_CONTAINED,
                BuiltInBlockExemptions.teardownVerdict(BuiltInBlockExemptions.ChromeFlag.ABSENT,
                        ChromeFilterExemption.observe(chrome), true));
        // Once Android confirms the hide on a later pass, the same request is allowed.
        chrome.refuseHide = false;
        pass(chrome, false, true, true, new ArrayList<>());
        assertEquals(BuiltInBlockExemptions.TeardownVerdict.ALLOWED,
                BuiltInBlockExemptions.teardownVerdict(BuiltInBlockExemptions.ChromeFlag.ABSENT,
                        ChromeFilterExemption.observe(chrome), true));
    }

    @Test
    public void aDisabledChromeIsObservedAsDisabledNotAvailable() {
        FakeChrome chrome = visibleChrome();
        chrome.enabled = false;
        assertEquals(Observed.DISABLED, ChromeFilterExemption.observe(chrome));
    }

    @Test
    public void aSuspendedChromeIsObservedAsSuspendedNotHidden() {
        FakeChrome chrome = visibleChrome();
        chrome.suspended = true;
        assertEquals(Observed.SUSPENDED, ChromeFilterExemption.observe(chrome));
    }
}
