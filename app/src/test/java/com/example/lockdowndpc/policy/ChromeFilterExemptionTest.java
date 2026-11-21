package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.policy.ChromeFilterExemption.Decision;
import com.example.lockdowndpc.policy.ChromeFilterExemption.Observed;

import org.junit.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Chrome's decision and visibility, driven through the production calls the
 * policy pass makes ({@code prepare}, then {@code applyVisibility} in the
 * sweep's place) against a fake Android layer that records every call. These
 * tests exercise Device Guard's own ordering and decisions; they make no claim
 * about what Chrome or Android does with the values.
 */
public final class ChromeFilterExemptionTest {

    private static final String PAC = "https://filter.example.org/proxy.pac";

    private static class FakeChrome implements ChromeFilterExemption.Gateway {
        final List<String> calls = new ArrayList<>();
        boolean installed = true;
        String signer = BuiltInBlockExemptions.CHROME_RELEASE_SIGNER_SHA256;
        Map<String, Object> restrictions = new LinkedHashMap<>();
        boolean keepRestrictions = true;
        boolean webViewProvider;
        boolean hidden;
        boolean suspended;
        boolean refuseSuspension;
        RuntimeException throwOnRead;
        RuntimeException throwOnObserve;

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

        @Override public boolean webViewProvider() { return webViewProvider; }

        @Override
        public void setHidden(boolean value) {
            calls.add("hide=" + value);
            hidden = value;
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
            if (refuseSuspension && value) {
                throw new IllegalStateException("suspension-refused");
            }
            suspended = value;
        }

        @Override public boolean suspended() { return suspended; }
    }

    /** One protected pass: the production prepare, then Chrome's sweep step. */
    private static Decision pass(FakeChrome chrome, boolean exempted, boolean protectionActive,
                                 boolean filterEnabled, List<String> errors) {
        Decision decision = ChromeFilterExemption.prepare(
                exempted, protectionActive, filterEnabled, filterEnabled ? PAC : null, chrome, errors);
        ChromeFilterExemption.applyVisibility(decision, chrome, errors);
        return decision;
    }

    private static FakeChrome visibleChrome() {
        FakeChrome chrome = new FakeChrome();
        chrome.hidden = false;
        return chrome;
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
        // apply() passes filterEnabled=false and no PAC for unreadable settings,
        // before its early return.
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
        assertTrue(errors.get(0).startsWith("chrome-exemption:"));
    }

    @Test
    public void theSweepStepNeverShowsChromeForANotShownDecision() {
        for (Decision decision : Decision.values()) {
            if (decision.shown()) {
                continue;
            }
            FakeChrome chrome = new FakeChrome();
            chrome.hidden = true;
            ChromeFilterExemption.applyVisibility(decision, chrome, new ArrayList<>());
            assertFalse(decision.name(), chrome.calls.contains("hide=false"));
            assertFalse(decision.name(), chrome.calls.contains("suspend=false"));
        }
    }

    // --- Ordering, through the production calls --------------------------------------

    @Test
    public void onResumeChromeIsContainedBeforeTheConfigurationIsWrittenAndShownOnlyAfterReadBack() {
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
        assertEquals(Observed.VISIBLE, ChromeFilterExemption.observe(chrome));
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

    // --- WebView provider ------------------------------------------------------------

    @Test
    public void aWebViewProviderChromeIsSuspendedNotHiddenAndNeverShownWhenNotAllowed() {
        FakeChrome chrome = visibleChrome();
        chrome.webViewProvider = true;
        List<String> errors = new ArrayList<>();
        pass(chrome, false, true, true, errors);
        assertEquals("suspend=true", chrome.calls.get(0));
        assertFalse(chrome.calls.contains("hide=true"));
        assertEquals(Observed.SUSPENDED, ChromeFilterExemption.observe(chrome));
        assertTrue(errors.isEmpty());
    }

    @Test
    public void aRefusedSuspensionIsAnErrorNotAContainment() {
        FakeChrome chrome = visibleChrome();
        chrome.webViewProvider = true;
        chrome.refuseSuspension = true;
        List<String> errors = new ArrayList<>();
        pass(chrome, false, true, true, errors);
        assertTrue(errors.toString(),
                errors.stream().anyMatch(e -> e.startsWith(ChromeFilterExemption.CONTAIN_UNVERIFIED_ERROR)));
        assertEquals(Observed.VISIBLE, ChromeFilterExemption.observe(chrome));
    }

    @Test
    public void aShownWebViewProviderIsUnsuspended() {
        FakeChrome chrome = visibleChrome();
        chrome.webViewProvider = true;
        chrome.suspended = true;
        assertEquals(Decision.SHOWN, pass(chrome, true, true, true, new ArrayList<>()));
        assertEquals(Observed.VISIBLE, ChromeFilterExemption.observe(chrome));
    }

    // --- Observation ------------------------------------------------------------------

    @Test
    public void anObservationThatThrowsIsUnknownNotHidden() {
        FakeChrome chrome = visibleChrome();
        chrome.throwOnObserve = new IllegalStateException("binder");
        assertEquals(Observed.UNKNOWN, ChromeFilterExemption.observe(chrome));
        List<String> errors = new ArrayList<>();
        ChromeFilterExemption.applyVisibility(Decision.NOT_EXEMPTED, chrome, errors);
        assertTrue("unknown is not reported as contained",
                errors.contains(ChromeFilterExemption.CONTAIN_UNVERIFIED_ERROR));
    }

    @Test
    public void aShowAndroidDidNotKeepIsReported() {
        FakeChrome chrome = new FakeChrome() {
            @Override
            public void setHidden(boolean value) {
                calls.add("hide=" + value);
                hidden = true;
            }
        };
        chrome.restrictions = new LinkedHashMap<>(BuiltInBlockExemptions.chromeRestrictions(PAC));
        List<String> errors = new ArrayList<>();
        pass(chrome, true, true, true, errors);
        assertTrue(errors.contains(ChromeFilterExemption.SHOW_UNVERIFIED_ERROR));
    }
}
