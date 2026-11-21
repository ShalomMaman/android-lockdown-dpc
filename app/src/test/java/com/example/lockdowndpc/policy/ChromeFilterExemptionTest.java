package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.policy.ChromeFilterExemption.Decision;

import org.junit.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The Chrome decision against a fake Android layer that records every call.
 * These tests exercise Device Guard's own ordering and decisions; they make no
 * claim about what Chrome or Android does with the values.
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
        RuntimeException throwOnRead;

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

        @Override public boolean hidden() { return hidden; }
    }

    private static Decision prepare(FakeChrome chrome, boolean exempted, boolean protectionActive,
                                    boolean filterEnabled, List<String> errors) {
        return ChromeFilterExemption.prepare(
                exempted, protectionActive, filterEnabled, filterEnabled ? PAC : null, chrome, errors);
    }

    // --- Hidden unless every condition holds ----------------------------------------

    @Test
    public void hiddenWithoutAnExemption() {
        FakeChrome chrome = new FakeChrome();
        assertEquals(Decision.NOT_EXEMPTED, prepare(chrome, false, true, true, new ArrayList<>()));
        assertTrue(chrome.hidden);
        assertFalse("nothing is configured without an exemption", chrome.calls.contains("write-config"));
    }

    @Test
    public void hiddenWhileProtectionIsPaused() {
        FakeChrome chrome = new FakeChrome();
        assertEquals(Decision.PROTECTION_PAUSED, prepare(chrome, true, false, true, new ArrayList<>()));
        assertTrue(chrome.hidden);
    }

    @Test
    public void hiddenWhileTheHomeFilterIsDisabled() {
        FakeChrome chrome = new FakeChrome();
        assertEquals(Decision.FILTER_DISABLED, prepare(chrome, true, true, false, new ArrayList<>()));
        assertTrue(chrome.hidden);
    }

    @Test
    public void hiddenWhenTheSignerIsNotGoogles() {
        FakeChrome chrome = new FakeChrome();
        chrome.signer = "ab".repeat(32);
        assertEquals(Decision.SIGNER_UNVERIFIED, prepare(chrome, true, true, true, new ArrayList<>()));
        assertTrue(chrome.hidden);
        assertFalse(chrome.calls.contains("write-config"));
    }

    @Test
    public void hiddenWhenTheConfigurationReadBackDoesNotMatch() {
        FakeChrome chrome = new FakeChrome();
        chrome.keepRestrictions = false;
        List<String> errors = new ArrayList<>();
        assertEquals(Decision.CONFIG_UNVERIFIED, prepare(chrome, true, true, true, errors));
        assertTrue(chrome.hidden);
        assertTrue(errors.contains(ChromeFilterExemption.CONFIG_UNVERIFIED_ERROR));
    }

    @Test
    public void anExceptionIsANotShownDecisionAndHides() {
        FakeChrome chrome = new FakeChrome();
        chrome.throwOnRead = new IllegalStateException("binder");
        List<String> errors = new ArrayList<>();
        assertEquals(Decision.ERROR, prepare(chrome, true, true, true, errors));
        assertTrue(chrome.hidden);
        assertTrue(errors.get(0).startsWith("chrome-exemption:"));
    }

    // --- Ordering ---------------------------------------------------------------------

    @Test
    public void configurationIsWrittenAndReadBackBeforeAnyUnhide() {
        FakeChrome chrome = new FakeChrome();
        chrome.hidden = true;
        Decision decision = prepare(chrome, true, true, true, new ArrayList<>());
        assertEquals(Decision.SHOWN, decision);
        assertFalse("prepare never unhides; the package pass does, later",
                chrome.calls.contains("hide=false"));
        // The package pass that follows:
        chrome.setHidden(!decision.shown());
        int write = chrome.calls.indexOf("write-config");
        int readBack = chrome.calls.lastIndexOf("read-config");
        int unhide = chrome.calls.indexOf("hide=false");
        assertTrue(write >= 0 && write < readBack && readBack < unhide);
        assertTrue(BuiltInBlockExemptions.restrictionsSatisfied(chrome.restrictions, PAC));
    }

    @Test
    public void aMatchingConfigurationIsNotRewritten() {
        FakeChrome chrome = new FakeChrome();
        chrome.restrictions = new LinkedHashMap<>(BuiltInBlockExemptions.chromeRestrictions(PAC));
        assertEquals(Decision.SHOWN, prepare(chrome, true, true, true, new ArrayList<>()));
        assertFalse(chrome.calls.contains("write-config"));
    }

    @Test
    public void whenNotShownHidingIsTheLastStepOfPrepare() {
        FakeChrome chrome = new FakeChrome();
        chrome.keepRestrictions = false;
        prepare(chrome, true, true, true, new ArrayList<>());
        assertEquals("hide=true", chrome.calls.get(chrome.calls.size() - 1));
    }

    @Test
    public void theWritePutsAMandatoryPacInProxySettingsAndDropsSeparateProxyKeys() {
        FakeChrome chrome = new FakeChrome();
        chrome.restrictions.put("ProxyMode", "direct");
        chrome.restrictions.put("ProxyPacUrl", "https://other.example/p.pac");
        assertEquals(Decision.SHOWN, prepare(chrome, true, true, true, new ArrayList<>()));
        assertFalse(chrome.restrictions.containsKey("ProxyMode"));
        assertFalse(chrome.restrictions.containsKey("ProxyPacUrl"));
        assertTrue(((String) chrome.restrictions.get("ProxySettings"))
                .contains("\"ProxyPacMandatory\":true"));
    }

    // --- WebView provider: existing behaviour ------------------------------------------

    @Test
    public void aWebViewProviderChromeIsNotHiddenHere() {
        FakeChrome chrome = new FakeChrome();
        chrome.webViewProvider = true;
        prepare(chrome, false, true, true, new ArrayList<>());
        assertFalse(chrome.calls.contains("hide=true"));
    }

    @Test
    public void aHideAndroidDidNotKeepIsReported() {
        FakeChrome chrome = new FakeChrome() {
            @Override
            public void setHidden(boolean value) {
                calls.add("hide=" + value);
            }
        };
        List<String> errors = new ArrayList<>();
        prepare(chrome, false, true, true, errors);
        assertTrue(errors.contains(ChromeFilterExemption.HIDE_UNVERIFIED_ERROR));
    }
}
