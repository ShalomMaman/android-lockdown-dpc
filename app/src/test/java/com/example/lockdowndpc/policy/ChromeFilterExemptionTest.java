package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.policy.ChromeFilterExemption.State;

import org.junit.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Controller-level regressions for the Chrome exemption: the grant, revocation
 * and teardown order the policy pass runs, against a fake Android gateway that
 * records every call and a ledger that survives "process death".
 */
public final class ChromeFilterExemptionTest {

    private static final String PAC = "https://filter.example.org/proxy.pac";
    private static final BuiltInBlockExemptions.FilterEvidence VERIFIED =
            new BuiltInBlockExemptions.FilterEvidence(true, true, true);

    /** Durable state, shared across simulated process restarts. */
    private static final class DurableLedger implements ChromeFilterExemption.Ledger {
        boolean granted;
        boolean pending;

        @Override public boolean granted() { return granted; }
        @Override public void setGranted(boolean value) { granted = value; }
        @Override public boolean revocationPending() { return pending; }
        @Override public void setRevocationPending(boolean value) { pending = value; }
    }

    private static class FakeChrome implements ChromeFilterExemption.Gateway {
        final List<String> calls = new ArrayList<>();
        boolean installed = true;
        String signer = BuiltInBlockExemptions.CHROME_RELEASE_SIGNER_SHA256;
        BuiltInBlockExemptions.FilterEvidence evidence = VERIFIED;
        Map<String, Object> restrictions = new LinkedHashMap<>();
        boolean acceptRestrictions = true;
        boolean webViewProvider;
        boolean hidden = true;
        boolean suspended;
        boolean refuseHide;
        RuntimeException throwOnEvidence;

        @Override public boolean installed() { return installed; }
        @Override public String currentSignerSha256() { return signer; }

        @Override
        public BuiltInBlockExemptions.FilterEvidence filterEvidence() {
            calls.add("evidence");
            if (throwOnEvidence != null) {
                throw throwOnEvidence;
            }
            return evidence;
        }

        @Override public String pacUrl() { return PAC; }

        @Override
        public Map<String, Object> restrictions() {
            calls.add("read-restrictions");
            return new LinkedHashMap<>(restrictions);
        }

        @Override
        public void setRestrictions(Map<String, Object> values) {
            calls.add("set-restrictions");
            if (acceptRestrictions) {
                restrictions = new LinkedHashMap<>(values);
            }
        }

        @Override public boolean webViewProvider() { return webViewProvider; }

        @Override
        public void setHidden(boolean value) {
            calls.add("hide=" + value);
            if (!refuseHide) {
                hidden = value;
            }
        }

        @Override public boolean hidden() { return hidden; }

        @Override
        public void setSuspended(boolean value) {
            calls.add("suspend=" + value);
            suspended = value;
        }

        @Override public boolean suspended() { return suspended; }
    }

    /** What the package pass does after prepare: show Chrome only when granted. */
    private static void packagePass(FakeChrome chrome, State prepared) {
        chrome.setHidden(prepared != State.ACTIVE);
    }

    // --- Grant ----------------------------------------------------------------

    @Test
    public void chromeStaysBlockedWhenTheExemptionIsOff() {
        FakeChrome chrome = new FakeChrome();
        DurableLedger ledger = new DurableLedger();
        List<String> errors = new ArrayList<>();
        State state = ChromeFilterExemption.prepare(false, chrome, ledger, errors);
        assertEquals(State.OFF, state);
        assertFalse(ledger.granted);
        assertFalse("nothing is configured for an exemption nobody asked for",
                chrome.calls.contains("set-restrictions"));
        assertTrue(errors.isEmpty());
    }

    @Test
    public void restrictionsAreWrittenAndReadBackBeforeTheGrant() {
        FakeChrome chrome = new FakeChrome();
        DurableLedger ledger = new DurableLedger();
        State state = ChromeFilterExemption.prepare(true, chrome, ledger, new ArrayList<>());
        assertEquals(State.ACTIVE, state);
        assertTrue("the grant is durable before the package pass shows Chrome", ledger.granted);
        assertTrue(BuiltInBlockExemptions.restrictionsSatisfied(
                chrome.restrictions, BuiltInBlockExemptions.chromeRestrictions(PAC)));
        int set = chrome.calls.indexOf("set-restrictions");
        assertTrue(set >= 0);
        assertTrue("read back after writing", chrome.calls.lastIndexOf("read-restrictions") > set);
        assertFalse("prepare never shows Chrome itself", chrome.calls.contains("hide=false"));
    }

    @Test
    public void restrictionsAndroidDidNotKeepPreventTheGrant() {
        FakeChrome chrome = new FakeChrome();
        chrome.acceptRestrictions = false;
        DurableLedger ledger = new DurableLedger();
        assertEquals(State.RESTRICTIONS_UNVERIFIED,
                ChromeFilterExemption.prepare(true, chrome, ledger, new ArrayList<>()));
        assertFalse(ledger.granted);
    }

    @Test
    public void aChromeNotSignedByGoogleIsNeverGranted() {
        FakeChrome chrome = new FakeChrome();
        chrome.signer = "ab".repeat(32);
        DurableLedger ledger = new DurableLedger();
        assertEquals(State.SIGNER_UNVERIFIED,
                ChromeFilterExemption.prepare(true, chrome, ledger, new ArrayList<>()));
        assertFalse(ledger.granted);
        assertFalse(chrome.calls.contains("set-restrictions"));
    }

    @Test
    public void anUnverifiedFilterIsNeverGranted() {
        for (BuiltInBlockExemptions.FilterEvidence evidence : List.of(
                new BuiltInBlockExemptions.FilterEvidence(false, true, true),
                new BuiltInBlockExemptions.FilterEvidence(true, false, true),
                new BuiltInBlockExemptions.FilterEvidence(true, true, false))) {
            FakeChrome chrome = new FakeChrome();
            chrome.evidence = evidence;
            DurableLedger ledger = new DurableLedger();
            assertEquals(State.FILTER_UNVERIFIED,
                    ChromeFilterExemption.prepare(true, chrome, ledger, new ArrayList<>()));
            assertFalse(ledger.granted);
        }
    }

    // --- Fail closed, revoke first ------------------------------------------------

    @Test
    public void aLapsedFilterRevokesBeforeAnythingElseOnTheNextPass() {
        FakeChrome chrome = new FakeChrome();
        DurableLedger ledger = new DurableLedger();
        packagePass(chrome, ChromeFilterExemption.prepare(true, chrome, ledger, new ArrayList<>()));
        assertFalse(chrome.hidden);

        chrome.calls.clear();
        chrome.evidence = BuiltInBlockExemptions.FilterEvidence.NONE;
        List<String> errors = new ArrayList<>();
        State state = ChromeFilterExemption.prepare(true, chrome, ledger, errors);
        assertEquals(State.FILTER_UNVERIFIED, state);
        assertTrue("revoked inside prepare, before the package pass", chrome.hidden);
        assertEquals("hide=true", chrome.calls.get(chrome.calls.size() - 1));
        assertFalse(ledger.granted);
        assertFalse(ledger.pending);
        assertTrue(ChromeFilterExemption.teardownAllowed(ledger));
    }

    @Test
    public void anExceptionRevokesAGrantedChrome() {
        FakeChrome chrome = new FakeChrome();
        DurableLedger ledger = new DurableLedger();
        packagePass(chrome, ChromeFilterExemption.prepare(true, chrome, ledger, new ArrayList<>()));
        chrome.throwOnEvidence = new IllegalStateException("binder");
        List<String> errors = new ArrayList<>();
        assertEquals(State.ERROR, ChromeFilterExemption.prepare(true, chrome, ledger, errors));
        assertTrue(chrome.hidden);
        assertFalse(ledger.granted);
        assertTrue(errors.get(0).startsWith("chrome-exemption:"));
    }

    @Test
    public void theFinalFilterReadBackRevokesAnEarlierGrant() {
        FakeChrome chrome = new FakeChrome();
        DurableLedger ledger = new DurableLedger();
        State prepared = ChromeFilterExemption.prepare(true, chrome, ledger, new ArrayList<>());
        packagePass(chrome, prepared);
        List<String> errors = new ArrayList<>();
        State finished = ChromeFilterExemption.finish(prepared, false, true, chrome, ledger, errors);
        assertEquals(State.FILTER_UNVERIFIED, finished);
        assertTrue(chrome.hidden);
        assertTrue(errors.contains(BuiltInBlockExemptions.BROWSER_FILTER_UNVERIFIED_ERROR));
    }

    @Test
    public void aRoutingFailureRevokes() {
        FakeChrome chrome = new FakeChrome();
        DurableLedger ledger = new DurableLedger();
        State prepared = ChromeFilterExemption.prepare(true, chrome, ledger, new ArrayList<>());
        packagePass(chrome, prepared);
        assertEquals(State.LINK_ROUTE_UNVERIFIED, ChromeFilterExemption.finish(
                prepared, true, false, chrome, ledger, new ArrayList<>()));
        assertTrue(chrome.hidden);
    }

    @Test
    public void restrictionsLostDuringThePassRevoke() {
        FakeChrome chrome = new FakeChrome();
        DurableLedger ledger = new DurableLedger();
        State prepared = ChromeFilterExemption.prepare(true, chrome, ledger, new ArrayList<>());
        packagePass(chrome, prepared);
        chrome.restrictions.remove("ProxyMode");
        assertEquals(State.RESTRICTIONS_UNVERIFIED, ChromeFilterExemption.finish(
                prepared, true, true, chrome, ledger, new ArrayList<>()));
        assertTrue(chrome.hidden);
    }

    @Test
    public void aWebViewProviderChromeIsSuspendedNotHidden() {
        FakeChrome chrome = new FakeChrome();
        chrome.webViewProvider = true;
        chrome.hidden = false;
        DurableLedger ledger = new DurableLedger();
        ledger.granted = true;
        chrome.evidence = BuiltInBlockExemptions.FilterEvidence.NONE;
        ChromeFilterExemption.prepare(true, chrome, ledger, new ArrayList<>());
        assertTrue(chrome.suspended);
        assertFalse("the WebView provider is never hidden", chrome.calls.contains("hide=true"));
        assertFalse(ledger.pending);
    }

    // --- Failed revoke, process death and boot ----------------------------------------

    @Test
    public void aFailedRevokeStaysPendingAndHoldsTheFilterTeardown() {
        FakeChrome chrome = new FakeChrome();
        DurableLedger ledger = new DurableLedger();
        packagePass(chrome, ChromeFilterExemption.prepare(true, chrome, ledger, new ArrayList<>()));
        chrome.refuseHide = true;
        List<String> errors = new ArrayList<>();
        ChromeFilterExemption.prepare(false, chrome, ledger, errors);
        assertFalse(chrome.hidden);
        assertTrue(ledger.pending);
        assertFalse("the VPN, proxy and CA stay while Chrome may be open",
                ChromeFilterExemption.teardownAllowed(ledger));
        assertTrue(errors.contains(BuiltInBlockExemptions.CHROME_REVOCATION_UNVERIFIED_ERROR));
    }

    @Test
    public void theBootPassRetriesAPendingRevocation() {
        DurableLedger ledger = new DurableLedger();
        ledger.pending = true;
        FakeChrome afterBoot = new FakeChrome();
        afterBoot.hidden = false;
        // The administrator withdrew Chrome and the process died before
        // Android confirmed; the first pass after boot completes it.
        List<String> errors = new ArrayList<>();
        State state = ChromeFilterExemption.prepare(false, afterBoot, ledger, errors);
        assertEquals(State.OFF, state);
        assertTrue(afterBoot.hidden);
        assertFalse(ledger.pending);
        assertTrue(ChromeFilterExemption.teardownAllowed(ledger));
    }

    @Test
    public void theBootPassReChecksAGrantRecordedBeforeProcessDeath() {
        DurableLedger ledger = new DurableLedger();
        FakeChrome before = new FakeChrome();
        ChromeFilterExemption.prepare(true, before, ledger, new ArrayList<>());
        assertTrue(ledger.granted);
        // The process dies after the grant was recorded; on boot the filter is
        // not yet confirmed.
        FakeChrome afterBoot = new FakeChrome();
        afterBoot.hidden = false;
        afterBoot.evidence = BuiltInBlockExemptions.FilterEvidence.NONE;
        ChromeFilterExemption.prepare(true, afterBoot, ledger, new ArrayList<>());
        assertTrue(afterBoot.hidden);
        assertFalse(ledger.granted);
    }

    @Test
    public void noGrantIsMadeOverAnUnconfirmedRevocation() {
        DurableLedger ledger = new DurableLedger();
        ledger.pending = true;
        FakeChrome chrome = new FakeChrome();
        chrome.hidden = false;
        chrome.refuseHide = true;
        List<String> errors = new ArrayList<>();
        assertEquals(State.REVOCATION_PENDING,
                ChromeFilterExemption.prepare(true, chrome, ledger, errors));
        assertFalse(ledger.granted);
        assertTrue(ledger.pending);

        chrome.refuseHide = false;
        assertEquals("granted only once the old block is confirmed",
                State.ACTIVE, ChromeFilterExemption.prepare(true, chrome, ledger, new ArrayList<>()));
        assertTrue(chrome.hidden);
        assertFalse(ledger.pending);
        assertTrue(ledger.granted);
    }

    @Test
    public void revocationIsMarkedPendingBeforeTheFirstAndroidCall() {
        DurableLedger ledger = new DurableLedger();
        ledger.granted = true;
        FakeChrome chrome = new FakeChrome() {
            @Override
            public void setHidden(boolean value) {
                assertTrue("pending must be durable before Android is asked", ledger.pending);
                super.setHidden(value);
            }
        };
        chrome.hidden = false;
        assertTrue(ChromeFilterExemption.revoke(chrome, ledger, new ArrayList<>()));
    }

    @Test
    public void anUninstalledChromeCompletesARevocation() {
        DurableLedger ledger = new DurableLedger();
        ledger.pending = true;
        FakeChrome chrome = new FakeChrome();
        chrome.installed = false;
        ChromeFilterExemption.prepare(true, chrome, ledger, new ArrayList<>());
        assertFalse(ledger.pending);
        assertFalse(ledger.granted);
    }

    @Test
    public void revokeIfGrantedDoesNothingWithoutARecord() {
        DurableLedger ledger = new DurableLedger();
        FakeChrome chrome = new FakeChrome();
        ChromeFilterExemption.revokeIfGranted(chrome, ledger, new ArrayList<>());
        assertTrue(chrome.calls.isEmpty());
    }
}
