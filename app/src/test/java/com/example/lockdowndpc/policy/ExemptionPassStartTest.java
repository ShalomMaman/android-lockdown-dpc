package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.policy.ChromeFilterExemption.Containment;
import com.example.lockdowndpc.policy.ChromeFilterExemption.Decision;
import com.example.lockdowndpc.policy.ExemptionPassStart.Stop;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

/** The start-of-pass order apply() runs, against recording steps. */
public final class ExemptionPassStartTest {

    private static class RecordingSteps implements ExemptionPassStart.Steps {
        final List<String> calls = new ArrayList<>();
        boolean deviceOwner = true;
        boolean homeFilterReadable = true;
        boolean chromeInScope = true;
        boolean filterTeardownRequested;
        Containment chromeContainment = Containment.CONTAINED;
        /** Protection reads as active only once the pass recorded that it started. */
        boolean started;
        Boolean protectionSeenByDecision;

        @Override public boolean deviceOwner() { return deviceOwner; }

        @Override
        public boolean homeFilterReadable() {
            calls.add("check-home-filter");
            return homeFilterReadable;
        }

        @Override
        public boolean filterTeardownRequested() {
            return filterTeardownRequested;
        }

        @Override
        public void containSocial(List<String> errors) {
            calls.add("contain-social");
        }

        @Override
        public void containWebViewProvider(List<String> errors) {
            calls.add("suspend-webview-provider");
        }

        @Override
        public void recordEarlyReadback(List<String> errors) {
            calls.add("record-readback");
        }

        @Override
        public Containment containChrome(List<String> errors) {
            calls.add("contain-chrome");
            return chromeInScope ? chromeContainment : null;
        }

        @Override
        public void markApplyStarted() {
            calls.add("start");
            started = true;
        }

        @Override
        public boolean protectionActive() {
            return started;
        }

        @Override
        public Decision decideChrome(Containment containment, boolean protectionActive, List<String> errors) {
            calls.add("decide-chrome");
            protectionSeenByDecision = protectionActive;
            return protectionActive ? Decision.SHOWN : Decision.PROTECTION_PAUSED;
        }
    }

    @Test
    public void containmentRunsBeforeEveryEarlyReturn() {
        RecordingSteps steps = new RecordingSteps();
        steps.homeFilterReadable = false;
        ExemptionPassStart.Start start = ExemptionPassStart.begin(steps, new ArrayList<>());
        assertEquals(Stop.CORRUPT_HOME_FILTER, start.stop());
        assertEquals(List.of("contain-social", "suspend-webview-provider", "contain-chrome",
                "check-home-filter", "record-readback"), steps.calls);
        assertFalse("nothing after the early return runs", steps.calls.contains("decide-chrome"));
    }

    @Test
    public void theDecisionSeesProtectionAsRecordedByThisPass() {
        // A pass resuming from pause: protection reads as paused until the pass
        // records that it started. The decision must see the started state.
        RecordingSteps steps = new RecordingSteps();
        ExemptionPassStart.Start start = ExemptionPassStart.begin(steps, new ArrayList<>());
        assertEquals(Stop.NONE, start.stop());
        assertEquals(Boolean.TRUE, steps.protectionSeenByDecision);
        assertEquals(Decision.SHOWN, start.chrome());
        assertTrue(steps.calls.indexOf("start") < steps.calls.indexOf("decide-chrome"));
        assertTrue(steps.calls.indexOf("contain-chrome") < steps.calls.indexOf("start"));
        assertTrue("a browser-backed WebView provider is suspended before protection starts",
                steps.calls.indexOf("suspend-webview-provider") < steps.calls.indexOf("start"));
    }

    /** A Chrome Android refuses to hide. */
    private static final class RefusingChrome implements ChromeFilterExemption.Gateway {
        boolean hidden;

        @Override public boolean installed() { return true; }
        @Override public String currentSignerSha256() { return BuiltInBlockExemptions.CHROME_RELEASE_SIGNER_SHA256; }
        @Override public java.util.Map<String, Object> restrictions() { return new java.util.HashMap<>(); }
        @Override public void setRestrictions(java.util.Map<String, Object> values) { }
        @Override public void setHidden(boolean value) { }
        @Override public boolean hidden() { return hidden; }
        @Override public void setSuspended(boolean value) { }
        @Override public boolean suspended() { return false; }
        @Override public boolean enabled() { return true; }
    }

    @Test
    public void filterTeardownWaitsWhenChromesHideIsRefused() {
        // Chrome visible, the administrator turns the filter off, Android
        // refuses the hide: the start tells the pass to keep VPN, PAC and CA.
        RecordingSteps steps = new RecordingSteps() {
            @Override
            public Containment containChrome(List<String> errors) {
                calls.add("contain-chrome");
                return ChromeFilterExemption.contain(true, false, null, new RefusingChrome(), errors);
            }
        };
        steps.filterTeardownRequested = true;
        List<String> errors = new ArrayList<>();
        ExemptionPassStart.Start start = ExemptionPassStart.begin(steps, errors);
        assertTrue(start.holdFilterTeardown());
        assertTrue(errors.contains(ChromeFilterExemption.CONTAIN_UNVERIFIED_ERROR));
    }

    @Test
    public void filterTeardownProceedsOnceChromeIsContained() {
        RecordingSteps steps = new RecordingSteps();
        steps.filterTeardownRequested = true;
        assertFalse(ExemptionPassStart.begin(steps, new ArrayList<>()).holdFilterTeardown());
        steps = new RecordingSteps();
        steps.chromeContainment = Containment.REFUSED;
        assertFalse("no hold when nothing is being torn down",
                ExemptionPassStart.begin(steps, new ArrayList<>()).holdFilterTeardown());
    }

    @Test
    public void outOfScopeChromeIsNotAvailableAndNotDecided() {
        RecordingSteps steps = new RecordingSteps();
        steps.chromeInScope = false;
        ExemptionPassStart.Start start = ExemptionPassStart.begin(steps, new ArrayList<>());
        assertEquals(Decision.NOT_AVAILABLE, start.chrome());
        assertFalse(steps.calls.contains("decide-chrome"));
    }

    @Test
    public void withoutADeviceOwnerNothingIsContainedOrDecided() {
        RecordingSteps steps = new RecordingSteps();
        steps.deviceOwner = false;
        ExemptionPassStart.Start start = ExemptionPassStart.begin(steps, new ArrayList<>());
        assertEquals(Stop.NOT_DEVICE_OWNER, start.stop());
        assertNull(start.chrome());
        assertFalse(steps.calls.contains("contain-social"));
        assertFalse(steps.calls.contains("record-readback"));
        assertFalse(steps.calls.contains("decide-chrome"));
    }
}
