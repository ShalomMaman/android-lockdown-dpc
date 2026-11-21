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

    private static final class RecordingSteps implements ExemptionPassStart.Steps {
        final List<String> calls = new ArrayList<>();
        boolean deviceOwner = true;
        boolean homeFilterReadable = true;
        boolean chromeInScope = true;
        /** Protection reads as active only once the pass recorded that it started. */
        boolean started;
        Boolean protectionSeenByDecision;

        @Override public boolean deviceOwner() { return deviceOwner; }

        @Override
        public boolean homeFilterReadable() {
            calls.add("check-home-filter");
            return homeFilterReadable;
        }

        HomeFilterPolicy.Settings storedFilter = new HomeFilterPolicy.Settings(
                new HomeFilterPolicy.Config(HomeFilterPolicy.DEFAULT_VPN_PACKAGE, "https://filter.example.org/p.pac"),
                true, null, false);
        BuiltInBlockExemptions.TeardownVerdict verdict = BuiltInBlockExemptions.TeardownVerdict.ALLOWED;

        @Override
        public HomeFilterPolicy.Settings storedFilter() {
            return storedFilter;
        }

        @Override
        public BuiltInBlockExemptions.TeardownVerdict teardownVerdict() {
            calls.add("teardown-guard");
            return verdict;
        }

        @Override
        public Decision unavailableDecision() {
            return Decision.NOT_AVAILABLE_ANDROID_VERSION;
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
            return chromeInScope ? Containment.CONTAINED : null;
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

    @Test
    public void aHeldDisableIsSettledOnceAfterContainmentAndLooksEnabledToEveryStep() {
        // A pending disable while Android does not report Chrome contained: the
        // start settles the enforced settings once, after containment and after
        // the pass started; system policy and reconciliation both take this value.
        RecordingSteps steps = new RecordingSteps();
        steps.storedFilter = steps.storedFilter.requestDisable();
        steps.verdict = BuiltInBlockExemptions.TeardownVerdict.CHROME_NOT_CONTAINED;
        ExemptionPassStart.Start start = ExemptionPassStart.begin(steps, new ArrayList<>());
        assertTrue(start.filter().held());
        assertTrue(start.filter().effective().enabled());
        assertTrue(steps.calls.indexOf("contain-chrome") < steps.calls.indexOf("teardown-guard"));
        assertTrue(steps.calls.indexOf("start") < steps.calls.indexOf("teardown-guard"));
        java.util.Map<SystemPolicyControl, Boolean> systemPolicy =
                HomeFilterPolicy.choicesFor(java.util.Map.of(), start.filter().effective().enabled());
        assertEquals(Boolean.TRUE, systemPolicy.get(SystemPolicyControl.APP_STORES_AND_INSTALLERS));
        assertFalse(start.filter().stored().enabled());
    }

    @Test
    public void outOfScopeChromeIsNotAvailableAndNotDecided() {
        RecordingSteps steps = new RecordingSteps();
        steps.chromeInScope = false;
        ExemptionPassStart.Start start = ExemptionPassStart.begin(steps, new ArrayList<>());
        assertEquals(Decision.NOT_AVAILABLE_ANDROID_VERSION, start.chrome());
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
