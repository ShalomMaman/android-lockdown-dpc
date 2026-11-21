package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.policy.BuiltInBlockExemptions.Settings;
import com.example.lockdowndpc.policy.BuiltInExemptionsController.Status;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

/** The change rule at the policy boundary, against a recording sink. */
public final class BuiltInExemptionsControllerTest {

    private static final String SIGNER = "aa".repeat(32);

    private static final class RecordingSink implements BuiltInExemptionsController.Sink {
        final List<String> calls = new ArrayList<>();
        boolean writeSucceeds = true;
        boolean auditSucceeds = true;
        boolean protectionActive = true;
        Settings written;

        @Override
        public boolean write(Settings settings) {
            calls.add("write");
            if (writeSucceeds) {
                written = settings;
            }
            return writeSucceeds;
        }

        @Override
        public boolean audit(String entry) {
            calls.add("audit:" + entry);
            return auditSucceeds;
        }

        @Override
        public boolean protectionActive() {
            return protectionActive;
        }

        @Override
        public LockdownPolicyController.PolicyResult applyPass() {
            calls.add("pass");
            return new LockdownPolicyController.PolicyResult(true, true, 0, 0, List.of());
        }
    }

    @Test
    public void aFailedCommitMakesNoChange() {
        RecordingSink sink = new RecordingSink();
        sink.writeSucceeds = false;
        BuiltInExemptionsController.Outcome outcome = BuiltInExemptionsController.change(
                Settings.NONE, settings -> settings.withChrome(true), true, "approve:chrome", sink);
        assertEquals(Status.NOT_SAVED, outcome.status());
        assertNull(outcome.result());
        assertEquals("no audit and no pass after a failed write", List.of("write"), sink.calls);
    }

    @Test
    public void looseningWithoutASessionIsRefusedBeforeAnyWrite() {
        RecordingSink sink = new RecordingSink();
        assertThrows(SecurityException.class, () -> BuiltInExemptionsController.change(
                Settings.NONE, settings -> settings.withSocial("com.whatsapp", SIGNER), false,
                "approve:com.whatsapp", sink));
        assertTrue(sink.calls.isEmpty());
    }

    @Test
    public void aRemovalIsAcceptedWithoutASessionAndApplied() {
        RecordingSink sink = new RecordingSink();
        Settings before = Settings.NONE.withSocial("com.whatsapp", SIGNER).withChrome(true);
        BuiltInExemptionsController.Outcome outcome = BuiltInExemptionsController.change(
                before, settings -> settings.withChrome(false), false, "remove:chrome", sink);
        assertEquals(Status.APPLIED, outcome.status());
        assertEquals(before.withChrome(false), sink.written);
        assertEquals(3, sink.calls.size());
        assertEquals("write", sink.calls.get(0));
        assertTrue(sink.calls.get(1).startsWith("audit:builtin-exemption: administrator remove:chrome: "));
        assertTrue(sink.calls.get(1).contains("chrome=true") && sink.calls.get(1).contains("-> chrome=false"));
        assertEquals("pass", sink.calls.get(2));
    }

    @Test
    public void anAuditThatDidNotPersistIsReportedButTheStoredChangeStillApplies() {
        RecordingSink sink = new RecordingSink();
        sink.auditSucceeds = false;
        BuiltInExemptionsController.Outcome outcome = BuiltInExemptionsController.change(
                Settings.NONE.withChrome(true), settings -> settings.withChrome(false), true,
                "remove:chrome", sink);
        assertEquals(Status.AUDIT_NOT_SAVED, outcome.status());
        assertEquals("pass", sink.calls.get(sink.calls.size() - 1));
    }

    @Test
    public void anApprovalWhileProtectionIsPausedIsStoredOnly() {
        RecordingSink sink = new RecordingSink();
        sink.protectionActive = false;
        BuiltInExemptionsController.Outcome outcome = BuiltInExemptionsController.change(
                Settings.NONE, settings -> settings.withChrome(true), true, "approve:chrome", sink);
        assertEquals(Status.SAVED, outcome.status());
        assertNull(outcome.result());
        assertEquals(Settings.NONE.withChrome(true), sink.written);
        assertTrue("no pass runs while paused", sink.calls.stream().noneMatch("pass"::equals));
    }

    @Test
    public void anUnchangedDecisionDoesNothing() {
        RecordingSink sink = new RecordingSink();
        assertEquals(Status.UNCHANGED, BuiltInExemptionsController.change(
                Settings.NONE, settings -> settings, true, "noop", sink).status());
        assertTrue(sink.calls.isEmpty());
    }
}
