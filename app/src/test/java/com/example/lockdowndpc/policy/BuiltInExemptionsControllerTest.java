package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.policy.BuiltInBlockExemptions.Settings;
import com.example.lockdowndpc.policy.BuiltInExemptionsController.Status;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/** The change rule at the policy boundary, against a recording sink. */
public final class BuiltInExemptionsControllerTest {

    private static final String SIGNER = "aa".repeat(32);

    private static class RecordingSink implements BuiltInExemptionsController.Sink {
        final List<String> calls = new ArrayList<>();
        boolean writeSucceeds = true;
        boolean auditSucceeds = true;
        boolean protectionActive = true;
        boolean untrusted;
        boolean filterSteady = true;
        boolean lockSucceeds = true;
        BuiltInBlockExemptions.Record record = BuiltInBlockExemptions.Record.EMPTY;
        Set<String> activeAdmins = Set.of();
        boolean containSucceeds = true;
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
        public boolean exemptionsUntrusted() {
            return untrusted;
        }

        @Override
        public boolean filterSteadyForChrome() {
            return filterSteady;
        }

        @Override
        public BuiltInBlockExemptions.Record record() {
            return record;
        }

        @Override
        public boolean lockCredentials() {
            calls.add("lock");
            return lockSucceeds;
        }

        @Override
        public void reconcileCredentialsLock() {
            calls.add("lock-reconcile");
        }

        @Override
        public boolean protectionActive() {
            return protectionActive;
        }

        @Override
        public Set<String> activeAdminPackages() {
            return activeAdmins;
        }

        @Override
        public boolean containRevoked(BuiltInBlockExemptions.Revocation revocation) {
            calls.add("contain:" + new java.util.TreeSet<>(revocation.social()) + ",chrome=" + revocation.chrome());
            return containSucceeds;
        }

        @Override
        public LockdownPolicyController.PolicyResult applyPass() {
            calls.add("pass");
            return new LockdownPolicyController.PolicyResult(true, true, 0, 0, List.of());
        }
    }

    @Test
    public void aFailedFirstGrantLeavesNoLockBehind() {
        RecordingSink sink = new RecordingSink();
        sink.writeSucceeds = false;
        BuiltInExemptionsController.Outcome outcome = BuiltInExemptionsController.change(
                Settings.NONE, settings -> settings.withChrome(true), true, "approve:chrome", sink);
        assertEquals(Status.NOT_SAVED, outcome.status());
        assertNull(outcome.result());
        // The lock is set before the write; after the failed write the record
        // is restored and the lock is reconciled against it before returning.
        assertEquals("no audit and no pass after a failed write",
                List.of("lock", "write", "lock-reconcile"), sink.calls);
    }

    // --- Active device administrators -------------------------------------------------

    @Test
    public void anActiveDeviceAdministratorIsNeverApproved() {
        RecordingSink sink = new RecordingSink();
        sink.activeAdmins = Set.of("com.whatsapp");
        BuiltInExemptionsController.Outcome outcome = BuiltInExemptionsController.change(
                Settings.NONE, settings -> settings.withSocial("com.whatsapp", SIGNER), true,
                "approve:com.whatsapp", sink);
        assertEquals(Status.ACTIVE_ADMIN_REFUSED, outcome.status());
        assertNull(outcome.result());
        assertNull(sink.written);
        assertTrue("nothing written, no lock, no pass", sink.calls.isEmpty());
    }

    @Test
    public void unreadableAdministratorsRefuseAnApprovalWithTheirOwnStatus() {
        RecordingSink sink = new RecordingSink();
        sink.activeAdmins = null;
        assertEquals(Status.ADMINS_UNREADABLE, BuiltInExemptionsController.change(
                Settings.NONE, settings -> settings.withSocial("com.whatsapp", SIGNER), true,
                "approve:com.whatsapp", sink).status());
        assertTrue(sink.calls.isEmpty());
    }

    @Test
    public void anotherAppsAdministratorDoesNotBlockAnApproval() {
        RecordingSink sink = new RecordingSink();
        sink.activeAdmins = Set.of("com.example.lockdowndpc");
        assertEquals(Status.APPLIED, BuiltInExemptionsController.change(
                Settings.NONE, settings -> settings.withSocial("com.whatsapp", SIGNER), true,
                "approve:com.whatsapp", sink).status());
    }

    // --- Tighten before revoking --------------------------------------------------------

    @Test
    public void aRevocationContainsTheAppBeforeTheRemovalIsCommitted() {
        RecordingSink sink = new RecordingSink();
        Settings before = Settings.NONE.withSocial("org.telegram.messenger", SIGNER).withSocial("com.whatsapp", SIGNER);
        BuiltInExemptionsController.Outcome outcome = BuiltInExemptionsController.change(
                before, settings -> settings.withoutSocial("org.telegram.messenger"), false,
                "remove:org.telegram.messenger", sink);
        assertEquals(Status.APPLIED, outcome.status());
        assertEquals("contain:[org.telegram.messenger],chrome=false", sink.calls.get(0));
        assertEquals("write", sink.calls.get(1));
        assertTrue(sink.calls.get(2).startsWith("audit:"));
        assertEquals("pass", sink.calls.get(3));
    }

    @Test
    public void aRefusedContainmentStillCommitsTheRemovalAndIsReported() {
        RecordingSink sink = new RecordingSink();
        sink.containSucceeds = false;
        Settings before = Settings.NONE.withSocial("org.telegram.messenger", SIGNER);
        BuiltInExemptionsController.Outcome outcome = BuiltInExemptionsController.change(
                before, settings -> settings.withoutSocial("org.telegram.messenger"), false,
                "remove:org.telegram.messenger", sink);
        assertEquals(Status.CONTAINMENT_REFUSED, outcome.status());
        assertEquals(Settings.NONE, sink.written);
        assertTrue(sink.calls.get(2), sink.calls.get(2).endsWith("(CONTAINMENT_REFUSED)"));
        assertEquals("the next pass keeps trying", "pass", sink.calls.get(3));
    }

    @Test
    public void aFailedCommitAfterContainmentSavesNothingElse() {
        RecordingSink sink = new RecordingSink();
        sink.writeSucceeds = false;
        Settings before = Settings.NONE.withChrome(true);
        assertEquals(Status.NOT_SAVED, BuiltInExemptionsController.change(
                before, settings -> settings.withChrome(false), true, "remove:chrome", sink).status());
        assertEquals(List.of("contain:[],chrome=true", "write", "lock-reconcile"), sink.calls);
    }

    @Test
    public void clearingContainsEveryApprovedAppFirst() {
        RecordingSink sink = new RecordingSink();
        sink.record = new BuiltInBlockExemptions.Record(
                Settings.NONE.withChrome(true).withSocial("com.whatsapp", SIGNER));
        assertEquals(Status.APPLIED, BuiltInExemptionsController.clear(true, sink).status());
        assertEquals("contain:[com.whatsapp],chrome=true", sink.calls.get(0));
        assertEquals("write", sink.calls.get(1));
    }

    @Test
    public void aGrantContainsNothing() {
        RecordingSink sink = new RecordingSink();
        BuiltInExemptionsController.change(Settings.NONE, settings -> settings.withSocial("com.whatsapp", SIGNER),
                true, "approve:com.whatsapp", sink);
        assertFalse(sink.calls.stream().anyMatch(call -> call.startsWith("contain:")));
    }

    @Test
    public void revokingAnAdministratorsApprovalIsStillAccepted() {
        RecordingSink sink = new RecordingSink();
        sink.activeAdmins = Set.of("com.whatsapp");
        Settings before = Settings.NONE.withSocial("com.whatsapp", SIGNER);
        assertEquals(Status.APPLIED, BuiltInExemptionsController.change(
                before, settings -> settings.withoutSocial("com.whatsapp"), false,
                "remove:com.whatsapp", sink).status());
        assertEquals(Settings.NONE, sink.written);
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
        assertEquals(4, sink.calls.size());
        assertEquals("contained before the removal is saved", "contain:[],chrome=true", sink.calls.get(0));
        assertEquals("write", sink.calls.get(1));
        assertTrue(sink.calls.get(2).startsWith(
                "audit:builtin-exemption: remove:chrome (no administrator session): "));
        assertTrue(sink.calls.get(2).contains("chrome=true") && sink.calls.get(2).contains("-> chrome=false"));
        assertEquals("pass", sink.calls.get(3));
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
    public void everyEditIsRefusedWhileProtectionIsPaused() {
        Settings saved = Settings.NONE.withChrome(true).withSocial("com.whatsapp", SIGNER);
        for (java.util.function.UnaryOperator<Settings> edit : List.<java.util.function.UnaryOperator<Settings>>of(
                settings -> settings.withChrome(true),
                settings -> settings.withChrome(false),
                settings -> settings.withoutSocial("com.whatsapp"),
                settings -> settings.withSocial("com.whatsapp", "bb".repeat(32)))) {
            RecordingSink sink = new RecordingSink();
            sink.protectionActive = false;
            BuiltInExemptionsController.Outcome outcome =
                    BuiltInExemptionsController.change(saved, edit, true, "edit", sink);
            assertEquals(Status.PAUSED_REFUSED, outcome.status());
            assertTrue("nothing written, no lock changed: " + sink.calls, sink.calls.isEmpty());
        }
        RecordingSink sink = new RecordingSink();
        sink.protectionActive = false;
        assertEquals(Status.PAUSED_REFUSED, BuiltInExemptionsController.clear(true, sink).status());
        assertTrue(sink.calls.isEmpty());
    }

    @Test
    public void aRemovalWithoutASessionIsAuditedAsSuch() {
        RecordingSink sink = new RecordingSink();
        BuiltInExemptionsController.change(Settings.NONE.withChrome(true),
                settings -> settings.withChrome(false), false, "remove:chrome", sink);
        String audit = sink.calls.get(2);
        assertTrue(audit, audit.contains("remove:chrome (no administrator session)"));
        assertFalse(audit, audit.contains("administrator remove"));
    }

    @Test
    public void whileAFailedSaveIsUnresolvedEvenARemovalNeedsASession() {
        // Passes enforce no exemptions while the latch is set; a removal that
        // saved would clear it and re-enable every other approval.
        RecordingSink sink = new RecordingSink();
        sink.untrusted = true;
        Settings saved = Settings.NONE.withChrome(true).withSocial("com.whatsapp", SIGNER);
        assertThrows(SecurityException.class, () -> BuiltInExemptionsController.change(
                saved, settings -> settings.withChrome(false), false, "remove:chrome", sink));
        assertTrue(sink.calls.isEmpty());
        assertEquals(Status.APPLIED, BuiltInExemptionsController.change(
                saved, settings -> settings.withChrome(false), true, "remove:chrome", sink).status());
    }

    /** Android's commit(): memory changes even when the disk write fails. */
    private static final class AndroidLikeBacking implements BuiltInExemptionsPersistence.Backing {
        Settings memory = Settings.NONE;
        Settings disk = Settings.NONE;
        boolean diskFails;

        @Override
        public BuiltInBlockExemptions.Record read() {
            return new BuiltInBlockExemptions.Record(memory);
        }

        @Override
        public boolean commit(Settings settings) {
            memory = settings;
            if (diskFails) {
                return false;
            }
            disk = settings;
            return true;
        }

        @Override
        public Object snapshot() {
            return memory;
        }

        @Override
        public void restore(Object snapshot) {
            memory = (Settings) snapshot;
        }
    }

    @Test
    public void aRetryAfterAFailedSaveKeepsEarlierApprovals() {
        AndroidLikeBacking backing = new AndroidLikeBacking();
        BuiltInExemptionsPersistence persistence = new BuiltInExemptionsPersistence(backing);
        RecordingSink sink = new RecordingSink() {
            @Override
            public boolean write(Settings settings) {
                return persistence.write(settings);
            }
        };
        // Chrome approved and saved.
        assertEquals(Status.APPLIED, BuiltInExemptionsController.change(persistence.record().enforced(),
                settings -> settings.withChrome(true), true, "approve:chrome", sink).status());
        // WhatsApp approval fails to save; passes now see no exemptions.
        backing.diskFails = true;
        assertEquals(Status.NOT_SAVED, BuiltInExemptionsController.change(persistence.record().enforced(),
                settings -> settings.withSocial("com.whatsapp", SIGNER), true, "approve:com.whatsapp",
                sink).status());
        assertEquals(Settings.NONE, persistence.read());
        // The retry starts from the last saved decision, not from the latch.
        backing.diskFails = false;
        assertEquals(Status.APPLIED, BuiltInExemptionsController.change(persistence.record().enforced(),
                settings -> settings.withSocial("com.whatsapp", SIGNER), true, "approve:com.whatsapp",
                sink).status());
        assertEquals(Settings.NONE.withChrome(true).withSocial("com.whatsapp", SIGNER), backing.disk);
        assertEquals(backing.disk, persistence.read());
    }

    @Test
    public void anApprovalForAnUninstalledAppCanBeRemoved() {
        // Nothing in the change rule depends on the package being installed.
        RecordingSink sink = new RecordingSink();
        Settings before = Settings.NONE.withSocial("com.discord", SIGNER);
        BuiltInExemptionsController.Outcome outcome = BuiltInExemptionsController.change(
                before, settings -> settings.withoutSocial("com.discord"), true, "remove:com.discord", sink);
        assertEquals(Status.APPLIED, outcome.status());
        assertEquals(Settings.NONE, sink.written);
    }

    @Test
    public void chromeIsNotApprovedOverAPendingFilterTeardown() {
        // A certificate removal Android refused left removeCa pending: the
        // filter is not steady, so the approval is refused before any write.
        RecordingSink sink = new RecordingSink();
        sink.filterSteady = false;
        BuiltInExemptionsController.Outcome outcome = BuiltInExemptionsController.change(
                Settings.NONE, settings -> settings.withChrome(true), true, "approve:chrome", sink);
        assertEquals(Status.FILTER_NOT_READY, outcome.status());
        assertTrue(sink.calls.isEmpty());
        assertNull(sink.written);
    }

    @Test
    public void aSocialApprovalDoesNotDependOnTheFilterState() {
        RecordingSink sink = new RecordingSink();
        sink.filterSteady = false;
        assertEquals(Status.APPLIED, BuiltInExemptionsController.change(Settings.NONE,
                settings -> settings.withSocial("com.whatsapp", SIGNER), true, "approve:com.whatsapp",
                sink).status());
    }

    @Test
    public void theCredentialsLockIsSetBeforeAChromeApprovalIsSaved() {
        RecordingSink sink = new RecordingSink();
        assertEquals(Status.APPLIED, BuiltInExemptionsController.change(
                Settings.NONE, settings -> settings.withChrome(true), true, "approve:chrome", sink).status());
        assertTrue(sink.calls.toString(), sink.calls.indexOf("lock") >= 0
                && sink.calls.indexOf("lock") < sink.calls.indexOf("write"));
    }

    @Test
    public void noLockNoChromeApproval() {
        RecordingSink sink = new RecordingSink();
        sink.lockSucceeds = false;
        assertEquals(Status.NOT_SAVED, BuiltInExemptionsController.change(
                Settings.NONE, settings -> settings.withChrome(true), true, "approve:chrome", sink).status());
        assertNull(sink.written);
        assertFalse(sink.calls.contains("write"));
    }

    @Test
    public void anUnreadableRecordRefusesOrdinaryEditsAndWritesNothing() {
        RecordingSink sink = new RecordingSink();
        sink.record = BuiltInBlockExemptions.Record.UNREADABLE;
        assertEquals(Status.NOT_SAVED, BuiltInExemptionsController.change(Settings.NONE,
                settings -> settings.withSocial("com.whatsapp", SIGNER), true, "approve:com.whatsapp",
                sink).status());
        assertEquals(Status.NOT_SAVED, BuiltInExemptionsController.change(Settings.NONE,
                settings -> settings.withChrome(false), true, "remove:chrome", sink).status());
        assertTrue(sink.calls.isEmpty());
    }

    @Test
    public void onlyAnExplicitClearMayOverwriteAnUnreadableRecord() {
        RecordingSink sink = new RecordingSink();
        sink.record = BuiltInBlockExemptions.Record.UNREADABLE;
        assertThrows(SecurityException.class, () -> BuiltInExemptionsController.clear(false, sink));
        assertTrue(sink.calls.isEmpty());
        assertEquals(Status.APPLIED, BuiltInExemptionsController.clear(true, sink).status());
        assertEquals(Settings.NONE, sink.written);
        assertTrue("the prior state is logged as read: " + sink.calls,
                sink.calls.stream().anyMatch(call -> call.contains(": unreadable -> chrome=false")));
        assertFalse("clearing does not touch the lock; the pass releases it under the guard",
                sink.calls.contains("lock"));
    }

    @Test
    public void anUnchangedDecisionDoesNothing() {
        RecordingSink sink = new RecordingSink();
        assertEquals(Status.UNCHANGED, BuiltInExemptionsController.change(
                Settings.NONE, settings -> settings, true, "noop", sink).status());
        assertTrue(sink.calls.isEmpty());
    }
}
