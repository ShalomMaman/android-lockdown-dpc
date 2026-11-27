package com.example.lockdowndpc.admin;

import static android.app.admin.DevicePolicyManager.PROVISIONING_MODE_FULLY_MANAGED_DEVICE;
import static android.app.admin.DevicePolicyManager.PROVISIONING_MODE_MANAGED_PROFILE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.policy.PolicyReconciliationCoordinator.ProvisioningResult;

import org.junit.Test;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.OptionalInt;
import java.util.Queue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

public final class ProvisioningFlowTest {
    private static final ProvisioningResult VERIFIED = new ProvisioningResult(true, List.of());
    private static final ProvisioningResult FAILED = new ProvisioningResult(
            false, List.of("link-filter-target-unverified:https"));
    private static final ProvisioningResult UNVERIFIED = new ProvisioningResult(false, List.of());
    @Test
    public void missingAllowedModesSelectsFullyManaged() {
        assertEquals(OptionalInt.of(PROVISIONING_MODE_FULLY_MANAGED_DEVICE),
                ProvisioningFlow.selectMode(false, null));
    }

    @Test
    public void selectsFullyManagedWhenItIsAllowedAlongsideWorkProfile() {
        assertEquals(OptionalInt.of(PROVISIONING_MODE_FULLY_MANAGED_DEVICE),
                ProvisioningFlow.selectMode(true, List.of(PROVISIONING_MODE_MANAGED_PROFILE,
                        PROVISIONING_MODE_FULLY_MANAGED_DEVICE)));
    }

    @Test
    public void workProfileOnlyIsRefused() {
        assertFalse(ProvisioningFlow.selectMode(
                true, List.of(PROVISIONING_MODE_MANAGED_PROFILE)).isPresent());
    }

    @Test
    public void presentButEmptyOrUnreadableAllowedModesAreRefused() {
        assertFalse(ProvisioningFlow.selectMode(true, List.of()).isPresent());
        assertFalse(ProvisioningFlow.selectMode(true, null).isPresent());
    }

    @Test
    public void verifiedPassReportsSuccess() {
        AtomicInteger passes = new AtomicInteger();
        List<ProvisioningResult> results = new ArrayList<>();

        ProvisioningFlow.completeCompliance(report -> {
            passes.incrementAndGet();
            report.accept(VERIFIED);
        }, results::add);

        assertEquals(1, passes.get());
        assertEquals(List.of(VERIFIED), results);
    }

    @Test
    public void unverifiedPassPreservesFailureCodes() {
        List<ProvisioningResult> results = new ArrayList<>();

        ProvisioningFlow.completeCompliance(report -> report.accept(FAILED), results::add);

        assertEquals(List.of(FAILED), results);
    }

    @Test
    public void missingVerificationIsTreatedAsFailure() {
        List<ProvisioningResult> results = new ArrayList<>();

        ProvisioningFlow.completeCompliance(report -> report.accept(null), results::add);

        assertEquals(List.of(UNVERIFIED), results);
    }

    @Test
    public void passThatCannotStartReportsCrashCode() {
        List<ProvisioningResult> results = new ArrayList<>();

        ProvisioningFlow.completeCompliance(report -> {
            throw new IllegalStateException("Policy queue unavailable");
        }, results::add);

        assertEquals(List.of(new ProvisioningResult(
                false, List.of("policy-pass-crashed:IllegalStateException"))), results);
    }

    @Test
    public void resultIsReportedOnlyOnce() {
        List<ProvisioningResult> results = new ArrayList<>();

        ProvisioningFlow.completeCompliance(report -> {
            report.accept(VERIFIED);
            report.accept(FAILED);
        }, results::add);

        assertEquals(List.of(VERIFIED), results);
    }

    @Test
    public void baselineNotDueReportsSuccessInlineWithoutStartingAPass() {
        Queue<Runnable> main = new ArrayDeque<>();
        ProvisioningFlow.PendingCompliance pending = new ProvisioningFlow.PendingCompliance(main::add, result -> {});
        List<ProvisioningResult> results = new ArrayList<>();

        pending.request(() -> false, () -> {
            throw new AssertionError("progress must not be shown");
        }, report -> {
            throw new AssertionError("a pass must not start");
        }, results::add);

        assertEquals(List.of(VERIFIED), results);
        assertTrue(main.isEmpty());
    }

    @Test
    public void duplicateLaunchesShareOnePassAndEveryLiveRequestReceivesTheResult() {
        Queue<Runnable> main = new ArrayDeque<>();
        ProvisioningFlow.PendingCompliance pending = new ProvisioningFlow.PendingCompliance(main::add, result -> {});
        AtomicReference<Consumer<ProvisioningResult>> verify = new AtomicReference<>();
        AtomicInteger progress = new AtomicInteger();
        List<ProvisioningResult> first = new ArrayList<>();
        List<ProvisioningResult> second = new ArrayList<>();

        pending.request(() -> true, progress::incrementAndGet, verify::set, first::add);
        pending.request(() -> false, progress::incrementAndGet, report -> {
            throw new AssertionError("a duplicate must not start another pass");
        }, second::add);
        assertEquals(2, progress.get());
        assertTrue(first.isEmpty());
        assertTrue(second.isEmpty());

        verify.get().accept(VERIFIED);
        main.remove().run();

        assertEquals(List.of(VERIFIED), first);
        assertEquals(List.of(VERIFIED), second);
        assertTrue(main.isEmpty());
    }

    @Test
    public void destroyingALaterLaunchLeavesTheEarlierRequestWaitingForTheSameResult() {
        Queue<Runnable> main = new ArrayDeque<>();
        ProvisioningFlow.PendingCompliance pending = new ProvisioningFlow.PendingCompliance(main::add, result -> {});
        AtomicReference<Consumer<ProvisioningResult>> verify = new AtomicReference<>();
        List<ProvisioningResult> first = new ArrayList<>();
        List<ProvisioningResult> destroyed = new ArrayList<>();
        Consumer<ProvisioningResult> deliverDestroyed = destroyed::add;

        pending.request(() -> true, () -> {}, verify::set, first::add);
        pending.request(() -> true, () -> {}, report -> {
            throw new AssertionError("a duplicate must not start another pass");
        }, deliverDestroyed);
        pending.detach(deliverDestroyed);

        verify.get().accept(FAILED);
        main.remove().run();

        assertEquals(List.of(FAILED), first);
        assertTrue(destroyed.isEmpty());
    }

    @Test
    public void baselineIsSkippedOnlyAfterRecordedComplianceOrCompletedSetupWithVerifiedProtection() {
        assertTrue(ProvisioningFlow.shouldApplyBaseline(false, false, false));
        assertTrue(ProvisioningFlow.shouldApplyBaseline(false, false, true));
        assertTrue(ProvisioningFlow.shouldApplyBaseline(true, false, false));
        assertFalse(ProvisioningFlow.shouldApplyBaseline(true, false, true));
        assertFalse(ProvisioningFlow.shouldApplyBaseline(false, true, false));
        assertFalse(ProvisioningFlow.shouldApplyBaseline(false, true, true));
        assertFalse(ProvisioningFlow.shouldApplyBaseline(true, true, false));
        assertFalse(ProvisioningFlow.shouldApplyBaseline(true, true, true));
    }

    @Test
    public void aFailedEarlierPassIsAppliedAgainEvenAfterSetupCompleted() {
        // Setup marked complete early, the last pass FAILED (enabled but not
        // verified), no compliance recorded: the baseline must run again.
        boolean lastPassVerified = false;
        assertTrue(ProvisioningFlow.shouldApplyBaseline(true, false, lastPassVerified));
    }
}
