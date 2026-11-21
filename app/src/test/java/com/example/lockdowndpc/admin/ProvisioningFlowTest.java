package com.example.lockdowndpc.admin;

import static android.app.Activity.RESULT_CANCELED;
import static android.app.Activity.RESULT_OK;
import static android.app.admin.DevicePolicyManager.PROVISIONING_MODE_FULLY_MANAGED_DEVICE;
import static android.app.admin.DevicePolicyManager.PROVISIONING_MODE_MANAGED_PROFILE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.OptionalInt;
import java.util.Queue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.IntConsumer;

public final class ProvisioningFlowTest {
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
    public void verifiedPassReturnsOk() {
        AtomicInteger passes = new AtomicInteger();
        List<Integer> results = new ArrayList<>();

        ProvisioningFlow.completeCompliance(report -> {
            passes.incrementAndGet();
            report.accept(true);
        }, results::add);

        assertEquals(1, passes.get());
        assertEquals(List.of(RESULT_OK), results);
    }

    @Test
    public void unverifiedPassReturnsCanceled() {
        List<Integer> results = new ArrayList<>();

        ProvisioningFlow.completeCompliance(report -> report.accept(false), results::add);

        assertEquals(List.of(RESULT_CANCELED), results);
    }

    @Test
    public void missingVerificationIsTreatedAsFailure() {
        List<Integer> results = new ArrayList<>();

        ProvisioningFlow.completeCompliance(report -> report.accept(null), results::add);

        assertEquals(List.of(RESULT_CANCELED), results);
    }

    @Test
    public void passThatCannotStartReturnsCanceled() {
        List<Integer> results = new ArrayList<>();

        ProvisioningFlow.completeCompliance(report -> {
            throw new IllegalStateException("Policy queue unavailable");
        }, results::add);

        assertEquals(List.of(RESULT_CANCELED), results);
    }

    @Test
    public void resultIsReportedOnlyOnce() {
        List<Integer> results = new ArrayList<>();

        ProvisioningFlow.completeCompliance(report -> {
            report.accept(true);
            report.accept(false);
        }, results::add);

        assertEquals(List.of(RESULT_OK), results);
    }

    @Test
    public void baselineNotDueReturnsOkInlineWithoutShowingProgressOrStartingAPass() {
        Queue<Runnable> main = new ArrayDeque<>();
        ProvisioningFlow.PendingCompliance pending = new ProvisioningFlow.PendingCompliance(main::add);
        List<Integer> results = new ArrayList<>();

        pending.request(() -> false, () -> {
            throw new AssertionError("progress must not be shown");
        }, report -> {
            throw new AssertionError("a pass must not start");
        }, results::add);

        assertEquals(List.of(RESULT_OK), results);
        assertTrue(main.isEmpty());
    }

    @Test
    public void duplicateLaunchesShareOnePassAndEveryLiveRequestReceivesTheResult() {
        Queue<Runnable> main = new ArrayDeque<>();
        ProvisioningFlow.PendingCompliance pending = new ProvisioningFlow.PendingCompliance(main::add);
        AtomicReference<Consumer<Boolean>> verify = new AtomicReference<>();
        AtomicInteger progress = new AtomicInteger();
        List<Integer> first = new ArrayList<>();
        List<Integer> second = new ArrayList<>();

        pending.request(() -> true, progress::incrementAndGet, verify::set, first::add);
        pending.request(() -> false, progress::incrementAndGet, report -> {
            throw new AssertionError("a duplicate must not start another pass");
        }, second::add);
        assertEquals(2, progress.get());
        assertTrue(first.isEmpty());
        assertTrue(second.isEmpty());

        verify.get().accept(true);
        main.remove().run();

        assertEquals(List.of(RESULT_OK), first);
        assertEquals(List.of(RESULT_OK), second);
        assertTrue(main.isEmpty());
    }

    @Test
    public void destroyingALaterLaunchLeavesTheEarlierRequestWaitingForTheSameResult() {
        Queue<Runnable> main = new ArrayDeque<>();
        ProvisioningFlow.PendingCompliance pending = new ProvisioningFlow.PendingCompliance(main::add);
        AtomicReference<Consumer<Boolean>> verify = new AtomicReference<>();
        List<Integer> first = new ArrayList<>();
        List<Integer> destroyed = new ArrayList<>();
        IntConsumer deliverDestroyed = destroyed::add;

        pending.request(() -> true, () -> {}, verify::set, first::add);
        pending.request(() -> true, () -> {}, report -> {
            throw new AssertionError("a duplicate must not start another pass");
        }, deliverDestroyed);
        pending.detach(deliverDestroyed);

        verify.get().accept(false);
        main.remove().run();

        assertEquals(List.of(RESULT_CANCELED), first);
        assertTrue(destroyed.isEmpty());
    }

    @Test
    public void baselineIsSkippedOnlyAfterRecordedComplianceOrCompletedSetupWithProtection() {
        assertTrue(ProvisioningFlow.shouldApplyBaseline(false, false, false));
        assertTrue(ProvisioningFlow.shouldApplyBaseline(false, false, true));
        assertTrue(ProvisioningFlow.shouldApplyBaseline(true, false, false));
        assertFalse(ProvisioningFlow.shouldApplyBaseline(true, false, true));
        assertFalse(ProvisioningFlow.shouldApplyBaseline(false, true, false));
        assertFalse(ProvisioningFlow.shouldApplyBaseline(false, true, true));
        assertFalse(ProvisioningFlow.shouldApplyBaseline(true, true, false));
        assertFalse(ProvisioningFlow.shouldApplyBaseline(true, true, true));
    }
}
