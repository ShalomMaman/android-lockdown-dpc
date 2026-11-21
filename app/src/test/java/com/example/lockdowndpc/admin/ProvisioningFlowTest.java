package com.example.lockdowndpc.admin;

import static android.app.Activity.RESULT_CANCELED;
import static android.app.Activity.RESULT_OK;
import static android.app.admin.DevicePolicyManager.PROVISIONING_MODE_FULLY_MANAGED_DEVICE;
import static android.app.admin.DevicePolicyManager.PROVISIONING_MODE_MANAGED_PROFILE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.OptionalInt;
import java.util.concurrent.atomic.AtomicInteger;

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

        ProvisioningFlow.completeCompliance(true, report -> {
            passes.incrementAndGet();
            report.accept(true);
        }, results::add);

        assertEquals(1, passes.get());
        assertEquals(List.of(RESULT_OK), results);
    }

    @Test
    public void unverifiedPassReturnsCanceled() {
        List<Integer> results = new ArrayList<>();

        ProvisioningFlow.completeCompliance(true, report -> report.accept(false), results::add);

        assertEquals(List.of(RESULT_CANCELED), results);
    }

    @Test
    public void missingVerificationIsTreatedAsFailure() {
        List<Integer> results = new ArrayList<>();

        ProvisioningFlow.completeCompliance(true, report -> report.accept(null), results::add);

        assertEquals(List.of(RESULT_CANCELED), results);
    }

    @Test
    public void passThatCannotStartReturnsCanceled() {
        List<Integer> results = new ArrayList<>();

        ProvisioningFlow.completeCompliance(true, report -> {
            throw new IllegalStateException("Policy queue unavailable");
        }, results::add);

        assertEquals(List.of(RESULT_CANCELED), results);
    }

    @Test
    public void resultIsReportedOnlyOnce() {
        List<Integer> results = new ArrayList<>();

        ProvisioningFlow.completeCompliance(true, report -> {
            report.accept(true);
            report.accept(false);
        }, results::add);

        assertEquals(List.of(RESULT_OK), results);
    }

    @Test
    public void baselineNotDueReturnsOkWithoutRunningAPass() {
        List<Integer> results = new ArrayList<>();

        ProvisioningFlow.completeCompliance(false, report -> {
            throw new AssertionError("must not run");
        }, results::add);

        assertEquals(List.of(RESULT_OK), results);
    }

    @Test
    public void baselineIsAppliedOnlyDuringFirstSetup() {
        assertTrue(ProvisioningFlow.shouldApplyBaseline(false, false));
        assertFalse(ProvisioningFlow.shouldApplyBaseline(true, false));
        assertFalse(ProvisioningFlow.shouldApplyBaseline(false, true));
        assertFalse(ProvisioningFlow.shouldApplyBaseline(true, true));
    }
}
