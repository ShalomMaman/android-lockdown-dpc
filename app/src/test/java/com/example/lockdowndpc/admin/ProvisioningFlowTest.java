package com.example.lockdowndpc.admin;

import static android.app.Activity.RESULT_OK;
import static android.app.admin.DevicePolicyManager.PROVISIONING_MODE_FULLY_MANAGED_DEVICE;
import static android.app.admin.DevicePolicyManager.PROVISIONING_MODE_MANAGED_PROFILE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;

import org.junit.Test;

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
    public void complianceAppliesTheBaselineExactlyOnceBeforeReturningSuccess() {
        AtomicInteger calls = new AtomicInteger();

        int result = ProvisioningFlow.completeCompliance(calls::incrementAndGet);

        assertEquals(1, calls.get());
        assertEquals(RESULT_OK, result);
    }

    @Test
    public void complianceDoesNotAcknowledgeAnInterruptedBaseline() {
        IllegalStateException failure = new IllegalStateException("Policy pass interrupted");
        IllegalStateException thrown = assertThrows(IllegalStateException.class,
                () -> ProvisioningFlow.completeCompliance(() -> {
                    throw failure;
                }));
        assertSame(failure, thrown);
    }
}
