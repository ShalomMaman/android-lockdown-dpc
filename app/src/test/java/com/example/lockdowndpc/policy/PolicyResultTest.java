package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.List;

public final class PolicyResultTest {
    @Test
    public void activeResultRequiresEveryCriticalCheckToPass() {
        assertThrows(IllegalArgumentException.class, () ->
                new LockdownPolicyController.PolicyResult(
                        true,
                        true,
                        3,
                        2,
                        List.of("חסימת חבילה לא אומתה")
                )
        );
    }

    @Test
    public void activeResultRequiresDeviceOwner() {
        assertThrows(IllegalArgumentException.class, () ->
                new LockdownPolicyController.PolicyResult(
                        false,
                        true,
                        0,
                        0,
                        List.of()
                )
        );
    }

    @Test
    public void verifiedErrorFreeResultCanBeActive() {
        LockdownPolicyController.PolicyResult result =
                new LockdownPolicyController.PolicyResult(true, true, 3, 2, List.of());

        assertTrue(result.applied());
    }
}
