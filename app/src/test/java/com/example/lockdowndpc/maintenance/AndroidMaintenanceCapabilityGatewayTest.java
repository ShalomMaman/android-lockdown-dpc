package com.example.lockdowndpc.maintenance;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import org.junit.Test;

/** Verifies that platform refusals remain visible restore failures. */
public final class AndroidMaintenanceCapabilityGatewayTest {

    @Test
    public void illegalArgumentAfterPresenceCheckIsNotTreatedAsPackageAbsence() {
        AndroidMaintenanceCapabilityGateway gateway =
                new AndroidMaintenanceCapabilityGateway(new ThrowingVisibilityDevice());

        java.util.List<String> failures = gateway.restore();

        assertFalse(failures.isEmpty());
        assertEquals(1, failures.size());
        assertEquals("maintenance-store-policy:com.android.vending:IllegalArgumentException",
                failures.get(0));
    }

    private static final class ThrowingVisibilityDevice
            implements AndroidMaintenanceCapabilityGateway.StoreVisibilityDevice {
        @Override
        public boolean isInstalled(String packageName) {
            return "com.android.vending".equals(packageName);
        }

        @Override
        public boolean isHidden(String packageName) {
            throw new IllegalArgumentException("OEM refusal");
        }

        @Override
        public boolean setHidden(String packageName, boolean hidden) {
            throw new AssertionError("the first read must fail before a write");
        }
    }
}
