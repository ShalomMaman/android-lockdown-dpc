package com.example.lockdowndpc.admin;

import static android.app.Activity.RESULT_OK;
import static android.app.admin.DevicePolicyManager.PROVISIONING_MODE_FULLY_MANAGED_DEVICE;

import java.util.List;
import java.util.OptionalInt;

final class ProvisioningFlow {
    private ProvisioningFlow() {}

    static OptionalInt selectMode(boolean hasAllowedModes, List<Integer> allowedModes) {
        if (!hasAllowedModes || (allowedModes != null
                && allowedModes.contains(PROVISIONING_MODE_FULLY_MANAGED_DEVICE))) {
            return OptionalInt.of(PROVISIONING_MODE_FULLY_MANAGED_DEVICE);
        }
        return OptionalInt.empty();
    }

    static int completeCompliance(Runnable applyBaseline) {
        applyBaseline.run();
        return RESULT_OK;
    }
}
