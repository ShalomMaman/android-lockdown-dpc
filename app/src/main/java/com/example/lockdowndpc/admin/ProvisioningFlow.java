package com.example.lockdowndpc.admin;

import static android.app.Activity.RESULT_CANCELED;
import static android.app.Activity.RESULT_OK;
import static android.app.admin.DevicePolicyManager.PROVISIONING_MODE_FULLY_MANAGED_DEVICE;

import java.util.List;
import java.util.OptionalInt;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.IntConsumer;

/** Platform-free decisions behind the two setup wizard handlers. */
final class ProvisioningFlow {
    private ProvisioningFlow() {}

    /** Starts one verified baseline pass and reports whether it was verified. */
    interface CompliancePass {
        void start(Consumer<Boolean> verified);
    }

    static OptionalInt selectMode(boolean hasAllowedModes, List<Integer> allowedModes) {
        if (!hasAllowedModes || (allowedModes != null
                && allowedModes.contains(PROVISIONING_MODE_FULLY_MANAGED_DEVICE))) {
            return OptionalInt.of(PROVISIONING_MODE_FULLY_MANAGED_DEVICE);
        }
        return OptionalInt.empty();
    }

    /**
     * Whether a compliance request still has to apply the baseline.
     *
     * <p>The wizard asks once, during setup. A request that arrives after setup
     * finished, or after an earlier request was verified, must not re-apply the
     * baseline: that would override protection an administrator has since
     * paused.
     */
    static boolean shouldApplyBaseline(boolean userSetupComplete, boolean complianceDone) {
        return !userSetupComplete && !complianceDone;
    }

    /**
     * Runs the compliance step and reports the activity result exactly once.
     *
     * <p>{@code RESULT_OK} is returned only for a verified pass, or when the
     * baseline is not due any more. An unverified pass, a pass that threw, or a
     * pass that could not be started returns {@code RESULT_CANCELED}.
     */
    static void completeCompliance(
            boolean applyBaseline,
            CompliancePass pass,
            IntConsumer result
    ) {
        AtomicBoolean reported = new AtomicBoolean();
        IntConsumer once = code -> {
            if (reported.compareAndSet(false, true)) {
                result.accept(code);
            }
        };
        if (!applyBaseline) {
            once.accept(RESULT_OK);
            return;
        }
        try {
            pass.start(verified -> once.accept(complianceResult(verified)));
        } catch (RuntimeException exception) {
            once.accept(RESULT_CANCELED);
        }
    }

    static int complianceResult(Boolean verified) {
        return Boolean.TRUE.equals(verified) ? RESULT_OK : RESULT_CANCELED;
    }
}
