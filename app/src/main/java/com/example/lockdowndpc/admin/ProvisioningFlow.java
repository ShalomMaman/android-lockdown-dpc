package com.example.lockdowndpc.admin;

import static android.app.Activity.RESULT_CANCELED;
import static android.app.Activity.RESULT_OK;
import static android.app.admin.DevicePolicyManager.PROVISIONING_MODE_FULLY_MANAGED_DEVICE;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.OptionalInt;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.IntConsumer;

/** Platform-free logic behind the two setup wizard handlers. */
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
     * <p>Some setup wizards can mark setup complete before they request compliance.
     * Skip only when a verified compliance pass was recorded or when setup is
     * complete and protection is already enabled. The recorded flag also preserves
     * an administrator's decision to pause protection after provisioning.
     */
    static boolean shouldApplyBaseline(
            boolean userSetupComplete, boolean complianceDone, boolean protectionEnabled
    ) {
        return !complianceDone && !(userSetupComplete && protectionEnabled);
    }

    /** Shares one pass among all live requests. All state is accessed on the main thread. */
    static final class PendingCompliance {
        private final Consumer<Runnable> postToMain;
        // Null means no pass is in flight. An empty set still has a pass running.
        private Set<IntConsumer> waiters;

        PendingCompliance(Consumer<Runnable> postToMain) {
            this.postToMain = postToMain;
        }

        void request(
                BooleanSupplier baselineDue, Runnable showProgress, CompliancePass pass,
                IntConsumer deliver
        ) {
            boolean start = waiters == null;
            if (start) {
                if (!baselineDue.getAsBoolean()) {
                    deliver.accept(RESULT_OK);
                    return;
                }
                waiters = new LinkedHashSet<>();
            }
            waiters.add(deliver);
            showProgress.run();
            if (start) {
                completeCompliance(pass, code -> postToMain.accept(() -> finish(code)));
            }
        }

        void detach(IntConsumer deliver) {
            if (waiters != null) {
                waiters.remove(deliver);
            }
        }

        private void finish(int code) {
            Set<IntConsumer> completed = waiters;
            waiters = null;
            for (IntConsumer deliver : completed) {
                deliver.accept(code);
            }
        }
    }

    /**
     * Runs the compliance step and reports the activity result exactly once.
     *
     * <p>A verified pass returns {@code RESULT_OK}. An unverified pass, a pass
     * that threw, or a pass that could not be started returns {@code RESULT_CANCELED}.
     */
    static void completeCompliance(CompliancePass pass, IntConsumer result) {
        AtomicBoolean reported = new AtomicBoolean();
        IntConsumer once = code -> {
            if (reported.compareAndSet(false, true)) {
                result.accept(code);
            }
        };
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
