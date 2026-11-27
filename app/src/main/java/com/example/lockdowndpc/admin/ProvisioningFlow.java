package com.example.lockdowndpc.admin;

import static android.app.admin.DevicePolicyManager.PROVISIONING_MODE_FULLY_MANAGED_DEVICE;

import com.example.lockdowndpc.policy.PolicyReconciliationCoordinator.ProvisioningResult;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.OptionalInt;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/** Platform-free logic behind the two setup wizard handlers. */
final class ProvisioningFlow {
    private ProvisioningFlow() {}

    /** Starts one baseline pass and reports its verification and diagnostics. */
    interface CompliancePass {
        void start(Consumer<ProvisioningResult> report);
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
     * complete and the last policy pass was verified (state ACTIVE). Enabled alone is
     * not evidence: a failed pass keeps protection enabled with state FAILED. The
     * recorded flag also preserves an administrator's decision to pause protection
     * after provisioning.
     */
    static boolean shouldApplyBaseline(
            boolean userSetupComplete, boolean complianceDone, boolean protectionVerified
    ) {
        return !complianceDone && !(userSetupComplete && protectionVerified);
    }

    /** Shares one pass among all live requests. All state is accessed on the main thread. */
    static final class PendingCompliance {
        private final Consumer<Runnable> postToMain;
        private final Consumer<ProvisioningResult> observePass;
        // Null means no pass is in flight. An empty set still has a pass running.
        private Set<Consumer<ProvisioningResult>> waiters;

        PendingCompliance(Consumer<Runnable> postToMain, Consumer<ProvisioningResult> observePass) {
            this.postToMain = postToMain;
            this.observePass = observePass;
        }

        void request(
                BooleanSupplier baselineDue, Runnable showProgress, CompliancePass pass,
                Consumer<ProvisioningResult> deliver
        ) {
            boolean start = waiters == null;
            if (start) {
                if (!baselineDue.getAsBoolean()) {
                    deliver.accept(new ProvisioningResult(true, List.of()));
                    return;
                }
                waiters = new LinkedHashSet<>();
            }
            waiters.add(deliver);
            showProgress.run();
            if (start) {
                completeCompliance(pass, result -> postToMain.accept(() -> finish(result)));
            }
        }

        void detach(Consumer<ProvisioningResult> deliver) {
            if (waiters != null) {
                waiters.remove(deliver);
            }
        }

        private void finish(ProvisioningResult result) {
            Set<Consumer<ProvisioningResult>> completed = waiters;
            waiters = null;
            observePass.accept(result);
            for (Consumer<ProvisioningResult> deliver : completed) {
                deliver.accept(result);
            }
        }
    }

    /**
     * Runs the compliance step and reports its outcome exactly once.
     */
    static void completeCompliance(CompliancePass pass, Consumer<ProvisioningResult> result) {
        AtomicBoolean reported = new AtomicBoolean();
        Consumer<ProvisioningResult> once = outcome -> {
            if (reported.compareAndSet(false, true)) {
                result.accept(outcome != null ? outcome : new ProvisioningResult(false, List.of()));
            }
        };
        try {
            pass.start(once);
        } catch (RuntimeException exception) {
            once.accept(ProvisioningResult.crashed(exception));
        }
    }
}
