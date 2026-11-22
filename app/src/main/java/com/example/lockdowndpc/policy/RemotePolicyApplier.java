package com.example.lockdowndpc.policy;

import android.content.Context;

import java.util.List;

/** Lifecycle target for a device whose marker bars local administration. */
final class RemotePolicyApplier {
    static final String UNAVAILABLE = "remote-policy-unavailable";

    private RemotePolicyApplier() {}

    static boolean reconcile(Context context, String reason) {
        // Journal projection and baseline recovery land in PRs 5 and 6.
        // Until then, enforce the existing policy with protection on and no maintenance.
        return PolicyReconciliationCoordinator.recordResult(
                context, reason, LockdownPolicyController.applyRemoteContainment(context));
    }

    static LockdownPolicyController.PolicyResult refusedLegacyPass() {
        return new LockdownPolicyController.PolicyResult(false, false, 0, 0, List.of(UNAVAILABLE));
    }
}
