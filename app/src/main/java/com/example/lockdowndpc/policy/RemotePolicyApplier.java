package com.example.lockdowndpc.policy;

import android.content.Context;

import java.util.List;

/** Lifecycle target for a device whose marker bars local administration. */
final class RemotePolicyApplier {
    static final String UNAVAILABLE = "remote-policy-unavailable";

    private RemotePolicyApplier() {}

    static boolean reconcile(Context context, String reason) {
        // Keep the pre-journal containment path for a marker seen on a gated build.
        var result = RemoteEnrolmentGate.permits()
                ? RemotePolicyRuntime.reconcile(context)
                : LockdownPolicyController.applyRemoteContainment(context);
        return PolicyReconciliationCoordinator.recordResult(context, reason, result);
    }

    static LockdownPolicyController.PolicyResult refusedLegacyPass() {
        return new LockdownPolicyController.PolicyResult(false, false, 0, 0, List.of(UNAVAILABLE));
    }
}
