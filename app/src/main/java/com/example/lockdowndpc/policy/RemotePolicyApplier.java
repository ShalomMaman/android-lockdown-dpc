package com.example.lockdowndpc.policy;

import android.content.Context;

import java.util.List;

/** Lifecycle target for a device whose marker bars local administration. */
final class RemotePolicyApplier {
    static final String UNAVAILABLE = "remote-policy-unavailable";

    private RemotePolicyApplier() {}

    static boolean reconcile(Context context, String reason) {
        // An unreadable marker still requires containment when the build gate is on.
        var result = RemoteEnrolmentGate.permits() && !ManagementModeStore.hasUnreadableRemoteIntent(context)
                ? RemotePolicyRuntime.reconcile(context)
                : LockdownPolicyController.applyRemoteContainment(context);
        return PolicyReconciliationCoordinator.recordResult(context, reason, result);
    }

    static LockdownPolicyController.PolicyResult refusedLegacyPass() {
        return new LockdownPolicyController.PolicyResult(false, false, 0, 0, List.of(UNAVAILABLE));
    }
}
