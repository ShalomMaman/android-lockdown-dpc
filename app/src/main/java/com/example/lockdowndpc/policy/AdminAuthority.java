package com.example.lockdowndpc.policy;

import android.app.admin.DevicePolicyManager;
import android.content.Context;

import com.example.lockdowndpc.security.AdminSession;

/** An administrator capability, checked again when the policy write executes. */
public sealed interface AdminAuthority permits AdminAuthority.LocalSession, AdminAuthority.PolicyPass {
    static AdminAuthority localSession(Context context) {
        if (ManagementModeStore.read(context) != ManagementMode.LOCAL_PIN) {
            return null;
        }
        long session = AdminSession.activeGeneration();
        return session == 0 ? null : new LocalSession(session);
    }

    static boolean permitsLocal(Context context, AdminAuthority authority) {
        return authority instanceof LocalSession local
                && ManagementModeStore.read(context) == ManagementMode.LOCAL_PIN
                && AdminSession.activeGeneration() == local.generation;
    }

    // Baseline, committed-policy and recovery authorities need their respective
    // enrollment or journal proofs before they can be issued.
    final class LocalSession implements AdminAuthority {
        private final long generation;

        private LocalSession(long generation) {
            this.generation = generation;
        }
    }

    /** Grants only enforcement bookkeeping to a Device Owner policy pass. */
    final class PolicyPass implements AdminAuthority {
        private final Context context;

        private PolicyPass(Context context) {
            this.context = context;
        }

        static PolicyPass forDeviceOwner(Context context) {
            DevicePolicyManager dpm = context.getSystemService(DevicePolicyManager.class);
            return dpm != null && dpm.isDeviceOwnerApp(context.getPackageName())
                    ? new PolicyPass(context) : null;
        }

        static boolean permits(Context context, AdminAuthority authority) {
            return authority instanceof PolicyPass pass && pass.context == context;
        }
    }
}
