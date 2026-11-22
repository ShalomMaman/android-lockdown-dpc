package com.example.lockdowndpc.policy;

import android.app.admin.DevicePolicyManager;
import android.content.Context;

import com.example.lockdowndpc.security.AdminSession;

/** An administrator capability, checked again when the policy write executes. */
public sealed interface AdminAuthority permits AdminAuthority.LocalSession, AdminAuthority.PolicyPass,
        AdminAuthority.CommittedPolicy {
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

    /** Issued on the policy thread for the duration of a journal projection/pass. */
    final class CommittedPolicy implements AdminAuthority, AutoCloseable {
        private final Context context;
        private final Thread thread = Thread.currentThread();
        private final String generation;
        private boolean active = true;

        private CommittedPolicy(Context context, String generation) {
            this.context = context;
            this.generation = generation;
        }

        static CommittedPolicy forProjection(Context context, String generation) {
            return new CommittedPolicy(context, generation);
        }

        static boolean permits(Context context, AdminAuthority authority) {
            return authority instanceof CommittedPolicy policy && policy.active
                    && policy.context == context && policy.thread == Thread.currentThread()
                    && ManagementModeStore.hasCommittedRemoteIntent(context)
                    && !ManagementModeStore.read(context).usesLocalPolicy();
        }

        String generation() {
            return generation;
        }

        @Override public void close() {
            active = false;
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
