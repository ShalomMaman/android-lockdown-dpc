package com.example.lockdowndpc.policy;

import android.content.Context;

import com.example.lockdowndpc.security.AdminSession;

import java.util.function.UnaryOperator;

/**
 * The policy boundary for built-in block exemptions.
 *
 * <p>Authorization lives here, not in the console: a change that makes anything
 * newly available requires a live administrator session at the moment it is
 * written, on the policy thread. A removal tightens the device, so it is
 * accepted without one. In both cases the change, every revocation it implies
 * and a change record are committed together before policy is applied; a
 * process that dies afterwards leaves the next pass — boot included — to
 * enforce the change and write its audited outcome.
 */
public final class BuiltInExemptionsController {

    private BuiltInExemptionsController() {}

    /** The outcome of one change. */
    public record Outcome(boolean changed, LockdownPolicyController.PolicyResult result) {}

    public static Outcome change(
            Context context,
            UnaryOperator<BuiltInBlockExemptions.Settings> operation,
            String trigger
    ) {
        return PolicyReconciliationCoordinator.callOnPolicyThread(() -> {
            BuiltInBlockExemptions.Settings before = BuiltInBlockExemptionsStore.read(context);
            BuiltInBlockExemptions.Settings after = operation.apply(before);
            if (before.equals(after)) {
                return new Outcome(false, null);
            }
            if (before.loosensTo(after) && !AdminSession.isUnlocked()) {
                throw new SecurityException("An unlocked administrator session is required");
            }
            BuiltInBlockExemptionsStore.writeChange(context, before, after, trigger);
            LockdownPolicyController.PolicyResult result = AllowedAppsStore.isProtectionEnabled(context)
                    ? LockdownPolicyController.apply(context)
                    : LockdownPolicyController.pause(context);
            // A pause pass does not evaluate exemptions; record its outcome here.
            LockdownPolicyController.flushExemptionChangeAudit(context, result.errors());
            return new Outcome(true, result);
        });
    }
}
