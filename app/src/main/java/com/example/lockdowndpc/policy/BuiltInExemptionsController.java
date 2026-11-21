package com.example.lockdowndpc.policy;

import android.content.Context;

import com.example.lockdowndpc.security.AdminSession;

import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.UnaryOperator;

/**
 * The policy boundary for built-in block exemptions.
 *
 * <p>A change that makes anything newly available needs a live administrator
 * session at the moment it is written, on the policy thread. A removal tightens
 * the device and is accepted without one. The decision is committed, then its
 * audit entry is committed, and only then does a policy pass run. A write that
 * does not persist changes nothing: no pass runs and the caller shows an error.
 */
public final class BuiltInExemptionsController {

    private BuiltInExemptionsController() {}

    /** The result of one change request. */
    public enum Status { UNCHANGED, APPLIED, NOT_SAVED, AUDIT_NOT_SAVED }

    public record Outcome(Status status, LockdownPolicyController.PolicyResult result) {}

    /** The side effects of a change, so the rule is testable without Android. */
    interface Sink {
        boolean write(BuiltInBlockExemptions.Settings settings);

        boolean audit(String entry);

        LockdownPolicyController.PolicyResult applyPass();
    }

    public static Outcome change(
            Context context,
            UnaryOperator<BuiltInBlockExemptions.Settings> operation,
            String trigger
    ) {
        return PolicyReconciliationCoordinator.callOnPolicyThread(() -> change(
                BuiltInBlockExemptionsStore.read(context),
                operation,
                AdminSession.isUnlocked(),
                trigger,
                new Sink() {
                    @Override
                    public boolean write(BuiltInBlockExemptions.Settings settings) {
                        return BuiltInBlockExemptionsStore.write(context, settings);
                    }

                    @Override
                    public boolean audit(String entry) {
                        return AuditLog.appendCommitted(context, entry);
                    }

                    @Override
                    public LockdownPolicyController.PolicyResult applyPass() {
                        return AllowedAppsStore.isProtectionEnabled(context)
                                ? LockdownPolicyController.apply(context)
                                : LockdownPolicyController.pause(context);
                    }
                }));
    }

    /**
     * Approved social packages whose single current signer matches the pin
     * right now, read with the hidden-package query. An unreadable signer is
     * not verified.
     */
    public static Set<String> verifiedSocial(Context context) {
        BuiltInBlockExemptions.Settings settings = BuiltInBlockExemptionsStore.read(context);
        LinkedHashSet<String> verified = new LinkedHashSet<>();
        for (String packageName : settings.socialPins().keySet()) {
            String signer = PackageIdentity.currentSignerSha256IncludingHidden(
                    context.getPackageManager(), packageName);
            if (BuiltInBlockExemptions.socialVisible(packageName, settings, signer)) {
                verified.add(packageName);
            }
        }
        return verified;
    }

    static Outcome change(
            BuiltInBlockExemptions.Settings before,
            UnaryOperator<BuiltInBlockExemptions.Settings> operation,
            boolean sessionUnlocked,
            String trigger,
            Sink sink
    ) {
        BuiltInBlockExemptions.Settings after = operation.apply(before);
        if (before.equals(after)) {
            return new Outcome(Status.UNCHANGED, null);
        }
        if (before.loosensTo(after) && !sessionUnlocked) {
            throw new SecurityException("An unlocked administrator session is required");
        }
        if (!sink.write(after)) {
            return new Outcome(Status.NOT_SAVED, null);
        }
        String entry = "builtin-exemption: administrator " + trigger + ": "
                + before.auditText() + " -> " + after.auditText();
        boolean audited = sink.audit(entry);
        // The decision is already persisted, so the pass runs either way: a
        // stored removal must take effect even if its audit line did not.
        LockdownPolicyController.PolicyResult result = sink.applyPass();
        return new Outcome(audited ? Status.APPLIED : Status.AUDIT_NOT_SAVED, result);
    }
}
