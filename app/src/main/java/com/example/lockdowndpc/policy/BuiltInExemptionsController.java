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
 * While protection is paused the decision is stored only; the next protected
 * pass enforces it. While an earlier failed save is unresolved, passes enforce
 * no exemptions at all, so any save — a removal included — would re-enable the
 * others; it therefore needs a live administrator session too.
 */
public final class BuiltInExemptionsController {

    private BuiltInExemptionsController() {}

    /** The result of one change request. */
    public enum Status {
        UNCHANGED,
        /** Stored and a protected pass ran; see the result. */
        APPLIED,
        /** Stored while protection is paused; nothing was applied. */
        SAVED,
        NOT_SAVED,
        /** Stored and, when protection is on, applied; the audit entry did not persist. */
        AUDIT_NOT_SAVED
    }

    public record Outcome(Status status, LockdownPolicyController.PolicyResult result) {}

    /** The side effects of a change, so the rule is testable without Android. */
    interface Sink {
        boolean write(BuiltInBlockExemptions.Settings settings);

        boolean audit(String entry);

        /** An earlier save failed and passes currently enforce no exemptions. */
        boolean exemptionsUntrusted();

        boolean protectionActive();

        LockdownPolicyController.PolicyResult applyPass();
    }

    public static Outcome change(
            Context context,
            UnaryOperator<BuiltInBlockExemptions.Settings> operation,
            String trigger
    ) {
        return PolicyReconciliationCoordinator.callOnPolicyThread(() -> change(
                BuiltInBlockExemptionsStore.readForEdit(context),
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
                    public boolean exemptionsUntrusted() {
                        return BuiltInBlockExemptionsStore.untrusted(context);
                    }

                    @Override
                    public boolean protectionActive() {
                        return AllowedAppsStore.isProtectionEnabled(context);
                    }

                    @Override
                    public LockdownPolicyController.PolicyResult applyPass() {
                        return LockdownPolicyController.apply(context);
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
        if ((before.loosensTo(after) || sink.exemptionsUntrusted()) && !sessionUnlocked) {
            throw new SecurityException("An unlocked administrator session is required");
        }
        if (!sink.write(after)) {
            return new Outcome(Status.NOT_SAVED, null);
        }
        String actor = sessionUnlocked
                ? "administrator " + trigger
                : trigger + " (no administrator session)";
        String entry = "builtin-exemption: " + actor + ": "
                + before.auditText() + " -> " + after.auditText();
        boolean audited = sink.audit(entry);
        if (!sink.protectionActive()) {
            return new Outcome(audited ? Status.SAVED : Status.AUDIT_NOT_SAVED, null);
        }
        // The decision is already persisted, so the pass runs either way: a
        // stored removal must take effect even if its audit line did not.
        LockdownPolicyController.PolicyResult result = sink.applyPass();
        return new Outcome(audited ? Status.APPLIED : Status.AUDIT_NOT_SAVED, result);
    }
}
