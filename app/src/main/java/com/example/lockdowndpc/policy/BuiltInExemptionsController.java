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
 * While protection is paused every exemption edit is refused, so each edit runs
 * straight through a protected pass (credentials lock, kiosk, hide). While an earlier failed save is unresolved, passes enforce
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
        /** Refused because protection is paused; nothing was written, no lock changed. */
        PAUSED_REFUSED,
        NOT_SAVED,
        /**
         * Chrome was not approved: the home filter is off, has a pending
         * change, or its CA is not installed. Nothing was saved.
         */
        FILTER_NOT_READY,
        /** Stored and, when protection is on, applied; the audit entry did not persist. */
        AUDIT_NOT_SAVED,
        /**
         * Not approved: the application is an active device administrator, which
         * Android would refuse to hide again. Nothing was saved.
         */
        ACTIVE_ADMIN_REFUSED,
        /** Not approved: Android's list of device administrators could not be read. Nothing was saved. */
        ADMINS_UNREADABLE,
        /**
         * The removal was stored and a pass ran, but Android refused to hide or
         * suspend a revoked application before the removal was saved; passes
         * keep trying and report {@code CONTAINMENT_REFUSED}.
         */
        CONTAINMENT_REFUSED
    }

    public record Outcome(Status status, LockdownPolicyController.PolicyResult result) {}

    /** The side effects of a change, so the rule is testable without Android. */
    interface Sink {
        boolean write(BuiltInBlockExemptions.Settings settings);

        boolean audit(String entry);

        /** An earlier save failed and passes currently enforce no exemptions. */
        boolean exemptionsUntrusted();

        /** The home filter is on, with nothing pending, and its CA (if any) installed. */
        boolean filterSteadyForChrome();

        /** The stored approval record, from the one reader: an unreadable record refuses ordinary edits. */
        BuiltInBlockExemptions.Record record();

        /**
         * Sets {@code DISALLOW_CONFIG_CREDENTIALS} and reads it back, before a
         * Chrome approval is saved, so the lock covers the approval's whole life.
         */
        boolean lockCredentials();

        /** Brings the credentials lock in line with the stored record and the guard, now. */
        void reconcileCredentialsLock();

        boolean protectionActive();

        /** Packages with an active device-administrator component; {@code null} when unreadable. */
        Set<String> activeAdminPackages();

        /**
         * Hides (or, when Android refuses, suspends) what a change revokes,
         * before the change is saved.
         *
         * @return whether Android confirmed every revoked application contained
         */
        boolean containRevoked(BuiltInBlockExemptions.Revocation revocation);

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
                androidSink(context)));
    }

    /**
     * The explicit administrator action for an unreadable approval record:
     * replaces it with "no exemptions". The credentials lock stays until a
     * pass finds the teardown guard would allow its release.
     */
    public static Outcome clearApprovals(Context context) {
        return PolicyReconciliationCoordinator.callOnPolicyThread(() -> clear(
                AdminSession.isUnlocked(), androidSink(context)));
    }

    private static Sink androidSink(Context context) {
        return new Sink() {
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
            public BuiltInBlockExemptions.Record record() {
                return BuiltInBlockExemptionsStore.record(context);
            }

            @Override
            public boolean lockCredentials() {
                return LockdownPolicyController.lockCredentials(context);
            }

            @Override
            public void reconcileCredentialsLock() {
                LockdownPolicyController.reconcileCredentialsLock(context);
            }

            @Override
            public boolean filterSteadyForChrome() {
                try {
                    HomeFilterController.Snapshot filter = HomeFilterController.read(context);
                    return BuiltInBlockExemptions.filterSteadyForChrome(
                            filter.settings(), filter.report().ca());
                } catch (RuntimeException exception) {
                    return false;
                }
            }

            @Override
            public boolean protectionActive() {
                return AllowedAppsStore.isProtectionEnabled(context);
            }

            @Override
            public Set<String> activeAdminPackages() {
                return LockdownPolicyController.activeAdminPackages(context);
            }

            @Override
            public boolean containRevoked(BuiltInBlockExemptions.Revocation revocation) {
                return LockdownPolicyController.containRevoked(context, revocation);
            }

            @Override
            public LockdownPolicyController.PolicyResult applyPass() {
                return LockdownPolicyController.apply(context);
            }
        };
    }

    /**
     * Approved social packages whose single current signer matches the pin
     * right now, read with the hidden-package query, and that are not active
     * device administrators. An unreadable signer is not verified.
     */
    public static Set<String> verifiedSocial(Context context) {
        BuiltInBlockExemptions.Settings settings = BuiltInBlockExemptionsStore.read(context);
        Set<String> activeAdmins = LockdownPolicyController.activeAdminPackages(context);
        LinkedHashSet<String> verified = new LinkedHashSet<>();
        for (String packageName : settings.socialPins().keySet()) {
            String signer = PackageIdentity.currentSignerSha256IncludingHidden(
                    context.getPackageManager(), packageName);
            if (BuiltInBlockExemptions.socialAllowed(packageName, settings, signer, activeAdmins)) {
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
        if (!sink.protectionActive()) {
            return new Outcome(Status.PAUSED_REFUSED, null);
        }
        if (sink.record().unreadable()) {
            // The edit baseline of an unreadable record is "none", so an ordinary
            // edit would silently drop whatever it holds. Only clearApprovals
            // may overwrite it.
            return new Outcome(Status.NOT_SAVED, null);
        }
        BuiltInBlockExemptions.Settings after = operation.apply(before);
        if (before.equals(after)) {
            return new Outcome(Status.UNCHANGED, null);
        }
        if ((before.loosensTo(after) || sink.exemptionsUntrusted()) && !sessionUnlocked) {
            throw new SecurityException("An unlocked administrator session is required");
        }
        if (after.chrome() && !before.chrome() && !sink.filterSteadyForChrome()) {
            // Approving Chrome over a pending teardown would let that teardown
            // finish under the approval.
            return new Outcome(Status.FILTER_NOT_READY, null);
        }
        Set<String> granted = BuiltInBlockExemptions.newlyPinned(before, after);
        if (!granted.isEmpty()) {
            // Android refuses to hide an active device administrator, so such an
            // approval could not be taken back; it is never granted.
            Set<String> activeAdmins = sink.activeAdminPackages();
            if (activeAdmins == null) {
                return new Outcome(Status.ADMINS_UNREADABLE, null);
            }
            if (granted.stream().anyMatch(activeAdmins::contains)) {
                return new Outcome(Status.ACTIVE_ADMIN_REFUSED, null);
            }
        }
        if (after.chrome() && !sink.lockCredentials()) {
            // The lock covers the approval from before it exists; no lock, no save.
            return new Outcome(Status.NOT_SAVED, null);
        }
        return commit(before.auditText(), BuiltInBlockExemptions.revoked(before, after),
                after, sessionUnlocked, trigger, sink);
    }

    static Outcome clear(boolean sessionUnlocked, Sink sink) {
        if (!sink.protectionActive()) {
            return new Outcome(Status.PAUSED_REFUSED, null);
        }
        if (!sessionUnlocked) {
            throw new SecurityException("An unlocked administrator session is required");
        }
        // The prior state is logged as it was read: "unreadable" when it was.
        // An unreadable record enforces nothing, so there is nothing to contain.
        BuiltInBlockExemptions.Record record = sink.record();
        return commit(record.auditText(),
                BuiltInBlockExemptions.revoked(record.enforced(), BuiltInBlockExemptions.Settings.NONE),
                BuiltInBlockExemptions.Settings.NONE, true, "clear-approvals", sink);
    }

    private static Outcome commit(
            String beforeText,
            BuiltInBlockExemptions.Revocation revocation,
            BuiltInBlockExemptions.Settings after,
            boolean sessionUnlocked,
            String trigger,
            Sink sink
    ) {
        // Tighten before revoking: what the change takes away is contained
        // first, so no interruption can leave a revoked app launchable without
        // its saved approval. A refusal still saves the removal — the next pass
        // keeps trying — and is reported. If the save then fails, the next pass
        // re-applies the approval that is still stored.
        boolean contained = revocation.isEmpty() || sink.containRevoked(revocation);
        if (!sink.write(after)) {
            // The record was restored; a lock set for this failed grant must not
            // outlive it, so the lock is brought in line with what is stored.
            sink.reconcileCredentialsLock();
            return new Outcome(Status.NOT_SAVED, null);
        }
        String actor = sessionUnlocked
                ? "administrator " + trigger
                : trigger + " (no administrator session)";
        String entry = "builtin-exemption: " + actor + ": "
                + beforeText + " -> " + after.auditText()
                + (contained ? "" : " (" + SocialContainment.REFUSED_ERROR + ")");
        boolean audited = sink.audit(entry);
        // The decision is already persisted, so the pass runs either way: a
        // stored removal must take effect even if its audit line did not.
        LockdownPolicyController.PolicyResult result = sink.applyPass();
        if (!contained) {
            return new Outcome(Status.CONTAINMENT_REFUSED, result);
        }
        return new Outcome(audited ? Status.APPLIED : Status.AUDIT_NOT_SAVED, result);
    }
}
