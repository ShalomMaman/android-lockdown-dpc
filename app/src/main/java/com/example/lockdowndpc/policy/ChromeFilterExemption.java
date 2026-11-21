package com.example.lockdowndpc.policy;

import java.util.List;
import java.util.Map;

/**
 * Grant and revocation of the Chrome exemption, in a fixed, fail-closed order.
 *
 * <p>Three invariants, each covered by a JVM test against a fake gateway:
 *
 * <ol>
 *   <li><b>Grant only on read-back.</b> Chrome is granted only when it is
 *       installed, signed by Google's release key, the home filter's Android
 *       settings are confirmed, and Chrome's managed configuration has been
 *       written <em>and read back</em>. The grant is recorded durably before the
 *       package pass may show Chrome, so a pass that dies midway still leaves a
 *       record the next pass revokes from.</li>
 *   <li><b>Revoke first.</b> When any condition fails, or any call throws,
 *       Chrome is hidden — or suspended when it is the WebView provider, which
 *       is never hidden — and that state is read back before anything else in
 *       the pass. A revocation that Android did not confirm stays pending across
 *       process death and is retried on every pass, including the boot pass.</li>
 *   <li><b>No teardown under a pending revocation.</b> While a revocation is
 *       unconfirmed, {@link #teardownAllowed} is false and the home filter keeps
 *       its VPN, proxy and CA in place.</li>
 * </ol>
 *
 * <p>Nothing here is time-based: every condition is something Device Guard
 * enforces itself and reads back on each pass.
 */
public final class ChromeFilterExemption {

    private ChromeFilterExemption() {}

    /** What the Chrome exemption resolved to on one pass. */
    public enum State {
        OFF(false),
        ACTIVE(true),
        NOT_INSTALLED(false),
        SIGNER_UNVERIFIED(false),
        FILTER_UNVERIFIED(false),
        RESTRICTIONS_UNVERIFIED(false),
        LINK_ROUTE_UNVERIFIED(false),
        /** Everything holds, but an earlier revocation is not confirmed yet. */
        REVOCATION_PENDING(false),
        ERROR(false);

        private final boolean available;

        State(boolean available) {
            this.available = available;
        }

        public boolean chromeAvailable() {
            return available;
        }
    }

    /** The Android side, as read-back operations. Any call may throw. */
    public interface Gateway {
        boolean installed();

        /** Chrome's single current signer, lower-case hex, or {@code ""}. */
        String currentSignerSha256();

        BuiltInBlockExemptions.FilterEvidence filterEvidence();

        /** The home filter's configured PAC URL. */
        String pacUrl();

        Map<String, Object> restrictions();

        void setRestrictions(Map<String, Object> values);

        boolean webViewProvider();

        void setHidden(boolean hidden);

        boolean hidden();

        void setSuspended(boolean suspended);

        boolean suspended();
    }

    /** Durable state that must survive process death. */
    public interface Ledger {
        boolean granted();

        void setGranted(boolean granted);

        boolean revocationPending();

        void setRevocationPending(boolean pending);
    }

    /**
     * The first step of every pass: decide, and revoke before anything else
     * when the decision is not a grant.
     *
     * @param requested the administrator's stored choice
     */
    public static State prepare(boolean requested, Gateway gateway, Ledger ledger, List<String> errors) {
        State state;
        try {
            state = evaluate(requested, gateway);
        } catch (RuntimeException exception) {
            errors.add("chrome-exemption:" + exception.getClass().getSimpleName());
            state = State.ERROR;
        }
        // A revocation still owed from an earlier pass is completed, and read
        // back, before any grant: never grant over an unconfirmed block.
        if (ledger.revocationPending() && !revoke(gateway, ledger, errors)) {
            return state == State.ACTIVE ? State.REVOCATION_PENDING : state;
        }
        if (state == State.ACTIVE) {
            ledger.setGranted(true);
        } else if (ledger.granted()) {
            revoke(gateway, ledger, errors);
        }
        return state;
    }

    /**
     * The last step of a pass that granted Chrome: the home filter's own
     * reconcile, link routing and the configuration must all still hold.
     * Anything else revokes.
     */
    public static State finish(
            State prepared,
            boolean filterStillConfirmed,
            boolean linksRouted,
            Gateway gateway,
            Ledger ledger,
            List<String> errors
    ) {
        if (prepared != State.ACTIVE) {
            return prepared;
        }
        State state;
        if (!filterStillConfirmed) {
            state = State.FILTER_UNVERIFIED;
        } else if (!linksRouted) {
            state = State.LINK_ROUTE_UNVERIFIED;
        } else {
            try {
                state = BuiltInBlockExemptions.restrictionsSatisfied(
                        gateway.restrictions(),
                        BuiltInBlockExemptions.chromeRestrictions(gateway.pacUrl()))
                        ? State.ACTIVE : State.RESTRICTIONS_UNVERIFIED;
            } catch (RuntimeException exception) {
                errors.add("chrome-exemption:" + exception.getClass().getSimpleName());
                state = State.ERROR;
            }
        }
        if (state != State.ACTIVE) {
            if (state == State.FILTER_UNVERIFIED) {
                errors.add(BuiltInBlockExemptions.BROWSER_FILTER_UNVERIFIED_ERROR);
            }
            revoke(gateway, ledger, errors);
        }
        return state;
    }

    /**
     * Blocks Chrome and reads the result back. The pending mark is written
     * before any Android call and cleared only after Android confirmed.
     *
     * @return whether Android confirmed Chrome is blocked
     */
    public static boolean revoke(Gateway gateway, Ledger ledger, List<String> errors) {
        ledger.setRevocationPending(true);
        boolean blocked;
        try {
            if (!gateway.installed()) {
                blocked = true;
            } else if (gateway.webViewProvider()) {
                gateway.setSuspended(true);
                blocked = gateway.suspended();
            } else {
                gateway.setHidden(true);
                blocked = gateway.hidden();
            }
        } catch (RuntimeException exception) {
            errors.add("chrome-exemption-revoke:" + exception.getClass().getSimpleName());
            blocked = false;
        }
        if (blocked) {
            ledger.setGranted(false);
            ledger.setRevocationPending(false);
        } else {
            errors.add(BuiltInBlockExemptions.CHROME_REVOCATION_UNVERIFIED_ERROR);
        }
        return blocked;
    }

    /** Revokes only when a grant or a pending revocation is on record. */
    public static void revokeIfGranted(Gateway gateway, Ledger ledger, List<String> errors) {
        if (ledger.granted() || ledger.revocationPending()) {
            revoke(gateway, ledger, errors);
        }
    }

    /** Whether the home filter may remove its VPN, proxy or CA now. */
    public static boolean teardownAllowed(Ledger ledger) {
        return !ledger.revocationPending();
    }

    private static State evaluate(boolean requested, Gateway gateway) {
        if (!requested) {
            return State.OFF;
        }
        if (!gateway.installed()) {
            return State.NOT_INSTALLED;
        }
        if (!BuiltInBlockExemptions.chromeSignerVerified(gateway.currentSignerSha256())) {
            return State.SIGNER_UNVERIFIED;
        }
        BuiltInBlockExemptions.FilterEvidence evidence = gateway.filterEvidence();
        if (evidence == null || !evidence.verified()) {
            return State.FILTER_UNVERIFIED;
        }
        // Configured before Chrome can be shown, and read back.
        Map<String, Object> required = BuiltInBlockExemptions.chromeRestrictions(gateway.pacUrl());
        Map<String, Object> current = gateway.restrictions();
        if (!BuiltInBlockExemptions.restrictionsSatisfied(current, required)) {
            gateway.setRestrictions(BuiltInBlockExemptions.mergeRestrictions(current, required));
        }
        if (!BuiltInBlockExemptions.restrictionsSatisfied(gateway.restrictions(), required)) {
            return State.RESTRICTIONS_UNVERIFIED;
        }
        return State.ACTIVE;
    }
}
