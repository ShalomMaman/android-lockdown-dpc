package com.example.lockdowndpc.kiosk;

/**
 * The authorization rules for every kiosk state change, in one pure place.
 *
 * <p>Two invariants carry the security contract and are covered by unit tests:
 *
 * <ul>
 *   <li>No transition an operator can trigger reaches {@link KioskState#ACTIVE}
 *       or leaves it without {@code adminAuthenticated}.</li>
 *   <li>{@link KioskAction#BOOT_RESTORE} is the only unauthenticated path into
 *       {@link KioskState#ACTIVE}, it is reachable only from a persisted
 *       {@code ACTIVE} state, and it falls into {@link KioskState#FAULT} when the
 *       stored configuration no longer validates.</li>
 * </ul>
 */
public final class KioskStateMachine {

    private KioskStateMachine() {}

    public enum KioskState {
        /** No kiosk configured. Managed app filtering behaves exactly as in 0.4. */
        OFF,
        /** A validated configuration exists but the device is not locked down. */
        ARMED,
        /** Lock task is the intended runtime state, including across reboot. */
        ACTIVE,
        /** Kiosk was active but cannot be honoured; the host shows a safe error. */
        FAULT;

        public static KioskState fromStoredName(String stored) {
            if (stored == null) {
                return OFF;
            }
            try {
                return valueOf(stored);
            } catch (IllegalArgumentException ignored) {
                // A corrupted state must not silently mean "locked" or "open"; it
                // means "kiosk cannot be honoured", which the host renders safely.
                return FAULT;
            }
        }
    }

    public enum KioskAction {
        /** Store or replace the configuration. */
        CONFIGURE,
        /** Enter lock task now. */
        ENTER,
        /** Leave lock task and return to the armed configuration. */
        EXIT,
        /** Drop the configuration entirely and return to managed filtering. */
        CLEAR,
        /** Reboot or process restart re-asserting a previously active kiosk. */
        BOOT_RESTORE,
        /** The runtime could not honour kiosk (invalid target, apply failure). */
        FAULT
    }

    /**
     * @param adminAuthenticated an administrator PIN session is currently valid
     * @param configValid        {@link KioskConfigValidator} accepted the stored config
     */
    public record Request(
            KioskState from,
            KioskAction action,
            boolean adminAuthenticated,
            boolean configValid
    ) {}

    public record Outcome(boolean allowed, KioskState state, String reason) {}

    public static Outcome transition(Request request) {
        if (request == null) {
            return new Outcome(false, KioskState.FAULT, "missing-request");
        }
        KioskState from = request.from() == null ? KioskState.OFF : request.from();
        KioskAction action = request.action();
        if (action == null) {
            return new Outcome(false, from, "missing-action");
        }

        return switch (action) {
            case CONFIGURE -> {
                if (!request.adminAuthenticated()) {
                    yield denied(from, "admin-authentication-required");
                }
                if (!request.configValid()) {
                    yield denied(from, "invalid-configuration");
                }
                // Reconfiguring while active re-arms rather than silently swapping
                // the target underneath a locked device.
                yield new Outcome(true, KioskState.ARMED, "configured");
            }
            case ENTER -> {
                if (!request.adminAuthenticated()) {
                    yield denied(from, "admin-authentication-required");
                }
                if (from != KioskState.ARMED && from != KioskState.ACTIVE && from != KioskState.FAULT) {
                    yield denied(from, "not-configured");
                }
                if (!request.configValid()) {
                    yield denied(from, "invalid-configuration");
                }
                yield new Outcome(true, KioskState.ACTIVE, "entered");
            }
            case EXIT -> {
                if (!request.adminAuthenticated()) {
                    yield denied(from, "admin-authentication-required");
                }
                if (from != KioskState.ACTIVE && from != KioskState.FAULT) {
                    yield denied(from, "not-active");
                }
                yield new Outcome(true, KioskState.ARMED, "exited");
            }
            case CLEAR -> {
                if (!request.adminAuthenticated()) {
                    yield denied(from, "admin-authentication-required");
                }
                yield new Outcome(true, KioskState.OFF, "cleared");
            }
            case BOOT_RESTORE -> {
                // Deliberately unauthenticated: a reboot must not become a way to
                // leave kiosk, so restoring is allowed only from a persisted ACTIVE.
                if (from != KioskState.ACTIVE) {
                    yield denied(from, "not-active-before-restart");
                }
                if (!request.configValid()) {
                    yield new Outcome(true, KioskState.FAULT, "configuration-no-longer-valid");
                }
                yield new Outcome(true, KioskState.ACTIVE, "restored");
            }
            case FAULT -> {
                if (from == KioskState.OFF) {
                    yield denied(from, "not-configured");
                }
                yield new Outcome(true, KioskState.FAULT, "faulted");
            }
        };
    }

    private static Outcome denied(KioskState from, String reason) {
        return new Outcome(false, from, reason);
    }
}
