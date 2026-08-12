package com.example.lockdowndpc.kiosk;

/**
 * The three explicit operating profiles of Device Guard 0.5.
 *
 * <p>{@link #OFF} keeps the historic managed app filtering behaviour untouched.
 * Kiosk is opt-in: an upgrade never selects {@link #SINGLE_APP} or
 * {@link #SINGLE_SITE} on its own.
 */
public enum KioskMode {
    /** Managed app filtering only. No lock task, no HOME takeover. */
    OFF,
    /** Lock task pinned to exactly one administrator-selected application. */
    SINGLE_APP,
    /** Lock task pinned to the in-app WebView host on exactly one HTTPS origin. */
    SINGLE_SITE;

    public static KioskMode fromStoredName(String stored) {
        if (stored == null) {
            return OFF;
        }
        try {
            return valueOf(stored);
        } catch (IllegalArgumentException ignored) {
            // Unknown or corrupted preference values fail closed to managed filtering.
            return OFF;
        }
    }
}
