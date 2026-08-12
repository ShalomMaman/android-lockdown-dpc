package com.example.lockdowndpc.kiosk;

import androidx.annotation.StringRes;

import com.example.lockdowndpc.R;
import com.example.lockdowndpc.kiosk.KioskStateMachine.KioskState;

/**
 * The single mapping from kiosk enums to localized resource identifiers.
 *
 * <p>Both the Kotlin console and the Java controller name profiles and states in
 * operator-facing text; keeping the mapping here stops the two from drifting and
 * keeps every kiosk word in {@code res/values/strings.xml} and
 * {@code res/values-iw/strings.xml}, where the parity check can see it.
 */
public final class KioskLabels {

    private KioskLabels() {}

    /** String resource naming {@code mode} to an operator. */
    @StringRes
    public static int profile(KioskMode mode) {
        if (mode == null) {
            return R.string.kiosk_profile_off;
        }
        return switch (mode) {
            case SINGLE_APP -> R.string.kiosk_profile_single_app;
            case SINGLE_SITE -> R.string.kiosk_profile_single_site;
            default -> R.string.kiosk_profile_off;
        };
    }

    /** Short description of what {@code mode} does. */
    @StringRes
    public static int profileSummary(KioskMode mode) {
        if (mode == null) {
            return R.string.kiosk_profile_off_summary;
        }
        return switch (mode) {
            case SINGLE_APP -> R.string.kiosk_profile_single_app_summary;
            case SINGLE_SITE -> R.string.kiosk_profile_single_site_summary;
            default -> R.string.kiosk_profile_off_summary;
        };
    }

    /** String resource naming {@code state} to an operator. */
    @StringRes
    public static int state(KioskState state) {
        if (state == null) {
            return R.string.kiosk_state_off;
        }
        return switch (state) {
            case ARMED -> R.string.kiosk_state_armed;
            case ACTIVE -> R.string.kiosk_state_active;
            case FAULT -> R.string.kiosk_state_fault;
            default -> R.string.kiosk_state_off;
        };
    }
}
