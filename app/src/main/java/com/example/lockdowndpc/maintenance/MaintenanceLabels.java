package com.example.lockdowndpc.maintenance;

import com.example.lockdowndpc.R;
import com.example.lockdowndpc.maintenance.MaintenanceStateMachine.CloseReason;
import com.example.lockdowndpc.maintenance.MaintenanceStateMachine.MaintenanceState;

import java.util.concurrent.TimeUnit;

/**
 * Maps maintenance values onto localized resources, in the same shape as
 * {@code SystemPolicyLabels} and {@code KioskLabels}.
 *
 * <p>Kept out of {@link MaintenanceCapability} and
 * {@link MaintenanceStateMachine} so those stay free of resource identifiers and
 * remain ordinary JVM-testable code. Every branch is exhaustive on purpose: a
 * capability or a close reason added without operator text will not compile.
 *
 * <p>Nothing here formats a secret. The arguments these strings take are
 * capability names, control names, a duration and a clock time — never a PIN, a
 * recovery code or a kiosk URL.
 */
public final class MaintenanceLabels {

    private MaintenanceLabels() {}

    public static int title(MaintenanceCapability capability) {
        return switch (capability) {
            case APP_STORE_ACCESS -> R.string.maint_capability_app_store_access_title;
            case LOCAL_APK_INSTALL -> R.string.maint_capability_local_apk_install_title;
            case SELECTED_SETTINGS -> R.string.maint_capability_selected_settings_title;
            case USB_FILE_TRANSFER -> R.string.maint_capability_usb_file_transfer_title;
            case ADB_DEBUGGING -> R.string.maint_capability_adb_debugging_title;
        };
    }

    /** What opening the capability actually exposes on the device in front of the operator. */
    public static int consequence(MaintenanceCapability capability) {
        return switch (capability) {
            case APP_STORE_ACCESS -> R.string.maint_capability_app_store_access_consequence;
            case LOCAL_APK_INSTALL -> R.string.maint_capability_local_apk_install_consequence;
            case SELECTED_SETTINGS -> R.string.maint_capability_selected_settings_consequence;
            case USB_FILE_TRANSFER -> R.string.maint_capability_usb_file_transfer_consequence;
            case ADB_DEBUGGING -> R.string.maint_capability_adb_debugging_consequence;
        };
    }

    public static int state(MaintenanceState state) {
        return state == MaintenanceState.OPEN
                ? R.string.maint_status_open
                : R.string.maint_status_closed;
    }

    /** The audit line for a window that closed, one per reason. */
    public static int closeAudit(CloseReason closeReason) {
        return switch (closeReason) {
            case EXPIRED -> R.string.maint_audit_close_expired;
            case REBOOT -> R.string.maint_audit_close_reboot;
            case ADMINISTRATOR_CANCELLED -> R.string.maint_audit_close_administrator_cancelled;
            case CLOCK_ANOMALY -> R.string.maint_audit_close_clock_anomaly;
            case UNREADABLE_RECORD -> R.string.maint_audit_close_unreadable_record;
            case OPEN_FAILED -> R.string.maint_audit_close_open_failed;
        };
    }

    /**
     * The explanation for a refused open, keyed by the state machine's token.
     *
     * <p>An unrecognised token falls back to a string that carries the token
     * itself rather than to silence, so a refusal added later is visibly
     * untranslated instead of invisible.
     */
    public static int refusal(String reason) {
        if (reason == null) {
            return R.string.maint_refused_generic;
        }
        return switch (reason) {
            case "admin-authentication-required" ->
                    R.string.maint_refused_admin_authentication_required;
            case "already-open" -> R.string.maint_refused_already_open;
            case "no-capability-selected" -> R.string.maint_refused_no_capability_selected;
            case "unknown-capability" -> R.string.maint_refused_unknown_capability;
            case "non-positive-duration" -> R.string.maint_refused_non_positive_duration;
            case "duration-above-maximum" -> R.string.maint_refused_duration_above_maximum;
            default -> R.string.maint_refused_generic;
        };
    }

    /**
     * The label for one offered duration.
     *
     * <p>Anything outside {@link MaintenanceStateMachine#OFFERED_DURATIONS_MILLIS}
     * falls back to a string that takes the length in minutes, so a duration
     * chosen elsewhere is still readable.
     */
    public static int duration(long millis) {
        if (millis == TimeUnit.MINUTES.toMillis(15)) {
            return R.string.maint_duration_15_minutes;
        }
        if (millis == TimeUnit.MINUTES.toMillis(30)) {
            return R.string.maint_duration_30_minutes;
        }
        if (millis == TimeUnit.HOURS.toMillis(1)) {
            return R.string.maint_duration_1_hour;
        }
        if (millis == TimeUnit.HOURS.toMillis(2)) {
            return R.string.maint_duration_2_hours;
        }
        if (millis == TimeUnit.HOURS.toMillis(4)) {
            return R.string.maint_duration_4_hours;
        }
        return R.string.maint_duration_custom_minutes;
    }

    /** Whole minutes, rounded up, for {@code maint_duration_custom_minutes}. */
    public static int durationMinutes(long millis) {
        return (int) ((Math.max(0L, millis) + 59_999L) / 60_000L);
    }
}
