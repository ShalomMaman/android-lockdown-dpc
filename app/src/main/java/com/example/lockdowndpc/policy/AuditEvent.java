package com.example.lockdowndpc.policy;

import java.util.HashSet;
import java.util.Set;

/** Stable event codes stored on devices and shared in health exports. Never rename or reuse a code. */
public enum AuditEvent {
    GENERIC("audit.generic"),
    PIN_SET("pin.set"),
    PIN_REPLACED("pin.replaced"),
    RECOVERY_ROTATED("admin.recovery.rotated"),
    POLICY_APPLIED("policy.apply"),
    POLICY_APPLY_FAILED("policy.apply.failed"),
    POLICY_PAUSED("policy.pause"),
    POLICY_PAUSE_FAILED("policy.pause.failed"),
    POLICY_MODE_CHANGED("policy.mode.changed"),
    POLICY_ALLOWLIST_SAVED("policy.allowlist.saved"),
    SYSTEM_SELECTION_SAVED("policy.system.selection.saved"),
    SYSTEM_SELECTION_REVOKED("policy.system.selection.revoked"),
    SYSTEM_POLICY_CHANGED("policy.system.control.changed"),
    SYSTEM_POLICY_APPLIED("policy.system.control.applied"),
    SYSTEM_POLICY_UNVERIFIED("policy.system.control.unverified"),
    PLAY_COMPATIBILITY_CHANGED("policy.play.compatibility.changed"),
    SCHEDULE_CHANGED("policy.schedule.changed"),
    POLICY_RESULT_FAILED("policy.result.failed"),
    RECONCILIATION_CRASHED("policy.reconciliation.crashed"),
    PAUSE_RECONCILIATION_CRASHED("policy.pause.reconciliation.crashed"),
    EXEMPTION_GRANTED("exemption.granted"),
    EXEMPTION_REVOKED("exemption.revoked"),
    EXEMPTIONS_CLEARED("exemption.cleared"),
    EXEMPTION_ROUTING_UNVERIFIED("exemption.routing.unverified"),
    EXEMPTION_ROUTING_RECOVERED("exemption.routing.recovered"),
    EXEMPTION_VISIBILITY_CHANGED("exemption.visibility.changed"),
    EXEMPTION_CONTAINMENT_CHANGED("exemption.containment.changed"),
    HOME_FILTER_CHANGED("filter.settings.changed"),
    KIOSK_CONFIGURED("kiosk.configured"),
    KIOSK_CLEARED("kiosk.cleared"),
    KIOSK_STARTED("kiosk.started"),
    KIOSK_START_FAILED("kiosk.start.failed"),
    KIOSK_EXITED("kiosk.exited"),
    KIOSK_ADMIN_ENTRY("kiosk.admin.entry"),
    KIOSK_RESTORED("kiosk.restored"),
    KIOSK_RESTORE_FAILED("kiosk.restore.failed"),
    KIOSK_RESTORE_CRASHED("kiosk.restore.crashed"),
    KIOSK_FAULTED("kiosk.faulted"),
    MAINTENANCE_OPENED("maintenance.opened"),
    MAINTENANCE_OPEN_FAILED("maintenance.open.failed"),
    MAINTENANCE_CLOSED("maintenance.closed"),
    MAINTENANCE_CLOSE_REASON("maintenance.close.reason"),
    MAINTENANCE_RESTORE_FAILED("maintenance.restore.failed"),
    MANAGEMENT_IDENTITY_REFUSED("management.identity.refused"),
    MANAGEMENT_PIN_ADDED("management.pin.added"),
    MANAGEMENT_PIN_REMOVED("management.pin.removed"),
    UPDATE_CHECK_FAILED("update.check.failed"),
    UPDATE_INSTALL_REQUESTED("update.install.requested"),
    UPDATE_INSTALL_RESULT_IGNORED("update.install.result.ignored"),
    UPDATE_INSTALLED("update.installed"),
    UPDATE_INSTALL_FAILED("update.install.failed"),
    HEALTH_EXPORTED("health.exported");

    /** Reserved for historical records that were written before event codes existed. */
    public static final String LEGACY_CODE = "legacy";

    private static final Set<String> KNOWN_CODES = collectCodes();

    private final String code;

    AuditEvent(String code) {
        this.code = code;
    }

    public String code() {
        return code;
    }

    /** Fixed, text-free codes recognized by storage and health export. */
    public static Set<String> knownCodes() {
        return KNOWN_CODES;
    }

    private static Set<String> collectCodes() {
        Set<String> codes = new HashSet<>();
        codes.add(LEGACY_CODE);
        for (AuditEvent event : values()) {
            codes.add(event.code());
        }
        return Set.copyOf(codes);
    }
}
