package com.example.lockdowndpc.policy;

import static java.util.Map.entry;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

public final class AuditEventTest {
    // These values are persisted and exported. New codes may be added here.
    private static final Map<AuditEvent, String> STABLE_CODES = Map.ofEntries(
            entry(AuditEvent.GENERIC, "audit.generic"),
            entry(AuditEvent.PIN_SET, "pin.set"),
            entry(AuditEvent.PIN_REPLACED, "pin.replaced"),
            entry(AuditEvent.RECOVERY_ROTATED, "admin.recovery.rotated"),
            entry(AuditEvent.POLICY_APPLIED, "policy.apply"),
            entry(AuditEvent.POLICY_APPLY_FAILED, "policy.apply.failed"),
            entry(AuditEvent.POLICY_PAUSED, "policy.pause"),
            entry(AuditEvent.POLICY_PAUSE_FAILED, "policy.pause.failed"),
            entry(AuditEvent.POLICY_MODE_CHANGED, "policy.mode.changed"),
            entry(AuditEvent.POLICY_ALLOWLIST_SAVED, "policy.allowlist.saved"),
            entry(AuditEvent.SYSTEM_SELECTION_SAVED, "policy.system.selection.saved"),
            entry(AuditEvent.SYSTEM_SELECTION_REVOKED, "policy.system.selection.revoked"),
            entry(AuditEvent.SYSTEM_POLICY_CHANGED, "policy.system.control.changed"),
            entry(AuditEvent.SYSTEM_POLICY_APPLIED, "policy.system.control.applied"),
            entry(AuditEvent.SYSTEM_POLICY_UNVERIFIED, "policy.system.control.unverified"),
            entry(AuditEvent.PLAY_COMPATIBILITY_CHANGED, "policy.play.compatibility.changed"),
            entry(AuditEvent.SCHEDULE_CHANGED, "policy.schedule.changed"),
            entry(AuditEvent.POLICY_RESULT_FAILED, "policy.result.failed"),
            entry(AuditEvent.RECONCILIATION_CRASHED, "policy.reconciliation.crashed"),
            entry(AuditEvent.PAUSE_RECONCILIATION_CRASHED, "policy.pause.reconciliation.crashed"),
            entry(AuditEvent.EXEMPTION_GRANTED, "exemption.granted"),
            entry(AuditEvent.EXEMPTION_REVOKED, "exemption.revoked"),
            entry(AuditEvent.EXEMPTIONS_CLEARED, "exemption.cleared"),
            entry(AuditEvent.EXEMPTION_ROUTING_UNVERIFIED, "exemption.routing.unverified"),
            entry(AuditEvent.EXEMPTION_ROUTING_RECOVERED, "exemption.routing.recovered"),
            entry(AuditEvent.EXEMPTION_VISIBILITY_CHANGED, "exemption.visibility.changed"),
            entry(AuditEvent.EXEMPTION_CONTAINMENT_CHANGED, "exemption.containment.changed"),
            entry(AuditEvent.HOME_FILTER_CHANGED, "filter.settings.changed"),
            entry(AuditEvent.KIOSK_CONFIGURED, "kiosk.configured"),
            entry(AuditEvent.KIOSK_CLEARED, "kiosk.cleared"),
            entry(AuditEvent.KIOSK_STARTED, "kiosk.started"),
            entry(AuditEvent.KIOSK_START_FAILED, "kiosk.start.failed"),
            entry(AuditEvent.KIOSK_EXITED, "kiosk.exited"),
            entry(AuditEvent.KIOSK_ADMIN_ENTRY, "kiosk.admin.entry"),
            entry(AuditEvent.KIOSK_RESTORED, "kiosk.restored"),
            entry(AuditEvent.KIOSK_RESTORE_FAILED, "kiosk.restore.failed"),
            entry(AuditEvent.KIOSK_RESTORE_CRASHED, "kiosk.restore.crashed"),
            entry(AuditEvent.KIOSK_FAULTED, "kiosk.faulted"),
            entry(AuditEvent.MAINTENANCE_OPENED, "maintenance.opened"),
            entry(AuditEvent.MAINTENANCE_OPEN_FAILED, "maintenance.open.failed"),
            entry(AuditEvent.MAINTENANCE_CLOSED, "maintenance.closed"),
            entry(AuditEvent.MAINTENANCE_CLOSE_REASON, "maintenance.close.reason"),
            entry(AuditEvent.MAINTENANCE_RESTORE_FAILED, "maintenance.restore.failed"),
            entry(AuditEvent.MANAGEMENT_IDENTITY_REFUSED, "management.identity.refused"),
            entry(AuditEvent.MANAGEMENT_PIN_ADDED, "management.pin.added"),
            entry(AuditEvent.MANAGEMENT_PIN_REMOVED, "management.pin.removed"),
            entry(AuditEvent.UPDATE_CHECK_FAILED, "update.check.failed"),
            entry(AuditEvent.UPDATE_INSTALL_REQUESTED, "update.install.requested"),
            entry(AuditEvent.UPDATE_INSTALL_RESULT_IGNORED, "update.install.result.ignored"),
            entry(AuditEvent.UPDATE_INSTALLED, "update.installed"),
            entry(AuditEvent.UPDATE_INSTALL_FAILED, "update.install.failed"),
            entry(AuditEvent.HEALTH_EXPORTED, "health.exported"));

    @Test
    public void eventCodesAreStableUniqueAndLowercaseDotted() {
        Map<AuditEvent, String> actual = new HashMap<>();
        for (AuditEvent event : AuditEvent.values()) {
            assertTrue(event.code(), event.code().matches("[a-z]+(\\.[a-z]+)+"));
            actual.put(event, event.code());
        }
        assertEquals(STABLE_CODES, actual);
        assertEquals("legacy", AuditEvent.LEGACY_CODE);
        assertEquals(actual.size() + 1, AuditEvent.knownCodes().size());
    }
}
