package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Apply, withdraw, verification failure and fault propagation.
 *
 * <p>The case that matters most is {@link #aSilentlyIgnoredRequestIsNeverReportedAsApplied()}:
 * a platform that accepts {@code addUserRestriction} and does nothing is
 * indistinguishable from a working one unless the restriction is read back. That
 * is the failure mode a switch-shaped console hides, and the reason every pass
 * here ends in a read.
 */
public final class SystemPolicyEnforcerTest {

    private static final int ANDROID_TEN = 29;

    @Test
    public void aRequestedControlIsAppliedOnlyWhenThePlatformConfirmsIt() {
        FakeGateway gateway = new FakeGateway();

        SystemPolicyReport report = SystemPolicyEnforcer.enforce(
                ANDROID_TEN, SystemPolicyProfile.PILOT, Map.of(), gateway);

        SystemPolicyControlStatus factoryReset =
                statusOf(report, SystemPolicyControl.FACTORY_RESET);
        assertEquals(SystemPolicyOutcome.APPLIED, factoryReset.outcome());
        assertTrue(factoryReset.requested());
        assertTrue(gateway.inForce.contains("no_factory_reset"));
        assertFalse(report.faulted());
    }

    @Test
    public void aSilentlyIgnoredRequestIsNeverReportedAsApplied() {
        // The platform accepts the call and changes nothing. Without the read-back
        // this is the exact case where a saved switch would imply enforcement.
        FakeGateway gateway = new FakeGateway();
        gateway.ignoreAdd.add("no_factory_reset");

        SystemPolicyReport report = SystemPolicyEnforcer.enforce(
                ANDROID_TEN, SystemPolicyProfile.PILOT, Map.of(), gateway);

        SystemPolicyControlStatus status = statusOf(report, SystemPolicyControl.FACTORY_RESET);
        assertEquals(SystemPolicyOutcome.FAILED, status.outcome());
        assertEquals("factory_reset:failed:not-in-force", status.summary());
        assertTrue(status.faultsProtection());
        assertTrue(report.faulted());
    }

    @Test
    public void aRefusedRequestFaultsProtectionAndNamesTheRestriction() {
        FakeGateway gateway = new FakeGateway();
        gateway.refuseAdd.add("no_safe_boot");

        SystemPolicyReport report = SystemPolicyEnforcer.enforce(
                ANDROID_TEN, SystemPolicyProfile.PILOT, Map.of(), gateway);

        SystemPolicyControlStatus status = statusOf(report, SystemPolicyControl.SAFE_BOOT);
        assertEquals(SystemPolicyOutcome.FAILED, status.outcome());
        assertTrue(status.detail().contains("no_safe_boot/SecurityException"));
        assertEquals(List.of(status), report.faults());
    }

    @Test
    public void anUnreadableRestrictionIsAFailureRatherThanAnAssumption() {
        FakeGateway gateway = new FakeGateway();
        gateway.unreadable.add("no_config_vpn");

        SystemPolicyReport report = SystemPolicyEnforcer.enforce(
                ANDROID_TEN, SystemPolicyProfile.PILOT, Map.of(), gateway);

        SystemPolicyControlStatus status = statusOf(report, SystemPolicyControl.VPN_CONFIGURATION);
        assertEquals(SystemPolicyOutcome.FAILED, status.outcome());
        assertTrue(status.detail().contains("no_config_vpn/unreadable"));
        assertTrue(report.faulted());
    }

    @Test
    public void halfOfAMultiRestrictionControlIsNotTheControl() {
        // Blocking sideloading for this user but not globally is not "unknown
        // sources blocked", so the control must not report as applied.
        FakeGateway gateway = new FakeGateway();
        gateway.ignoreAdd.add("no_install_unknown_sources_globally");

        SystemPolicyReport report = SystemPolicyEnforcer.enforce(
                ANDROID_TEN, SystemPolicyProfile.PILOT, Map.of(), gateway);

        assertEquals(
                SystemPolicyOutcome.FAILED,
                statusOf(report, SystemPolicyControl.UNKNOWN_SOURCE_INSTALLS).outcome());
        assertTrue(gateway.inForce.contains("no_install_unknown_sources"));
    }

    @Test
    public void anAdvisoryRefusalIsReportedButDoesNotFaultProtection() {
        FakeGateway gateway = new FakeGateway();
        gateway.refuseAdd.add("no_config_wifi");

        SystemPolicyReport report = SystemPolicyEnforcer.enforce(
                ANDROID_TEN,
                SystemPolicyProfile.PILOT,
                Map.of(SystemPolicyControl.WIFI_CONFIGURATION, true),
                gateway);

        SystemPolicyControlStatus status = statusOf(report, SystemPolicyControl.WIFI_CONFIGURATION);
        assertEquals(SystemPolicyOutcome.FAILED, status.outcome());
        assertTrue(status.failed());
        assertFalse(status.faultsProtection());
        assertFalse("an OEM Wi-Fi refusal must not brick a working device", report.faulted());
        assertEquals(List.of(status), report.nonFaultingFailures());
    }

    @Test
    public void anUnsupportedReleaseReportsUnsupportedAndSendsNothing() {
        FakeGateway gateway = new FakeGateway();

        SystemPolicyReport report = SystemPolicyEnforcer.enforce(
                26, SystemPolicyProfile.PILOT, Map.of(), gateway);

        SystemPolicyControlStatus dateTime = statusOf(report, SystemPolicyControl.DATE_AND_TIME);
        assertEquals(SystemPolicyOutcome.UNSUPPORTED, dateTime.outcome());
        assertFalse(dateTime.supported());
        assertEquals("needs-sdk-28", dateTime.detail());
        assertFalse(gateway.touched.contains("no_config_date_time"));

        // Requested but impossible is a reported gap, never a fault: an older
        // Android is not a broken device and faulting would strand it.
        assertTrue(dateTime.requested());
        assertFalse(dateTime.faultsProtection());
        assertFalse(report.faulted());
        assertTrue(report.unsupportedButRequested().contains(dateTime));
    }

    @Test
    public void aPartlySupportedControlSaysSoEvenWhenItSucceeds() {
        FakeGateway gateway = new FakeGateway();

        SystemPolicyReport report = SystemPolicyEnforcer.enforce(
                26, SystemPolicyProfile.PILOT, Map.of(), gateway);

        SystemPolicyControlStatus users =
                statusOf(report, SystemPolicyControl.USER_AND_PROFILE_CREATION);
        assertEquals(SystemPolicyOutcome.APPLIED, users.outcome());
        assertTrue(users.detail().contains("unavailable-no_user_switch"));
        assertTrue(gateway.inForce.contains("no_add_user"));
        assertFalse(gateway.touched.contains("no_user_switch"));
    }

    @Test
    public void aControlSwitchedOffIsWithdrawnAndVerifiedWithdrawn() {
        FakeGateway gateway = new FakeGateway();
        gateway.inForce.add("no_config_tethering");

        SystemPolicyReport report = SystemPolicyEnforcer.enforce(
                ANDROID_TEN,
                SystemPolicyProfile.PILOT,
                Map.of(SystemPolicyControl.TETHERING, false),
                gateway);

        SystemPolicyControlStatus status = statusOf(report, SystemPolicyControl.TETHERING);
        assertEquals(SystemPolicyOutcome.NOT_REQUESTED, status.outcome());
        assertFalse(gateway.inForce.contains("no_config_tethering"));
    }

    @Test
    public void aRestrictionThatWillNotComeOffIsReportedWithoutFaultingProtection() {
        // The device is stricter than asked, not weaker. Faulting here would
        // strand an administrator who is trying to open a capability back up —
        // including one restoring ADB access for service.
        FakeGateway gateway = new FakeGateway();
        gateway.inForce.add("no_config_tethering");
        gateway.refuseClear.add("no_config_tethering");

        SystemPolicyReport report = SystemPolicyEnforcer.enforce(
                ANDROID_TEN,
                SystemPolicyProfile.PILOT,
                Map.of(SystemPolicyControl.TETHERING, false),
                gateway);

        SystemPolicyControlStatus status = statusOf(report, SystemPolicyControl.TETHERING);
        assertEquals(SystemPolicyOutcome.FAILED, status.outcome());
        assertFalse(status.faultsProtection());
        assertTrue(report.failures().contains(status));
    }

    @Test
    public void releaseWithdrawsEveryControlIncludingOnesNoProfileDefaultsOn() {
        FakeGateway gateway = new FakeGateway();
        gateway.inForce.addAll(SystemPolicyControl.allRestrictionKeys(ANDROID_TEN));

        SystemPolicyReport report = SystemPolicyEnforcer.release(ANDROID_TEN, gateway);

        assertTrue("pause must leave nothing enforced", gateway.inForce.isEmpty());
        for (SystemPolicyControlStatus status : report.statuses()) {
            assertFalse(status.requested());
            assertEquals(status.control().toString(),
                    SystemPolicyOutcome.NOT_REQUESTED, status.outcome());
        }
        assertFalse(report.faulted());
    }

    @Test
    public void releaseReportsARestrictionItCouldNotWithdraw() {
        FakeGateway gateway = new FakeGateway();
        gateway.inForce.add("no_control_apps");
        gateway.refuseClear.add("no_control_apps");

        SystemPolicyReport report = SystemPolicyEnforcer.release(ANDROID_TEN, gateway);

        List<SystemPolicyControlStatus> failures = report.failures();
        assertEquals(1, failures.size());
        assertEquals(SystemPolicyControl.APP_CONTROL_SETTINGS, failures.get(0).control());
        // pause() turns any failure into a pause error, so this still stops the
        // console from claiming a clean pause even though it is not a fault.
        assertFalse(report.faulted());
    }

    @Test
    public void aFaultingReportCannotBeReportedAsAnAppliedPolicy() {
        // The seam between this feature and the existing reconciliation result:
        // faults become errors, and PolicyResult refuses to be "applied" with any.
        FakeGateway gateway = new FakeGateway();
        gateway.ignoreAdd.add("no_uninstall_apps");

        SystemPolicyReport report = SystemPolicyEnforcer.enforce(
                ANDROID_TEN, SystemPolicyProfile.PILOT, Map.of(), gateway);

        assertTrue(report.faulted());
        List<String> errors = report.faults().stream()
                .map(status -> "system-policy:" + status.summary())
                .toList();
        assertEquals(List.of("system-policy:app_uninstall:failed:not-in-force"), errors);
        assertThrows(
                IllegalArgumentException.class,
                () -> new LockdownPolicyController.PolicyResult(true, true, 0, 0, errors));
    }

    @Test
    public void aCleanPassProducesNoErrorsAtAll() {
        FakeGateway gateway = new FakeGateway();

        SystemPolicyReport report = SystemPolicyEnforcer.enforce(
                ANDROID_TEN, SystemPolicyProfile.PRODUCTION, Map.of(), gateway);

        assertTrue(report.faults().isEmpty());
        assertTrue(report.failures().isEmpty());
        assertTrue(gateway.inForce.contains("no_debugging_features"));
        assertNotNull(new LockdownPolicyController.PolicyResult(true, true, 0, 0, List.of()));
    }

    private static SystemPolicyControlStatus statusOf(
            SystemPolicyReport report,
            SystemPolicyControl control
    ) {
        SystemPolicyControlStatus status = report.statusOf(control);
        assertNotNull("no status reported for " + control, status);
        return status;
    }

    /** An in-memory device whose refusals can be scripted. */
    private static final class FakeGateway implements SystemPolicyGateway {

        final Set<String> inForce = new LinkedHashSet<>();
        final Set<String> touched = new LinkedHashSet<>();
        final Set<String> refuseAdd = new HashSet<>();
        final Set<String> refuseClear = new HashSet<>();
        /** Accepts the call and changes nothing, like an OEM build that no-ops. */
        final Set<String> ignoreAdd = new HashSet<>();
        final Set<String> unreadable = new HashSet<>();

        @Override
        public void addRestriction(String key) {
            touched.add(key);
            if (refuseAdd.contains(key)) {
                throw new SecurityException("refused " + key);
            }
            if (ignoreAdd.contains(key)) {
                return;
            }
            inForce.add(key);
        }

        @Override
        public void clearRestriction(String key) {
            touched.add(key);
            if (refuseClear.contains(key)) {
                throw new SecurityException("refused " + key);
            }
            inForce.remove(key);
        }

        @Override
        public boolean isRestrictionInForce(String key) {
            if (unreadable.contains(key)) {
                throw new IllegalStateException("unreadable " + key);
            }
            return inForce.contains(key);
        }
    }
}
