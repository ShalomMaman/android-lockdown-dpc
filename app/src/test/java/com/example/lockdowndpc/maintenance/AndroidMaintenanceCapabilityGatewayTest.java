package com.example.lockdowndpc.maintenance;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * Platform refusals stay visible, and the Google Play precondition is a real
 * device write that is read back rather than an intention.
 */
public final class AndroidMaintenanceCapabilityGatewayTest {

    private static final String PLAY_STORE = "com.android.vending";
    private static final long HALF_HOUR = TimeUnit.MINUTES.toMillis(30);

    @Test
    public void illegalArgumentAfterPresenceCheckIsNotTreatedAsPackageAbsence() {
        AndroidMaintenanceCapabilityGateway gateway =
                new AndroidMaintenanceCapabilityGateway(new ThrowingVisibilityDevice(), false);

        List<String> failures = gateway.restore();

        assertFalse(failures.isEmpty());
        assertEquals(1, failures.size());
        assertEquals("maintenance-store-policy:com.android.vending:IllegalArgumentException",
                failures.get(0));
    }

    @Test
    public void aLocalApkWindowHidesThePlayStoreBeforeAnythingElseHappens() {
        RecordingVisibilityDevice device = new RecordingVisibilityDevice();
        AndroidMaintenanceCapabilityGateway gateway =
                new AndroidMaintenanceCapabilityGateway(device, true);

        List<String> failures = gateway.prepare(windowFor(MaintenanceCapability.LOCAL_APK_INSTALL));

        assertEquals(List.of(), failures);
        assertTrue("the Store must actually be hidden", device.hidden.contains(PLAY_STORE));
        assertEquals(List.of("set:" + PLAY_STORE + ":true"), device.writes);
    }

    @Test
    public void aPreconditionThatCannotBeProvedIsReportedAsAFailure() {
        // The platform accepts the call and changes nothing — the case a write
        // without a read-back would report as a hidden Store.
        RecordingVisibilityDevice device = new RecordingVisibilityDevice();
        device.ignoreWrites.add(PLAY_STORE);
        AndroidMaintenanceCapabilityGateway gateway =
                new AndroidMaintenanceCapabilityGateway(device, true);

        List<String> failures = gateway.prepare(windowFor(MaintenanceCapability.LOCAL_APK_INSTALL));

        assertEquals(1, failures.size());
        assertTrue(
                "a precondition failure must name itself: " + failures.get(0),
                failures.get(0).startsWith("maintenance-precondition:"));
        assertFalse(device.hidden.contains(PLAY_STORE));
    }

    @Test
    public void aStoreAccessWindowLeavesThePreconditionAlone() {
        // Application-store access is authorised, so the window owns store
        // visibility and unhides the stores in open(), after the restrictions.
        RecordingVisibilityDevice device = new RecordingVisibilityDevice();
        AndroidMaintenanceCapabilityGateway gateway =
                new AndroidMaintenanceCapabilityGateway(device, true);

        assertEquals(
                List.of(),
                gateway.prepare(windowFor(MaintenanceCapability.APP_STORE_ACCESS)));
        assertEquals("nothing may be written by this precondition", List.of(), device.writes);
    }

    @Test
    public void strictModeNeedsNoPrecondition() {
        // Without the opt-in the Store is hidden by the base policy already, so
        // a device that never enabled compatibility keeps today's behaviour.
        RecordingVisibilityDevice device = new RecordingVisibilityDevice();
        AndroidMaintenanceCapabilityGateway gateway =
                new AndroidMaintenanceCapabilityGateway(device, false);

        assertEquals(
                List.of(),
                gateway.prepare(windowFor(MaintenanceCapability.LOCAL_APK_INSTALL)));
        assertEquals(List.of(), device.writes);
    }

    @Test
    public void anAbsentStoreIsNotAPreconditionFailure() {
        // A device without the Play Store installed has nothing to withhold.
        RecordingVisibilityDevice device = new RecordingVisibilityDevice();
        device.installed = false;
        AndroidMaintenanceCapabilityGateway gateway =
                new AndroidMaintenanceCapabilityGateway(device, true);

        assertEquals(
                List.of(),
                gateway.prepare(windowFor(MaintenanceCapability.LOCAL_APK_INSTALL)));
        assertEquals(List.of(), device.writes);
    }

    private static MaintenanceWindow windowFor(MaintenanceCapability capability) {
        return new MaintenanceWindow(
                EnumSet.of(capability),
                HALF_HOUR,
                1_700_000_000_000L,
                60_000L,
                1_700_000_000_000L,
                60_000L);
    }

    /** Records every write in order so the ordering claims are testable. */
    private static final class RecordingVisibilityDevice
            implements AndroidMaintenanceCapabilityGateway.StoreVisibilityDevice {

        final Set<String> hidden = new LinkedHashSet<>();
        final List<String> writes = new ArrayList<>();
        /** Accepts the call and changes nothing, like an OEM build that no-ops. */
        final Set<String> ignoreWrites = new LinkedHashSet<>();
        boolean installed = true;

        @Override
        public boolean isInstalled(String packageName) {
            return installed;
        }

        @Override
        public boolean isHidden(String packageName) {
            return hidden.contains(packageName);
        }

        @Override
        public boolean setHidden(String packageName, boolean hide) {
            writes.add("set:" + packageName + ":" + hide);
            if (ignoreWrites.contains(packageName)) {
                return false;
            }
            if (hide) {
                hidden.add(packageName);
            } else {
                hidden.remove(packageName);
            }
            return true;
        }
    }

    private static final class ThrowingVisibilityDevice
            implements AndroidMaintenanceCapabilityGateway.StoreVisibilityDevice {
        @Override
        public boolean isInstalled(String packageName) {
            return PLAY_STORE.equals(packageName);
        }

        @Override
        public boolean isHidden(String packageName) {
            throw new IllegalArgumentException("OEM refusal");
        }

        @Override
        public boolean setHidden(String packageName, boolean hidden) {
            throw new AssertionError("the first read must fail before a write");
        }
    }
}
