package com.example.lockdowndpc.policy;

import android.app.Activity;
import android.app.admin.DeviceAdminReceiver;
import android.app.admin.DevicePolicyManager;
import android.app.job.JobParameters;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.net.Uri;
import android.os.Looper;
import android.os.PersistableBundle;
import android.os.SystemClock;
import android.os.UserManager;

import com.example.lockdowndpc.admin.LockdownAdminReceiver;
import com.example.lockdowndpc.admin.LockdownDeviceAdminService;
import com.example.lockdowndpc.admin.ProvisioningModeActivity;
import com.example.lockdowndpc.kiosk.KioskConfigStore;
import com.example.lockdowndpc.kiosk.KioskController;
import com.example.lockdowndpc.kiosk.KioskStateMachine.KioskState;
import com.example.lockdowndpc.maintenance.MaintenanceCapability;
import com.example.lockdowndpc.maintenance.MaintenanceCoordinator;
import com.example.lockdowndpc.maintenance.MaintenanceGuard;
import com.example.lockdowndpc.maintenance.MaintenanceStateMachine.OpenRequest;
import com.example.lockdowndpc.maintenance.MaintenanceStore;
import com.example.lockdowndpc.maintenance.MaintenanceStoreFixture;
import com.example.lockdowndpc.maintenance.MaintenanceWindow;
import com.example.lockdowndpc.receivers.PolicyRefreshReceiver;
import com.example.lockdowndpc.security.AdminPinStore;
import com.example.lockdowndpc.security.AdminSession;
import com.example.lockdowndpc.testing.MemoryPreferences;
import com.example.lockdowndpc.ui.ConsoleScreen;
import com.example.lockdowndpc.ui.MainActivityKt;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.Shadows;
import org.robolectric.annotation.Config;
import org.robolectric.shadow.api.Shadow;
import org.robolectric.shadows.ShadowBroadcastReceiver;
import org.robolectric.shadows.ShadowDevicePolicyManager;
import org.robolectric.shadows.ShadowJobService;
import org.robolectric.shadows.ShadowPackageManager;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 32, shadows = LockdownPolicyApplyTest.FilterDevicePolicy.class)
public class ModeBoundaryTest {
    private Context context;

    @Before
    public void setUp() {
        context = RuntimeEnvironment.getApplication();
        ShadowDevicePolicyManager devicePolicy = Shadow.extract(
                context.getSystemService(DevicePolicyManager.class));
        assertTrue(devicePolicy.setDeviceOwner(LockdownAdminReceiver.componentName(context)));
    }

    @After
    public void lockSession() {
        AdminSession.lock();
    }

    @Test
    public void enrollingRoutesEveryEntryPointAwayFromLocalPolicy() {
        exerciseRemoteBoundary(ManagementMode.ENROLLING);
    }

    @Test
    public void remoteRoutesEveryEntryPointAwayFromLocalPolicy() {
        exerciseRemoteBoundary(ManagementMode.REMOTE);
    }

    @Test
    public void unreadableMarkerDoesNotPermitLocalProvisioningOrPinSetup() {
        assertTrue(marker().edit().putString(ManagementModeStore.MARKER_KEY, "broken").commit());
        assertEquals(ManagementMode.ENROLLING, ManagementModeStore.read(context));
        assertEquals(ConsoleScreen.REMOTE_STATUS, MainActivityKt.initialScreen(context));
        assertFalse(ManagementModeStore.selectLocal(context));
        assertFalse(AdminPinStore.setInitialPin(context, "123456"));
    }

    @Test
    public void unreadableMarkerContainsNewlyInstalledAppAndClosesLiveMaintenance() throws Exception {
        assertTrue(ManagementModeStore.selectLocal(context));
        assertTrue(SystemPolicyStore.setRequested(context, SystemPolicyControl.DEVELOPER_OPTIONS_AND_ADB, true));
        assertTrue(AllowedAppsStore.setProtectionMode(context, AllowedAppsStore.ProtectionMode.ALLOW_SELECTED));
        assertTrue(AllowedAppsStore.setAllowedPackages(context, Set.of(), Set.of(), Set.of()));
        // A stale local pause must not release anything under the unreadable marker.
        assertFalse(AllowedAppsStore.isProtectionEnabled(context));
        File marker = new File(context.createDeviceProtectedStorageContext().getFilesDir(),
                ManagementModeStore.MARKER_FILE);
        Files.write(marker.toPath(), new byte[]{0});
        assertEquals(ManagementMode.ENROLLING, ManagementModeStore.read(context));

        var service = Robolectric.buildService(LockdownDeviceAdminService.class).create();
        try {
            flushPolicyThread();
            var dpm = context.getSystemService(DevicePolicyManager.class);
            var admin = LockdownAdminReceiver.componentName(context);
            long wall = System.currentTimeMillis();
            long elapsed = SystemClock.elapsedRealtime();
            assertTrue(MaintenanceStoreFixture.saveWindow(context, new MaintenanceWindow(
                    EnumSet.of(MaintenanceCapability.ADB_DEBUGGING), TimeUnit.MINUTES.toMillis(15),
                    wall, elapsed, wall, elapsed)));
            dpm.clearUserRestriction(admin, UserManager.DISALLOW_DEBUGGING_FEATURES);
            assertFalse(dpm.getUserRestrictions(admin).getBoolean(UserManager.DISALLOW_DEBUGGING_FEATURES));

            String installed = "com.example.newlyinstalled";
            PackageInfo info = new PackageInfo();
            info.packageName = installed;
            info.applicationInfo = new ApplicationInfo();
            info.applicationInfo.packageName = installed;
            info.applicationInfo.enabled = true;
            ShadowPackageManager packages = Shadow.extract(context.getPackageManager());
            packages.installPackage(info);
            assertFalse(dpm.isApplicationHidden(admin, installed));
            context.sendBroadcast(new Intent(Intent.ACTION_PACKAGE_ADDED,
                    Uri.fromParts("package", installed, null)));
            Shadows.shadowOf(Looper.getMainLooper()).idle();
            flushPolicyThread();

            assertEquals(Intent.ACTION_PACKAGE_ADDED + ":" + installed,
                    ReconciliationRecord.read(context).trigger());
            assertTrue(dpm.isApplicationHidden(admin, installed) || dpm.isPackageSuspended(admin, installed));
            assertTrue(AllowedAppsStore.getManagedPackages(context).contains(installed));
            assertTrue(dpm.getUserRestrictions(admin).getBoolean(UserManager.DISALLOW_DEBUGGING_FEATURES));
            assertNull(MaintenanceStore.readWindow(context));
            assertFalse(MaintenanceStore.restorePending(context));
            assertFalse(AllowedAppsStore.isProtectionEnabled(context));
        } finally {
            service.destroy();
        }
    }

    @Test
    public void unreadableMarkerAllowsOnlyTheExistingKioskToBeRestored() {
        assertTrue(context.getSharedPreferences("kiosk_policy", Context.MODE_PRIVATE).edit()
                .putString("kiosk_state", "ACTIVE").putString("kiosk_mode", "SINGLE_SITE")
                .putString("kiosk_site_url", "https://example.com/").commit());
        assertTrue(marker().edit().putString(ManagementModeStore.MARKER_KEY, "broken").commit());

        KioskController.Result restored = PolicyReconciliationCoordinator.callOnPolicyThread(
                () -> KioskController.restoreAfterBoot(context));
        flushPolicyThread();

        assertEquals("restored", restored.reason());
        assertEquals(KioskState.ACTIVE, KioskConfigStore.readState(context));
        assertTrue(context.getSystemService(DevicePolicyManager.class)
                .isLockTaskPermitted(context.getPackageName()));
        assertNull(AdminAuthority.localSession(context));
    }

    @Test
    public void failedMarkerWritePreservesPreviousContent() throws Exception {
        File directory = context.createDeviceProtectedStorageContext().getFilesDir();
        File previous = new File(directory, ManagementModeStore.MARKER_FILE);
        byte[] oldContent = {1};
        Files.write(previous.toPath(), oldContent);
        // A directory cannot be opened as the staged output.
        assertThrows(IOException.class, () -> ManagementModeStore.publishMarker(previous, directory));
        assertArrayEquals(oldContent, Files.readAllBytes(previous.toPath()));
        assertTrue(ManagementModeStore.hasCommittedRemoteIntent(context));
    }

    @Test
    public void markerGateOffLeavesLocalSetupAvailable() {
        org.junit.Assume.assumeFalse(RemoteEnrolmentGate.permits());
        PersistableBundle extras = new PersistableBundle();
        extras.putString("dg.remote.unknown", "anything");
        Intent request = new Intent().putExtra(
                DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE, extras);
        assertFalse(RemoteEnrolmentGate.permits());
        assertFalse(RemoteEnrolmentGate.permitsLocalProvisioning(request));
        assertFalse(ManagementModeStore.markRemoteIntent(context));
        assertTrue(marker().getAll().isEmpty());
        assertEquals(ManagementMode.UNDECIDED, ManagementModeStore.read(context));
        assertEquals(ConsoleScreen.PIN_SETUP, MainActivityKt.initialScreen(context));
        assertEquals(AdminPinStore.Status.NOT_CONFIGURED, AdminPinStore.verify(context, "123456").status());
        assertTrue(ManagementModeStore.selectLocal(context));
        assertEquals(ManagementMode.LOCAL_PIN, ManagementModeStore.read(context));
        assertEquals(ConsoleScreen.PIN_SETUP, MainActivityKt.initialScreen(context));
    }

    @Test
    public void modeActivityAndAdminReceiverRejectRemoteExtrasBeforeWritingMode() {
        org.junit.Assume.assumeFalse(RemoteEnrolmentGate.permits());
        PersistableBundle extras = new PersistableBundle();
        extras.putString("dg.remote.unknown", "anything");
        Intent mode = new Intent(DevicePolicyManager.ACTION_GET_PROVISIONING_MODE)
                .putExtra(DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE, extras)
                .putIntegerArrayListExtra(DevicePolicyManager.EXTRA_PROVISIONING_ALLOWED_PROVISIONING_MODES,
                        new ArrayList<>(List.of(DevicePolicyManager.PROVISIONING_MODE_FULLY_MANAGED_DEVICE)));
        try (var activity = Robolectric.buildActivity(ProvisioningModeActivity.class, mode).create()) {
            assertEquals(Activity.RESULT_CANCELED, Shadows.shadowOf(activity.get()).getResultCode());
        }

        Intent completed = new Intent(DeviceAdminReceiver.ACTION_PROFILE_PROVISIONING_COMPLETE)
                .putExtra(DevicePolicyManager.EXTRA_PROVISIONING_ADMIN_EXTRAS_BUNDLE, extras);
        new LockdownAdminReceiver().onProfileProvisioningComplete(context, completed);
        assertTrue(marker().getAll().isEmpty());
        assertTrue(modeRecord().getAll().isEmpty());
        assertEquals(ManagementMode.UNDECIDED, ManagementModeStore.read(context));
    }

    @Test
    public void failedLocalModeCommitCannotCreateTheFirstPin() {
        SharedPreferences failedMode = new MemoryPreferences(Map.of()).preferences();
        Context faulted = new ContextWrapper(context) {
            @Override
            public SharedPreferences getSharedPreferences(String name, int mode) {
                return ManagementModeStore.MODE_PREFS.equals(name)
                        ? failedMode : super.getSharedPreferences(name, mode);
            }
        };

        assertFalse(AdminPinStore.setInitialPin(faulted, "123456"));
        assertFalse(AdminPinStore.hasPin(context));
        assertTrue(failedMode.getAll().isEmpty());
        assertEquals(ManagementMode.UNDECIDED, ManagementModeStore.read(faulted));
    }

    private void exerciseRemoteBoundary(ManagementMode mode) {
        assertTrue(ManagementModeStore.selectLocal(context));
        MaintenanceCoordinator staleMaintenance = MaintenanceGuard.coordinatorFor(context);
        assertNotNull(staleMaintenance);
        long wall = System.currentTimeMillis();
        long elapsed = SystemClock.elapsedRealtime();
        long duration = TimeUnit.MINUTES.toMillis(15);
        EnumSet<MaintenanceCapability> capabilities = EnumSet.of(MaintenanceCapability.ADB_DEBUGGING);
        MaintenanceWindow window = new MaintenanceWindow(capabilities, duration, wall, elapsed, wall, elapsed);
        assertTrue(MaintenanceStoreFixture.saveWindow(context, window));
        assertNotNull(MaintenanceStore.liveWindow(context));
        assertFalse(MaintenanceStore.clearForRemoteIntent(context));

        // Exercise mode precedence with stale local state and an unreadable
        // protection flag. Reading that flag on a remote route would throw.
        SharedPreferences legacy = context.getSharedPreferences("lockdown_policy", Context.MODE_PRIVATE);
        assertTrue(legacy.edit().putString("protection_enabled", "local-only").commit());
        assertTrue(marker().edit().putBoolean(ManagementModeStore.MARKER_KEY, true).commit());
        if (mode == ManagementMode.REMOTE) {
            assertTrue(modeRecord().edit().putString(ManagementModeStore.MODE_KEY, "REMOTE").commit());
        }
        assertEquals(mode, ManagementModeStore.read(context));

        assertEquals(ConsoleScreen.REMOTE_STATUS, MainActivityKt.initialScreen(context));
        assertFalse(AdminPinStore.setInitialPin(context, "123456"));
        AdminSession.unlock(); // Simulate an authority left over from the local console.
        assertFalse(AdminPinStore.replacePin(context, "123456"));
        assertEquals(AdminPinStore.Status.ERROR, AdminPinStore.verify(context, "123456").status());
        assertFalse(AdminPinStore.hasPin(context));
        assertNull(AdminAuthority.localSession(context));

        PolicyRefreshReceiver receiver = new PolicyRefreshReceiver();
        context.registerReceiver(receiver, new IntentFilter(Intent.ACTION_BOOT_COMPLETED));
        try {
            context.sendBroadcast(new Intent(Intent.ACTION_BOOT_COMPLETED).setPackage(context.getPackageName()));
            Shadows.shadowOf(Looper.getMainLooper()).idle();
            flushPolicyThread();
            ShadowBroadcastReceiver boot = Shadow.extract(receiver);
            assertTrue(boot.wentAsync());
        } finally {
            context.unregisterReceiver(receiver);
        }
        assertEquals(Intent.ACTION_BOOT_COMPLETED, ReconciliationRecord.read(context).trigger());
        assertFalse(ReconciliationRecord.read(context).detail().contains(RemotePolicyApplier.UNAVAILABLE));

        ScheduleSweepJobService sweep = Robolectric.buildService(ScheduleSweepJobService.class).create().get();
        assertTrue(sweep.onStartJob(Shadow.newInstanceOf(JobParameters.class)));
        flushPolicyThread();
        ShadowJobService sweepState = Shadow.extract(sweep);
        assertTrue(sweepState.getIsJobFinished());
        assertEquals("schedule-catch-up:sweep", ReconciliationRecord.read(context).trigger());
        assertFalse(ReconciliationRecord.read(context).detail().contains(RemotePolicyApplier.UNAVAILABLE));

        OpenRequest request = new OpenRequest(capabilities, duration, true, true);
        assertEquals("maintenance-mode-refused", staleMaintenance.open(window, request).reason());
        assertEquals("maintenance-mode-refused",
                MaintenanceGuard.open(context, staleMaintenance, window, request).reason());
        assertNull(MaintenanceGuard.refresh(context));
        assertNull(MaintenanceStore.liveWindow(context));
        assertFalse(KioskController.restoreAfterBoot(context).allowed());
        assertFalse(LockdownPolicyController.pause(context).applied());
        assertEquals("local-only", legacy.getString("protection_enabled", null));

        assertTrue(MaintenanceStore.clearForRemoteIntent(context));
        assertNull(MaintenanceStore.readWindow(context));
        assertFalse(MaintenanceStore.restorePending(context));
        assertEquals(mode, ManagementModeStore.read(context));
    }

    private SharedPreferences marker() {
        return context.createDeviceProtectedStorageContext()
                .getSharedPreferences(ManagementModeStore.MARKER_PREFS, Context.MODE_PRIVATE);
    }

    private SharedPreferences modeRecord() {
        return context.getSharedPreferences(ManagementModeStore.MODE_PREFS, Context.MODE_PRIVATE);
    }

    private static void flushPolicyThread() {
        PolicyReconciliationCoordinator.callOnPolicyThread(() -> null);
        PolicyReconciliationCoordinator.callOnPolicyThread(() -> null);
    }
}
