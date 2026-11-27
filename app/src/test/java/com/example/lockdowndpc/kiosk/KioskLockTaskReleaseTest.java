package com.example.lockdowndpc.kiosk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;

import com.example.lockdowndpc.admin.LockdownAdminReceiver;
import com.example.lockdowndpc.kiosk.KioskStateMachine.KioskState;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;
import org.robolectric.annotation.Implementation;
import org.robolectric.annotation.Implements;
import org.robolectric.shadow.api.Shadow;
import org.robolectric.shadows.ShadowDevicePolicyManager;

import java.util.ArrayList;
import java.util.List;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 32, shadows = KioskLockTaskReleaseTest.RefusingClear.class)
public final class KioskLockTaskReleaseTest {
    private Context context;
    private DevicePolicyManager dpm;
    private ComponentName admin;
    private RefusingClear shadow;

    @Before
    public void setUp() {
        context = RuntimeEnvironment.getApplication();
        dpm = context.getSystemService(DevicePolicyManager.class);
        admin = LockdownAdminReceiver.componentName(context);
        shadow = Shadow.extract(dpm);
        assertTrue(shadow.setDeviceOwner(admin));
    }

    @Test
    public void offAcceptsRefusedClearOnlyWhenListWasAndRemainsEmpty() {
        assertEquals(List.of(), reconcile());
        assertEquals(1, shadow.clearAttempts);
        assertEquals(2, shadow.reads);
    }

    @Test
    public void offStillFailsRefusedClearWhenListWasNotEmpty() {
        shadow.before = new String[]{"com.example.other"};
        assertEquals(List.of("kiosk-lock-task-release:SecurityException"), reconcile());
    }

    @Test
    public void offStillFailsWhenEmptyPostStateCannotBeVerified() {
        shadow.after = null;
        assertEquals(List.of("kiosk-lock-task-release-unverified"), reconcile());
    }

    @Test
    public void offFailsRefusedClearWhenPostReadListIsNotEmpty() {
        shadow.after = new String[]{"com.example.other"};
        assertEquals(List.of("kiosk-lock-task-release-unverified"), reconcile());
        assertEquals(1, shadow.clearAttempts);
        assertEquals(2, shadow.reads);
    }

    @Test
    public void offFailsRefusedClearWhenPreReadThrows() {
        shadow.preReadThrows = true;
        assertEquals(List.of("kiosk-lock-task-release:SecurityException"), reconcile());
        assertEquals(1, shadow.clearAttempts);
        assertEquals(1, shadow.reads);
    }

    @Test
    public void offStateWithSingleAppModeFailsRefusedClear() {
        assertTrue(KioskConfigStore.writeConfig(
                context, KioskConfig.singleApp("com.example.target"), "", KioskState.OFF));
        assertEquals(List.of("kiosk-lock-task-release:SecurityException"), reconcile());
        assertEquals(1, shadow.clearAttempts);
        assertEquals(0, shadow.reads);
    }

    @Test
    public void armedStillFailsRefusedClearEvenWithAnEmptyList() {
        assertTrue(KioskConfigStore.writeConfig(
                context, KioskConfig.singleApp("com.example.target"), "", KioskState.ARMED));
        assertEquals(List.of("kiosk-lock-task-release:SecurityException"), reconcile());
    }

    private List<String> reconcile() {
        List<String> errors = new ArrayList<>();
        KioskController.reconcile(context, dpm, admin, errors);
        return errors;
    }

    @Implements(DevicePolicyManager.class)
    public static class RefusingClear extends ShadowDevicePolicyManager {
        private String[] before = new String[0];
        private String[] after = new String[0];
        private boolean preReadThrows;
        private int clearAttempts;
        private int reads;

        @Implementation
        protected void setLockTaskPackages(ComponentName admin, String[] packages) {
            assertEquals(0, packages.length);
            clearAttempts++;
            throw new SecurityException("Clear refused");
        }

        @Implementation
        protected String[] getLockTaskPackages(ComponentName admin) {
            reads++;
            if (clearAttempts == 0 && preReadThrows) {
                throw new IllegalStateException("Allowlist unreadable");
            }
            return clearAttempts == 0 ? before : after;
        }
    }
}
