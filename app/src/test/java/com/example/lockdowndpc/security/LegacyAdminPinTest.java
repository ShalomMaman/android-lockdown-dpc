package com.example.lockdowndpc.security;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;
import android.provider.Settings;
import android.util.Base64;

import com.example.lockdowndpc.policy.ManagementMode;
import com.example.lockdowndpc.policy.ManagementModeStore;
import com.example.lockdowndpc.testing.MemoryPreferences;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowSystemClock;

import java.time.Duration;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 32)
public class LegacyAdminPinTest {
    private static final String PIN = "123456";
    private static final SecretKey KEY = new SecretKeySpec(new byte[32], "HmacSHA256");
    private Context context;
    private SharedPreferences pinStore;

    @Before
    public void seedLegacyPin() throws Exception {
        context = RuntimeEnvironment.getApplication();
        assertTrue(Settings.Global.putInt(context.getContentResolver(), Settings.Global.BOOT_COUNT, 1));
        pinStore = context.getSharedPreferences("admin_security", Context.MODE_PRIVATE);
        byte[] salt = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
        assertTrue(pinStore.edit()
                .putString("pin_salt", Base64.encodeToString(salt, Base64.NO_WRAP))
                .putString("pin_verifier", Base64.encodeToString(
                        AdminPinStore.createVerifier(PIN, salt, KEY), Base64.NO_WRAP))
                .commit());
    }

    @Test
    public void realLegacyPinUnlocksAndMigratesMode() {
        String verifier = pinStore.getString("pin_verifier", null);
        assertEquals(AdminPinStore.Status.SUCCESS, verify(context));
        assertEquals("LOCAL_PIN", context.getSharedPreferences("management_mode", Context.MODE_PRIVATE)
                .getString("mode", null));
        assertEquals(verifier, pinStore.getString("pin_verifier", null));
    }

    @Test
    public void verifiesAndConsumesRecoveryCodeThenSavesExactlyOneNewPinWithoutASession() throws Exception {
        String recoveryCode = "1234-5678-9012";
        byte[] salt = new byte[16];
        assertTrue(pinStore.edit()
                .putString("recovery_salt", Base64.encodeToString(salt, Base64.NO_WRAP))
                .putString("recovery_verifier", Base64.encodeToString(
                        AdminPinStore.createVerifier("123456789012", salt, KEY), Base64.NO_WRAP))
                .commit());
        AdminSession.unlock();
        var result = AdminPinStore.verify(context, recoveryCode, () -> KEY);
        assertEquals(AdminPinStore.Status.SUCCESS, result.status());
        assertTrue(result.usedRecoveryCode());
        assertTrue(AdminPinStore.hasPendingRecoveryPinReset(context));
        assertFalse(AdminSession.isUnlocked());
        assertEquals(AdminPinStore.Status.ERROR, verify(context));
        assertEquals(AdminPinStore.Status.ERROR, AdminPinStore.verify(context, recoveryCode, () -> KEY).status());
        assertThrows(SecurityException.class, () -> AdminPinStore.rotateRecoveryCode(context));

        var before = pinStore.getAll();
        assertThrows(IllegalArgumentException.class,
                () -> AdminPinStore.completeRecoveryPinReset(context, "12345", () -> KEY));
        assertEquals(before, pinStore.getAll());
        MemoryPreferences failed = new MemoryPreferences(before);
        SharedPreferences pendingStore = failed.preferences();
        Context faulted = withStore("admin_security", pendingStore);
        String newPin = "654321";
        assertThrows(SecurityException.class, () -> AdminPinStore.completeRecoveryPinReset(faulted, newPin, () -> KEY));
        assertEquals(before, pendingStore.getAll());

        failed.failCommit = false;
        assertFalse(AdminPinStore.replacePin(faulted, newPin));
        assertTrue(AdminPinStore.completeRecoveryPinReset(faulted, newPin, () -> KEY));
        assertEquals(1, failed.successfulCommits);
        assertFalse(pendingStore.contains("recovery_pin_reset_pending"));
        assertFalse(before.get("pin_verifier").equals(pendingStore.getString("pin_verifier", null)));
        assertFalse(AdminSession.isUnlocked());
        assertFalse(AdminPinStore.completeRecoveryPinReset(faulted, PIN, () -> KEY));
        assertEquals(AdminPinStore.Status.INVALID, verify(faulted));
        assertEquals(AdminPinStore.Status.SUCCESS, AdminPinStore.verify(faulted, newPin, () -> KEY).status());
    }

    @Test
    public void failedMigrationStillUnlocksAndVerifyRetriesTheWrite() {
        MemoryPreferences failed = new MemoryPreferences(Map.of());
        SharedPreferences modeStore = failed.preferences();
        Context faulted = withStore("management_mode", modeStore);
        assertEquals(ManagementMode.LOCAL_PIN, ManagementModeStore.read(faulted));
        assertFalse(modeStore.contains("mode"));

        assertEquals(AdminPinStore.Status.SUCCESS, verify(faulted));
        assertFalse(modeStore.contains("mode"));

        failed.failCommit = false;
        assertEquals(AdminPinStore.Status.SUCCESS, verify(faulted));
        assertEquals("LOCAL_PIN", modeStore.getString("mode", null));
    }

    @Test
    public void validPinUnlocksEvenWhenClearingFailuresCannotBePersisted() {
        assertTrue(pinStore.edit().putInt("pin_failures", 2).commit());
        SharedPreferences failedPinStore = new MemoryPreferences(pinStore.getAll()).preferences();

        assertEquals(AdminPinStore.Status.SUCCESS, verify(withStore("admin_security", failedPinStore)));
        assertEquals(2, failedPinStore.getInt("pin_failures", -1));
    }

    @Test
    public void failedDiskWritesStillCountWrongPinsAndLockOutTheCorrectPin() {
        SharedPreferences failedPinStore = new MemoryPreferences(pinStore.getAll()).preferences();
        Context faulted = withStore("admin_security", failedPinStore);
        int threshold = PinLockoutPolicy.FIRST_PENALTY_FAILURE;

        for (int attempt = 1; attempt < threshold; attempt++) {
            assertEquals(AdminPinStore.Status.INVALID, AdminPinStore.verify(faulted, "654321", () -> KEY).status());
            assertEquals(attempt, failedPinStore.getInt("pin_failures", -1));
        }
        var rejected = AdminPinStore.verify(faulted, "654321", () -> KEY);
        assertEquals(AdminPinStore.Status.LOCKED, rejected.status());
        assertEquals(PinLockoutPolicy.penaltyMillis(threshold), rejected.remainingMillis());
        assertEquals(threshold, failedPinStore.getInt("pin_failures", -1));
        assertEquals(AdminPinStore.Status.LOCKED, verify(faulted));

        ShadowSystemClock.advanceBy(Duration.ofMillis(rejected.remainingMillis()));
        assertEquals(AdminPinStore.Status.SUCCESS, verify(faulted));
    }

    @Test
    public void editorFailureBeforeUpdatingMemoryStillCountsWrongPins() {
        MemoryPreferences failed = new MemoryPreferences(pinStore.getAll());
        failed.throwBeforeCommit = true;
        Context faulted = withStore("admin_security", failed.preferences());

        for (int attempt = 1; attempt < PinLockoutPolicy.FIRST_PENALTY_FAILURE; attempt++) {
            assertEquals(AdminPinStore.Status.INVALID, AdminPinStore.verify(faulted, "654321", () -> KEY).status());
        }
        assertEquals(AdminPinStore.Status.LOCKED, AdminPinStore.verify(faulted, "654321", () -> KEY).status());
        assertEquals(AdminPinStore.Status.LOCKED, verify(faulted));
    }

    @Test
    public void unreadableFailureCountArmsTheExistingPenaltyBeforeCheckingThePin() {
        assertTrue(pinStore.edit().putString("pin_failures", "corrupt").commit());

        var locked = AdminPinStore.verify(context, PIN, () -> KEY);
        assertEquals(AdminPinStore.Status.LOCKED, locked.status());
        assertEquals(PinLockoutPolicy.penaltyMillis(PinLockoutPolicy.FIRST_PENALTY_FAILURE),
                locked.remainingMillis());
        assertEquals(AdminPinStore.Status.LOCKED, verify(context));

        ShadowSystemClock.advanceBy(Duration.ofMillis(locked.remainingMillis()));
        assertEquals(AdminPinStore.Status.SUCCESS, verify(context));
    }

    private static AdminPinStore.Status verify(Context context) {
        return AdminPinStore.verify(context, PIN, () -> KEY).status();
    }

    private Context withStore(String name, SharedPreferences store) {
        return new ContextWrapper(context) {
            @Override
            public SharedPreferences getSharedPreferences(String requested, int mode) {
                return name.equals(requested) ? store : super.getSharedPreferences(requested, mode);
            }
        };
    }
}
