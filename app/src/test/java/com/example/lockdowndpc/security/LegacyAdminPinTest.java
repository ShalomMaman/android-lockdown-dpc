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

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 32)
public class LegacyAdminPinTest {
    private static final String PIN = "123456";
    private static final String NEW_PIN = "654321";
    private static final String RECOVERY_CODE = "1234-5678-9012";
    private static final SecretKey KEY = new SecretKeySpec(new byte[32], "HmacSHA256");
    private final AdminPinStore store = new AdminPinStore();
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
    public void processDeathDiscardsTheGrantAndLeavesTheOldRecoveryCodeValid() throws Exception {
        seedRecoveryCode(pinStore);
        var before = pinStore.getAll();
        var grant = verifyRecovery(store, context);

        var restarted = new AdminPinStore();
        assertNull(restarted.completeRecoveryPinReset(context, null, NEW_PIN, () -> KEY));
        assertNull(restarted.completeRecoveryPinReset(context, grant, NEW_PIN, () -> KEY));
        assertEquals(before, pinStore.getAll());
        assertNotNull(verifyRecovery(restarted, context));
        assertEquals(before, pinStore.getAll());
    }

    @Test
    public void expiredGrantCannotResetThePinAndTheOldRecoveryCodeStillVerifies() throws Exception {
        seedRecoveryCode(pinStore);
        var before = pinStore.getAll();
        var grant = verifyRecovery(store, context);
        ShadowSystemClock.advanceBy(Duration.ofMillis(AdminSession.SESSION_MILLIS));

        assertNull(store.completeRecoveryPinReset(context, grant, NEW_PIN, () -> KEY));
        assertEquals(before, pinStore.getAll());
        assertNotNull(verifyRecovery(store, context));
    }

    @Test
    public void leavingLocalModeRevokesTheGrantEvenIfLocalModeReturns() throws Exception {
        startConsoleRecovery(context);
        var before = pinStore.getAll();
        var mode = context.getSharedPreferences("management_mode", Context.MODE_PRIVATE);
        assertTrue(mode.edit().putString("mode", ManagementMode.ENROLLING.name()).commit());
        assertEquals(ManagementMode.ENROLLING, ManagementModeStore.read(context));
        assertTrue(mode.edit().putString("mode", ManagementMode.LOCAL_PIN.name()).commit());

        assertNull(AdminPinStore.getRecoveryGrant(context));
        assertEquals(before, pinStore.getAll());
        assertNotNull(verifyConsoleRecovery(context).recoveryGrant());
    }

    @Test
    public void recoveryResetRejectsReusingEitherPreviousCredential() throws Exception {
        seedRecoveryCode(pinStore);
        var before = pinStore.getAll();
        var grant = verifyRecovery(store, context);
        for (String rejected : new String[]{PIN, RECOVERY_CODE.replace("-", "")}) {
            var error = assertThrows(IllegalArgumentException.class,
                    () -> store.completeRecoveryPinReset(context, grant, rejected, () -> KEY));
            assertEquals(AdminPinStore.PIN_REUSE_ERROR, error.getMessage());
        }
        var formatError = assertThrows(IllegalArgumentException.class,
                () -> store.completeRecoveryPinReset(context, grant, "12345", () -> KEY));
        assertEquals(AdminPinStore.PIN_FORMAT_ERROR, formatError.getMessage());
        assertEquals(before, pinStore.getAll());
        assertNotNull(store.completeRecoveryPinReset(context, grant, NEW_PIN, () -> KEY));
    }

    @Test
    public void recoveryResetDoesNotTrustTheInMemoryUpdateOnDiskFailure() throws Exception {
        seedRecoveryCode(pinStore);
        var before = pinStore.getAll();
        MemoryPreferences failed = new MemoryPreferences(before);
        SharedPreferences pendingStore = failed.preferences();
        Context faulted = withStore("admin_security", pendingStore);
        var grant = verifyRecovery(store, faulted);

        assertThrows(SecurityException.class,
                () -> store.completeRecoveryPinReset(faulted, grant, NEW_PIN, () -> KEY));
        assertEquals(before, pendingStore.getAll());
        assertEquals(before, pinStore.getAll());
        assertEquals(0, failed.successfulCommits);
        assertNotNull(verifyRecovery(new AdminPinStore(), context));

        failed.failCommit = false;
        assertNotNull(store.completeRecoveryPinReset(faulted, grant, NEW_PIN, () -> KEY));
        assertEquals(1, failed.successfulCommits);
    }

    @Test
    public void recoveryResetSavesPinAndNewCodeTogetherAndRetiresTheGrant() throws Exception {
        assertAtomicRecoveryReset(true);
    }

    @Test
    public void recoveryResetReturnsNewCodeWhenCommitReturnsFalseAfterWritingToDisk() throws Exception {
        assertAtomicRecoveryReset(false);
    }

    @Test
    public void successfulCommitRemovesALeftoverBackupBeforeAcceptingTheReset() throws Exception {
        seedRecoveryCode(pinStore);
        Path backup = recoveryPreferencesFile(".bak");
        AtomicInteger commits = new AtomicInteger();
        Context faulted = withStore("admin_security", diskWritingPreferences(pinStore, true, commits,
                () -> Files.createFile(backup)));
        var grant = verifyRecovery(store, faulted);

        assertNotNull(store.completeRecoveryPinReset(faulted, grant, NEW_PIN, () -> KEY));
        assertTrue(Files.notExists(backup));
        assertEquals(1, commits.get());
    }

    @Test
    public void successfulCommitWithAnUndeletableBackupRollsBackAndKeepsTheGrant() throws Exception {
        seedRecoveryCode(pinStore);
        assertTrue(pinStore.edit().putBoolean("recovery_pin_reset_pending", true)
                .putInt("pin_failures", 2).commit());
        var before = pinStore.getAll();
        Path backup = recoveryPreferencesFile(".bak");
        Path child = backup.resolve("keep");
        AtomicInteger commits = new AtomicInteger();
        Context faulted = withStore("admin_security", diskWritingPreferences(pinStore, true, commits,
                () -> {
                    Files.createDirectory(backup);
                    Files.createFile(child);
                }));
        var grant = verifyRecovery(store, faulted);

        assertThrows(SecurityException.class,
                () -> store.completeRecoveryPinReset(faulted, grant, NEW_PIN, () -> KEY));
        assertTrue(Files.exists(child));
        assertEquals(before, pinStore.getAll());
        assertEquals(2, commits.get());

        Files.delete(child);
        Files.delete(backup);
        assertNotNull(store.completeRecoveryPinReset(faulted, grant, NEW_PIN, () -> KEY));
    }

    @Test
    public void readbackRejectsDuplicateCredentialKeys() throws Exception {
        seedRecoveryCode(pinStore);
        var before = pinStore.getAll();
        Path file = recoveryPreferencesFile("");
        AtomicInteger commits = new AtomicInteger();
        Context faulted = withStore("admin_security", diskWritingPreferences(pinStore, false, commits,
                () -> {
                    String xml = Files.readString(file);
                    String duplicate = "<string name=\"pin_salt\">" + pinStore.getString("pin_salt", "") + "</string>";
                    Files.writeString(file, xml.replace("</map>", duplicate + "</map>"));
                }));
        var grant = verifyRecovery(store, faulted);

        assertThrows(SecurityException.class,
                () -> store.completeRecoveryPinReset(faulted, grant, NEW_PIN, () -> KEY));
        assertEquals(before, pinStore.getAll());
        assertEquals(2, commits.get());
    }

    private Path recoveryPreferencesFile(String suffix) {
        return context.getDataDir().toPath().resolve("shared_prefs/admin_security.xml" + suffix);
    }

    private void assertAtomicRecoveryReset(boolean commitResult) throws Exception {
        seedRecoveryCode(pinStore);
        assertTrue(pinStore.edit().putBoolean("recovery_pin_reset_pending", true)
                .putInt("pin_failures", 2).commit());
        var before = pinStore.getAll();
        AtomicInteger commits = new AtomicInteger();
        Context faulted = withStore("admin_security", diskWritingPreferences(pinStore, commitResult, commits, () -> {}));

        AdminSession.unlock();
        var grant = verifyRecovery(store, faulted);
        assertFalse(AdminSession.isUnlocked());
        assertEquals(0, commits.get());
        assertEquals(before, pinStore.getAll());

        String newCode = store.completeRecoveryPinReset(faulted, grant, NEW_PIN, () -> KEY);
        assertNotNull(newCode);
        assertEquals(1, commits.get());
        assertFalse(pinStore.contains("recovery_pin_reset_pending"));
        assertEquals(0, pinStore.getInt("pin_failures", -1));
        assertFalse(AdminSession.isUnlocked());
        assertNull(store.completeRecoveryPinReset(faulted, grant, PIN, () -> KEY));
        assertEquals(1, commits.get());

        assertEquals(AdminPinStore.Status.INVALID, verify(context));
        assertEquals(AdminPinStore.Status.INVALID, store.verifyCredential(context, RECOVERY_CODE, () -> KEY).status());
        assertEquals(AdminPinStore.Status.SUCCESS, store.verifyCredential(context, NEW_PIN, () -> KEY).status());
        assertNotNull(store.verifyCredential(context, newCode, () -> KEY).recoveryGrant());
    }

    private static SharedPreferences diskWritingPreferences(
            SharedPreferences prefs, boolean commitResult, AtomicInteger commits, AfterCommit afterFirstCommit) {
        return (SharedPreferences) Proxy.newProxyInstance(SharedPreferences.class.getClassLoader(),
                new Class<?>[]{SharedPreferences.class}, (proxy, method, args) -> {
                    if (!method.getName().equals("edit")) {
                        return method.invoke(prefs, args);
                    }
                    SharedPreferences.Editor editor = prefs.edit();
                    return Proxy.newProxyInstance(SharedPreferences.Editor.class.getClassLoader(),
                            new Class<?>[]{SharedPreferences.Editor.class}, (wrapper, editMethod, editArgs) -> {
                                if (editMethod.getName().equals("commit")) {
                                    int attempt = commits.incrementAndGet();
                                    assertTrue(editor.commit());
                                    if (attempt == 1) {
                                        afterFirstCommit.run();
                                    }
                                    return commitResult;
                                }
                                editMethod.invoke(editor, editArgs);
                                return wrapper;
                            });
                });
    }

    @FunctionalInterface
    private interface AfterCommit {
        void run() throws IOException;
    }

    private static AdminPinStore.RecoveryGrant verifyRecovery(AdminPinStore store, Context context) {
        var verification = store.verifyCredential(context, RECOVERY_CODE, () -> KEY);
        assertEquals(AdminPinStore.Status.SUCCESS, verification.status());
        assertNotNull(verification.recoveryGrant());
        return verification.recoveryGrant();
    }

    private static void seedRecoveryCode(SharedPreferences prefs) throws Exception {
        byte[] salt = new byte[16];
        assertTrue(prefs.edit()
                .putString("recovery_salt", Base64.encodeToString(salt, Base64.NO_WRAP))
                .putString("recovery_verifier", Base64.encodeToString(
                        AdminPinStore.createVerifier(RECOVERY_CODE.replace("-", ""), salt, KEY), Base64.NO_WRAP))
                .commit());
    }

    public static void startConsoleRecovery(Context context) throws Exception {
        SharedPreferences prefs = context.getSharedPreferences("admin_security", Context.MODE_PRIVATE);
        seedRecoveryCode(prefs);
        assertNotNull(verifyConsoleRecovery(context).recoveryGrant());
    }

    public static AdminPinStore.Verification verifyConsoleRecovery(Context context) {
        return AdminPinStore.verify(context, RECOVERY_CODE, () -> KEY);
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
