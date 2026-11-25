package com.example.lockdowndpc.security;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;
import android.provider.Settings;
import android.util.Base64;

import com.example.lockdowndpc.policy.ManagementMode;
import com.example.lockdowndpc.policy.ManagementModeStore;
import com.example.lockdowndpc.testing.MemoryPreferences;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowSystemClock;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.spec.SecretKeySpec;

import static java.util.concurrent.TimeUnit.MILLISECONDS;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/** An attempt is charged on disk before the candidate is compared, in every verification path. */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 32)
public class AdminPinAttemptTest {
    private static final String PIN = "123456";
    private static final String WRONG_PIN = "000000";
    private static final String NEW_PIN = "654321";
    private static final String RECOVERY_CODE = "1234-5678-9012";
    private static final int THRESHOLD = PinLockoutPolicy.FIRST_PENALTY_FAILURE;
    private static final ProbeKey KEY = new ProbeKey(() -> {});
    private Context context;
    private SharedPreferences prefs;

    @Before
    public void seedPin() throws Exception {
        context = RuntimeEnvironment.getApplication();
        assertTrue(Settings.Global.putInt(context.getContentResolver(), Settings.Global.BOOT_COUNT, 1));
        prefs = context.getSharedPreferences("admin_security", Context.MODE_PRIVATE);
        byte[] salt = new byte[16];
        assertTrue(prefs.edit()
                .putString("pin_salt", Base64.encodeToString(salt, Base64.NO_WRAP))
                .putString("pin_verifier", Base64.encodeToString(
                        AdminPinStore.createVerifier(PIN, salt, KEY), Base64.NO_WRAP))
                .commit());
        setMode(ManagementMode.LOCAL_PIN);
    }

    @After
    public void clearProcessState() {
        AdminPinStore.clearRecoveryGrant();
        AdminSession.lock();
    }

    // ---- The charge lands before the comparison -------------------------------------------

    @Test
    public void everyCandidateIsChargedOnDiskBeforeItIsCompared() throws Exception {
        LegacyAdminPinTest.seedRecoveryCode(prefs);
        for (String candidate : new String[]{WRONG_PIN, PIN, RECOVERY_CODE}) {
            assertTrue(prefs.edit().putInt("pin_failures", 2).commit());
            List<Integer> duringCompare = new ArrayList<>();
            verify(context, candidate, () -> duringCompare.add(failuresOnDisk()));
            assertFalse(candidate, duringCompare.isEmpty());
            assertTrue(candidate + duringCompare, duringCompare.stream().allMatch(count -> count == 3));
            AdminPinStore.clearRecoveryGrant();
        }
    }

    @Test
    public void theLastAllowedAttemptHasItsPenaltyOnDiskBeforeItIsCompared() {
        assertTrue(prefs.edit().putInt("pin_failures", THRESHOLD - 1).commit());
        List<String> duringCompare = new ArrayList<>();
        assertEquals(AdminPinStore.Status.SUCCESS,
                verify(context, PIN, () -> duringCompare.add(onDisk("pin_lockout_penalty"))).status());
        assertFalse(duringCompare.isEmpty());
        assertTrue(duringCompare.stream().allMatch(
                value -> value.equals(Long.toString(PinLockoutPolicy.penaltyMillis(THRESHOLD)))));
    }

    @Test
    public void replacingChargesTheCurrentPinOnDiskBeforeItIsCompared() {
        for (String current : new String[]{WRONG_PIN, PIN}) {
            assertTrue(prefs.edit().putInt("pin_failures", 1).commit());
            List<Integer> duringCompare = new ArrayList<>();
            AtomicInteger uses = new AtomicInteger();
            AdminPinStore.replaceWithCurrent(context, current, NEW_PIN, () -> new ProbeKey(() -> {
                // The second key use hashes the new PIN, after the current one matched.
                if (uses.getAndIncrement() == 0) {
                    duringCompare.add(failuresOnDisk());
                }
            }));
            assertEquals(List.of(2), duringCompare);
        }
    }

    @Test
    public void killingTheProcessDuringTheComparisonGivesNoFreeGuess() {
        for (String candidate : new String[]{WRONG_PIN, PIN}) {
            assertKilledAttemptsLockOut(faulted -> verify(faulted, candidate, AdminPinAttemptTest::kill));
            assertKilledAttemptsLockOut(faulted -> AdminPinStore.replaceWithCurrent(
                    faulted, candidate, NEW_PIN, () -> new ProbeKey(AdminPinAttemptTest::kill)));
        }
    }

    private void assertKilledAttemptsLockOut(Consumer<Context> attempt) {
        MemoryPreferences disk = writableCopy();
        SharedPreferences store = disk.preferences();
        Context restarted = withPinStore(store);
        for (int kills = 1; kills <= THRESHOLD; kills++) {
            assertThrows(ProcessKilled.class, () -> attempt.accept(restarted));
            disk.restart();
            assertEquals(kills, store.getInt("pin_failures", -1));
        }
        var locked = verify(restarted, PIN, AdminPinAttemptTest::unexpectedCompare);
        assertEquals(AdminPinStore.Status.LOCKED, locked.status());
        assertEquals(PinLockoutPolicy.penaltyMillis(THRESHOLD), locked.remainingMillis());
    }

    @Test
    public void anErrorAfterTheComparisonStartedKeepsTheCharge() {
        // The PIN is compared first, so an unusable recovery record must not make wrong PINs free.
        assertTrue(prefs.edit().putString("recovery_salt", "?").putString("recovery_verifier", "?").commit());
        for (int attempt = 1; attempt <= THRESHOLD; attempt++) {
            assertEquals(AdminPinStore.Status.ERROR, verify(context, WRONG_PIN).status());
            assertEquals(attempt, failuresOnDisk());
        }
        assertEquals(AdminPinStore.Status.LOCKED, verify(context, PIN, AdminPinAttemptTest::unexpectedCompare).status());
    }

    // ---- Refusal when the charge cannot be stored -----------------------------------------

    @Test
    public void anAttemptThatCannotBeChargedIsRefusedWithoutComparing() {
        for (boolean throwing : new boolean[]{false, true}) {
            MemoryPreferences failing = writableCopy();
            failing.failCommit = true;
            failing.throwBeforeCommit = throwing;
            Context faulted = withPinStore(failing.preferences());
            for (int attempt = 1; attempt < THRESHOLD; attempt++) {
                assertEquals(AdminPinStore.Status.ERROR,
                        verify(faulted, PIN, AdminPinAttemptTest::unexpectedCompare).status());
            }
            assertEquals(AdminPinStore.Status.LOCKED,
                    verify(faulted, PIN, AdminPinAttemptTest::unexpectedCompare).status());
            assertEquals(0, failing.successfulCommits);
        }
    }

    @Test
    public void replacingIsRefusedWithoutComparingWhenTheChargeCannotBeStored() {
        MemoryPreferences failing = writableCopy();
        failing.failCommit = true;
        SharedPreferences store = failing.preferences();
        String verifier = store.getString("pin_verifier", null);

        var result = AdminPinStore.replaceWithCurrent(withPinStore(store), PIN, NEW_PIN,
                () -> new ProbeKey(AdminPinAttemptTest::unexpectedCompare));
        assertEquals(AdminPinStore.Status.ERROR, result.verification().status());
        assertFalse(result.replaced());
        assertEquals(verifier, store.getString("pin_verifier", null));
    }

    @Test
    public void aWrittenChargeIsRequiredAgainAfterStorageRecovers() {
        MemoryPreferences failing = writableCopy();
        failing.failCommit = true;
        SharedPreferences store = failing.preferences();
        Context faulted = withPinStore(store);
        assertEquals(AdminPinStore.Status.ERROR, verify(faulted, PIN).status());
        failing.failCommit = false;
        assertEquals(AdminPinStore.Status.SUCCESS, verify(faulted, PIN).status());
        failing.restart();
        assertEquals(0, store.getInt("pin_failures", -1));
    }

    // ---- Unchanged limits and timing ------------------------------------------------------

    @Test
    public void wrongPinsReachEachPenaltyAfterTheSameNumberOfGuesses() {
        for (int failure = 1; failure <= THRESHOLD + 4; failure++) {
            long penalty = PinLockoutPolicy.penaltyMillis(failure);
            var result = verify(context, WRONG_PIN);
            assertEquals(penalty == 0 ? AdminPinStore.Status.INVALID : AdminPinStore.Status.LOCKED, result.status());
            assertEquals(penalty, result.remainingMillis());
            assertEquals(failure, failuresOnDisk());
            if (penalty > 0) {
                ShadowSystemClock.advanceBy(Duration.ofMillis(penalty - 1));
                var waiting = verify(context, PIN, AdminPinAttemptTest::unexpectedCompare);
                assertEquals(AdminPinStore.Status.LOCKED, waiting.status());
                assertEquals(1L, waiting.remainingMillis());
                assertEquals(failure, failuresOnDisk());
                ShadowSystemClock.advanceBy(Duration.ofMillis(1));
            }
        }
    }

    @Test
    public void theCorrectPinSucceedsOnEveryAllowedAttemptAndResetsTheCounter() {
        for (int failures = 0; failures <= THRESHOLD + 4; failures++) {
            assertTrue(prefs.edit().putInt("pin_failures", failures).commit());
            assertEquals(AdminPinStore.Status.SUCCESS, verify(context, PIN).status());
            assertEquals(0, failuresOnDisk());
            assertEquals("0", onDisk("pin_lockout_penalty"));
            assertEquals("0", onDisk("pin_lockout_until"));
        }
        for (int failure = 1; failure < THRESHOLD; failure++) {
            assertEquals(AdminPinStore.Status.INVALID, verify(context, WRONG_PIN).status());
        }
        assertEquals(AdminPinStore.Status.SUCCESS, verify(context, PIN).status());
        assertEquals(AdminPinStore.Status.INVALID, verify(context, WRONG_PIN).status());
    }

    @Test
    public void thePenaltyIsMeasuredFromTheEndOfTheComparison() {
        assertTrue(prefs.edit().putInt("pin_failures", THRESHOLD - 1).commit());
        assertEquals(AdminPinStore.Status.LOCKED,
                verify(context, WRONG_PIN, () -> ShadowSystemClock.advanceBy(Duration.ofSeconds(2))).status());
        assertEquals(PinLockoutPolicy.penaltyMillis(THRESHOLD), verify(context, PIN).remainingMillis());
    }

    @Test
    public void aCorrectPinWhoseRefundCannotBeStoredSucceedsButStaysCharged() {
        assertTrue(prefs.edit().putInt("pin_failures", THRESHOLD - 1).commit());
        MemoryPreferences failing = writableCopy();
        Context faulted = withPinStore(failing.preferences());
        assertEquals(AdminPinStore.Status.SUCCESS,
                verify(faulted, PIN, () -> failing.failCommit = true).status());
        assertEquals(AdminPinStore.Status.LOCKED,
                verify(faulted, PIN, AdminPinAttemptTest::unexpectedCompare).status());
    }

    @Test
    public void aRecoveryCodeLeavesTheEarlierCountAndAServedPenaltyAsTheyWere() throws Exception {
        LegacyAdminPinTest.seedRecoveryCode(prefs);
        for (int failure = 1; failure <= THRESHOLD; failure++) {
            verify(context, WRONG_PIN);
        }
        ShadowSystemClock.advanceBy(Duration.ofMillis(PinLockoutPolicy.penaltyMillis(THRESHOLD)));
        var before = prefs.getAll();
        assertNotNull(verify(context, RECOVERY_CODE).recoveryGrant());
        assertEquals(before, prefs.getAll());
        AdminPinStore.clearRecoveryGrant();

        var next = verify(context, WRONG_PIN);
        assertEquals(PinLockoutPolicy.penaltyMillis(THRESHOLD + 1), next.remainingMillis());
    }

    @Test
    public void nothingIsChargedWhenNothingCanBeCompared() {
        var before = prefs.getAll();
        for (AdminPinStore.HmacKeySource unavailable : List.<AdminPinStore.HmacKeySource>of(
                () -> null, () -> { throw new IllegalStateException("key unavailable"); })) {
            assertEquals(AdminPinStore.Status.ERROR, AdminPinStore.verify(context, PIN, unavailable).status());
        }
        for (String empty : new String[]{null, ""}) {
            assertEquals(AdminPinStore.Status.ERROR,
                    verify(context, empty, AdminPinAttemptTest::unexpectedCompare).status());
        }
        assertEquals(before, prefs.getAll());
    }

    // ---- Concurrency ----------------------------------------------------------------------

    @Test
    public void aSecondCallerCannotCompareUnderTheFirstCallersCharge() throws Exception {
        assertTrue(prefs.edit().putInt("pin_failures", THRESHOLD - 1).commit());
        CountDownLatch comparing = new CountDownLatch(1);
        CountDownLatch finish = new CountDownLatch(1);
        ExecutorService callers = Executors.newFixedThreadPool(2);
        try {
            Future<AdminPinStore.Verification> first = callers.submit(() -> verify(context, WRONG_PIN, () -> {
                comparing.countDown();
                await(finish);
            }));
            await(comparing);
            List<Future<AdminPinStore.Verification>> others = List.of(
                    callers.submit(() -> verify(context, PIN, AdminPinAttemptTest::unexpectedCompare)),
                    callers.submit(() -> AdminPinStore.replaceWithCurrent(context, PIN, NEW_PIN,
                            () -> new ProbeKey(AdminPinAttemptTest::unexpectedCompare)).verification()));
            assertThrows(TimeoutException.class, () -> others.get(0).get(100, MILLISECONDS));
            finish.countDown();

            assertEquals(AdminPinStore.Status.LOCKED, first.get(30, SECONDS).status());
            for (var other : others) {
                assertEquals(AdminPinStore.Status.LOCKED, other.get(30, SECONDS).status());
            }
            assertEquals(THRESHOLD, failuresOnDisk());
        } finally {
            finish.countDown();
            callers.shutdownNow();
        }
    }

    @Test
    public void parallelWrongPinsAreEachCharged() throws Exception {
        ExecutorService callers = Executors.newFixedThreadPool(2);
        try {
            AtomicInteger compares = new AtomicInteger();
            List<Future<AdminPinStore.Verification>> results = new ArrayList<>();
            for (int caller = 0; caller < THRESHOLD + 3; caller++) {
                results.add(callers.submit(() -> verify(context, WRONG_PIN, compares::incrementAndGet)));
            }
            int locked = 0;
            for (var result : results) {
                locked += result.get(30, SECONDS).status() == AdminPinStore.Status.LOCKED ? 1 : 0;
            }
            assertEquals(THRESHOLD, compares.get());
            assertEquals(4, locked);
            assertEquals(THRESHOLD, failuresOnDisk());
        } finally {
            callers.shutdownNow();
        }
    }

    // ---- replaceWithCurrent refusals ------------------------------------------------------

    @Test
    public void replacingIsRefusedOutsideLocalPinMode() {
        for (ManagementMode mode : new ManagementMode[]{
                ManagementMode.UNDECIDED, ManagementMode.ENROLLING, ManagementMode.REMOTE}) {
            setMode(mode);
            var before = prefs.getAll();
            var result = AdminPinStore.replaceWithCurrent(context, PIN, NEW_PIN,
                    () -> new ProbeKey(AdminPinAttemptTest::unexpectedCompare));
            assertEquals(mode.name(), AdminPinStore.Status.ERROR, result.verification().status());
            assertFalse(result.replaced());
            assertEquals(before, prefs.getAll());
        }
    }

    @Test
    public void replacingIsRefusedWhenTheModeChangesDuringVerification() {
        String verifier = prefs.getString("pin_verifier", null);
        var result = AdminPinStore.replaceWithCurrent(context, PIN, NEW_PIN,
                () -> new ProbeKey(() -> setMode(ManagementMode.ENROLLING)));
        assertEquals(AdminPinStore.Status.SUCCESS, result.verification().status());
        assertFalse(result.replaced());
        assertEquals(verifier, prefs.getString("pin_verifier", null));
    }

    @Test
    public void replacingIsRefusedWhenTheModeChangesBeforeTheNewPinIsStored() {
        String verifier = prefs.getString("pin_verifier", null);
        AtomicInteger uses = new AtomicInteger();
        var result = AdminPinStore.replaceWithCurrent(context, PIN, NEW_PIN, () -> {
            // The second key is fetched to hash the new PIN.
            if (uses.getAndIncrement() == 1) {
                setMode(ManagementMode.ENROLLING);
            }
            return KEY;
        });
        assertEquals(2, uses.get());
        assertFalse(result.replaced());
        assertEquals(verifier, prefs.getString("pin_verifier", null));
    }

    @Test
    public void theNewPinIsStoredUnderTheModeLock() {
        MemoryPreferences disk = writableCopy();
        AtomicInteger pinWrites = new AtomicInteger();
        disk.beforeCommit = keys -> {
            if (keys.contains("pin_verifier")) {
                pinWrites.incrementAndGet();
                assertTrue(Thread.holdsLock(ManagementModeStore.class));
            }
        };
        assertTrue(AdminPinStore.replaceWithCurrent(
                withPinStore(disk.preferences()), PIN, NEW_PIN, () -> KEY).replaced());
        assertEquals(1, pinWrites.get());
    }

    @Test
    public void replacingIsRefusedWhileARecoveryGrantIsLive() throws Exception {
        LegacyAdminPinTest.seedRecoveryCode(prefs);
        var grant = verify(context, RECOVERY_CODE).recoveryGrant();
        assertNotNull(grant);
        var before = prefs.getAll();

        var result = AdminPinStore.replaceWithCurrent(context, PIN, NEW_PIN,
                () -> new ProbeKey(AdminPinAttemptTest::unexpectedCompare));
        assertEquals(AdminPinStore.Status.ERROR, result.verification().status());
        assertFalse(result.replaced());
        assertEquals(before, prefs.getAll());
        assertSame(grant, AdminPinStore.getRecoveryGrant(context));

        AdminPinStore.clearRecoveryGrant();
        assertTrue(AdminPinStore.replaceWithCurrent(context, PIN, NEW_PIN, () -> KEY).replaced());
    }

    @Test
    public void replacingIsRefusedWithoutAPin() {
        assertTrue(prefs.edit().clear().commit());
        var result = AdminPinStore.replaceWithCurrent(context, PIN, NEW_PIN,
                () -> new ProbeKey(AdminPinAttemptTest::unexpectedCompare));
        assertEquals(AdminPinStore.Status.NOT_CONFIGURED, result.verification().status());
        assertFalse(result.replaced());
        assertEquals(Map.of(), prefs.getAll());
    }

    @Test
    public void replacingWithARecoveryCodeIsRefusedAndDropsTheGrant() throws Exception {
        LegacyAdminPinTest.seedRecoveryCode(prefs);
        String verifier = prefs.getString("pin_verifier", null);
        var result = AdminPinStore.replaceWithCurrent(context, RECOVERY_CODE, NEW_PIN, () -> KEY);
        assertNotNull(result.verification().recoveryGrant());
        assertFalse(result.replaced());
        assertNull(AdminPinStore.getRecoveryGrant(context));
        assertEquals(verifier, prefs.getString("pin_verifier", null));
    }

    @Test
    public void replacingRejectsAnInvalidNewPinWithoutChargingAnAttempt() {
        var before = prefs.getAll();
        for (String invalid : new String[]{null, "", "12345", "1234567890123", "12345a"}) {
            var error = assertThrows(IllegalArgumentException.class, () -> AdminPinStore.replaceWithCurrent(
                    context, PIN, invalid, () -> new ProbeKey(AdminPinAttemptTest::unexpectedCompare)));
            assertEquals(AdminPinStore.PIN_FORMAT_ERROR, error.getMessage());
        }
        assertEquals(before, prefs.getAll());
    }

    @Test
    public void replacingKeepsTheOldPinAndTheChargeWhenTheNewPinCannotBeStored() {
        MemoryPreferences failing = writableCopy();
        SharedPreferences store = failing.preferences();
        String verifier = store.getString("pin_verifier", null);
        var error = assertThrows(SecurityException.class, () -> AdminPinStore.replaceWithCurrent(
                withPinStore(store), PIN, NEW_PIN, () -> new ProbeKey(() -> failing.failCommit = true)));
        assertEquals("admin-pin-save-failed", error.getMessage());
        assertEquals(verifier, store.getString("pin_verifier", null));
        failing.restart();
        assertEquals(verifier, store.getString("pin_verifier", null));
        assertEquals(1, store.getInt("pin_failures", -1));
    }

    @Test
    public void replacingWithTheCurrentPinStoresTheNewOneAndResetsTheCounter() {
        assertTrue(prefs.edit().putInt("pin_failures", THRESHOLD - 1).commit());
        assertTrue(AdminPinStore.replaceWithCurrent(context, PIN, NEW_PIN, () -> KEY).replaced());
        assertEquals(0, failuresOnDisk());
        assertEquals(AdminPinStore.Status.INVALID, verify(context, PIN).status());
        assertEquals(AdminPinStore.Status.SUCCESS, verify(context, NEW_PIN).status());
    }

    // ---- The console session --------------------------------------------------------------

    @Test
    public void theConsoleRotatesTheRecoveryCodeOnlyInItsOwnLiveSession() {
        AdminSession.unlock();
        long session = AdminSession.activeGeneration();
        var before = prefs.getAll();
        AdminSession.unlock();
        assertNull(AdminPinStore.rotateRecoveryCode(context, session, () -> KEY));
        long current = AdminSession.activeGeneration();
        // The session ends after the rotation was authorized and started.
        assertNull(AdminPinStore.rotateRecoveryCode(context, current, () -> {
            AdminSession.lock();
            return KEY;
        }));
        assertNull(AdminPinStore.rotateRecoveryCode(context, current, () -> KEY));
        assertNull(AdminPinStore.rotateRecoveryCode(context, 0L, () -> KEY));
        assertEquals(before, prefs.getAll());

        AdminSession.unlock();
        String code = AdminPinStore.rotateRecoveryCode(context, AdminSession.activeGeneration(), () -> KEY);
        assertNotNull(verify(context, code).recoveryGrant());
    }

    @Test
    public void onlyAPinMatchInLocalModeOpensTheSession() throws Exception {
        LegacyAdminPinTest.seedRecoveryCode(prefs);
        for (String refused : new String[]{WRONG_PIN, "", null}) {
            AdminPinStore.verifyAndUnlock(context, refused, () -> KEY);
            assertFalse(AdminSession.isUnlocked());
        }
        assertNotNull(AdminPinStore.verifyAndUnlock(context, RECOVERY_CODE, () -> KEY).recoveryGrant());
        assertFalse(AdminSession.isUnlocked());
        AdminPinStore.clearRecoveryGrant();

        assertEquals(AdminPinStore.Status.ERROR, AdminPinStore.verifyAndUnlock(context, PIN,
                () -> new ProbeKey(() -> setMode(ManagementMode.ENROLLING))).status());
        assertFalse(AdminSession.isUnlocked());

        setMode(ManagementMode.LOCAL_PIN);
        assertEquals(AdminPinStore.Status.SUCCESS,
                AdminPinStore.verifyAndUnlock(context, PIN, () -> KEY).status());
        assertTrue(AdminSession.isUnlocked());
    }

    @Test
    public void thePinCannotBeReplacedBetweenItsMatchAndTheUnlock() throws Exception {
        String verifier = prefs.getString("pin_verifier", null);
        Thread console = new Thread(() -> AdminPinStore.verifyAndUnlock(context, PIN, () -> KEY));
        Thread shell = new Thread(() -> AdminPinStore.replaceWithCurrent(context, PIN, NEW_PIN, () -> KEY));
        synchronized (AdminSession.class) {
            console.start();
            // The PIN matched; only the unlock itself waits for the session.
            awaitBlockedOnSession(console);
            shell.start();
            shell.join(3_000);
            assertEquals(verifier, prefs.getString("pin_verifier", null));
        }
        console.join(30_000);
        shell.join(30_000);
        assertEquals(AdminPinStore.Status.SUCCESS, verify(context, NEW_PIN).status());
        assertFalse(AdminSession.isUnlocked());
    }

    private static void awaitBlockedOnSession(Thread thread) throws InterruptedException {
        for (int wait = 0; wait < 3_000; wait++) {
            if (thread.getState() == Thread.State.BLOCKED && thread.getStackTrace()[0].getClassName()
                    .equals(AdminSession.class.getName())) {
                return;
            }
            Thread.sleep(10);
        }
        throw new AssertionError("The console never reached the unlock");
    }

    // ---- Fixtures -------------------------------------------------------------------------

    private static AdminPinStore.Verification verify(Context context, String candidate) {
        return AdminPinStore.verify(context, candidate, () -> KEY);
    }

    private static AdminPinStore.Verification verify(Context context, String candidate, Runnable onCompare) {
        return AdminPinStore.verify(context, candidate, () -> new ProbeKey(onCompare));
    }

    private void setMode(ManagementMode mode) {
        assertTrue(context.getSharedPreferences("management_mode", Context.MODE_PRIVATE)
                .edit().putString("mode", mode.name()).commit());
    }

    private MemoryPreferences writableCopy() {
        MemoryPreferences copy = new MemoryPreferences(prefs.getAll());
        copy.failCommit = false;
        return copy;
    }

    private Context withPinStore(SharedPreferences store) {
        return new ContextWrapper(context) {
            @Override
            public SharedPreferences getSharedPreferences(String name, int mode) {
                return "admin_security".equals(name) ? store : super.getSharedPreferences(name, mode);
            }
        };
    }

    private int failuresOnDisk() {
        return Integer.parseInt(onDisk("pin_failures"));
    }

    /** Reads the file itself: the in-memory map would also show an unwritten change. */
    private String onDisk(String key) {
        Path file = context.getDataDir().toPath().resolve("shared_prefs/admin_security.xml");
        try {
            Matcher value = Pattern.compile("name=\"" + key + "\" value=\"(-?\\d+)\"").matcher(Files.readString(file));
            return value.find() ? value.group(1) : "-1";
        } catch (IOException exception) {
            throw new UncheckedIOException(exception);
        }
    }

    private static void kill() {
        throw new ProcessKilled();
    }

    private static void unexpectedCompare() {
        throw new AssertionError("A refused attempt must not be compared");
    }

    private static void await(CountDownLatch latch) {
        try {
            assertTrue(latch.await(30, SECONDS));
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new AssertionError(exception);
        }
    }

    private static final class ProcessKilled extends Error {}

    /** Runs a hook when the MAC first uses the key, after the charge and before the comparison. */
    private static final class ProbeKey extends SecretKeySpec {
        private final transient Runnable onUse;

        ProbeKey(Runnable onUse) {
            super(new byte[32], "HmacSHA256");
            this.onUse = onUse;
        }

        @Override
        public byte[] getEncoded() {
            // Null while the superclass is being constructed.
            if (onUse != null) {
                onUse.run();
            }
            return super.getEncoded();
        }
    }
}
