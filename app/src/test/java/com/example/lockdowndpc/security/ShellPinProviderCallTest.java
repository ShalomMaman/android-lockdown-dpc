package com.example.lockdowndpc.security;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.Process;
import android.provider.Settings;

import com.example.lockdowndpc.testing.MemoryPreferences;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowBinder;
import org.robolectric.shadows.ShadowSystemClock;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreSpi;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.time.Duration;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Map;
import java.util.Set;

import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/** Drives the real provider entry point, caller check and PIN store together. */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 32)
public class ShellPinProviderCallTest {
    private static final String PIN = "123456";
    private static final String WRONG_PIN = "000000";
    private static final String NEW_PIN = "654321";
    private static final int THRESHOLD = PinLockoutPolicy.FIRST_PENALTY_FAILURE;
    private static final String[] METHODS = {
            ShellPinProvider.METHOD_SET_INITIAL, ShellPinProvider.METHOD_VERIFY, ShellPinProvider.METHOD_REPLACE};
    private final Provider keystore = new TestKeyStoreProvider();
    private Context context;
    private SharedPreferences prefs;
    private ShellPinProvider provider;

    @Before
    public void attachProvider() {
        Security.addProvider(keystore);
        context = RuntimeEnvironment.getApplication();
        assertTrue(Settings.Global.putInt(context.getContentResolver(), Settings.Global.BOOT_COUNT, 1));
        prefs = context.getSharedPreferences("admin_security", Context.MODE_PRIVATE);
        provider = attached(context);
        ShadowBinder.setCallingUid(Process.SHELL_UID);
    }

    @After
    public void resetProcess() {
        Security.removeProvider(keystore.getName());
        ShadowBinder.reset();
        AdminPinStore.clearRecoveryGrant();
        AdminSession.lock();
    }

    @Test
    public void everyCallerExceptShellIsRefusedWithoutTouchingThePin() {
        setPin();
        var before = prefs.getAll();
        int[] refused = {Process.ROOT_UID, Process.SYSTEM_UID, Process.PHONE_UID, Process.myUid(),
                Process.FIRST_APPLICATION_UID, Process.SHELL_UID - 1, Process.SHELL_UID + 1,
                // The shell app id inside another Android user is a different UID.
                100_000 + Process.SHELL_UID, -1};
        for (int uid : refused) {
            ShadowBinder.setCallingUid(uid);
            for (String method : new String[]{METHODS[0], METHODS[1], METHODS[2], "unknown", null}) {
                for (Bundle extras : new Bundle[]{null, extras(PIN, NEW_PIN)}) {
                    Bundle result = provider.call(method, null, extras);
                    assertEquals("uid=" + uid, ShellPinProvider.STATUS_REFUSED_CALLER, status(result));
                    assertEquals(Set.of(ShellPinProvider.KEY_STATUS), result.keySet());
                }
            }
        }
        assertEquals(before, prefs.getAll());
    }

    @Test
    public void shellCanSetVerifyAndReplaceThePin() {
        assertEquals(ShellPinProvider.STATUS_NOT_CONFIGURED, status(verify(PIN)));

        Bundle set = setPin();
        assertNotNull(set.getString(ShellPinProvider.KEY_RECOVERY));
        assertEquals(ShellPinProvider.STATUS_PIN_EXISTS, status(call(METHODS[0], null, NEW_PIN)));
        assertEquals(ShellPinProvider.STATUS_MATCH, status(verify(PIN)));
        assertEquals(ShellPinProvider.STATUS_MISMATCH, status(verify(NEW_PIN)));

        Bundle replaced = call(METHODS[2], PIN, NEW_PIN);
        assertEquals(ShellPinProvider.STATUS_OK, status(replaced));
        assertNotNull(replaced.getString(ShellPinProvider.KEY_RECOVERY));
        assertEquals(ShellPinProvider.STATUS_MATCH, status(verify(NEW_PIN)));
        assertEquals(ShellPinProvider.STATUS_MISMATCH, status(verify(PIN)));
        assertFalse(AdminSession.isUnlocked());
    }

    @Test
    public void verifyAndReplaceShareOneLockout() {
        setPin();
        for (int failure = 1; failure < THRESHOLD; failure++) {
            Bundle result = failure % 2 == 0 ? verify(WRONG_PIN) : call(METHODS[2], WRONG_PIN, NEW_PIN);
            assertEquals(ShellPinProvider.STATUS_MISMATCH, status(result));
            assertEquals(failure, prefs.getInt("pin_failures", -1));
        }
        assertLocked(call(METHODS[2], WRONG_PIN, NEW_PIN));
        assertLocked(verify(PIN));
        assertLocked(call(METHODS[2], PIN, NEW_PIN));

        ShadowSystemClock.advanceBy(Duration.ofMillis(PinLockoutPolicy.penaltyMillis(THRESHOLD)));
        assertEquals(ShellPinProvider.STATUS_MATCH, status(verify(PIN)));
        assertEquals(0, prefs.getInt("pin_failures", -1));
    }

    @Test
    public void shellCannotUseTheRecoveryCode() {
        String recovery = setPin().getString(ShellPinProvider.KEY_RECOVERY);
        String verifier = prefs.getString("pin_verifier", null);
        assertEquals(ShellPinProvider.STATUS_MISMATCH, status(verify(recovery)));
        assertEquals(ShellPinProvider.STATUS_MISMATCH, status(call(METHODS[2], recovery, NEW_PIN)));
        assertNull(AdminPinStore.getRecoveryGrant(context));
        assertEquals(verifier, prefs.getString("pin_verifier", null));
    }

    @Test
    public void shellCannotReplaceWhileTheConsoleHoldsARecoveryGrant() {
        String recovery = setPin().getString(ShellPinProvider.KEY_RECOVERY);
        var grant = AdminPinStore.verify(context, recovery).recoveryGrant();
        assertNotNull(grant);
        assertError("verify-failed", call(METHODS[2], PIN, NEW_PIN));
        assertEquals(grant, AdminPinStore.getRecoveryGrant(context));
    }

    @Test
    public void shellIsRefusedOutsideLocalPinMode() {
        setPin();
        var before = prefs.getAll();
        assertTrue(context.getSharedPreferences("management_mode", Context.MODE_PRIVATE)
                .edit().putString("mode", "ENROLLING").commit());
        assertError("verify-failed", verify(PIN));
        assertError("verify-failed", call(METHODS[2], PIN, NEW_PIN));
        assertEquals(before, prefs.getAll());

        assertTrue(prefs.edit().clear().commit());
        assertEquals(ShellPinProvider.STATUS_REFUSED, status(call(METHODS[0], null, PIN)));
        assertEquals(Map.of(), prefs.getAll());
    }

    @Test
    public void unknownMethodsAreRefusedWithoutTouchingThePin() {
        setPin();
        var before = prefs.getAll();
        for (String method : new String[]{null, "", "reset", "VERIFY", "verify ", "x".repeat(100_000)}) {
            assertError("unknown-method", call(method, PIN, NEW_PIN));
        }
        assertEquals(before, prefs.getAll());
    }

    @Test
    public void missingArgumentsAreRefusedWithoutUsingAnAttempt() {
        Bundle wrongType = new Bundle();
        wrongType.putInt(ShellPinProvider.EXTRA_PIN, 123456);
        wrongType.putInt(ShellPinProvider.EXTRA_CURRENT, 123456);
        for (Bundle missing : new Bundle[]{null, new Bundle(), wrongType}) {
            assertEquals(ShellPinProvider.STATUS_INVALID_PIN, status(provider.call(METHODS[0], null, missing)));
        }
        assertFalse(AdminPinStore.hasPin(context));

        setPin();
        var before = prefs.getAll();
        for (Bundle missing : new Bundle[]{null, new Bundle(), wrongType}) {
            assertError("verify-failed", provider.call(METHODS[1], null, missing));
            assertEquals(ShellPinProvider.STATUS_INVALID_PIN, status(provider.call(METHODS[2], null, missing)));
        }
        // The PIN is an extra; the call argument is ignored.
        assertError("verify-failed", provider.call(METHODS[1], PIN, null));
        assertEquals(ShellPinProvider.STATUS_INVALID_PIN, status(call(METHODS[2], PIN, null)));
        assertError("verify-failed", call(METHODS[2], null, NEW_PIN));
        assertEquals(before, prefs.getAll());
    }

    @Test
    public void oversizedArgumentsAreRefusedAndAnOversizedGuessIsCharged() {
        String[] oversized = {"1234567890123", "1".repeat(100_000)};
        for (String pin : oversized) {
            assertEquals(ShellPinProvider.STATUS_INVALID_PIN, status(call(METHODS[0], null, pin)));
        }
        assertFalse(AdminPinStore.hasPin(context));

        setPin();
        String verifier = prefs.getString("pin_verifier", null);
        for (String pin : oversized) {
            assertEquals(ShellPinProvider.STATUS_INVALID_PIN, status(call(METHODS[2], PIN, pin)));
        }
        assertEquals(0, prefs.getInt("pin_failures", -1));

        int charged = 0;
        for (String pin : oversized) {
            assertEquals(ShellPinProvider.STATUS_MISMATCH, status(verify(pin)));
            assertEquals(++charged, prefs.getInt("pin_failures", -1));
            assertEquals(ShellPinProvider.STATUS_MISMATCH, status(call(METHODS[2], pin, NEW_PIN)));
            assertEquals(++charged, prefs.getInt("pin_failures", -1));
        }
        assertEquals(verifier, prefs.getString("pin_verifier", null));
    }

    @Test
    public void shellAttemptsAreRefusedWhenTheyCannotBeCharged() {
        setPin();
        MemoryPreferences failing = new MemoryPreferences(prefs.getAll());
        SharedPreferences store = failing.preferences();
        ShellPinProvider faulted = attached(new ContextWrapper(context) {
            @Override
            public Context getApplicationContext() {
                return this;
            }

            @Override
            public SharedPreferences getSharedPreferences(String name, int mode) {
                return "admin_security".equals(name) ? store : super.getSharedPreferences(name, mode);
            }
        });
        String verifier = store.getString("pin_verifier", null);
        assertError("verify-failed", faulted.call(METHODS[1], null, extras(null, PIN)));
        assertError("verify-failed", faulted.call(METHODS[2], null, extras(PIN, NEW_PIN)));
        assertEquals(verifier, store.getString("pin_verifier", null));

        failing.failCommit = false;
        assertEquals(ShellPinProvider.STATUS_MATCH,
                status(faulted.call(METHODS[1], null, extras(null, PIN))));
    }

    @Test
    public void anUnavailableKeystoreIsReportedWithoutUsingAnAttempt() {
        setPin();
        var before = prefs.getAll();
        Security.removeProvider(keystore.getName());
        assertError("verify-failed", verify(PIN));
        assertEquals(before, prefs.getAll());

        assertTrue(prefs.edit().clear().commit());
        assertError("admin-pin-save-failed", call(METHODS[0], null, PIN));
        assertFalse(AdminPinStore.hasPin(context));
    }

    @Test
    public void aProviderWithoutAContextIsRefused() {
        assertError("context-unavailable", new ShellPinProvider().call(METHODS[1], null, extras(null, PIN)));
    }

    private static ShellPinProvider attached(Context context) {
        ShellPinProvider provider = new ShellPinProvider();
        provider.attachInfo(context, null);
        return provider;
    }

    private Bundle setPin() {
        Bundle result = call(METHODS[0], null, PIN);
        assertEquals(ShellPinProvider.STATUS_OK, status(result));
        return result;
    }

    private Bundle verify(String pin) {
        return call(METHODS[1], null, pin);
    }

    private Bundle call(String method, String current, String pin) {
        return provider.call(method, null, extras(current, pin));
    }

    private static Bundle extras(String current, String pin) {
        Bundle extras = new Bundle();
        if (current != null) {
            extras.putString(ShellPinProvider.EXTRA_CURRENT, current);
        }
        if (pin != null) {
            extras.putString(ShellPinProvider.EXTRA_PIN, pin);
        }
        return extras;
    }

    private static String status(Bundle result) {
        return result.getString(ShellPinProvider.KEY_STATUS);
    }

    private static void assertError(String code, Bundle result) {
        assertEquals(ShellPinProvider.STATUS_ERROR, status(result));
        assertEquals(code, result.getString(ShellPinProvider.KEY_CODE));
        assertEquals(Set.of(ShellPinProvider.KEY_STATUS, ShellPinProvider.KEY_CODE), result.keySet());
    }

    private static void assertLocked(Bundle result) {
        assertEquals(ShellPinProvider.STATUS_LOCKED, status(result));
        assertEquals(PinLockoutPolicy.penaltyMillis(THRESHOLD),
                result.getLong(ShellPinProvider.KEY_REMAINING_MILLIS));
    }

    /** The JVM has no AndroidKeyStore; this one always holds a fixed test key. */
    public static final class TestKeyStoreProvider extends Provider {
        public TestKeyStoreProvider() {
            super("ShellPinProviderCallTest", "1", "Fixed HMAC key for tests");
            put("KeyStore.AndroidKeyStore", TestKeyStore.class.getName());
        }
    }

    public static final class TestKeyStore extends KeyStoreSpi {
        @Override
        public Key engineGetKey(String alias, char[] password) {
            return new SecretKeySpec(new byte[32], "HmacSHA256");
        }

        @Override
        public boolean engineContainsAlias(String alias) {
            return true;
        }

        @Override
        public void engineLoad(InputStream stream, char[] password) {}

        @Override
        public Certificate[] engineGetCertificateChain(String alias) {
            return null;
        }

        @Override
        public Certificate engineGetCertificate(String alias) {
            return null;
        }

        @Override
        public Date engineGetCreationDate(String alias) {
            return null;
        }

        @Override
        public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void engineSetCertificateEntry(String alias, Certificate certificate) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void engineDeleteEntry(String alias) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Enumeration<String> engineAliases() {
            return Collections.emptyEnumeration();
        }

        @Override
        public int engineSize() {
            return 1;
        }

        @Override
        public boolean engineIsKeyEntry(String alias) {
            return true;
        }

        @Override
        public boolean engineIsCertificateEntry(String alias) {
            return false;
        }

        @Override
        public String engineGetCertificateAlias(Certificate certificate) {
            return null;
        }

        @Override
        public void engineStore(OutputStream stream, char[] password) {
            throw new UnsupportedOperationException();
        }
    }
}
