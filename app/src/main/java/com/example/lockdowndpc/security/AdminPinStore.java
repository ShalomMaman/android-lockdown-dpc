package com.example.lockdowndpc.security;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.SystemClock;
import android.provider.Settings;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import com.example.lockdowndpc.policy.ManagementMode;
import com.example.lockdowndpc.policy.ManagementModeStore;

import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.IdentityHashMap;
import java.util.Map;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Stores and verifies the administrator PIN and the one-time recovery code.
 *
 * <p>Throttling state is evaluated by {@link PinLockoutPolicy}, which measures an
 * active penalty with monotonic time so that changing the device clock cannot
 * shorten it. Every write that carries failed-attempt or recovery state is
 * committed synchronously: an asynchronous {@code apply()} can be lost if the
 * device reboots (or is rebooted deliberately) right after a failed attempt.
 */
public final class AdminPinStore {
    private static final String TAG = "AdminPinStore";
    private static final String PREFS = "admin_security";
    private static final String KEY_SALT = "pin_salt";
    private static final String KEY_VERIFIER = "pin_verifier";
    private static final String KEY_FAILURES = "pin_failures";
    /** Legacy wall-clock deadline; still written for downgrade compatibility. */
    private static final String KEY_LOCKOUT_UNTIL = "pin_lockout_until";
    private static final String KEY_LOCKOUT_BOOT_KIND = "pin_lockout_boot_kind";
    private static final String KEY_LOCKOUT_BOOT_VALUE = "pin_lockout_boot_value";
    private static final String KEY_LOCKOUT_ELAPSED_UNTIL = "pin_lockout_elapsed_until";
    private static final String KEY_LOCKOUT_PENALTY = "pin_lockout_penalty";
    private static final String KEY_RECOVERY_SALT = "recovery_salt";
    private static final String KEY_RECOVERY_VERIFIER = "recovery_verifier";
    private static final String KEY_RECOVERY_PIN_RESET_PENDING = "recovery_pin_reset_pending";
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "lockdown_admin_pin_hmac_v1";
    private static final int PBKDF2_ITERATIONS = 210_000;
    private static final int PIN_KEY_BITS = 256;
    // Guarded by AdminPinStore.class. A failed editor might also fail to update memory.
    private static final Map<SharedPreferences, PinLockoutPolicy.LockoutState> unpersistedLockouts =
            new IdentityHashMap<>();

    private AdminPinStore() {}

    public static boolean hasPin(Context context) {
        return hasPin(prefs(context));
    }

    private static boolean hasPin(SharedPreferences prefs) {
        return prefs.contains(KEY_SALT) && prefs.contains(KEY_VERIFIER);
    }

    public static synchronized boolean hasPendingRecoveryPinReset(Context context) {
        return hasPendingRecoveryPinReset(prefs(context));
    }

    private static boolean hasPendingRecoveryPinReset(SharedPreferences prefs) {
        return prefs.getBoolean(KEY_RECOVERY_PIN_RESET_PENDING, false);
    }

    /** Returns false if another setup has already stored a PIN. */
    public static synchronized boolean setInitialPin(Context context, String pin) {
        if (!ManagementModeStore.selectLocal(context)) {
            return false;
        }
        SharedPreferences prefs = prefs(context);
        return setInitialPin(prefs, () -> writePin(prefs, pin, AdminPinStore::getOrCreateHmacKey));
    }

    static synchronized boolean setInitialPin(SharedPreferences prefs, Runnable save) {
        if (hasPin(prefs)) {
            return false;
        }
        save.run();
        return true;
    }

    /** Returns false when there is no live administrator session. */
    public static synchronized boolean replacePin(Context context, String pin) {
        if (!AdminSession.isUnlocked()
                || ManagementModeStore.read(context) != ManagementMode.LOCAL_PIN) {
            return false;
        }
        SharedPreferences prefs = prefs(context);
        if (hasPendingRecoveryPinReset(prefs)) {
            return false;
        }
        writePin(prefs, pin, AdminPinStore::getOrCreateHmacKey);
        return true;
    }

    /** A consumed recovery code authorizes only the next PIN write. */
    public static boolean completeRecoveryPinReset(Context context, String pin) {
        return completeRecoveryPinReset(context, pin, AdminPinStore::getOrCreateHmacKey);
    }

    static synchronized boolean completeRecoveryPinReset(Context context, String pin, HmacKeySource keySource) {
        if (ManagementModeStore.read(context) != ManagementMode.LOCAL_PIN) {
            return false;
        }
        SharedPreferences prefs = prefs(context);
        if (!hasPendingRecoveryPinReset(prefs)) {
            return false;
        }
        writePin(prefs, pin, keySource);
        return true;
    }

    private static void writePin(SharedPreferences prefs, String pin, HmacKeySource keySource) {
        if (!isValidPin(pin)) {
            throw new IllegalArgumentException("pin-must-contain-6-to-12-digits");
        }
        boolean saved;
        try {
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            byte[] verifier = createVerifier(pin, salt, keySource.get());
            SharedPreferences.Editor editor = putLockout(
                    prefs.edit()
                            .putString(KEY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
                            .putString(KEY_VERIFIER, Base64.encodeToString(verifier, Base64.NO_WRAP))
                            .remove(KEY_RECOVERY_PIN_RESET_PENDING),
                    PinLockoutPolicy.LockoutState.CLEARED);
            saved = DurablePreferences.commit(prefs, editor, KEY_SALT, KEY_VERIFIER, KEY_RECOVERY_PIN_RESET_PENDING,
                    KEY_FAILURES, KEY_LOCKOUT_BOOT_KIND, KEY_LOCKOUT_BOOT_VALUE,
                    KEY_LOCKOUT_ELAPSED_UNTIL, KEY_LOCKOUT_PENALTY, KEY_LOCKOUT_UNTIL);
        } catch (Exception exception) {
            throw new SecurityException("admin-pin-save-failed", exception);
        }
        if (!saved) {
            throw new SecurityException("admin-pin-save-failed");
        }
        unpersistedLockouts.remove(prefs);
    }

    public static synchronized String rotateRecoveryCode(Context context) throws SecurityException {
        if (ManagementModeStore.read(context) != ManagementMode.LOCAL_PIN) {
            throw new SecurityException("recovery-code-mode-refused");
        }
        SharedPreferences prefs = prefs(context);
        if (hasPendingRecoveryPinReset(prefs)) {
            throw new SecurityException("recovery-pin-reset-pending");
        }
        try {
            SecureRandom random = new SecureRandom();
            StringBuilder code = new StringBuilder(12);
            for (int index = 0; index < 12; index++) {
                code.append(random.nextInt(10));
            }
            byte[] salt = new byte[16];
            random.nextBytes(salt);
            byte[] verifier = createVerifier(code.toString(), salt, getOrCreateHmacKey());
            if (!DurablePreferences.commit(prefs, prefs.edit()
                    .putString(KEY_RECOVERY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
                    .putString(KEY_RECOVERY_VERIFIER, Base64.encodeToString(verifier, Base64.NO_WRAP)),
                    KEY_RECOVERY_SALT, KEY_RECOVERY_VERIFIER)) {
                throw new SecurityException("recovery-code-save-failed");
            }
            return code.substring(0, 4) + "-" + code.substring(4, 8) + "-" + code.substring(8);
        } catch (Exception exception) {
            throw new SecurityException("recovery-code-create-failed", exception);
        }
    }

    public static Verification verify(Context context, String pin) {
        return verify(context, pin, AdminPinStore::getOrCreateHmacKey);
    }

    @FunctionalInterface
    interface HmacKeySource {
        SecretKey get() throws Exception;
    }

    static synchronized Verification verify(Context context, String pin, HmacKeySource keySource) {
        // Read again at authentication time so a failed legacy-mode migration
        // during startup is retried before the PIN is checked.
        ManagementMode mode = ManagementModeStore.read(context);
        if (!mode.usesLocalPolicy()) {
            return new Verification(Status.ERROR, 0L, false);
        }
        SharedPreferences prefs = prefs(context);
        if (!hasPin(prefs)) {
            return new Verification(Status.NOT_CONFIGURED, 0L, false);
        }

        if (mode != ManagementMode.LOCAL_PIN || hasPendingRecoveryPinReset(prefs)) {
            return new Verification(Status.ERROR, 0L, false);
        }
        PinLockoutPolicy.BootId boot = currentBootId(context);
        long elapsed = SystemClock.elapsedRealtime();
        long wall = System.currentTimeMillis();
        int failures = readFailureCount(prefs);
        PinLockoutPolicy.LockoutState stored = unpersistedLockouts.get(prefs);
        if (stored == null) {
            stored = readLockout(prefs, failures < 0 ? PinLockoutPolicy.FIRST_PENALTY_FAILURE : failures);
        }
        PinLockoutPolicy.Evaluation evaluation = PinLockoutPolicy.evaluate(stored, boot, elapsed, wall);
        if (failures < 0 && !evaluation.locked()) {
            evaluation = PinLockoutPolicy.lockUnreadableCounter(evaluation.state(), boot, elapsed, wall);
        }
        if (evaluation.locked()) {
            if (evaluation.persistRequired() || failures < 0) {
                persistTighterLockout(prefs, evaluation.state());
            }
            return new Verification(Status.LOCKED, evaluation.remainingMillis(), false);
        }

        try {
            SecretKey hmacKey = keySource.get();
            if (matches(pin, prefs.getString(KEY_SALT, ""),
                    prefs.getString(KEY_VERIFIER, ""), hmacKey)) {
                clearLockoutAfterMatch(prefs);
                return new Verification(Status.SUCCESS, 0L, false);
            }

            String recoverySalt = prefs.getString(KEY_RECOVERY_SALT, null);
            String recoveryVerifier = prefs.getString(KEY_RECOVERY_VERIFIER, null);
            String normalizedRecovery = pin == null ? "" : pin.replace("-", "").replace(" ", "");
            if (recoverySalt != null && recoveryVerifier != null
                    && matches(normalizedRecovery, recoverySalt, recoveryVerifier, hmacKey)) {
                return consumeMatchedRecoveryCode(prefs);
            }
        } catch (Exception exception) {
            return new Verification(Status.ERROR, 0L, false);
        }

        PinLockoutPolicy.LockoutState next = PinLockoutPolicy.afterFailure(
                evaluation.state(),
                boot,
                SystemClock.elapsedRealtime(),
                System.currentTimeMillis()
        );
        persistTighterLockout(prefs, next);
        long delay = next.penaltyMillis();
        return new Verification(delay == 0 ? Status.INVALID : Status.LOCKED, delay, false);
    }

    private static void clearLockoutAfterMatch(SharedPreferences prefs) {
        try {
            if (DurablePreferences.commit(prefs,
                    putLockout(prefs.edit(), PinLockoutPolicy.LockoutState.CLEARED), KEY_FAILURES,
                    KEY_LOCKOUT_BOOT_KIND, KEY_LOCKOUT_BOOT_VALUE, KEY_LOCKOUT_ELAPSED_UNTIL,
                    KEY_LOCKOUT_PENALTY, KEY_LOCKOUT_UNTIL)) {
                unpersistedLockouts.remove(prefs);
            } else {
                Log.w(TAG, "Could not persist lockout counter reset after a valid PIN");
            }
        } catch (RuntimeException exception) {
            Log.w(TAG, "Could not persist lockout counter reset after a valid PIN", exception);
        }
    }

    /** Consume the code and persist authorization for the PIN reset in one write. */
    static synchronized Verification consumeMatchedRecoveryCode(SharedPreferences prefs) {
        SharedPreferences.Editor editor = putLockout(
                prefs.edit()
                        .remove(KEY_RECOVERY_SALT)
                        .remove(KEY_RECOVERY_VERIFIER)
                        .putBoolean(KEY_RECOVERY_PIN_RESET_PENDING, true),
                PinLockoutPolicy.LockoutState.CLEARED);
        boolean consumed = DurablePreferences.commit(prefs, editor, KEY_RECOVERY_PIN_RESET_PENDING,
                KEY_RECOVERY_SALT, KEY_RECOVERY_VERIFIER, KEY_FAILURES, KEY_LOCKOUT_BOOT_KIND,
                KEY_LOCKOUT_BOOT_VALUE, KEY_LOCKOUT_ELAPSED_UNTIL, KEY_LOCKOUT_PENALTY, KEY_LOCKOUT_UNTIL);
        if (!consumed) {
            return new Verification(Status.ERROR, 0L, false);
        }
        AdminSession.lock();
        unpersistedLockouts.remove(prefs);
        return new Verification(Status.SUCCESS, 0L, true);
    }

    public static boolean isValidPin(String pin) {
        return pin != null && pin.matches("[0-9]{6,12}");
    }

    static byte[] createVerifier(String pin, byte[] salt, SecretKey hmacKey) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(pin.toCharArray(), salt, PBKDF2_ITERATIONS, PIN_KEY_BITS);
        byte[] derived;
        try {
            derived = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec)
                    .getEncoded();
        } finally {
            spec.clearPassword();
        }

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(hmacKey);
        mac.update(ByteBuffer.allocate(4).putInt(salt.length).array());
        mac.update(salt);
        try {
            return mac.doFinal(derived);
        } finally {
            Arrays.fill(derived, (byte) 0);
        }
    }

    private static boolean matches(
            String candidate,
            String encodedSalt,
            String encodedVerifier,
            SecretKey hmacKey
    ) throws Exception {
        byte[] salt = Base64.decode(encodedSalt, Base64.NO_WRAP);
        byte[] expected = Base64.decode(encodedVerifier, Base64.NO_WRAP);
        byte[] actual = createVerifier(candidate == null ? "" : candidate, salt, hmacKey);
        return MessageDigest.isEqual(expected, actual);
    }

    private static SecretKey getOrCreateHmacKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
        keyStore.load(null);
        if (keyStore.containsAlias(KEY_ALIAS)) {
            return (SecretKey) keyStore.getKey(KEY_ALIAS, null);
        }

        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, KEYSTORE);
        generator.init(new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
        ).setDigests(KeyProperties.DIGEST_SHA256).build());
        return generator.generateKey();
    }

    /**
     * Identifies the running boot. {@code BOOT_COUNT} is a secure setting that an
     * unprivileged local user cannot change. When it is unavailable the boot is
     * identified by the wall time it started at; a clock change then looks like a
     * reboot, which re-arms the penalty instead of shortening it.
     */
    private static PinLockoutPolicy.BootId currentBootId(Context context) {
        try {
            return PinLockoutPolicy.BootId.ofBootCount(
                    Settings.Global.getInt(context.getContentResolver(), Settings.Global.BOOT_COUNT)
            );
        } catch (Settings.SettingNotFoundException | RuntimeException unavailable) {
            return PinLockoutPolicy.BootId.ofBootWallTime(
                    System.currentTimeMillis() - SystemClock.elapsedRealtime()
            );
        }
    }

    private static PinLockoutPolicy.LockoutState readLockout(SharedPreferences prefs, int failures) {
        PinLockoutPolicy.BootKind kind = PinLockoutPolicy.BootKind.NONE;
        try {
            kind = PinLockoutPolicy.BootKind.valueOf(
                    prefs.getString(KEY_LOCKOUT_BOOT_KIND, PinLockoutPolicy.BootKind.NONE.name())
            );
        } catch (IllegalArgumentException | NullPointerException | ClassCastException unusable) {
            // Unreadable identity: treated as a different boot, which re-arms.
        }
        return new PinLockoutPolicy.LockoutState(
                failures,
                new PinLockoutPolicy.BootId(kind, readLong(prefs, KEY_LOCKOUT_BOOT_VALUE)),
                readLong(prefs, KEY_LOCKOUT_ELAPSED_UNTIL),
                readLong(prefs, KEY_LOCKOUT_PENALTY),
                readLong(prefs, KEY_LOCKOUT_UNTIL)
        );
    }

    private static void persistTighterLockout(SharedPreferences prefs, PinLockoutPolicy.LockoutState state) {
        // Android normally updates the in-memory map even when the disk write fails.
        // Never roll that tightening back. Keep the state here if the editor failed.
        try {
            if (putLockout(prefs.edit(), state).commit()) {
                unpersistedLockouts.remove(prefs);
                return;
            }
            Log.w(TAG, "Could not persist stricter PIN lockout");
        } catch (RuntimeException exception) {
            Log.w(TAG, "Could not persist stricter PIN lockout", exception);
        }
        unpersistedLockouts.put(prefs, state);
    }

    private static SharedPreferences.Editor putLockout(
            SharedPreferences.Editor editor,
            PinLockoutPolicy.LockoutState state
    ) {
        return editor
                .putInt(KEY_FAILURES, state.failures())
                .putString(KEY_LOCKOUT_BOOT_KIND, state.armedBoot().kind().name())
                .putLong(KEY_LOCKOUT_BOOT_VALUE, state.armedBoot().value())
                .putLong(KEY_LOCKOUT_ELAPSED_UNTIL, state.armedElapsedDeadline())
                .putLong(KEY_LOCKOUT_PENALTY, state.penaltyMillis())
                // Supplemental evidence only: read for migration from versions
                // that stored nothing else, and honoured by an older version if
                // this build is ever replaced by one.
                .putLong(KEY_LOCKOUT_UNTIL, state.wallDeadline());
    }

    private static int readFailureCount(SharedPreferences prefs) {
        try {
            return prefs.getInt(KEY_FAILURES, 0);
        } catch (RuntimeException unusable) {
            return -1;
        }
    }

    private static long readLong(SharedPreferences prefs, String key) {
        try {
            return prefs.getLong(key, 0L);
        } catch (ClassCastException unusable) {
            return 0L;
        }
    }

    private static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    public enum Status {
        SUCCESS,
        INVALID,
        LOCKED,
        NOT_CONFIGURED,
        ERROR
    }

    public record Verification(Status status, long remainingMillis, boolean usedRecoveryCode) {}
}
