package com.example.lockdowndpc.security;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.SystemClock;
import android.provider.Settings;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

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
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "lockdown_admin_pin_hmac_v1";
    private static final int PBKDF2_ITERATIONS = 210_000;
    private static final int PIN_KEY_BITS = 256;

    private AdminPinStore() {}

    public static boolean hasPin(Context context) {
        SharedPreferences prefs = prefs(context);
        return prefs.contains(KEY_SALT) && prefs.contains(KEY_VERIFIER);
    }

    public static void setNewPin(Context context, String pin) throws SecurityException {
        if (!isValidPin(pin)) {
            throw new IllegalArgumentException("הקוד חייב להכיל 6 עד 12 ספרות");
        }
        try {
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);
            byte[] verifier = createVerifier(pin, salt, getOrCreateHmacKey());
            putLockout(
                    prefs(context).edit()
                            .putString(KEY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
                            .putString(KEY_VERIFIER, Base64.encodeToString(verifier, Base64.NO_WRAP)),
                    PinLockoutPolicy.LockoutState.CLEARED
            ).commit();
        } catch (Exception exception) {
            throw new SecurityException("לא ניתן לשמור את קוד המנהל", exception);
        }
    }

    public static String rotateRecoveryCode(Context context) throws SecurityException {
        try {
            SecureRandom random = new SecureRandom();
            StringBuilder code = new StringBuilder(12);
            for (int index = 0; index < 12; index++) {
                code.append(random.nextInt(10));
            }
            byte[] salt = new byte[16];
            random.nextBytes(salt);
            byte[] verifier = createVerifier(code.toString(), salt, getOrCreateHmacKey());
            prefs(context).edit()
                    .putString(KEY_RECOVERY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
                    .putString(KEY_RECOVERY_VERIFIER, Base64.encodeToString(verifier, Base64.NO_WRAP))
                    .commit();
            return code.substring(0, 4) + "-" + code.substring(4, 8) + "-" + code.substring(8);
        } catch (Exception exception) {
            throw new SecurityException("לא ניתן ליצור קוד שחזור", exception);
        }
    }

    public static Verification verify(Context context, String pin) {
        if (!hasPin(context)) {
            return new Verification(Status.NOT_CONFIGURED, 0L, false);
        }

        SharedPreferences prefs = prefs(context);
        PinLockoutPolicy.BootId boot = currentBootId(context);
        PinLockoutPolicy.Evaluation evaluation = PinLockoutPolicy.evaluate(
                readLockout(prefs),
                boot,
                SystemClock.elapsedRealtime(),
                System.currentTimeMillis()
        );
        if (evaluation.persistRequired()) {
            // Re-armed, migrated or served: record it before the attempt is judged.
            putLockout(prefs.edit(), evaluation.state()).commit();
        }
        if (evaluation.locked()) {
            return new Verification(Status.LOCKED, evaluation.remainingMillis(), false);
        }

        try {
            SecretKey hmacKey = getOrCreateHmacKey();
            if (matches(pin, prefs.getString(KEY_SALT, ""),
                    prefs.getString(KEY_VERIFIER, ""), hmacKey)) {
                putLockout(prefs.edit(), PinLockoutPolicy.LockoutState.CLEARED).commit();
                return new Verification(Status.SUCCESS, 0L, false);
            }

            String recoverySalt = prefs.getString(KEY_RECOVERY_SALT, null);
            String recoveryVerifier = prefs.getString(KEY_RECOVERY_VERIFIER, null);
            String normalizedRecovery = pin == null ? "" : pin.replace("-", "").replace(" ", "");
            if (recoverySalt != null && recoveryVerifier != null
                    && matches(normalizedRecovery, recoverySalt, recoveryVerifier, hmacKey)) {
                putLockout(
                        prefs.edit()
                                .remove(KEY_RECOVERY_SALT)
                                .remove(KEY_RECOVERY_VERIFIER),
                        PinLockoutPolicy.LockoutState.CLEARED
                ).commit();
                return new Verification(Status.SUCCESS, 0L, true);
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
        putLockout(prefs.edit(), next).commit();
        long delay = next.penaltyMillis();
        return new Verification(delay == 0 ? Status.INVALID : Status.LOCKED, delay, false);
    }

    public static boolean isValidPin(String pin) {
        return pin != null && pin.matches("[0-9]{6,12}");
    }

    private static byte[] createVerifier(String pin, byte[] salt, SecretKey hmacKey) throws Exception {
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

    private static PinLockoutPolicy.LockoutState readLockout(SharedPreferences prefs) {
        PinLockoutPolicy.BootKind kind = PinLockoutPolicy.BootKind.NONE;
        try {
            kind = PinLockoutPolicy.BootKind.valueOf(
                    prefs.getString(KEY_LOCKOUT_BOOT_KIND, PinLockoutPolicy.BootKind.NONE.name())
            );
        } catch (IllegalArgumentException | NullPointerException | ClassCastException unusable) {
            // Unreadable identity: treated as a different boot, which re-arms.
        }
        return new PinLockoutPolicy.LockoutState(
                readInt(prefs, KEY_FAILURES),
                new PinLockoutPolicy.BootId(kind, readLong(prefs, KEY_LOCKOUT_BOOT_VALUE)),
                readLong(prefs, KEY_LOCKOUT_ELAPSED_UNTIL),
                readLong(prefs, KEY_LOCKOUT_PENALTY),
                readLong(prefs, KEY_LOCKOUT_UNTIL)
        );
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

    private static int readInt(SharedPreferences prefs, String key) {
        try {
            return prefs.getInt(key, 0);
        } catch (ClassCastException unusable) {
            return 0;
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
