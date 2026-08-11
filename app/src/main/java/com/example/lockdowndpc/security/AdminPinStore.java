package com.example.lockdowndpc.security;

import android.content.Context;
import android.content.SharedPreferences;
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

public final class AdminPinStore {
    private static final String PREFS = "admin_security";
    private static final String KEY_SALT = "pin_salt";
    private static final String KEY_VERIFIER = "pin_verifier";
    private static final String KEY_FAILURES = "pin_failures";
    private static final String KEY_LOCKOUT_UNTIL = "pin_lockout_until";
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
            prefs(context).edit()
                    .putString(KEY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP))
                    .putString(KEY_VERIFIER, Base64.encodeToString(verifier, Base64.NO_WRAP))
                    .putInt(KEY_FAILURES, 0)
                    .putLong(KEY_LOCKOUT_UNTIL, 0L)
                    .apply();
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
                    .apply();
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
        long remaining = prefs.getLong(KEY_LOCKOUT_UNTIL, 0L) - System.currentTimeMillis();
        if (remaining > 0) {
            return new Verification(Status.LOCKED, remaining, false);
        }

        try {
            SecretKey hmacKey = getOrCreateHmacKey();
            if (matches(pin, prefs.getString(KEY_SALT, ""),
                    prefs.getString(KEY_VERIFIER, ""), hmacKey)) {
                prefs.edit().putInt(KEY_FAILURES, 0).putLong(KEY_LOCKOUT_UNTIL, 0L).apply();
                return new Verification(Status.SUCCESS, 0L, false);
            }

            String recoverySalt = prefs.getString(KEY_RECOVERY_SALT, null);
            String recoveryVerifier = prefs.getString(KEY_RECOVERY_VERIFIER, null);
            String normalizedRecovery = pin == null ? "" : pin.replace("-", "").replace(" ", "");
            if (recoverySalt != null && recoveryVerifier != null
                    && matches(normalizedRecovery, recoverySalt, recoveryVerifier, hmacKey)) {
                prefs.edit()
                        .remove(KEY_RECOVERY_SALT)
                        .remove(KEY_RECOVERY_VERIFIER)
                        .putInt(KEY_FAILURES, 0)
                        .putLong(KEY_LOCKOUT_UNTIL, 0L)
                        .apply();
                return new Verification(Status.SUCCESS, 0L, true);
            }
        } catch (Exception exception) {
            return new Verification(Status.ERROR, 0L, false);
        }

        int failures = prefs.getInt(KEY_FAILURES, 0) + 1;
        long delay = lockoutDelayMillis(failures);
        long until = delay == 0 ? 0L : System.currentTimeMillis() + delay;
        prefs.edit().putInt(KEY_FAILURES, failures).putLong(KEY_LOCKOUT_UNTIL, until).apply();
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

    private static long lockoutDelayMillis(int failures) {
        if (failures < 5) {
            return 0L;
        }
        if (failures == 5) {
            return 60_000L;
        }
        if (failures == 6) {
            return 5 * 60_000L;
        }
        if (failures == 7) {
            return 30 * 60_000L;
        }
        return 60 * 60_000L;
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
