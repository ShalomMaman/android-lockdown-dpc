package com.example.lockdowndpc.security;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.SystemClock;
import android.provider.Settings;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.util.Xml;

import com.example.lockdowndpc.policy.ManagementMode;
import com.example.lockdowndpc.policy.ManagementModeStore;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.Set;

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
    public static final String PIN_FORMAT_ERROR = "pin-must-contain-6-to-12-digits";
    public static final String PIN_REUSE_ERROR = "pin-must-differ-from-previous-credentials";

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
    // Remove this key on write for devices that ran the unreleased reset flow.
    private static final String OBSOLETE_RESET_MARKER = "recovery_pin_reset_pending";
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String KEY_ALIAS = "lockdown_admin_pin_hmac_v1";
    private static final int PBKDF2_ITERATIONS = 210_000;
    private static final int PIN_KEY_BITS = 256;
    // Guarded by AdminPinStore.class. A failed editor might also fail to update memory.
    private static final Map<SharedPreferences, PinLockoutPolicy.LockoutState> unpersistedLockouts =
            new IdentityHashMap<>();
    private static final AdminPinStore PROCESS = new AdminPinStore();

    // Guarded by ManagementModeStore.class so a mode transition can revoke it
    // without acquiring AdminPinStore.class in the opposite order.
    private RecoveryGrant activeRecoveryGrant;

    AdminPinStore() {}

    public static boolean hasPin(Context context) {
        return hasPin(prefs(context));
    }

    private static boolean hasPin(SharedPreferences prefs) {
        return prefs.contains(KEY_SALT) && prefs.contains(KEY_VERIFIER);
    }

    public static synchronized RecoveryGrant getRecoveryGrant(Context context) {
        return PROCESS.liveRecoveryGrant(context);
    }

    public static synchronized long getRecoveryGrantRemainingMillis(Context context, RecoveryGrant grant) {
        if (grant == null || grant != PROCESS.liveRecoveryGrant(context)) {
            return 0L;
        }
        return grant.remainingMillis();
    }

    public static void clearRecoveryGrant() {
        synchronized (ManagementModeStore.class) {
            PROCESS.activeRecoveryGrant = null;
        }
    }

    private RecoveryGrant liveRecoveryGrant(Context context) {
        synchronized (ManagementModeStore.class) {
            if (activeRecoveryGrant == null) {
                return null;
            }
            if (ManagementModeStore.read(context) != ManagementMode.LOCAL_PIN
                    || activeRecoveryGrant.remainingMillis() == 0L) {
                activeRecoveryGrant = null;
                return null;
            }
            return activeRecoveryGrant.prefs == prefs(context) ? activeRecoveryGrant : null;
        }
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
        if (PROCESS.liveRecoveryGrant(context) != null) {
            return false;
        }
        writePin(prefs, pin, AdminPinStore::getOrCreateHmacKey);
        return true;
    }

    /**
     * Atomically verifies {@code current} through the normal lockout policy and,
     * on a plain PIN match (no recovery-code grant), writes {@code newPin}.
     */
    static synchronized ReplaceResult replaceWithCurrent(Context context, String current, String newPin) {
        return PROCESS.replaceWithCurrentLocked(context, current, newPin, AdminPinStore::getOrCreateHmacKey);
    }

    private ReplaceResult replaceWithCurrentLocked(
            Context context,
            String current,
            String newPin,
            HmacKeySource keySource
    ) {
        if (!isValidPin(newPin)) {
            throw new IllegalArgumentException(PIN_FORMAT_ERROR);
        }
        Verification verification = verifyLocked(context, current, keySource);
        if (verification.status() != Status.SUCCESS) {
            return new ReplaceResult(verification, false);
        }
        if (verification.recoveryGrant() != null) {
            clearRecoveryGrant();
            return new ReplaceResult(verification, false);
        }
        if (ManagementModeStore.read(context) != ManagementMode.LOCAL_PIN) {
            return new ReplaceResult(verification, false);
        }
        SharedPreferences prefs = prefs(context);
        if (!hasPin(prefs) || liveRecoveryGrant(context) != null) {
            return new ReplaceResult(verification, false);
        }
        writePin(prefs, newPin, keySource);
        return new ReplaceResult(verification, true);
    }

    /** Returns the new recovery code, or null when the grant can no longer authorize a reset. */
    public static String completeRecoveryPinReset(Context context, RecoveryGrant grant, String pin) {
        return PROCESS.completeRecoveryPinReset(context, grant, pin, AdminPinStore::getOrCreateHmacKey);
    }

    String completeRecoveryPinReset(Context context, RecoveryGrant grant, String pin, HmacKeySource keySource) {
        synchronized (AdminPinStore.class) {
            if (grant == null || grant != liveRecoveryGrant(context)) {
                return null;
            }
            SharedPreferences prefs = grant.prefs;
            if (!isValidPin(pin)) {
                throw new IllegalArgumentException(PIN_FORMAT_ERROR);
            }
            RecoveryCode recovery;
            Credential replacement;
            try {
                SecretKey key = keySource.get();
                if (matches(pin, prefs.getString(KEY_SALT, ""), prefs.getString(KEY_VERIFIER, ""), key)
                        || grant.recovery.matches(pin, key)) {
                    throw new IllegalArgumentException(PIN_REUSE_ERROR);
                }
                SecureRandom random = new SecureRandom();
                replacement = Credential.create(pin, key, random);
                recovery = newRecoveryCode(key, random, pin, grant.recovery);
                // Check after derivation and serialize the write with mode transitions.
                synchronized (ManagementModeStore.class) {
                    if (grant != liveRecoveryGrant(context)) {
                        return null;
                    }
                    SharedPreferences.Editor editor = putLockout(
                            recovery.credential.write(replacement.write(edit(prefs), KEY_SALT, KEY_VERIFIER),
                                    KEY_RECOVERY_SALT, KEY_RECOVERY_VERIFIER),
                            PinLockoutPolicy.LockoutState.CLEARED);
                    File file = new File(context.getDataDir(), "shared_prefs/" + PREFS + ".xml");
                    File backup = new File(file.getPath() + ".bak");
                    if (!DurablePreferences.commit(prefs, editor, committed -> committed
                                    ? removeRecoveryResetBackup(backup)
                                    : recoveryResetPersisted(file, backup, replacement, recovery.credential),
                            KEY_SALT, KEY_VERIFIER, KEY_RECOVERY_SALT, KEY_RECOVERY_VERIFIER,
                            KEY_FAILURES, KEY_LOCKOUT_BOOT_KIND, KEY_LOCKOUT_BOOT_VALUE,
                            KEY_LOCKOUT_ELAPSED_UNTIL, KEY_LOCKOUT_PENALTY, KEY_LOCKOUT_UNTIL,
                            OBSOLETE_RESET_MARKER)) {
                        throw new SecurityException("admin-pin-save-failed");
                    }
                    activeRecoveryGrant = null;
                }
            } catch (IllegalArgumentException invalidPin) {
                throw invalidPin;
            } catch (Exception exception) {
                throw new SecurityException("admin-pin-save-failed", exception);
            }
            unpersistedLockouts.remove(prefs);
            return recovery.formatted();
        }
    }

    private static void writePin(SharedPreferences prefs, String pin, HmacKeySource keySource) {
        if (!isValidPin(pin)) {
            throw new IllegalArgumentException(PIN_FORMAT_ERROR);
        }
        boolean saved;
        try {
            Credential credential = Credential.create(pin, keySource.get(), new SecureRandom());
            SharedPreferences.Editor editor = putLockout(
                    credential.write(edit(prefs), KEY_SALT, KEY_VERIFIER),
                    PinLockoutPolicy.LockoutState.CLEARED);
            saved = DurablePreferences.commit(prefs, editor, KEY_SALT, KEY_VERIFIER,
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
        if (PROCESS.liveRecoveryGrant(context) != null) {
            throw new SecurityException("recovery-pin-reset-pending");
        }
        try {
            RecoveryCode recovery = newRecoveryCode(getOrCreateHmacKey(), new SecureRandom(), null, null);
            if (!DurablePreferences.commit(prefs,
                    recovery.credential.write(edit(prefs), KEY_RECOVERY_SALT, KEY_RECOVERY_VERIFIER),
                    KEY_RECOVERY_SALT, KEY_RECOVERY_VERIFIER)) {
                throw new SecurityException("recovery-code-save-failed");
            }
            return recovery.formatted();
        } catch (Exception exception) {
            throw new SecurityException("recovery-code-create-failed", exception);
        }
    }

    public static Verification verify(Context context, String pin) {
        return verify(context, pin, AdminPinStore::getOrCreateHmacKey);
    }

    static Verification verify(Context context, String pin, HmacKeySource keySource) {
        return PROCESS.verifyCredential(context, pin, keySource);
    }

    @FunctionalInterface
    interface HmacKeySource {
        SecretKey get() throws Exception;
    }

    Verification verifyCredential(Context context, String pin, HmacKeySource keySource) {
        synchronized (AdminPinStore.class) {
            return verifyLocked(context, pin, keySource);
        }
    }

    private Verification verifyLocked(Context context, String pin, HmacKeySource keySource) {
        // Read again at authentication time so a failed legacy-mode migration
        // during startup is retried before the PIN is checked.
        ManagementMode mode = ManagementModeStore.read(context);
        if (!mode.usesLocalPolicy()) {
            return new Verification(Status.ERROR, 0L, null);
        }
        SharedPreferences prefs = prefs(context);
        if (!hasPin(prefs)) {
            return new Verification(Status.NOT_CONFIGURED, 0L, null);
        }

        if (mode != ManagementMode.LOCAL_PIN || liveRecoveryGrant(context) != null) {
            return new Verification(Status.ERROR, 0L, null);
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
            return new Verification(Status.LOCKED, evaluation.remainingMillis(), null);
        }

        try {
            SecretKey hmacKey = keySource.get();
            if (matches(pin, prefs.getString(KEY_SALT, ""),
                    prefs.getString(KEY_VERIFIER, ""), hmacKey)) {
                clearLockoutAfterMatch(prefs);
                return new Verification(Status.SUCCESS, 0L, null);
            }

            String recoverySalt = prefs.getString(KEY_RECOVERY_SALT, null);
            String recoveryVerifier = prefs.getString(KEY_RECOVERY_VERIFIER, null);
            String normalizedRecovery = pin == null ? "" : pin.replace("-", "").replace(" ", "");
            if (recoverySalt != null && recoveryVerifier != null
                    && matches(normalizedRecovery, recoverySalt, recoveryVerifier, hmacKey)) {
                synchronized (ManagementModeStore.class) {
                    if (ManagementModeStore.read(context) != ManagementMode.LOCAL_PIN) {
                        return new Verification(Status.ERROR, 0L, null);
                    }
                    AdminSession.lock();
                    activeRecoveryGrant = new RecoveryGrant(prefs, new Credential(recoverySalt, recoveryVerifier));
                    return new Verification(Status.SUCCESS, 0L, activeRecoveryGrant);
                }
            }
        } catch (Exception exception) {
            return new Verification(Status.ERROR, 0L, null);
        }

        PinLockoutPolicy.LockoutState next = PinLockoutPolicy.afterFailure(
                evaluation.state(),
                boot,
                SystemClock.elapsedRealtime(),
                System.currentTimeMillis()
        );
        persistTighterLockout(prefs, next);
        long delay = next.penaltyMillis();
        return new Verification(delay == 0 ? Status.INVALID : Status.LOCKED, delay, null);
    }

    private static void clearLockoutAfterMatch(SharedPreferences prefs) {
        try {
            if (DurablePreferences.commit(prefs,
                    putLockout(edit(prefs), PinLockoutPolicy.LockoutState.CLEARED), KEY_FAILURES,
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
            if (putLockout(edit(prefs), state).commit()) {
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

    private static SharedPreferences.Editor edit(SharedPreferences prefs) {
        return prefs.edit().remove(OBSOLETE_RESET_MARKER);
    }

    private static RecoveryCode newRecoveryCode(SecretKey key, SecureRandom random, String pin, Credential previous)
            throws Exception {
        String code;
        do {
            StringBuilder digits = new StringBuilder(12);
            for (int index = 0; index < 12; index++) {
                digits.append(random.nextInt(10));
            }
            code = digits.toString();
        } while (code.equals(pin) || (previous != null && previous.matches(code, key)));
        return new RecoveryCode(code, Credential.create(code, key, random));
    }

    private static boolean removeRecoveryResetBackup(File backup) {
        try {
            // Android may leave the backup behind even when commit returns true.
            Files.deleteIfExists(backup.toPath());
        } catch (IOException ignored) {
            // The reset only succeeds if the backup is confirmed absent below.
        }
        return Files.notExists(backup.toPath());
    }

    /**
     * SharedPreferences exposes the new values in memory even on a failed disk write.
     * On an ambiguous result check the credential pairs actually persisted to disk.
     * Android restores the backup on load if it is still present.
     */
    private static boolean recoveryResetPersisted(File file, File backup, Credential pin, Credential recovery) {
        if (!Files.notExists(backup.toPath())) {
            return false;
        }
        Map<String, String> expected = Map.of(
                KEY_SALT, pin.salt, KEY_VERIFIER, pin.verifier,
                KEY_RECOVERY_SALT, recovery.salt, KEY_RECOVERY_VERIFIER, recovery.verifier);
        Set<String> verified = new HashSet<>();
        try (FileInputStream input = new FileInputStream(file)) {
            XmlPullParser parser = Xml.newPullParser();
            parser.setInput(input, null);
            for (int event = parser.next(); event != XmlPullParser.END_DOCUMENT; event = parser.next()) {
                if (event == XmlPullParser.START_TAG && parser.getDepth() == 2) {
                    String name = parser.getAttributeValue(null, "name");
                    String value = name == null ? null : expected.get(name);
                    if (value != null && (!verified.add(name) || !"string".equals(parser.getName())
                            || !value.equals(parser.nextText()))) {
                        return false;
                    }
                }
            }
            return verified.size() == expected.size() && Files.notExists(backup.toPath());
        } catch (IOException | XmlPullParserException unreadable) {
            return false;
        }
    }

    private record Credential(String salt, String verifier) {
        static Credential create(String value, SecretKey key, SecureRandom random) throws Exception {
            byte[] salt = new byte[16];
            random.nextBytes(salt);
            return new Credential(Base64.encodeToString(salt, Base64.NO_WRAP),
                    Base64.encodeToString(createVerifier(value, salt, key), Base64.NO_WRAP));
        }

        boolean matches(String value, SecretKey key) throws Exception {
            return AdminPinStore.matches(value, salt, verifier, key);
        }

        SharedPreferences.Editor write(SharedPreferences.Editor editor, String saltKey, String verifierKey) {
            return editor.putString(saltKey, salt).putString(verifierKey, verifier);
        }
    }

    private record RecoveryCode(String digits, Credential credential) {
        String formatted() {
            return digits.substring(0, 4) + "-" + digits.substring(4, 8) + "-" + digits.substring(8);
        }
    }

    public static final class RecoveryGrant {
        private final SharedPreferences prefs;
        private final Credential recovery;
        private final long issuedAt;

        private RecoveryGrant(SharedPreferences prefs, Credential recovery) {
            this(prefs, recovery, SystemClock.elapsedRealtime());
        }

        private RecoveryGrant(SharedPreferences prefs, Credential recovery, long issuedAt) {
            this.prefs = prefs;
            this.recovery = recovery;
            this.issuedAt = issuedAt;
        }

        static RecoveryGrant forTest() {
            return new RecoveryGrant(null, null, 0L);
        }

        private long remainingMillis() {
            long elapsed = SystemClock.elapsedRealtime() - issuedAt;
            return elapsed < 0L ? 0L : Math.max(0L, AdminSession.SESSION_MILLIS - elapsed);
        }
    }

    public enum Status {
        SUCCESS,
        INVALID,
        LOCKED,
        NOT_CONFIGURED,
        ERROR
    }

    public record Verification(Status status, long remainingMillis, RecoveryGrant recoveryGrant) {}

    record ReplaceResult(Verification verification, boolean replaced) {}
}
