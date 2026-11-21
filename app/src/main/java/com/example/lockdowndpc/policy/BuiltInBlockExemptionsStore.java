package com.example.lockdowndpc.policy;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.SystemClock;

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.function.BooleanSupplier;

/**
 * Stored exemptions from the built-in block catalogues, the last read-back and
 * the evidence a later pass needs to continue a verified one.
 *
 * <p>The decision and the read-back live in separate preference files: nothing
 * but {@link BuiltInExemptionsPersistence} ever commits the decision's file, so
 * a read-back commit can never make a failed decision durable. Every reader of
 * the decision — enforcement, kiosk eligibility, the teardown guard, the
 * console and the edit path — goes through {@link #record}, which parses with
 * {@link BuiltInBlockExemptions#parseRecord}, the one parser.
 */
public final class BuiltInBlockExemptionsStore {

    private static final String PREFS = "builtin_block_exemptions";
    private static final String READBACK_PREFS = "builtin_block_exemptions_readback";
    private static final String KEY_VERIFIED_FILTER = "verified_filter";
    private static final String KEY_VERIFIED_BOOT = "verified_boot";
    private static final String KEY_RELEASED_FILTER = "chrome_released_filter";
    private static final String KEY_RELEASED_BOOT = "chrome_released_boot";
    private static final String KEY_RELEASED_AT = "chrome_released_at";
    private static final String KEY_READBACK_FOR = "for";
    private static final String KEY_CHROME_DECISION = "chrome_decision";
    private static final String KEY_CHROME_OBSERVED = "chrome_observed";

    /** How long after its own Chrome release a pass counts as caused by that release. */
    static final long OWN_RELEASE_WINDOW_MS = 60_000L;

    private static volatile BuiltInExemptionsPersistence persistence;

    private BuiltInBlockExemptionsStore() {}

    /** The stored approval record, read by the one parser. */
    public static BuiltInBlockExemptions.Record record(Context context) {
        return persistence(context).record();
    }

    /** What a policy pass enforces: none while unreadable or while a failed write is unresolved. */
    public static BuiltInBlockExemptions.Settings read(Context context) {
        return persistence(context).read();
    }

    /** The stored decision as the baseline for an edit ({@code NONE} when unreadable; edits are refused then). */
    public static BuiltInBlockExemptions.Settings readForEdit(Context context) {
        return record(context).enforced();
    }

    /** The Chrome flag of the stored record: present, absent or unreadable. */
    public static BuiltInBlockExemptions.ChromeFlag chromeFlag(Context context) {
        return record(context).flag();
    }

    /** An earlier save failed and passes currently enforce no exemptions. */
    static boolean untrusted(Context context) {
        return persistence(context).untrusted();
    }

    /** Persists the decision. {@code false} means nothing changed. */
    static boolean write(Context context, BuiltInBlockExemptions.Settings settings) {
        return persistence(context).write(settings);
    }

    private static BuiltInExemptionsPersistence persistence(Context context) {
        BuiltInExemptionsPersistence current = persistence;
        if (current == null) {
            synchronized (BuiltInBlockExemptionsStore.class) {
                current = persistence;
                if (current == null) {
                    Context app = context.getApplicationContext();
                    java.io.File file = new java.io.File(app.getApplicationInfo().dataDir,
                            "shared_prefs/" + PREFS + ".xml");
                    current = persistenceFor(app.getSharedPreferences(PREFS, Context.MODE_PRIVATE), file::exists);
                    persistence = current;
                }
            }
        }
        return current;
    }

    /** The store's persistence over a given preference file, for the store tests. */
    static BuiltInExemptionsPersistence persistenceFor(SharedPreferences prefs, BooleanSupplier fileExists) {
        return new BuiltInExemptionsPersistence(new PreferencesBacking(prefs, fileExists));
    }

    private static final String[] RECORD_KEYS = {
            BuiltInBlockExemptions.KEY_CHROME,
            BuiltInBlockExemptions.KEY_SOCIAL_PINS,
            BuiltInBlockExemptions.KEY_FORMAT
    };

    private record PreferencesBacking(SharedPreferences prefs, BooleanSupplier fileExists)
            implements BuiltInExemptionsPersistence.Backing {

        @Override
        public BuiltInBlockExemptions.Record read() {
            return BuiltInBlockExemptions.parseRecord(prefs.getAll(), fileExists.getAsBoolean());
        }

        @Override
        public boolean commit(BuiltInBlockExemptions.Settings settings) {
            LinkedHashSet<String> pins = new LinkedHashSet<>();
            settings.socialPins().forEach((name, digest) -> pins.add(name + "=" + digest));
            return prefs.edit()
                    .putBoolean(BuiltInBlockExemptions.KEY_CHROME, settings.chrome())
                    .putStringSet(BuiltInBlockExemptions.KEY_SOCIAL_PINS, pins)
                    .putInt(BuiltInBlockExemptions.KEY_FORMAT, BuiltInBlockExemptions.FORMAT_VERSION)
                    .commit();
        }

        @Override
        public Object snapshot() {
            Map<String, ?> all = prefs.getAll();
            HashMap<String, Object> raw = new HashMap<>();
            for (String key : RECORD_KEYS) {
                if (all.containsKey(key)) {
                    Object value = all.get(key);
                    raw.put(key, value instanceof Set<?> set ? new LinkedHashSet<>(set) : value);
                }
            }
            return raw;
        }

        /** Exactly the prior raw values: nothing added, so an unreadable record stays unreadable. */
        @Override
        @SuppressWarnings("unchecked")
        public void restore(Object snapshot) {
            Map<String, Object> raw = (Map<String, Object>) snapshot;
            SharedPreferences.Editor editor = prefs.edit();
            for (String key : RECORD_KEYS) {
                Object value = raw.get(key);
                if (!raw.containsKey(key)) {
                    editor.remove(key);
                } else if (value instanceof Boolean flag) {
                    editor.putBoolean(key, flag);
                } else if (value instanceof String text) {
                    editor.putString(key, text);
                } else if (value instanceof Set<?> set) {
                    editor.putStringSet(key, (Set<String>) set);
                } else if (value instanceof Integer number) {
                    editor.putInt(key, number);
                } else if (value instanceof Long number) {
                    editor.putLong(key, number);
                } else if (value instanceof Float number) {
                    editor.putFloat(key, number);
                } else {
                    editor.remove(key);
                }
            }
            editor.commit();
        }
    }

    /**
     * What the last pass decided for Chrome and what Android reported then. The
     * console shows the decision as the reason for the last pass only; every
     * Android state it shows is read live. The observation is kept so the pass
     * can audit a change.
     */
    public record Readback(
            String forSettings,
            ChromeFilterExemption.Decision chromeDecision,
            BuiltInBlockExemptions.Observed chromeObserved
    ) {
        public boolean describes(BuiltInBlockExemptions.Settings settings) {
            return forSettings.equals(settings.auditText());
        }
    }

    static boolean saveReadback(Context context, Readback readback) {
        return saveReadback(readbackPrefs(context), readback);
    }

    static boolean saveReadback(SharedPreferences prefs, Readback readback) {
        return prefs.edit()
                .putString(KEY_READBACK_FOR, readback.forSettings())
                .putString(KEY_CHROME_DECISION, readback.chromeDecision().name())
                .putString(KEY_CHROME_OBSERVED, readback.chromeObserved().name())
                .commit();
    }

    /**
     * Records that a protected pass ended verified for these home filter
     * settings in this boot. A later pass continues it only when all of that
     * still holds; see {@link BuiltInBlockExemptions#continuesVerifiedPass}.
     */
    static void recordVerifiedPass(Context context, HomeFilterPolicy.Settings filter) {
        readbackPrefs(context).edit()
                .putString(KEY_VERIFIED_FILTER, BuiltInBlockExemptions.filterFingerprint(filter))
                .putLong(KEY_VERIFIED_BOOT, bootCount(context))
                .commit();
    }

    /**
     * Records that this pass itself showed Chrome, on confirmed filter
     * evidence. Showing a hidden package makes Android announce it as added,
     * which queues another pass; that pass is caused by this release and may
     * continue it (it still re-checks Chrome's signer and configuration).
     */
    static void recordChromeRelease(Context context, HomeFilterPolicy.Settings filter) {
        readbackPrefs(context).edit()
                .putString(KEY_RELEASED_FILTER, BuiltInBlockExemptions.filterFingerprint(filter))
                .putLong(KEY_RELEASED_BOOT, bootCount(context))
                .putLong(KEY_RELEASED_AT, SystemClock.elapsedRealtime())
                .commit();
    }

    /**
     * Whether the pass about to start continues the last verified one, or
     * follows this process's own Chrome release moments ago. Read before the
     * pass starts; the release record is used once.
     */
    static boolean continuesVerifiedPass(Context context, HomeFilterPolicy.Settings filter) {
        try {
            SharedPreferences prefs = readbackPrefs(context);
            String fingerprint = BuiltInBlockExemptions.filterFingerprint(filter);
            long boot = bootCount(context);
            boolean ownRelease = prefs.contains(KEY_RELEASED_AT)
                    && BuiltInBlockExemptions.continuesVerifiedPass(true,
                            prefs.getString(KEY_RELEASED_FILTER, null), fingerprint,
                            prefs.getLong(KEY_RELEASED_BOOT, -1L), boot)
                    && SystemClock.elapsedRealtime() - prefs.getLong(KEY_RELEASED_AT, Long.MIN_VALUE / 2)
                        < OWN_RELEASE_WINDOW_MS;
            prefs.edit().remove(KEY_RELEASED_FILTER).remove(KEY_RELEASED_BOOT).remove(KEY_RELEASED_AT).commit();
            return ownRelease || BuiltInBlockExemptions.continuesVerifiedPass(
                    AllowedAppsStore.isProtectionEnabled(context)
                            && AllowedAppsStore.getPolicyState(context) == AllowedAppsStore.PolicyState.ACTIVE,
                    prefs.getString(KEY_VERIFIED_FILTER, null),
                    fingerprint,
                    prefs.getLong(KEY_VERIFIED_BOOT, -1L),
                    boot);
        } catch (RuntimeException exception) {
            return false;
        }
    }

    /**
     * Removes all continuation evidence, durably. A pause does this before it
     * changes anything and refuses itself when the commit fails, so a later
     * pass can never continue a verified pass across a pause.
     */
    static boolean invalidateContinuation(Context context) {
        return invalidateContinuation(readbackPrefs(context));
    }

    static boolean invalidateContinuation(SharedPreferences prefs) {
        return prefs.edit()
                .remove(KEY_VERIFIED_FILTER)
                .remove(KEY_VERIFIED_BOOT)
                .remove(KEY_RELEASED_FILTER)
                .remove(KEY_RELEASED_BOOT)
                .remove(KEY_RELEASED_AT)
                .commit();
    }

    /** The device's boot count, or {@code -1} when it cannot be read (never a continuation). */
    private static long bootCount(Context context) {
        try {
            return android.provider.Settings.Global.getInt(
                    context.getContentResolver(), android.provider.Settings.Global.BOOT_COUNT, -1);
        } catch (RuntimeException exception) {
            return -1L;
        }
    }

    /** The last read-back, or {@code null} when none was recorded. */
    public static Readback readback(Context context) {
        return readback(readbackPrefs(context));
    }

    static Readback readback(SharedPreferences prefs) {
        try {
            String forSettings = prefs.getString(KEY_READBACK_FOR, null);
            String decision = prefs.getString(KEY_CHROME_DECISION, null);
            String observed = prefs.getString(KEY_CHROME_OBSERVED, null);
            if (forSettings == null || decision == null || observed == null) {
                return null;
            }
            return new Readback(
                    forSettings,
                    ChromeFilterExemption.Decision.valueOf(decision),
                    BuiltInBlockExemptions.Observed.valueOf(observed));
        } catch (IllegalArgumentException | ClassCastException exception) {
            return null;
        }
    }

    private static SharedPreferences readbackPrefs(Context context) {
        return context.getSharedPreferences(READBACK_PREFS, Context.MODE_PRIVATE);
    }
}
