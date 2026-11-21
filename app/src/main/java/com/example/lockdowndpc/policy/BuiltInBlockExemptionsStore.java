package com.example.lockdowndpc.policy;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Stored exemptions from the built-in block catalogues, and the last read-back.
 *
 * <p>The decision and the read-back live in separate preference files: nothing
 * but {@link BuiltInExemptionsPersistence} ever commits the decision's file, so
 * a read-back commit can never make a failed decision durable. The decision
 * defaults to "no exemptions", so a device that never touches the feature
 * behaves exactly as before; a stored value that no longer validates reads as
 * no exemption.
 */
public final class BuiltInBlockExemptionsStore {

    private static final String PREFS = "builtin_block_exemptions";
    private static final String READBACK_PREFS = "builtin_block_exemptions_readback";
    private static final String KEY_CHROME = "chrome";
    private static final String KEY_SOCIAL_PINS = "social_pins";
    private static final String KEY_FORMAT = "format";
    private static final String KEY_VERIFIED_FILTER = "verified_filter";
    private static final String KEY_VERIFIED_BOOT = "verified_boot";
    private static final String KEY_READBACK_FOR = "for";
    private static final String KEY_CHROME_DECISION = "chrome_decision";
    private static final String KEY_CHROME_OBSERVED = "chrome_observed";

    private static volatile BuiltInExemptionsPersistence persistence;

    private BuiltInBlockExemptionsStore() {}

    /** The decision a policy pass enforces; none while a failed write is unresolved. */
    public static BuiltInBlockExemptions.Settings read(Context context) {
        return persistence(context).read();
    }

    /** The last durable decision, the baseline for an administrator's next edit. */
    public static BuiltInBlockExemptions.Settings readForEdit(Context context) {
        return persistence(context).readForEdit();
    }

    /**
     * The stored Chrome flag read on its own from the raw record, for the home
     * filter teardown guard. A malformed record is {@code UNREADABLE}, never
     * "absent".
     */
    public static BuiltInBlockExemptions.ChromeFlag chromeFlag(Context context) {
        try {
            java.util.Map<String, ?> raw = context.getApplicationContext()
                    .getSharedPreferences(PREFS, Context.MODE_PRIVATE).getAll();
            return BuiltInBlockExemptions.chromeFlag(raw.get(KEY_CHROME), raw.get(KEY_SOCIAL_PINS),
                    raw.get(KEY_FORMAT), fileHasContent(context));
        } catch (RuntimeException exception) {
            return BuiltInBlockExemptions.ChromeFlag.UNREADABLE;
        }
    }

    /**
     * Whether the decision's preference file exists on disk with content. A
     * damaged file Android loads as an empty map still exists, so a missing
     * format marker then means "unreadable", not "nothing saved".
     */
    private static boolean fileHasContent(Context context) {
        java.io.File file = new java.io.File(context.getApplicationInfo().dataDir,
                "shared_prefs/" + PREFS + ".xml");
        return file.isFile() && file.length() > 0;
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
                    SharedPreferences prefs = context.getApplicationContext()
                            .getSharedPreferences(PREFS, Context.MODE_PRIVATE);
                    current = new BuiltInExemptionsPersistence(new PreferencesBacking(prefs));
                    persistence = current;
                }
            }
        }
        return current;
    }

    private record PreferencesBacking(SharedPreferences prefs)
            implements BuiltInExemptionsPersistence.Backing {

        @Override
        public BuiltInBlockExemptions.Settings read() {
            try {
                LinkedHashMap<String, String> pins = new LinkedHashMap<>();
                for (String entry : prefs.getStringSet(KEY_SOCIAL_PINS, Set.of())) {
                    int split = entry.indexOf('=');
                    if (split <= 0) {
                        return BuiltInBlockExemptions.Settings.NONE;
                    }
                    pins.put(entry.substring(0, split), entry.substring(split + 1));
                }
                return new BuiltInBlockExemptions.Settings(prefs.getBoolean(KEY_CHROME, false), pins);
            } catch (IllegalArgumentException | ClassCastException exception) {
                return BuiltInBlockExemptions.Settings.NONE;
            }
        }

        @Override
        public Object snapshot() {
            java.util.Map<String, ?> all = prefs.getAll();
            java.util.HashMap<String, Object> raw = new java.util.HashMap<>();
            for (String key : new String[]{KEY_CHROME, KEY_SOCIAL_PINS, KEY_FORMAT}) {
                if (all.containsKey(key)) {
                    Object value = all.get(key);
                    raw.put(key, value instanceof Set<?> set ? new LinkedHashSet<>(set) : value);
                }
            }
            return raw;
        }

        @Override
        @SuppressWarnings("unchecked")
        public void restore(Object snapshot) {
            java.util.Map<String, Object> raw = new java.util.HashMap<>((java.util.Map<String, Object>) snapshot);
            if (raw.isEmpty()) {
                // Nothing was saved before: restore "nothing saved" with the
                // marker, so the file this restore creates is not read as damage.
                raw.put(KEY_FORMAT, BuiltInBlockExemptions.FORMAT_VERSION);
            }
            SharedPreferences.Editor editor = prefs.edit();
            for (String key : new String[]{KEY_CHROME, KEY_SOCIAL_PINS, KEY_FORMAT}) {
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

        @Override
        public boolean commit(BuiltInBlockExemptions.Settings settings) {
            LinkedHashSet<String> pins = new LinkedHashSet<>();
            settings.socialPins().forEach((name, digest) -> pins.add(name + "=" + digest));
            return prefs.edit()
                    .putBoolean(KEY_CHROME, settings.chrome())
                    .putStringSet(KEY_SOCIAL_PINS, pins)
                    .putInt(KEY_FORMAT, BuiltInBlockExemptions.FORMAT_VERSION)
                    .commit();
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

    /** Whether the pass about to start continues the last verified one. Read before it starts. */
    static boolean continuesVerifiedPass(Context context, HomeFilterPolicy.Settings filter) {
        try {
            SharedPreferences prefs = readbackPrefs(context);
            return BuiltInBlockExemptions.continuesVerifiedPass(
                    AllowedAppsStore.isProtectionEnabled(context)
                            && AllowedAppsStore.getPolicyState(context) == AllowedAppsStore.PolicyState.ACTIVE,
                    prefs.getString(KEY_VERIFIED_FILTER, null),
                    BuiltInBlockExemptions.filterFingerprint(filter),
                    prefs.getLong(KEY_VERIFIED_BOOT, -1L),
                    bootCount(context));
        } catch (RuntimeException exception) {
            return false;
        }
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
