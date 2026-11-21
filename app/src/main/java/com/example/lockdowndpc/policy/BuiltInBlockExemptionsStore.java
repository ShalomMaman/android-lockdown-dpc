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
            return BuiltInBlockExemptions.chromeFlag(raw.get(KEY_CHROME), raw.get(KEY_SOCIAL_PINS));
        } catch (RuntimeException exception) {
            return BuiltInBlockExemptions.ChromeFlag.UNREADABLE;
        }
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
        public boolean commit(BuiltInBlockExemptions.Settings settings) {
            LinkedHashSet<String> pins = new LinkedHashSet<>();
            settings.socialPins().forEach((name, digest) -> pins.add(name + "=" + digest));
            return prefs.edit()
                    .putBoolean(KEY_CHROME, settings.chrome())
                    .putStringSet(KEY_SOCIAL_PINS, pins)
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
