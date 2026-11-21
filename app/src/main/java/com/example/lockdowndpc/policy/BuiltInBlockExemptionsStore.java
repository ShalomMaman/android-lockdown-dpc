package com.example.lockdowndpc.policy;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Stored exemptions from the built-in block catalogues and the last read-back.
 *
 * <p>A separate preference file defaulting to "no exemptions", so a device that
 * never touches the feature behaves exactly as before. Writes use
 * {@code commit()} and report its result: a write that did not persist is not
 * a change, and the caller shows an error instead of applying anything. A
 * stored value that no longer validates reads as no exemption.
 */
public final class BuiltInBlockExemptionsStore {

    private static final String PREFS = "builtin_block_exemptions";
    private static final String KEY_CHROME = "chrome";
    private static final String KEY_SOCIAL_PINS = "social_pins";
    private static final String KEY_READBACK_FOR = "readback_for";
    private static final String KEY_READBACK_CHROME = "readback_chrome_decision";
    private static final String KEY_READBACK_CHROME_VISIBLE = "readback_chrome_visible";
    private static final String KEY_READBACK_SOCIAL_VISIBLE = "readback_social_visible";
    private static final String KEY_READBACK_SOCIAL_MISMATCH = "readback_social_signer_mismatch";

    private BuiltInBlockExemptionsStore() {}

    /** The stored decision; anything that no longer validates reads as none. */
    public static BuiltInBlockExemptions.Settings read(Context context) {
        SharedPreferences prefs = prefs(context);
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

    /** Persists the decision in one commit. {@code false} means nothing changed. */
    static boolean write(Context context, BuiltInBlockExemptions.Settings settings) {
        LinkedHashSet<String> pins = new LinkedHashSet<>();
        settings.socialPins().forEach((name, digest) -> pins.add(name + "=" + digest));
        return prefs(context).edit()
                .putBoolean(KEY_CHROME, settings.chrome())
                .putStringSet(KEY_SOCIAL_PINS, pins)
                .commit();
    }

    /**
     * What the last pass read back from Android, and the decision text it was
     * computed for, so the console never presents it as evidence for a newer
     * decision.
     */
    public record Readback(
            String forSettings,
            ChromeFilterExemption.Decision chromeDecision,
            boolean chromeVisible,
            Set<String> socialVisible,
            Set<String> socialSignerMismatch
    ) {
        public Readback {
            socialVisible = Set.copyOf(socialVisible);
            socialSignerMismatch = Set.copyOf(socialSignerMismatch);
        }

        public boolean describes(BuiltInBlockExemptions.Settings settings) {
            return forSettings.equals(settings.auditText());
        }
    }

    static boolean saveReadback(Context context, Readback readback) {
        return prefs(context).edit()
                .putString(KEY_READBACK_FOR, readback.forSettings())
                .putString(KEY_READBACK_CHROME, readback.chromeDecision().name())
                .putBoolean(KEY_READBACK_CHROME_VISIBLE, readback.chromeVisible())
                .putStringSet(KEY_READBACK_SOCIAL_VISIBLE, new LinkedHashSet<>(readback.socialVisible()))
                .putStringSet(KEY_READBACK_SOCIAL_MISMATCH,
                        new LinkedHashSet<>(readback.socialSignerMismatch()))
                .commit();
    }

    /** The last read-back, or {@code null} when none was recorded. */
    public static Readback readback(Context context) {
        SharedPreferences prefs = prefs(context);
        try {
            String forSettings = prefs.getString(KEY_READBACK_FOR, null);
            String decision = prefs.getString(KEY_READBACK_CHROME, null);
            if (forSettings == null || decision == null) {
                return null;
            }
            return new Readback(
                    forSettings,
                    ChromeFilterExemption.Decision.valueOf(decision),
                    prefs.getBoolean(KEY_READBACK_CHROME_VISIBLE, false),
                    prefs.getStringSet(KEY_READBACK_SOCIAL_VISIBLE, Set.of()),
                    prefs.getStringSet(KEY_READBACK_SOCIAL_MISMATCH, Set.of()));
        } catch (IllegalArgumentException | ClassCastException exception) {
            return null;
        }
    }

    private static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }
}
