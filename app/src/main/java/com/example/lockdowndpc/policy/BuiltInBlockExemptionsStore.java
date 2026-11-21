package com.example.lockdowndpc.policy;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Stored administrator exemptions from the built-in block catalogues, the last
 * home filter canary result they depend on, and the last read-back.
 *
 * <p>A separate preference file defaulting to "no exemptions", so a device that
 * never touches the feature, and a pilot upgraded into this build, behaves
 * exactly as before. Writes use {@code commit()} because a boot reconciliation
 * reads them before the process is guaranteed to survive. Nothing infers an
 * exemption: it is written only where an authenticated administrator confirmed
 * it, and a stored value that no longer validates is read as no exemption.
 */
public final class BuiltInBlockExemptionsStore {

    private static final String PREFS = "builtin_block_exemptions";
    private static final String KEY_BROWSER = "browser_package";
    private static final String KEY_SOCIAL = "social_packages";
    private static final String KEY_CHANGED_AT = "changed_at";
    private static final String KEY_CANARY_URL = "canary_url";
    private static final String KEY_CANARY_BODY = "canary_body";
    private static final String KEY_CANARY_PASSED = "canary_passed";
    private static final String KEY_CANARY_AT = "canary_at";
    private static final String KEY_READBACK_BROWSER_STATE = "readback_browser_state";
    private static final String KEY_READBACK_BROWSER_VISIBLE = "readback_browser_visible";
    private static final String KEY_READBACK_SOCIAL_VISIBLE = "readback_social_visible";
    private static final String KEY_READBACK_AT = "readback_at";

    private BuiltInBlockExemptionsStore() {}

    /** The stored decision; anything that no longer validates reads as none. */
    public static BuiltInBlockExemptions.Settings read(Context context) {
        SharedPreferences prefs = prefs(context);
        try {
            String browser = prefs.getString(KEY_BROWSER, null);
            Set<String> social = prefs.getStringSet(KEY_SOCIAL, Set.of());
            return new BuiltInBlockExemptions.Settings(browser, new LinkedHashSet<>(social));
        } catch (IllegalArgumentException | ClassCastException exception) {
            // Fail closed: a corrupt or out-of-catalogue value never loosens.
            return BuiltInBlockExemptions.Settings.NONE;
        }
    }

    /**
     * Records the decision and drops the read-back that described the previous
     * one, so the console never shows yesterday's confirmation for a choice that
     * has just changed. The caller owns authentication and the audit line.
     */
    public static synchronized void write(Context context, BuiltInBlockExemptions.Settings settings) {
        boolean saved = prefs(context).edit()
                .putString(KEY_BROWSER, settings.browserPackage())
                .putStringSet(KEY_SOCIAL, new LinkedHashSet<>(settings.socialExemptions()))
                .putLong(KEY_CHANGED_AT, System.currentTimeMillis())
                .remove(KEY_READBACK_BROWSER_STATE)
                .remove(KEY_READBACK_BROWSER_VISIBLE)
                .remove(KEY_READBACK_SOCIAL_VISIBLE)
                .remove(KEY_READBACK_AT)
                .commit();
        if (!saved) {
            throw new IllegalStateException("Could not persist built-in block exemptions");
        }
    }

    /**
     * Records the outcome of a canary check for exactly this canary.
     *
     * <p>The result counts only while the configured canary is the same one; a
     * changed URL or expected body is a different check that has not run.
     */
    public static void recordCanary(Context context, HomeFilterPolicy.Canary canary, boolean passed) {
        if (canary == null) {
            clearCanary(context);
            return;
        }
        prefs(context).edit()
                .putString(KEY_CANARY_URL, canary.url())
                .putString(KEY_CANARY_BODY, canary.expectedBody())
                .putBoolean(KEY_CANARY_PASSED, passed)
                .putLong(KEY_CANARY_AT, System.currentTimeMillis())
                .commit();
    }

    /** Whether the last recorded canary check is for {@code canary} and passed. */
    public static boolean canaryPassed(Context context, HomeFilterPolicy.Canary canary) {
        if (canary == null) {
            return false;
        }
        SharedPreferences prefs = prefs(context);
        try {
            return prefs.getBoolean(KEY_CANARY_PASSED, false)
                    && canary.url().equals(prefs.getString(KEY_CANARY_URL, null))
                    && canary.expectedBody().equals(prefs.getString(KEY_CANARY_BODY, null));
        } catch (ClassCastException exception) {
            return false;
        }
    }

    /** Drops any canary evidence, e.g. when the home filter settings change. */
    public static void clearCanary(Context context) {
        prefs(context).edit()
                .remove(KEY_CANARY_URL)
                .remove(KEY_CANARY_BODY)
                .remove(KEY_CANARY_PASSED)
                .remove(KEY_CANARY_AT)
                .commit();
    }

    /** What the last policy pass read back from Android. */
    public record Readback(
            BuiltInBlockExemptions.BrowserState browserState,
            boolean browserConfirmedAvailable,
            Set<String> socialConfirmedAvailable,
            long at
    ) {
        public Readback {
            socialConfirmedAvailable = Set.copyOf(socialConfirmedAvailable);
        }
    }

    static void saveReadback(
            Context context,
            BuiltInBlockExemptions.BrowserState browserState,
            boolean browserConfirmedAvailable,
            Set<String> socialConfirmedAvailable
    ) {
        prefs(context).edit()
                .putString(KEY_READBACK_BROWSER_STATE, browserState.name())
                .putBoolean(KEY_READBACK_BROWSER_VISIBLE, browserConfirmedAvailable)
                .putStringSet(KEY_READBACK_SOCIAL_VISIBLE, new LinkedHashSet<>(socialConfirmedAvailable))
                .putLong(KEY_READBACK_AT, System.currentTimeMillis())
                .apply();
    }

    /** The last read-back, or {@code null} when no pass has run since the last change. */
    public static Readback readback(Context context) {
        SharedPreferences prefs = prefs(context);
        try {
            String state = prefs.getString(KEY_READBACK_BROWSER_STATE, null);
            if (state == null) {
                return null;
            }
            return new Readback(
                    BuiltInBlockExemptions.BrowserState.valueOf(state),
                    prefs.getBoolean(KEY_READBACK_BROWSER_VISIBLE, false),
                    prefs.getStringSet(KEY_READBACK_SOCIAL_VISIBLE, Set.of()),
                    prefs.getLong(KEY_READBACK_AT, 0L));
        } catch (IllegalArgumentException | ClassCastException exception) {
            return null;
        }
    }

    private static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }
}
