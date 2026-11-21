package com.example.lockdowndpc.policy;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Stored exemptions from the built-in block catalogues, the durable Chrome
 * grant ledger, pending revocations, the change awaiting its audited outcome,
 * and the last read-back.
 *
 * <p>A separate preference file defaulting to "no exemptions", so a device that
 * never touches the feature behaves exactly as before. Every write that a
 * later pass depends on uses {@code commit()}: a boot reconciliation reads it
 * before the process is guaranteed to survive. A stored value that no longer
 * validates is read as no exemption.
 */
@SuppressLint("ApplySharedPref")
public final class BuiltInBlockExemptionsStore {

    private static final String PREFS = "builtin_block_exemptions";
    private static final String KEY_CHROME = "chrome_through_filter";
    private static final String KEY_SOCIAL_PINS = "social_pins";
    private static final String KEY_CHROME_GRANTED = "chrome_granted";
    private static final String KEY_CHROME_REVOCATION_PENDING = "chrome_revocation_pending";
    private static final String KEY_SOCIAL_REVOCATIONS = "social_revocations_pending";
    private static final String KEY_PENDING_CHANGE = "pending_change";
    private static final String KEY_READBACK_CHROME_STATE = "readback_chrome_state";
    private static final String KEY_READBACK_CHROME_AVAILABLE = "readback_chrome_available";
    private static final String KEY_READBACK_SOCIAL_AVAILABLE = "readback_social_available";
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

    /**
     * Records an accepted change in one commit: the new decision, every
     * revocation it implies as pending, and the change record whose audited
     * outcome a policy pass writes. The caller owns authorization.
     *
     * @return the change ID
     */
    static synchronized String writeChange(
            Context context,
            BuiltInBlockExemptions.Settings before,
            BuiltInBlockExemptions.Settings after,
            String trigger
    ) {
        String changeId = UUID.randomUUID().toString().substring(0, 8);
        Set<String> revoked = before.revokedBy(after);
        LinkedHashSet<String> socialRevocations = new LinkedHashSet<>(socialRevocationsPending(context));
        for (String packageName : revoked) {
            if (!BuiltInBlockExemptions.CHROME.equals(packageName)) {
                socialRevocations.add(packageName);
            }
        }
        socialRevocations.removeAll(after.socialPins().keySet());
        LinkedHashSet<String> pins = new LinkedHashSet<>();
        after.socialPins().forEach((name, digest) -> pins.add(name + "=" + digest));
        SharedPreferences.Editor editor = prefs(context).edit()
                .putBoolean(KEY_CHROME, after.chromeThroughFilter())
                .putStringSet(KEY_SOCIAL_PINS, pins)
                .putStringSet(KEY_SOCIAL_REVOCATIONS, socialRevocations)
                .putString(KEY_PENDING_CHANGE, String.join("|", changeId, trigger,
                        before.auditText(), after.auditText()));
        if (revoked.contains(BuiltInBlockExemptions.CHROME)) {
            editor.putBoolean(KEY_CHROME_REVOCATION_PENDING, true);
        }
        if (!editor.commit()) {
            throw new IllegalStateException("Could not persist built-in block exemptions");
        }
        return changeId;
    }

    /** The durable Chrome grant ledger. */
    static ChromeFilterExemption.Ledger ledger(Context context) {
        SharedPreferences prefs = prefs(context);
        return new ChromeFilterExemption.Ledger() {
            @Override
            public boolean granted() {
                return prefs.getBoolean(KEY_CHROME_GRANTED, false);
            }

            @Override
            public void setGranted(boolean granted) {
                if (granted() != granted) {
                    prefs.edit().putBoolean(KEY_CHROME_GRANTED, granted).commit();
                }
            }

            @Override
            public boolean revocationPending() {
                return prefs.getBoolean(KEY_CHROME_REVOCATION_PENDING, false);
            }

            @Override
            public void setRevocationPending(boolean pending) {
                if (revocationPending() != pending) {
                    prefs.edit().putBoolean(KEY_CHROME_REVOCATION_PENDING, pending).commit();
                }
            }
        };
    }

    public static boolean chromeRevocationPending(Context context) {
        return prefs(context).getBoolean(KEY_CHROME_REVOCATION_PENDING, false);
    }

    /** Social packages whose removal Android has not yet confirmed. */
    public static Set<String> socialRevocationsPending(Context context) {
        try {
            return Collections.unmodifiableSet(new LinkedHashSet<>(
                    prefs(context).getStringSet(KEY_SOCIAL_REVOCATIONS, Set.of())));
        } catch (ClassCastException exception) {
            return Set.of();
        }
    }

    static void setSocialRevocationsPending(Context context, Set<String> pending) {
        prefs(context).edit().putStringSet(KEY_SOCIAL_REVOCATIONS, new LinkedHashSet<>(pending)).commit();
    }

    /** Takes the change awaiting its audited outcome, or {@code null}. */
    static synchronized String takePendingChange(Context context) {
        SharedPreferences prefs = prefs(context);
        String change = prefs.getString(KEY_PENDING_CHANGE, null);
        if (change != null) {
            prefs.edit().remove(KEY_PENDING_CHANGE).commit();
        }
        return change;
    }

    /** What the last policy pass read back from Android. */
    public record Readback(
            ChromeFilterExemption.State chromeState,
            boolean chromeConfirmedAvailable,
            Set<String> socialConfirmedAvailable,
            Set<String> socialSignerMismatch
    ) {
        public Readback {
            socialConfirmedAvailable = Set.copyOf(socialConfirmedAvailable);
            socialSignerMismatch = Set.copyOf(socialSignerMismatch);
        }
    }

    static void saveReadback(Context context, Readback readback) {
        prefs(context).edit()
                .putString(KEY_READBACK_CHROME_STATE, readback.chromeState().name())
                .putBoolean(KEY_READBACK_CHROME_AVAILABLE, readback.chromeConfirmedAvailable())
                .putStringSet(KEY_READBACK_SOCIAL_AVAILABLE,
                        new LinkedHashSet<>(readback.socialConfirmedAvailable()))
                .putStringSet(KEY_READBACK_SOCIAL_MISMATCH,
                        new LinkedHashSet<>(readback.socialSignerMismatch()))
                .commit();
    }

    /** The last read-back, or {@code null} when no pass has recorded one. */
    public static Readback readback(Context context) {
        SharedPreferences prefs = prefs(context);
        try {
            String state = prefs.getString(KEY_READBACK_CHROME_STATE, null);
            if (state == null) {
                return null;
            }
            return new Readback(
                    ChromeFilterExemption.State.valueOf(state),
                    prefs.getBoolean(KEY_READBACK_CHROME_AVAILABLE, false),
                    prefs.getStringSet(KEY_READBACK_SOCIAL_AVAILABLE, Set.of()),
                    prefs.getStringSet(KEY_READBACK_SOCIAL_MISMATCH, Set.of()));
        } catch (IllegalArgumentException | ClassCastException exception) {
            return null;
        }
    }

    private static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }
}
