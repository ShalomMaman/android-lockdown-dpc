package com.example.lockdowndpc.policy;

import android.content.Context;
import android.content.SharedPreferences;

final class HomeFilterStore {
    private static final String PREFS = "home_filter";
    private static final String PACKAGE = "vpn_package";
    private static final String PAC = "pac_url";
    private static final String ENABLED = "enabled";
    private static final String CA = "ca";
    private static final String REMOVE_CA = "remove_ca";
    private static final String READBACK = "last_readback";

    private HomeFilterStore() {}

    static HomeFilterPolicy.Settings read(Context context) {
        SharedPreferences prefs = prefs(context);
        if (!prefs.contains(PAC)) {
            return HomeFilterPolicy.Settings.OFF;
        }
        return new HomeFilterPolicy.Settings(
                new HomeFilterPolicy.Config(prefs.getString(PACKAGE, ""), prefs.getString(PAC, "")),
                prefs.getBoolean(ENABLED, false),
                prefs.getString(CA, null),
                prefs.getBoolean(REMOVE_CA, false));
    }

    static void write(Context context, HomeFilterPolicy.Settings settings) {
        SharedPreferences.Editor editor = prefs(context).edit().remove(READBACK);
        if (settings.configured()) {
            editor.putString(PACKAGE, settings.config().vpnPackage())
                    .putString(PAC, settings.config().pacUrl())
                    .putBoolean(ENABLED, settings.enabled())
                    .putString(CA, settings.ca())
                    .putBoolean(REMOVE_CA, settings.removeCa());
        } else {
            editor.clear();
        }
        if (!editor.commit()) {
            throw new IllegalStateException("Could not persist home filter settings");
        }
    }

    static void saveReadback(Context context, HomeFilterPolicy.Report report) {
        String states = String.join(",", report.vpn().name(), report.proxy().name(),
                report.ca().name(), report.restrictions().name());
        prefs(context).edit().putString(READBACK, states).apply();
    }

    static HomeFilterPolicy.Report includeApplyEvidence(Context context, boolean enabled,
                                                       HomeFilterPolicy.Report live) {
        String[] last = prefs(context).getString(READBACK, "").split(",");
        if (last.length != 4) {
            return enabled ? live.withProxyApplyEvidence(HomeFilterPolicy.State.UNCONFIRMED) : live;
        }
        if (enabled) {
            HomeFilterPolicy.State evidence = HomeFilterPolicy.State.UNCONFIRMED;
            if (HomeFilterPolicy.State.CONFIRMED.name().equals(last[1])) {
                evidence = HomeFilterPolicy.State.CONFIRMED;
            } else if (HomeFilterPolicy.State.REFUSED.name().equals(last[1])) {
                evidence = HomeFilterPolicy.State.REFUSED;
            }
            live = live.withProxyApplyEvidence(evidence);
        }
        // Give fresh confirmations and missing-package evidence precedence.
        // A previous confirmation is never used in place of a fresh read.
        return new HomeFilterPolicy.Report(withRefusal(live.vpn(), last[0]),
                withRefusal(live.proxy(), last[1]), withRefusal(live.ca(), last[2]),
                withRefusal(live.restrictions(), last[3]));
    }

    private static HomeFilterPolicy.State withRefusal(HomeFilterPolicy.State live, String last) {
        return live == HomeFilterPolicy.State.UNCONFIRMED
                && HomeFilterPolicy.State.REFUSED.name().equals(last)
                ? HomeFilterPolicy.State.REFUSED : live;
    }

    static Runnable watch(Context context, Runnable listener) {
        SharedPreferences preferences = prefs(context);
        SharedPreferences.OnSharedPreferenceChangeListener attached = (ignored, key) -> listener.run();
        preferences.registerOnSharedPreferenceChangeListener(attached);
        return () -> preferences.unregisterOnSharedPreferenceChangeListener(attached);
    }

    private static SharedPreferences prefs(Context context) {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }
}
