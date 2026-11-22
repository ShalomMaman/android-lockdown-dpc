package com.example.lockdowndpc.policy;

import android.content.Context;
import android.content.SharedPreferences;

import com.example.lockdowndpc.security.DurablePreferences;

import org.json.JSONArray;
import org.json.JSONException;

import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Supplier;

final class HomeFilterStore {
    private static final String PREFS = "home_filter";
    private static final String PACKAGE = "vpn_package";
    private static final String PAC = "pac_url";
    private static final String ENABLED = "enabled";
    private static final String CA = "ca";
    private static final String REMOVE_CA = "remove_ca";
    private static final String RETIRED_FILTER = "remote_retired_filter";
    private static final String RETIRED_CA = "remote_retired_ca";
    private static final String READBACK = "last_readback";
    private static final String SIGNER_PIN = "signer_pin";
    private static final String TAILNET_ID = "tailnet_id";
    private static final String LOGIN_URL = "login_url";
    private static final String EXIT_NODE_ID = "exit_node_id";
    private static final String ORGANIZATION = "organization";
    private static final String CANARY_URL = "canary_url";
    private static final String CANARY_BODY = "canary_body";
    private static final int MAX_ENCODED_CA_CHARS = ((HomeFilterCertificate.MAX_BYTES + 2) / 3) * 4;

    private HomeFilterStore() {}

    static HomeFilterPolicy.Settings read(Context context) {
        return read(prefs(context));
    }

    static synchronized HomeFilterPolicy.Settings read(SharedPreferences prefs) {
        if (!prefs.contains(PAC)) {
            if (prefs.contains(PACKAGE) || prefs.contains(ENABLED) || prefs.contains(CA)
                    || prefs.contains(REMOVE_CA) || prefs.contains(SIGNER_PIN)
                    || prefs.contains(TAILNET_ID) || prefs.contains(LOGIN_URL)
                    || prefs.contains(EXIT_NODE_ID) || prefs.contains(ORGANIZATION)
                    || prefs.contains(CANARY_URL) || prefs.contains(CANARY_BODY)) {
                throw new IllegalArgumentException("Home filter PAC is missing");
            }
            return HomeFilterPolicy.Settings.OFF;
        }
        boolean hasRouting = prefs.contains(TAILNET_ID) || prefs.contains(LOGIN_URL)
                || prefs.contains(EXIT_NODE_ID) || prefs.contains(ORGANIZATION);
        HomeFilterPolicy.Routing routing = hasRouting ? new HomeFilterPolicy.Routing(
                prefs.getString(TAILNET_ID, ""), prefs.getString(LOGIN_URL, ""),
                prefs.getString(EXIT_NODE_ID, ""), prefs.getString(ORGANIZATION, "")) : null;
        HomeFilterPolicy.Canary canary = prefs.contains(CANARY_URL) || prefs.contains(CANARY_BODY)
                ? new HomeFilterPolicy.Canary(prefs.getString(CANARY_URL, ""),
                        prefs.getString(CANARY_BODY, "")) : null;
        // Detect invalid preference types here as well as invalid configuration values.
        prefs.getString(READBACK, "");
        String ca = prefs.getString(CA, null);
        if (ca != null && (ca.isEmpty() || ca.length() > MAX_ENCODED_CA_CHARS
                || Base64.getDecoder().decode(ca).length == 0)) {
            throw new IllegalArgumentException("Invalid stored home filter certificate");
        }
        return new HomeFilterPolicy.Settings(
                new HomeFilterPolicy.Config(prefs.getString(PACKAGE, ""), prefs.getString(PAC, ""),
                        prefs.getString(SIGNER_PIN, ""), routing, canary),
                prefs.getBoolean(ENABLED, false),
                ca,
                prefs.getBoolean(REMOVE_CA, false));
    }

    static HomeFilterPolicy.Settings readOrReport(Supplier<HomeFilterPolicy.Settings> read,
                                                   Runnable markApplyFailed) {
        try {
            return read.get();
        } catch (IllegalArgumentException | ClassCastException | NullPointerException ignored) {
            markApplyFailed.run();
            return null;
        }
    }

    static void write(Context context, HomeFilterPolicy.Settings settings) {
        write(prefs(context), settings);
    }

    /**
     * Persists the settings. Android's {@code commit()} updates the in-memory
     * map before writing to disk, so after a failed commit every later reader
     * would see the new values anyway; the previous values are therefore written
     * back before the failure is reported, which restores memory whatever the
     * disk does.
     */
    static synchronized void write(SharedPreferences prefs, HomeFilterPolicy.Settings settings) {
        HomeFilterPolicy.Settings previous = read(prefs);
        String previousReadback = prefs.getString(READBACK, null);
        if (!DurablePreferences.commit(edit(prefs, settings),
                () -> edit(prefs, previous).putString(READBACK, previousReadback))) {
            throw new IllegalStateException("Could not persist home filter settings");
        }
    }

    private static SharedPreferences.Editor edit(SharedPreferences prefs, HomeFilterPolicy.Settings settings) {
        SharedPreferences.Editor editor = prefs.edit().remove(READBACK);
        if (settings.configured()) {
            HomeFilterPolicy.Config config = settings.config();
            HomeFilterPolicy.Routing routing = config.routing();
            HomeFilterPolicy.Canary canary = config.canary();
            editor.putString(PACKAGE, config.vpnPackage())
                    .putString(PAC, config.pacUrl())
                    .putString(SIGNER_PIN, config.signerPin())
                    .putString(TAILNET_ID, routing == null ? null : routing.tailnetId())
                    .putString(LOGIN_URL, routing == null ? null : routing.loginUrl())
                    .putString(EXIT_NODE_ID, routing == null ? null : routing.exitNodeId())
                    .putString(ORGANIZATION, routing == null ? null : routing.organizationName())
                    .putString(CANARY_URL, canary == null ? null : canary.url())
                    .putString(CANARY_BODY, canary == null ? null : canary.expectedBody())
                    .putBoolean(ENABLED, settings.enabled())
                    .putString(CA, settings.ca())
                    .putBoolean(REMOVE_CA, settings.removeCa());
        } else {
            editor.clear();
        }
        return editor;
    }

    static final int MAX_RETIRED = 16;

    private static final String[] REMOTE_KEYS = {PACKAGE, PAC, ENABLED, CA, REMOVE_CA, READBACK,
            SIGNER_PIN, TAILNET_ID, LOGIN_URL, EXIT_NODE_ID, ORGANIZATION, CANARY_URL, CANARY_BODY, RETIRED_CA, RETIRED_FILTER};

    static synchronized boolean projectRemote(Context context, HomeFilterPolicy.Settings target) {
        SharedPreferences prefs = prefs(context);
        HomeFilterPolicy.Settings previous = read(prefs);
        Set<String> retired = new HashSet<>(retiredCas(context));
        if (previous.ca() != null) retired.add(previous.ca());
        if (target.ca() != null) retired.remove(target.ca());
        Set<String> retiredFilters = new HashSet<>(prefs.getStringSet(RETIRED_FILTER, Set.of()));
        if (previous.configured() && !previous.config().equals(target.config())) {
            retiredFilters.add(encodeConfig(previous.config()));
        }
        if (target.configured()) retiredFilters.remove(encodeConfig(target.config()));
        // Each entry is a cleanup this device still owes, so none is dropped. A
        // fleet that keeps replacing an unverified filter is stopped here instead.
        if (retired.size() > MAX_RETIRED || retiredFilters.size() > MAX_RETIRED) return false;
        // Keep the configuration that could still be live across projection and process failures.
        HomeFilterPolicy.Settings settings = !target.enabled() && previous.configured()
                ? new HomeFilterPolicy.Settings(previous.config(), false, null, false) : target;
        return DurablePreferences.commit(prefs, edit(prefs, settings).putStringSet(RETIRED_CA, retired)
                .putStringSet(RETIRED_FILTER, retiredFilters), REMOTE_KEYS);
    }

    static synchronized Set<String> retiredCas(Context context) {
        return new HashSet<>(prefs(context).getStringSet(RETIRED_CA, Set.of()));
    }

    static synchronized Set<HomeFilterPolicy.Config> retiredFilters(Context context) {
        Set<HomeFilterPolicy.Config> filters = new HashSet<>();
        for (String encoded : prefs(context).getStringSet(RETIRED_FILTER, Set.of())) {
            try {
                JSONArray values = new JSONArray(encoded);
                HomeFilterPolicy.Routing routing = values.length() == 2 ? null : new HomeFilterPolicy.Routing(
                        values.getString(2), values.getString(3), values.getString(4), values.getString(5));
                filters.add(new HomeFilterPolicy.Config(values.getString(0), values.getString(1), "", routing, null));
            } catch (JSONException corrupt) {
                throw new IllegalArgumentException("Invalid retired filter configuration", corrupt);
            }
        }
        return filters;
    }

    private static String encodeConfig(HomeFilterPolicy.Config config) {
        JSONArray values = new JSONArray().put(config.vpnPackage()).put(config.pacUrl());
        var routing = config.routing();
        if (routing != null) {
            values.put(routing.tailnetId()).put(routing.loginUrl()).put(routing.exitNodeId())
                    .put(routing.organizationName());
        }
        return values.toString();
    }

    static synchronized boolean finishRemote(Context context) {
        SharedPreferences prefs = prefs(context);
        HomeFilterPolicy.Settings settings = read(prefs);
        if (retiredCas(context).isEmpty() && retiredFilters(context).isEmpty()
                && (settings.enabled() || !settings.configured())) return true;
        return DurablePreferences.commit(prefs, edit(prefs, settings.enabled() ? settings : HomeFilterPolicy.Settings.OFF)
                .remove(RETIRED_CA).remove(RETIRED_FILTER), REMOTE_KEYS);
    }

    static void saveReadback(Context context, HomeFilterPolicy.Report report) {
        String states = String.join(",", report.vpn().name(), report.proxy().name(),
                report.ca().name(), report.restrictions().name(), report.privateDns().name());
        prefs(context).edit().putString(READBACK, states).apply();
    }

    static HomeFilterPolicy.Report includeApplyEvidence(Context context, boolean enabled,
                                                       HomeFilterPolicy.Report live) {
        String[] last = prefs(context).getString(READBACK, "").split(",");
        if (last.length != 4 && last.length != 5) {
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
                withRefusal(live.restrictions(), last[3]),
                last.length == 5 ? withRefusal(live.privateDns(), last[4]) : live.privateDns());
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
