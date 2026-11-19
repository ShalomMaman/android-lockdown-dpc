package com.example.lockdowndpc.policy;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

/** Requested settings and live read-back for the home filter. No Android services here. */
public final class HomeFilterPolicy {
    public static final String DEFAULT_VPN_PACKAGE = "com.tailscale.ipn";
    private static final int SDK_WITH_LOCKDOWN_READBACK = 29;
    public static final Set<SystemPolicyControl> REQUIRED_CONTROLS = Set.of(
            SystemPolicyControl.VPN_CONFIGURATION,
            SystemPolicyControl.PRIVATE_DNS,
            SystemPolicyControl.NETWORK_RESET,
            SystemPolicyControl.FACTORY_RESET,
            SystemPolicyControl.SAFE_BOOT,
            SystemPolicyControl.USER_AND_PROFILE_CREATION);

    private HomeFilterPolicy() {}

    public record Config(String vpnPackage, String pacUrl) {
        public Config {
            vpnPackage = vpnPackage.trim();
            if (vpnPackage.isEmpty()) {
                vpnPackage = DEFAULT_VPN_PACKAGE;
            }
            if (!vpnPackage.matches("[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*)+")) {
                throw new IllegalArgumentException("Invalid VPN package");
            }
            pacUrl = validatePacUrl(pacUrl);
        }

        private static String validatePacUrl(String input) {
            try {
                URI uri = new URI(input.trim());
                String scheme = uri.getScheme();
                if (scheme != null
                        && (scheme.equalsIgnoreCase("https") || scheme.equalsIgnoreCase("http"))
                        && uri.getHost() != null && uri.getRawUserInfo() == null
                        && uri.getRawFragment() == null && !uri.getRawAuthority().endsWith(":")
                        && uri.getPort() <= 65535
                        && uri.getPort() != 0) {
                    String url = uri.toASCIIString();
                    return scheme.toLowerCase(Locale.ROOT) + url.substring(scheme.length());
                }
            } catch (URISyntaxException ignored) {
                // Report a generic validation error without embedding the supplied URL.
            }
            throw new IllegalArgumentException("Invalid PAC URL");
        }
    }

    /** A disabled configuration is kept only while Android still owes cleanup. */
    public record Settings(Config config, boolean enabled, String ca, boolean removeCa) {
        public static final Settings OFF = new Settings(null, false, null, false);

        public boolean configured() {
            return config != null;
        }

        public Settings requestDisable() {
            return new Settings(config, false, ca, ca != null);
        }

        public Settings requestRemoveCa() {
            return new Settings(config, enabled, ca, ca != null);
        }

        public Settings afterReadback(Report report) {
            if (!enabled && report.removed()) {
                return OFF;
            }
            if (removeCa && report.ca() == State.CONFIRMED) {
                return new Settings(config, enabled, null, false);
            }
            return this;
        }
    }

    public enum State {
        NOT_REQUESTED, CONFIRMED, UNCONFIRMED, MISSING_VPN, HIDDEN_VPN, UNTRUSTED_VPN, REFUSED
    }

    public enum PackageState { INSTALLED, MISSING, HIDDEN, UNTRUSTED }

    public record VpnState(String packageName, boolean lockdown, boolean noExemptions) {}

    public record Report(State vpn, State proxy, State ca, State restrictions) {
        public boolean active(Settings settings) {
            return settings.enabled() && vpn == State.CONFIRMED && proxy == State.CONFIRMED
                    && (ca == State.CONFIRMED || ca == State.NOT_REQUESTED)
                    && restrictions == State.CONFIRMED;
        }

        public Report withProxyApplyEvidence(State applyEvidence) {
            State verified = proxy == State.CONFIRMED ? applyEvidence : proxy;
            return new Report(vpn, verified, ca, restrictions);
        }

        public boolean removed() {
            return vpn == State.CONFIRMED && proxy == State.CONFIRMED
                    && (ca == State.CONFIRMED || ca == State.NOT_REQUESTED)
                    && restrictions == State.CONFIRMED;
        }
    }

    public interface Gateway {
        PackageState vpnPackageState(String packageName);
        String alwaysOnPackage();
        VpnState vpnState();
        boolean setVpn(String packageName);
        String proxyPacUrl();
        boolean setProxy(String pacUrl);
        boolean hasCa(String certificate);
        boolean setCa(String certificate, boolean install);
        boolean restrictionsMatch(boolean enabled);
    }

    static Map<SystemPolicyControl, Boolean> requireControls(Map<SystemPolicyControl, Boolean> base) {
        Map<SystemPolicyControl, Boolean> choices = new LinkedHashMap<>(base);
        for (SystemPolicyControl control : REQUIRED_CONTROLS) {
            choices.put(control, true);
        }
        return choices;
    }

    public static State inspectVpn(Settings settings, int sdk, Gateway gateway) {
        return evaluateVpn(settings, sdk, gateway, false);
    }

    public static Report inspect(Settings settings, int sdk, Gateway gateway) {
        return evaluate(settings, sdk, gateway, false);
    }

    public static Report reconcile(Settings settings, int sdk, Gateway gateway) {
        return evaluate(settings, sdk, gateway, true);
    }

    private static Report evaluate(Settings settings, int sdk, Gateway gateway, boolean write) {
        if (!settings.configured()) {
            return new Report(State.NOT_REQUESTED, State.NOT_REQUESTED,
                    State.NOT_REQUESTED, State.NOT_REQUESTED);
        }
        State vpn = evaluateVpn(settings, sdk, gateway, write);
        // Android 8 and 9 accept the lockdown write but cannot verify it. The profile
        // remains unconfirmed on those releases even if the other settings succeed.
        boolean vpnReadyForChanges = vpn == State.CONFIRMED
                || (sdk < SDK_WITH_LOCKDOWN_READBACK && vpn == State.UNCONFIRMED);
        Config config = settings.config();
        BooleanSupplier proxyMatches = () -> config.pacUrl().equals(gateway.proxyPacUrl());
        State proxy;
        if (!settings.enabled()) {
            proxy = removeIfMatching(config.pacUrl(), gateway::proxyPacUrl,
                    () -> gateway.setProxy(null), write);
        } else if (write) {
            // A matching proxy might come from Wi-Fi. Require the global setter
            // to complete successfully as well as seeing the expected PAC URL.
            if (!vpnReadyForChanges) {
                proxy = State.UNCONFIRMED;
            } else if (!confirmed(() -> gateway.setProxy(config.pacUrl()))) {
                proxy = State.REFUSED;
            } else {
                proxy = verify(proxyMatches, () -> false, false);
            }
        } else {
            proxy = verify(proxyMatches, () -> false, false);
        }
        State ca = State.NOT_REQUESTED;
        if (settings.ca() != null) {
            boolean install = settings.enabled() && !settings.removeCa();
            ca = verify(() -> gateway.hasCa(settings.ca()) == install,
                    () -> gateway.setCa(settings.ca(), install),
                    write && (!install || vpnReadyForChanges));
        }
        State restrictions = verify(() -> gateway.restrictionsMatch(settings.enabled()),
                () -> false, false);
        return new Report(vpn, proxy, ca, restrictions);
    }

    private static State evaluateVpn(Settings settings, int sdk, Gateway gateway, boolean write) {
        if (!settings.configured()) {
            return State.NOT_REQUESTED;
        }
        String packageName = settings.config().vpnPackage();
        if (!settings.enabled()) {
            return removeIfMatching(packageName, gateway::alwaysOnPackage,
                    () -> gateway.setVpn(null), write);
        }
        try {
            switch (gateway.vpnPackageState(packageName)) {
                case MISSING: return State.MISSING_VPN;
                case HIDDEN: return State.HIDDEN_VPN;
                case UNTRUSTED: return State.UNTRUSTED_VPN;
                case INSTALLED: break;
            }
            if (sdk < SDK_WITH_LOCKDOWN_READBACK) {
                return write && !gateway.setVpn(packageName) ? State.REFUSED : State.UNCONFIRMED;
            }
            return verify(
                    () -> {
                        VpnState state = gateway.vpnState();
                        return packageName.equals(state.packageName()) && state.lockdown()
                                && state.noExemptions();
                    },
                    () -> gateway.setVpn(packageName), write);
        } catch (RuntimeException ignored) {
            return write ? State.REFUSED : State.UNCONFIRMED;
        }
    }

    private static State removeIfMatching(String configured, Supplier<String> readback,
                                          BooleanSupplier clear, boolean write) {
        try {
            if (!configured.equals(readback.get())) {
                return State.CONFIRMED;
            }
        } catch (RuntimeException ignored) {
            // Without a read we cannot tell whether the current value belongs
            // to this policy. Preserve it and let a later pass try again.
            return State.UNCONFIRMED;
        }
        return write ? applyAndVerify(() -> !configured.equals(readback.get()), clear)
                : State.UNCONFIRMED;
    }

    private static State verify(BooleanSupplier readback, BooleanSupplier apply, boolean write) {
        if (confirmed(readback)) {
            return State.CONFIRMED;
        }
        if (!write) {
            return State.UNCONFIRMED;
        }
        return applyAndVerify(readback, apply);
    }

    private static State applyAndVerify(BooleanSupplier readback, BooleanSupplier apply) {
        boolean accepted;
        try {
            accepted = apply.getAsBoolean();
        } catch (RuntimeException ignored) {
            accepted = false;
        }
        if (confirmed(readback)) {
            return State.CONFIRMED;
        }
        return accepted ? State.UNCONFIRMED : State.REFUSED;
    }

    private static boolean confirmed(BooleanSupplier readback) {
        try {
            return readback.getAsBoolean();
        } catch (RuntimeException ignored) {
            return false;
        }
    }
}
