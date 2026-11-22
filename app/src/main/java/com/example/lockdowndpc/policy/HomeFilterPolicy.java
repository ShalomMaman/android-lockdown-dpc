package com.example.lockdowndpc.policy;

import android.os.UserManager;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

/** Requested settings and live read-back for the home filter. No Android services here. */
public final class HomeFilterPolicy {
    public static final String DEFAULT_VPN_PACKAGE = "com.tailscale.ipn";
    public static final String DEFAULT_LOGIN_URL = "https://controlplane.tailscale.com";
    private static final int MIN_SDK = 29;
    private static final int PRIVATE_PROFILE_SDK = 35;
    // Additional profile restrictions belong to the home filter only.
    private static final List<SystemPolicyControl.Restriction> PROFILE_RESTRICTIONS = List.of(
            new SystemPolicyControl.Restriction(UserManager.DISALLOW_ADD_MANAGED_PROFILE, MIN_SDK),
            new SystemPolicyControl.Restriction(UserManager.DISALLOW_ADD_PRIVATE_PROFILE, PRIVATE_PROFILE_SDK));
    public static final Set<SystemPolicyControl> REQUIRED_CONTROLS = Set.of(
            SystemPolicyControl.VPN_CONFIGURATION,
            SystemPolicyControl.PRIVATE_DNS,
            SystemPolicyControl.NETWORK_RESET,
            SystemPolicyControl.FACTORY_RESET,
            SystemPolicyControl.SAFE_BOOT,
            SystemPolicyControl.USER_AND_PROFILE_CREATION,
            SystemPolicyControl.DATE_AND_TIME,
            SystemPolicyControl.APP_UNINSTALL,
            SystemPolicyControl.APP_CONTROL_SETTINGS,
            SystemPolicyControl.UNKNOWN_SOURCE_INSTALLS,
            SystemPolicyControl.APP_STORES_AND_INSTALLERS);

    private HomeFilterPolicy() {}

    public record Config(String vpnPackage, String pacUrl, String signerPin, Routing routing, Canary canary) {
        public Config(String vpnPackage, String pacUrl) {
            this(vpnPackage, pacUrl, "", null, null);
        }

        public Config {
            vpnPackage = vpnPackage.trim();
            if (vpnPackage.isEmpty()) {
                vpnPackage = DEFAULT_VPN_PACKAGE;
            }
            if (!vpnPackage.matches("[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*)+")) {
                throw new IllegalArgumentException("Invalid VPN package");
            }
            pacUrl = validateUrl(pacUrl, true);
            signerPin = LockdownPackages.normalizeDigest(signerPin);
            if (!signerPin.isEmpty() && !signerPin.matches("[0-9a-f]{64}")) {
                throw new IllegalArgumentException("Invalid VPN signing certificate digest");
            }
        }
    }

    public record Routing(String tailnetId, String loginUrl, String exitNodeId, String organizationName) {
        public Routing {
            tailnetId = tailnetId.trim();
            loginUrl = validateUrl(loginUrl, false);
            exitNodeId = exitNodeId.trim();
            organizationName = organizationName.trim();
            if (!tailnetId.matches("T[A-Za-z0-9]+")
                    || !exitNodeId.matches("[A-Za-z0-9_-]+") || organizationName.isEmpty()) {
                throw new IllegalArgumentException("Invalid Tailscale routing settings");
            }
        }

        // Verified against Tailscale's Android app_restrictions.xml and system policy docs.
        Map<String, Object> restrictions() {
            return Map.of(
                    "ForceEnabled", true,
                    "Tailnet", "required:" + tailnetId,
                    "LoginURL", loginUrl,
                    "ExitNodeID", exitNodeId,
                    "ExitNodesPicker", "hide",
                    // Local-network routes would skip the exit node (e.g. a proxy on another LAN device).
                    "ExitNodeAllowLANAccess", "never",
                    "ManagedByOrganizationName", organizationName);
        }
    }

    public record Canary(String url, String expectedBody) {
        public Canary {
            url = validateUrl(url, false);
            if (expectedBody.isBlank() || expectedBody.getBytes(StandardCharsets.UTF_8).length > 1024) {
                throw new IllegalArgumentException("Invalid canary response");
            }
        }
    }

    private static String validateUrl(String input, boolean allowHttp) {
        try {
            URI uri = new URI(input.trim());
            String scheme = uri.getScheme();
            if (("https".equalsIgnoreCase(scheme) || (allowHttp && "http".equalsIgnoreCase(scheme)))
                    && uri.getHost() != null && uri.getRawUserInfo() == null
                    && uri.getRawFragment() == null && !uri.getRawAuthority().endsWith(":")
                    && uri.getPort() <= 65535 && uri.getPort() != 0) {
                String url = uri.toASCIIString();
                return scheme.toLowerCase(Locale.ROOT) + url.substring(scheme.length());
            }
        } catch (URISyntaxException ignored) {
            // Report a generic validation error without embedding the supplied URL.
        }
        throw new IllegalArgumentException("Invalid home filter URL");
    }

    public static boolean supportedOn(int sdk) {
        return sdk >= MIN_SDK;
    }

    public static boolean permitsRelaxing(Set<SystemPolicyControl> controls) {
        return Collections.disjoint(REQUIRED_CONTROLS, controls);
    }

    static List<SystemPolicyControl.Restriction> profileRestrictions(int sdk) {
        return PROFILE_RESTRICTIONS.stream().filter(restriction -> restriction.supportedOn(sdk))
                .collect(java.util.stream.Collectors.toList());
    }

    /** A disabled configuration is kept only while Android still owes cleanup. */
    public record Settings(Config config, boolean enabled, String ca, boolean removeCa) {
        public static final Settings OFF = new Settings(null, false, null, false);

        public boolean configured() {
            return config != null;
        }

        boolean keepsVpnVisible(String packageName) {
            // A built-in blocked browser, store or social application never
            // inherits the VPN's visibility, whatever was entered as the VPN.
            return enabled && configured() && config.vpnPackage().equals(packageName)
                    && !BuiltInBlockExemptions.isBuiltInBlocked(packageName);
        }

        boolean packageShouldBeHidden(String packageName, boolean blockedByPackagePolicy) {
            return blockedByPackagePolicy && !keepsVpnVisible(packageName);
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

    public record VpnState(String packageName, boolean lockdown, Set<String> exemptions) {
        public VpnState {
            if (exemptions != null) exemptions = Set.copyOf(exemptions);
        }

        public VpnState(String packageName, boolean lockdown, boolean noExemptions) {
            this(packageName, lockdown, noExemptions ? Set.of() : null);
        }

        public boolean noExemptions() {
            return exemptions != null && exemptions.isEmpty();
        }
    }

    public enum ProbeState { NOT_RUN, PASSED, FAILED }

    public enum Status {
        OFF, REMOVAL_PENDING, SETTINGS_UNCONFIRMED, ANDROID_SETTINGS_CONFIRMED,
        PROBE_PENDING, PROBE_FAILED, FILTER_ACTIVE
    }

    public record Report(State vpn, State proxy, State ca, State restrictions, State privateDns) {
        public boolean androidSettingsConfirmed(Settings settings) {
            return settings.enabled() && removed() && privateDns == State.CONFIRMED;
        }

        public Status status(Settings settings, ProbeState probe) {
            if (!settings.configured()) return Status.OFF;
            if (!settings.enabled()) return Status.REMOVAL_PENDING;
            if (!androidSettingsConfirmed(settings)) return Status.SETTINGS_UNCONFIRMED;
            if (settings.config().canary() == null) return Status.ANDROID_SETTINGS_CONFIRMED;
            return switch (probe) {
                case NOT_RUN -> Status.PROBE_PENDING;
                case PASSED -> Status.FILTER_ACTIVE;
                case FAILED -> Status.PROBE_FAILED;
            };
        }

        public Report withProxyApplyEvidence(State applyEvidence) {
            State verified = proxy == State.CONFIRMED ? applyEvidence : proxy;
            return new Report(vpn, verified, ca, restrictions, privateDns);
        }

        public boolean removed() {
            return vpn == State.CONFIRMED && proxy == State.CONFIRMED
                    && (ca == State.CONFIRMED || ca == State.NOT_REQUESTED)
                    && restrictions == State.CONFIRMED;
        }
    }

    public interface Gateway {
        PackageState vpnPackageState(Config config);
        String alwaysOnPackage();
        VpnState vpnState();
        boolean setVpn(String packageName);
        default boolean restoreVpn(VpnState previous) {
            return previous.lockdown() && previous.noExemptions() && setVpn(previous.packageName());
        }
        boolean uninstallBlocked(String packageName);
        boolean setVpnUninstallBlocked(String packageName, boolean blocked);
        boolean retainVpnUninstallBlock(String packageName);
        Map<String, Object> managedConfig(String packageName);
        boolean setManagedConfig(String packageName, Map<String, Object> changes, boolean enabled);
        /** Captures the complete configuration and returns a rollback that verifies it after restoration. */
        BooleanSupplier captureManagedConfig(String packageName);
        boolean privateDnsOpportunistic();
        boolean setPrivateDnsOpportunistic();
        String proxyPacUrl();
        boolean setProxy(String pacUrl);
        boolean hasCa(String certificate);
        boolean setCa(String certificate, boolean install);
        boolean restrictionsMatch(boolean enabled);
        boolean setProfileRestrictions(boolean enabled);
    }

    static PackageState installedVpnState(LockdownPackages.SignerVerdict signer) {
        return signer == LockdownPackages.SignerVerdict.MATCH
                ? PackageState.INSTALLED : PackageState.UNTRUSTED;
    }

    /** The base choices a pass enforces for a home filter in this (effective) state. */
    public static Map<SystemPolicyControl, Boolean> choicesFor(
            Map<SystemPolicyControl, Boolean> base, boolean filterEnabled) {
        return filterEnabled ? requireControls(base) : base;
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
        if (!settings.configured()) return new Report(State.NOT_REQUESTED, State.NOT_REQUESTED,
                State.NOT_REQUESTED, State.NOT_REQUESTED, State.NOT_REQUESTED);
        if (settings.enabled() && !supportedOn(sdk)) return new Report(State.REFUSED,
                State.NOT_REQUESTED, State.NOT_REQUESTED, State.NOT_REQUESTED, State.REFUSED);

        State vpn = evaluateVpn(settings, sdk, gateway, write);
        boolean vpnReadyForChanges = vpn == State.CONFIRMED;
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
                () -> gateway.setProfileRestrictions(settings.enabled()), write);
        State privateDns = settings.enabled()
                ? verify(gateway::privateDnsOpportunistic, gateway::setPrivateDnsOpportunistic,
                        write && vpnReadyForChanges)
                : State.NOT_REQUESTED;
        return new Report(vpn, proxy, ca, restrictions, privateDns);
    }

    /** Removes only settings issued for a superseded filter, preserving an active replacement. */
    static boolean reconcileRetiredConfig(Config previous, Config active, Gateway gateway) {
        return retireProxy(previous, active, gateway) && releaseVpnSettings(previous, active, gateway)
                && clearVpnLockdown(previous, active, gateway);
    }

    /** The first half of a teardown: the superseded PAC proxy. The VPN lockdown is untouched. */
    static boolean retireProxy(Config previous, Config active, Gateway gateway) {
        return (active != null && previous.pacUrl().equals(active.pacUrl()))
                || removeIfMatching(previous.pacUrl(), gateway::proxyPacUrl,
                        () -> gateway.setProxy(null), true) == State.CONFIRMED;
    }

    /**
     * The second step: the superseded uninstall block and managed routing
     * settings, each read back. The VPN lockdown is still untouched, so a
     * refusal here leaves it in force.
     */
    static boolean releaseVpnSettings(Config previous, Config active, Gateway gateway) {
        String packageName = previous.vpnPackage();
        if ((active == null || !packageName.equals(active.vpnPackage()))
                && verify(() -> gateway.retainVpnUninstallBlock(packageName) || !gateway.uninstallBlocked(packageName),
                        () -> gateway.setVpnUninstallBlocked(packageName, false), true) != State.CONFIRMED) {
            return false;
        }
        if (previous.routing() == null) return true;
        Map<String, Object> retired = new LinkedHashMap<>(previous.routing().restrictions());
        if (active != null && packageName.equals(active.vpnPackage()) && active.routing() != null) {
            retired.entrySet().removeAll(active.routing().restrictions().entrySet());
        }
        return retired.isEmpty() || verify(
                () -> retired.entrySet().stream().noneMatch(gateway.managedConfig(packageName).entrySet()::contains),
                () -> gateway.setManagedConfig(packageName, retired, false), true) == State.CONFIRMED;
    }

    /** The filter's profile restrictions, released and read back before the VPN lockdown goes. */
    static boolean releaseProfileRestrictions(Gateway gateway) {
        return verify(() -> gateway.restrictionsMatch(false),
                () -> gateway.setProfileRestrictions(false), true) == State.CONFIRMED;
    }

    /** The last Android call of a teardown: the superseded VPN lockdown itself. */
    static boolean clearVpnLockdown(Config previous, Config active, Gateway gateway) {
        String packageName = previous.vpnPackage();
        return (active != null && packageName.equals(active.vpnPackage()))
                || removeIfMatching(packageName, gateway::alwaysOnPackage,
                        () -> gateway.setVpn(null), true) == State.CONFIRMED;
    }

    private static State evaluateVpn(Settings settings, int sdk, Gateway gateway, boolean write) {
        if (!settings.configured()) {
            return State.NOT_REQUESTED;
        }
        String packageName = settings.config().vpnPackage();
        Routing routing = settings.config().routing();
        Map<String, Object> expected = routing == null ? Map.of() : routing.restrictions();
        if (!settings.enabled()) {
            State vpn = removeIfMatching(packageName, gateway::alwaysOnPackage,
                    () -> gateway.setVpn(null), write);
            if (vpn != State.CONFIRMED || routing == null) return vpn;
            State mdm = verify(() -> expected.entrySet().stream().noneMatch(
                            gateway.managedConfig(packageName).entrySet()::contains),
                    () -> gateway.setManagedConfig(packageName, expected, false), write);
            if (mdm != State.CONFIRMED) return mdm;
            return verify(() -> gateway.retainVpnUninstallBlock(packageName)
                            || !gateway.uninstallBlocked(packageName),
                    () -> gateway.setVpnUninstallBlocked(packageName, false), write);
        }
        if (!supportedOn(sdk)) return State.REFUSED;
        try {
            switch (gateway.vpnPackageState(settings.config())) {
                case MISSING: return State.MISSING_VPN;
                case HIDDEN: return State.HIDDEN_VPN;
                case UNTRUSTED: return State.UNTRUSTED_VPN;
                case INSTALLED: break;
            }
            if (routing == null) return State.UNCONFIRMED;
            State blocked = verify(() -> gateway.uninstallBlocked(packageName),
                    () -> gateway.setVpnUninstallBlocked(packageName, true), write);
            if (blocked != State.CONFIRMED) return blocked;
            State mdm = verify(() -> gateway.managedConfig(packageName).entrySet()
                            .containsAll(expected.entrySet()),
                    () -> gateway.setManagedConfig(packageName, expected, true), write);
            if (mdm != State.CONFIRMED) return mdm;
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
