package com.example.lockdowndpc.policy;

import android.os.Build;
import android.os.UserManager;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The system policy controls an authenticated administrator can request, each
 * bound to the official {@link UserManager} restrictions that implement it.
 *
 * <p>Every restriction here is a documented Android Enterprise device-owner
 * restriction applied through {@code DevicePolicyManager#addUserRestriction},
 * which is the same supported surface Google's TestDPC drives. Nothing in this
 * class reaches for a hidden API, a shell command, root or an accessibility
 * service, and no control claims an OEM behaviour Android does not define.
 *
 * <p>The restriction names resolve to compile-time {@code String} constants, so
 * naming {@code DISALLOW_ADD_WIFI_CONFIG}-era constants costs nothing at runtime
 * on an older device — the literal is inlined and the class never loads
 * {@code UserManager}. What is <em>not</em> free is sending a restriction the
 * running release does not implement, so {@link #minSdk()} gates every send and
 * an ungated control reports {@link SystemPolicyOutcome#UNSUPPORTED} instead.
 *
 * <h2>Defaults and pilot migration</h2>
 *
 * <p>{@link DefaultPolicy#ENFORCED_SINCE_PILOT} is exactly the set 0.5.1 applied
 * unconditionally. A pilot device that upgrades with no stored choices therefore
 * enforces byte-identically to 0.5.1 — {@code SystemPolicyMigrationTest} pins
 * that. The two genuinely new capabilities are opt-in, and debugging is on by
 * default only for the production profile.
 */
public enum SystemPolicyControl {

    /**
     * Developer options, USB debugging and ADB.
     *
     * <p>The one control that can remove the pilot's break-glass access, so it is
     * the one control keyed to {@link SystemPolicyProfile}. Roadmap gate 3 —
     * a real signed higher-version self-update on hardware — is what makes it
     * safe to enable on a pilot, and that gate is not met yet.
     */
    DEVELOPER_OPTIONS_AND_ADB(
            "developer_options_and_adb",
            Criticality.CRITICAL,
            DefaultPolicy.PRODUCTION_ONLY,
            restriction(UserManager.DISALLOW_DEBUGGING_FEATURES, Build.VERSION_CODES.O)),

    /** Mounting the device as storage over USB. */
    USB_FILE_TRANSFER(
            "usb_file_transfer",
            Criticality.CRITICAL,
            DefaultPolicy.ENFORCED_SINCE_PILOT,
            restriction(UserManager.DISALLOW_USB_FILE_TRANSFER, Build.VERSION_CODES.O)),

    /**
     * Sideloading from unknown sources.
     *
     * <p>Two restrictions: the per-user one, and the Android 10 global one that
     * also covers profiles. On Android 9 the global key is simply absent, which
     * is reported rather than hidden.
     */
    UNKNOWN_SOURCE_INSTALLS(
            "unknown_source_installs",
            Criticality.CRITICAL,
            DefaultPolicy.ENFORCED_SINCE_PILOT,
            restriction(UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES, Build.VERSION_CODES.O),
            restriction(UserManager.DISALLOW_INSTALL_UNKNOWN_SOURCES_GLOBALLY, Build.VERSION_CODES.Q)),

    /**
     * All package installation, including app stores and package installers.
     *
     * <p>Opt-in on every profile, and deliberately not part of production
     * hardening. Android documents {@code DISALLOW_INSTALL_APPS} as also
     * preventing the device owner from installing packages, which is exactly the
     * mechanism {@code SecureUpdateManager} uses to install a signed Device Guard
     * update. Defaulting it on would disable self-update — the very path roadmap
     * gate 3 requires before ADB can be withdrawn. An administrator may still
     * choose it, and the console says plainly what it costs.
     */
    APP_STORES_AND_INSTALLERS(
            "app_stores_and_installers",
            Criticality.CRITICAL,
            DefaultPolicy.OPT_IN,
            restriction(UserManager.DISALLOW_INSTALL_APPS, Build.VERSION_CODES.O)),

    /** Adding or removing accounts. */
    ACCOUNT_MODIFICATION(
            "account_modification",
            Criticality.CRITICAL,
            DefaultPolicy.ENFORCED_SINCE_PILOT,
            restriction(UserManager.DISALLOW_MODIFY_ACCOUNTS, Build.VERSION_CODES.O)),

    /** Configuring a VPN. */
    VPN_CONFIGURATION(
            "vpn_configuration",
            Criticality.CRITICAL,
            DefaultPolicy.ENFORCED_SINCE_PILOT,
            restriction(UserManager.DISALLOW_CONFIG_VPN, Build.VERSION_CODES.O)),

    /** Resetting network settings. */
    NETWORK_RESET(
            "network_reset",
            Criticality.CRITICAL,
            DefaultPolicy.ENFORCED_SINCE_PILOT,
            restriction(UserManager.DISALLOW_NETWORK_RESET, Build.VERSION_CODES.O)),

    /** Tethering and portable hotspot. */
    TETHERING(
            "tethering",
            Criticality.CRITICAL,
            DefaultPolicy.ENFORCED_SINCE_PILOT,
            restriction(UserManager.DISALLOW_CONFIG_TETHERING, Build.VERSION_CODES.O)),

    /**
     * Changing Wi-Fi access points.
     *
     * <p>Advisory rather than critical, and opt-in. This is the control the
     * roadmap qualifies with "where supported": Android defines the restriction,
     * but what a given OEM Settings build actually refuses varies, and a device
     * that cannot join a network is not recoverable from this console. A refusal
     * is recorded and shown, and does not fault protection.
     */
    WIFI_CONFIGURATION(
            "wifi_configuration",
            Criticality.ADVISORY,
            DefaultPolicy.OPT_IN,
            restriction(UserManager.DISALLOW_CONFIG_WIFI, Build.VERSION_CODES.O)),

    /** Changing the private DNS mode. */
    PRIVATE_DNS(
            "private_dns",
            Criticality.CRITICAL,
            DefaultPolicy.ENFORCED_SINCE_PILOT,
            restriction(UserManager.DISALLOW_CONFIG_PRIVATE_DNS, Build.VERSION_CODES.Q)),

    /** Changing the system date, time and time zone. */
    DATE_AND_TIME(
            "date_and_time",
            Criticality.CRITICAL,
            DefaultPolicy.ENFORCED_SINCE_PILOT,
            restriction(UserManager.DISALLOW_CONFIG_DATE_TIME, Build.VERSION_CODES.P)),

    /** Booting into Safe Boot, which would otherwise start the device without the DPC's policy. */
    SAFE_BOOT(
            "safe_boot",
            Criticality.CRITICAL,
            DefaultPolicy.ENFORCED_SINCE_PILOT,
            restriction(UserManager.DISALLOW_SAFE_BOOT, Build.VERSION_CODES.O)),

    /** Factory reset from Settings. */
    FACTORY_RESET(
            "factory_reset",
            Criticality.CRITICAL,
            DefaultPolicy.ENFORCED_SINCE_PILOT,
            restriction(UserManager.DISALLOW_FACTORY_RESET, Build.VERSION_CODES.O)),

    /** Creating users and profiles, and switching between them. */
    USER_AND_PROFILE_CREATION(
            "user_and_profile_creation",
            Criticality.CRITICAL,
            DefaultPolicy.ENFORCED_SINCE_PILOT,
            restriction(UserManager.DISALLOW_ADD_USER, Build.VERSION_CODES.O),
            restriction(UserManager.DISALLOW_USER_SWITCH, Build.VERSION_CODES.P)),

    /** Uninstalling applications. */
    APP_UNINSTALL(
            "app_uninstall",
            Criticality.CRITICAL,
            DefaultPolicy.ENFORCED_SINCE_PILOT,
            restriction(UserManager.DISALLOW_UNINSTALL_APPS, Build.VERSION_CODES.O)),

    /** Force-stop, clear-data and the other application-control settings. */
    APP_CONTROL_SETTINGS(
            "app_control_settings",
            Criticality.CRITICAL,
            DefaultPolicy.ENFORCED_SINCE_PILOT,
            restriction(UserManager.DISALLOW_APPS_CONTROL, Build.VERSION_CODES.O));

    /** Whether a refused request is allowed to leave protection claiming to be active. */
    public enum Criticality {
        /** A refused request faults protection. */
        CRITICAL,
        /** A refused request is recorded and shown, but does not fault protection. */
        ADVISORY
    }

    /** What a control does when an administrator has expressed no choice. */
    public enum DefaultPolicy {
        /** On everywhere. Exactly what Pilot 0.5.1 already enforced unconditionally. */
        ENFORCED_SINCE_PILOT,
        /** On for {@link SystemPolicyProfile#PRODUCTION} only; off for pilots. */
        PRODUCTION_ONLY,
        /** Off everywhere until an administrator asks for it. */
        OPT_IN
    }

    /**
     * One Android user restriction and the lowest release this build may send it on.
     *
     * <p>{@code minSdk} is a send-gate, not a claim about when Android introduced
     * the constant. This application's own {@code minSdk} is 26, so a restriction
     * that predates 26 is recorded as {@link Build.VERSION_CODES#O}: it means
     * "every release this build can run on implements it", which is the only
     * statement that matters here and the only one that can be verified from the
     * build configuration rather than from memory. The levels that genuinely gate
     * behaviour inside the supported range — {@link Build.VERSION_CODES#P} for
     * date/time and user switching, {@link Build.VERSION_CODES#Q} for global
     * unknown sources and private DNS — are recorded exactly, because those are
     * the ones that make a control report
     * {@link SystemPolicyOutcome#UNSUPPORTED} on a real device.
     *
     * @param key    the {@link UserManager} restriction key
     * @param minSdk the lowest {@code Build.VERSION.SDK_INT} this build may send it on
     */
    public record Restriction(String key, int minSdk) {
        public Restriction {
            if (key == null || key.isBlank()) {
                throw new IllegalArgumentException("A restriction needs a key");
            }
        }

        public boolean supportedOn(int sdkInt) {
            return sdkInt >= minSdk;
        }
    }

    private final String storageKey;
    private final Criticality criticality;
    private final DefaultPolicy defaultPolicy;
    private final List<Restriction> restrictions;

    SystemPolicyControl(
            String storageKey,
            Criticality criticality,
            DefaultPolicy defaultPolicy,
            Restriction... restrictions
    ) {
        this.storageKey = storageKey;
        this.criticality = criticality;
        this.defaultPolicy = defaultPolicy;
        this.restrictions = List.of(restrictions);
    }

    private static Restriction restriction(String key, int minSdk) {
        return new Restriction(key, minSdk);
    }

    /** Stable preference key, independent of the enum constant's name. */
    public String storageKey() {
        return storageKey;
    }

    public Criticality criticality() {
        return criticality;
    }

    public boolean critical() {
        return criticality == Criticality.CRITICAL;
    }

    public DefaultPolicy defaultPolicy() {
        return defaultPolicy;
    }

    /** Every restriction this control is made of, supported here or not. */
    public List<Restriction> restrictions() {
        return restrictions;
    }

    /** The first API level at which any part of this control does something. */
    public int minSdk() {
        int lowest = Integer.MAX_VALUE;
        for (Restriction restriction : restrictions) {
            lowest = Math.min(lowest, restriction.minSdk());
        }
        return lowest;
    }

    /** Whether this release implements at least one of the control's restrictions. */
    public boolean supportedOn(int sdkInt) {
        return !supportedRestrictions(sdkInt).isEmpty();
    }

    /** Only the restrictions worth sending on this release. */
    public List<Restriction> supportedRestrictions(int sdkInt) {
        return restrictions.stream().filter(r -> r.supportedOn(sdkInt)).collect(java.util.stream.Collectors.toList());
    }

    /**
     * Restrictions this control would use that the running release cannot honour.
     * Shown rather than hidden: a partially supported control is a real gap.
     */
    public List<Restriction> unsupportedRestrictions(int sdkInt) {
        return restrictions.stream().filter(r -> !r.supportedOn(sdkInt)).collect(java.util.stream.Collectors.toList());
    }

    /** Whether this control is on when the administrator has expressed no choice. */
    public boolean defaultRequested(SystemPolicyProfile profile) {
        return switch (defaultPolicy) {
            case ENFORCED_SINCE_PILOT -> true;
            case PRODUCTION_ONLY -> profile == SystemPolicyProfile.PRODUCTION;
            case OPT_IN -> false;
        };
    }

    /** The complete default posture of a profile, used by the migration proof. */
    public static Map<SystemPolicyControl, Boolean> defaultsFor(SystemPolicyProfile profile) {
        LinkedHashMap<SystemPolicyControl, Boolean> defaults = new LinkedHashMap<>();
        for (SystemPolicyControl control : values()) {
            defaults.put(control, control.defaultRequested(profile));
        }
        return Collections.unmodifiableMap(defaults);
    }

    /** Looks a control up by its stored key; {@code null} for an unknown key. */
    public static SystemPolicyControl fromStorageKey(String storageKey) {
        return Arrays.stream(values())
                .filter(control -> control.storageKey.equals(storageKey))
                .findFirst()
                .orElse(null);
    }

    /** Every restriction key any control manages, for a complete release on pause. */
    public static List<String> allRestrictionKeys(int sdkInt) {
        return Arrays.stream(values())
                .flatMap(control -> control.supportedRestrictions(sdkInt).stream())
                .map(Restriction::key)
                .distinct()
                .collect(java.util.stream.Collectors.toList());
    }
}
