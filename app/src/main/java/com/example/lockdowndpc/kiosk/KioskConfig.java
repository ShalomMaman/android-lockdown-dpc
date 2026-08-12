package com.example.lockdowndpc.kiosk;

/**
 * Administrator-authored kiosk configuration.
 *
 * <p>Storage-shaped and free of Android APIs. Whether a configuration is
 * <em>usable</em> is decided by {@link KioskConfigValidator}, never by this
 * record, so a stored value that has become stale (target uninstalled, site
 * policy tightened) is caught on every apply rather than trusted.
 */
public record KioskConfig(KioskMode mode, String targetPackage, String siteUrl) {

    public static final KioskConfig OFF = new KioskConfig(KioskMode.OFF, "", "");

    public KioskConfig {
        mode = mode == null ? KioskMode.OFF : mode;
        targetPackage = targetPackage == null ? "" : targetPackage.trim();
        siteUrl = siteUrl == null ? "" : siteUrl.trim();
    }

    public static KioskConfig singleApp(String targetPackage) {
        return new KioskConfig(KioskMode.SINGLE_APP, targetPackage, "");
    }

    public static KioskConfig singleSite(String siteUrl) {
        return new KioskConfig(KioskMode.SINGLE_SITE, "", siteUrl);
    }

    public boolean requiresAppTarget() {
        return mode == KioskMode.SINGLE_APP;
    }

    public boolean requiresSite() {
        return mode == KioskMode.SINGLE_SITE;
    }
}
