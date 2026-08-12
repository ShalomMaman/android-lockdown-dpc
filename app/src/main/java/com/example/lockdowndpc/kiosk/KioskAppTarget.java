package com.example.lockdowndpc.kiosk;

/**
 * What the device actually reports about a candidate single-app kiosk target.
 *
 * <p>The Android-side resolver fills this in from {@code PackageManager} and the
 * essential-system-package classification; {@link KioskConfigValidator} then
 * decides purely, which is what makes the rules testable off-device.
 *
 * @param packageName             package the administrator selected
 * @param installed               present with {@code FLAG_INSTALLED} for this user
 * @param enabled                 application component state is enabled
 * @param launchable              resolves a MAIN/LAUNCHER entry point
 * @param essentialSystemComponent classified as a package Device Guard must never
 *                                take over (system UI, settings provider, IME, …)
 * @param deviceGuardItself       the DPC's own package
 */
public record KioskAppTarget(
        String packageName,
        boolean installed,
        boolean enabled,
        boolean launchable,
        boolean essentialSystemComponent,
        boolean deviceGuardItself
) {
    public KioskAppTarget {
        packageName = packageName == null ? "" : packageName.trim();
    }

    /** A target that could not be resolved at all. */
    public static KioskAppTarget missing(String packageName) {
        return new KioskAppTarget(packageName, false, false, false, false, false);
    }
}
