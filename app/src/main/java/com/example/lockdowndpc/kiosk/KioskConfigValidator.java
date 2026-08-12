package com.example.lockdowndpc.kiosk;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Decides whether a {@link KioskConfig} may be armed or entered.
 *
 * <p>Pure by design: every rule below is a JVM test, so "kiosk refused to start
 * because the target was uninstalled" is proven without a device.
 */
public final class KioskConfigValidator {

    private static final Pattern PACKAGE_NAME = Pattern.compile(
            "^[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z0-9_]+)+$"
    );

    private KioskConfigValidator() {}

    /**
     * @param normalizedSiteUrl normalized target URL for {@link KioskMode#SINGLE_SITE},
     *                          otherwise {@code ""}
     * @param origin            containment origin for single-site, otherwise {@code null}
     */
    public record Validation(
            boolean valid,
            List<String> errors,
            String normalizedSiteUrl,
            KioskOrigin origin
    ) {
        public Validation {
            errors = List.copyOf(errors);
            if (valid && !errors.isEmpty()) {
                throw new IllegalArgumentException("A valid kiosk configuration cannot carry errors");
            }
        }
    }

    /**
     * @param target resolved device state for the configured package; may be
     *               {@code null} for modes that do not use an app target
     */
    public static Validation validate(KioskConfig config, KioskAppTarget target) {
        List<String> errors = new ArrayList<>();
        if (config == null) {
            return new Validation(false, List.of("missing-config"), "", null);
        }

        switch (config.mode()) {
            case OFF -> {
                return new Validation(true, List.of(), "", null);
            }
            case SINGLE_APP -> {
                validateAppTarget(config, target, errors);
                return new Validation(errors.isEmpty(), errors, "", null);
            }
            case SINGLE_SITE -> {
                KioskUrl.Result normalized = KioskUrl.normalize(config.siteUrl());
                if (!normalized.ok()) {
                    errors.add("site:" + normalized.error());
                    return new Validation(false, errors, "", null);
                }
                return new Validation(
                        true,
                        List.of(),
                        normalized.value().url(),
                        normalized.value().origin()
                );
            }
            default -> {
                return new Validation(false, List.of("unknown-mode"), "", null);
            }
        }
    }

    private static void validateAppTarget(
            KioskConfig config,
            KioskAppTarget target,
            List<String> errors
    ) {
        String packageName = config.targetPackage();
        if (packageName.isEmpty()) {
            errors.add("target:not-selected");
            return;
        }
        if (!PACKAGE_NAME.matcher(packageName).matches()) {
            errors.add("target:invalid-package-name");
            return;
        }
        if (target == null) {
            errors.add("target:unresolved");
            return;
        }
        if (!packageName.equals(target.packageName())) {
            // The resolver must answer about the package that was selected; a
            // mismatch means the selection was substituted somewhere.
            errors.add("target:selection-mismatch");
            return;
        }
        if (target.deviceGuardItself()) {
            errors.add("target:is-device-guard");
        }
        if (target.essentialSystemComponent()) {
            errors.add("target:essential-system-component");
        }
        if (!target.installed()) {
            errors.add("target:not-installed");
        }
        if (!target.enabled()) {
            errors.add("target:not-enabled");
        }
        if (!target.launchable()) {
            errors.add("target:not-launchable");
        }
    }
}
