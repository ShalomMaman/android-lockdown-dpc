package com.example.lockdowndpc.kiosk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class KioskConfigValidatorTest {

    private static KioskAppTarget healthy(String packageName) {
        return new KioskAppTarget(packageName, true, true, true, false, false);
    }

    @Test
    public void offIsAlwaysValidAndCarriesNoTarget() {
        KioskConfigValidator.Validation validation =
                KioskConfigValidator.validate(KioskConfig.OFF, null);

        assertTrue(validation.valid());
        assertEquals("", validation.normalizedSiteUrl());
        assertNull(validation.origin());
    }

    @Test
    public void singleAppAcceptsAnInstalledEnabledLaunchableTarget() {
        KioskConfigValidator.Validation validation = KioskConfigValidator.validate(
                KioskConfig.singleApp("com.example.reader"),
                healthy("com.example.reader")
        );

        assertTrue(validation.errors().toString(), validation.valid());
    }

    @Test
    public void singleAppRejectsAnUnselectedOrMalformedTarget() {
        assertEquals(
                java.util.List.of("target:not-selected"),
                KioskConfigValidator.validate(KioskConfig.singleApp(""), null).errors()
        );
        assertEquals(
                java.util.List.of("target:invalid-package-name"),
                KioskConfigValidator.validate(
                        KioskConfig.singleApp("not a package"), null).errors()
        );
        assertEquals(
                java.util.List.of("target:unresolved"),
                KioskConfigValidator.validate(
                        KioskConfig.singleApp("com.example.reader"), null).errors()
        );
    }

    @Test
    public void singleAppRejectsDeviceGuardItself() {
        KioskConfigValidator.Validation validation = KioskConfigValidator.validate(
                KioskConfig.singleApp("com.example.lockdowndpc"),
                new KioskAppTarget("com.example.lockdowndpc", true, true, true, false, true)
        );

        assertFalse(validation.valid());
        assertTrue(validation.errors().contains("target:is-device-guard"));
    }

    @Test
    public void singleAppRejectsCriticalSystemComponents() {
        KioskConfigValidator.Validation validation = KioskConfigValidator.validate(
                KioskConfig.singleApp("com.android.systemui"),
                new KioskAppTarget("com.android.systemui", true, true, true, true, false)
        );

        assertFalse(validation.valid());
        assertTrue(validation.errors().contains("target:essential-system-component"));
    }

    @Test
    public void singleAppRejectsUninstalledDisabledOrUnlaunchableTargets() {
        KioskConfigValidator.Validation validation = KioskConfigValidator.validate(
                KioskConfig.singleApp("com.example.reader"),
                new KioskAppTarget("com.example.reader", false, false, false, false, false)
        );

        assertFalse(validation.valid());
        assertTrue(validation.errors().contains("target:not-installed"));
        assertTrue(validation.errors().contains("target:not-enabled"));
        assertTrue(validation.errors().contains("target:not-launchable"));
    }

    @Test
    public void singleAppRejectsAResolverAnsweringAboutAnotherPackage() {
        KioskConfigValidator.Validation validation = KioskConfigValidator.validate(
                KioskConfig.singleApp("com.example.reader"),
                healthy("com.example.other")
        );

        assertEquals(java.util.List.of("target:selection-mismatch"), validation.errors());
    }

    @Test
    public void singleSiteNormalizesAndDerivesTheContainmentOrigin() {
        KioskConfigValidator.Validation validation = KioskConfigValidator.validate(
                KioskConfig.singleSite("  HTTPS://Portal.School.Example  "),
                null
        );

        assertTrue(validation.valid());
        assertEquals("https://portal.school.example/", validation.normalizedSiteUrl());
        assertEquals("https://portal.school.example", validation.origin().value());
    }

    @Test
    public void singleSiteRejectsEveryNonHttpsTarget() {
        assertEquals(
                java.util.List.of("site:scheme-not-https"),
                KioskConfigValidator.validate(
                        KioskConfig.singleSite("http://portal.school.example"), null).errors()
        );
        assertEquals(
                java.util.List.of("site:credentials-in-url"),
                KioskConfigValidator.validate(
                        KioskConfig.singleSite("https://a:b@portal.school.example"), null).errors()
        );
        assertEquals(
                java.util.List.of("site:missing-url"),
                KioskConfigValidator.validate(KioskConfig.singleSite(""), null).errors()
        );
    }

    @Test
    public void validationCannotClaimValidWhileCarryingErrors() {
        org.junit.Assert.assertThrows(IllegalArgumentException.class, () ->
                new KioskConfigValidator.Validation(true, java.util.List.of("boom"), "", null)
        );
    }
}
