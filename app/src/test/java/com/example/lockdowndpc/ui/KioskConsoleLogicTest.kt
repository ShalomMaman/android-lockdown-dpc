package com.example.lockdowndpc.ui

import com.example.lockdowndpc.kiosk.KioskController
import com.example.lockdowndpc.kiosk.KioskStateMachine.KioskState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.TimeUnit

/**
 * The console's own decisions: which refusal an operator is looking at, which
 * concrete configuration problem to name, and what the site editor shows while
 * an address is being typed.
 *
 * All pure, so the flow that is otherwise only reachable on a Device
 * Owner-provisioned handset is proven here instead.
 */
class KioskConsoleLogicTest {

    private fun transitionResult() = KioskController.Result(
        true,
        KioskState.OFF,
        "exited",
        emptyList(),
    )

    @Test
    fun kioskActionWaiterDistinguishesVerifiedFailureFromCompletion() {
        val attempt = awaitKioskAction(1, TimeUnit.SECONDS) { done ->
            done.accept(false)
            transitionResult()
        }

        assertTrue(attempt.reconciliationCompleted)
        assertFalse(attempt.reconciliationVerified)
    }

    @Test
    fun kioskActionWaiterDoesNotTreatTimeoutAsSuccess() {
        val attempt = awaitKioskAction(0, TimeUnit.MILLISECONDS) {
            transitionResult()
        }

        assertFalse(attempt.reconciliationCompleted)
        assertFalse(attempt.reconciliationVerified)
    }

    @Test
    fun kioskActionWaiterAcceptsOnlyAnExplicitVerifiedCompletion() {
        val attempt = awaitKioskAction(1, TimeUnit.SECONDS) { done ->
            done.accept(true)
            transitionResult()
        }

        assertTrue(attempt.reconciliationCompleted)
        assertTrue(attempt.reconciliationVerified)
    }

    @Test
    fun everyStateMachineRefusalIsClassified() {
        assertEquals(
            KioskFailure.AUTH_REQUIRED,
            kioskFailureOf("admin-authentication-required"),
        )
        assertEquals(KioskFailure.INVALID_CONFIGURATION, kioskFailureOf("invalid-configuration"))
        assertEquals(KioskFailure.NOT_CONFIGURED, kioskFailureOf("not-configured"))
        assertEquals(KioskFailure.NOT_ACTIVE, kioskFailureOf("not-active"))
        assertEquals(KioskFailure.NOT_ACTIVE, kioskFailureOf("not-active-before-restart"))
        assertEquals(KioskFailure.NOT_DEVICE_OWNER, kioskFailureOf("not-device-owner"))
    }

    @Test
    fun anUnrecognisedRefusalStaysUnknownRatherThanReassuring() {
        // The console then prints the raw code, which is what a support call
        // needs. Mapping an unknown reason onto a friendly bucket would hide the
        // one piece of information that identifies a new failure mode.
        assertEquals(KioskFailure.UNKNOWN, kioskFailureOf("something-new"))
        assertEquals(KioskFailure.UNKNOWN, kioskFailureOf(null))
        assertEquals(KioskFailure.UNKNOWN, kioskFailureOf(""))
    }

    @Test
    fun successReasonsAreDistinguishedFromRefusals() {
        // "allowed and recorded" versus "refused" need opposite next steps, and
        // the reason string is what tells them apart: a recorded transition whose
        // device pass reported errors still carries a success reason.
        listOf("configured", "entered", "exited", "cleared", "restored").forEach {
            assertTrue(it, isKioskSuccessReason(it))
        }
        listOf(
            "admin-authentication-required",
            "invalid-configuration",
            "not-active",
            "not-device-owner",
            "already-restored",
            "",
        ).forEach { assertFalse(it, isKioskSuccessReason(it)) }
        assertFalse(isKioskSuccessReason(null))
    }

    @Test
    fun everyValidatorTargetErrorIsClassified() {
        assertEquals(
            KioskConfigProblem.TARGET_NOT_SELECTED,
            kioskConfigProblemOf("target:not-selected"),
        )
        assertEquals(
            KioskConfigProblem.TARGET_INVALID_NAME,
            kioskConfigProblemOf("target:invalid-package-name"),
        )
        assertEquals(
            KioskConfigProblem.TARGET_UNRESOLVED,
            kioskConfigProblemOf("target:unresolved"),
        )
        assertEquals(
            KioskConfigProblem.TARGET_MISMATCH,
            kioskConfigProblemOf("target:selection-mismatch"),
        )
        assertEquals(
            KioskConfigProblem.TARGET_DEVICE_GUARD,
            kioskConfigProblemOf("target:is-device-guard"),
        )
        assertEquals(
            KioskConfigProblem.TARGET_PROTECTED,
            kioskConfigProblemOf("target:essential-system-component"),
        )
        assertEquals(
            KioskConfigProblem.TARGET_NOT_INSTALLED,
            kioskConfigProblemOf("target:not-installed"),
        )
        assertEquals(
            KioskConfigProblem.TARGET_NOT_ENABLED,
            kioskConfigProblemOf("target:not-enabled"),
        )
        assertEquals(
            KioskConfigProblem.TARGET_NOT_LAUNCHABLE,
            kioskConfigProblemOf("target:not-launchable"),
        )
    }

    @Test
    fun siteErrorsCollapseOntoTheAdviceAnOperatorCanAct() {
        assertEquals(KioskConfigProblem.SITE_MISSING, kioskConfigProblemOf("site:missing-url"))
        assertEquals(KioskConfigProblem.SITE_SCHEME, kioskConfigProblemOf("site:scheme-not-https"))
        assertEquals(
            KioskConfigProblem.SITE_CREDENTIALS,
            kioskConfigProblemOf("site:credentials-in-url"),
        )
        assertEquals(KioskConfigProblem.SITE_HOST, kioskConfigProblemOf("site:invalid-host"))
        assertEquals(KioskConfigProblem.SITE_HOST, kioskConfigProblemOf("site:missing-host"))
        assertEquals(KioskConfigProblem.SITE_PORT, kioskConfigProblemOf("site:invalid-port"))
        // Everything else reads as "this is not one absolute HTTPS address",
        // because naming a dot segment or a C1 control to an operator helps
        // nobody.
        listOf(
            "site:unparsable-url",
            "site:opaque-url",
            "site:relative-url",
            "site:illegal-character",
            "site:url-too-long",
            "site:invalid-path",
            "site:relative-path-segment",
        ).forEach { assertEquals(it, KioskConfigProblem.SITE_MALFORMED, kioskConfigProblemOf(it)) }
    }

    @Test
    fun anUnknownProblemCodeIsNotSilentlyDropped() {
        assertEquals(KioskConfigProblem.UNKNOWN, kioskConfigProblemOf("missing-config"))
        assertEquals(KioskConfigProblem.UNKNOWN, kioskConfigProblemOf("unknown-mode"))
        assertEquals(KioskConfigProblem.UNKNOWN, kioskConfigProblemOf("target:brand-new"))
        assertEquals(KioskConfigProblem.UNKNOWN, kioskConfigProblemOf(null))
    }

    @Test
    fun anEmptyAddressFieldIsNotAnError() {
        val preview = kioskSitePreviewOf("   ")

        assertFalse(preview.entered)
        assertFalse(preview.usable)
        assertNull(preview.problem)
    }

    @Test
    fun previewShowsTheAddressThatWillActuallyBeOpened() {
        val preview = kioskSitePreviewOf("  HTTPS://Portal.School.Example  ")

        assertTrue(preview.usable)
        assertEquals("https://portal.school.example/", preview.normalizedUrl)
        assertEquals("https://portal.school.example", preview.origin)
    }

    @Test
    fun previewKeepsAPathAndShowsTheNarrowerOrigin() {
        // The origin is the containment unit, and it is deliberately narrower
        // than the address: a path is opened, but the whole origin is reachable.
        val preview = kioskSitePreviewOf("https://portal.school.example:8443/lms/home")

        assertTrue(preview.usable)
        assertEquals("https://portal.school.example:8443/lms/home", preview.normalizedUrl)
        assertEquals("https://portal.school.example:8443", preview.origin)
    }

    @Test
    fun previewRefusesEveryAddressTheDeviceWouldRefuse() {
        assertEquals(
            KioskConfigProblem.SITE_SCHEME,
            kioskSitePreviewOf("http://portal.school.example").problem,
        )
        assertEquals(
            KioskConfigProblem.SITE_CREDENTIALS,
            kioskSitePreviewOf("https://user:secret@portal.school.example").problem,
        )
        assertEquals(
            KioskConfigProblem.SITE_HOST,
            kioskSitePreviewOf("https://portal").problem,
        )
        assertEquals(
            KioskConfigProblem.SITE_MALFORMED,
            kioskSitePreviewOf("javascript:alert(1)").problem,
        )
        // A non-ASCII host is refused rather than repaired, which removes the
        // whole homograph class; an internationalized domain is configured in
        // its punycode form instead.
        assertFalse(kioskSitePreviewOf("https://פורטל.example").usable)
        assertFalse(kioskSitePreviewOf("intent://portal.school.example#Intent;end").usable)
        assertFalse(kioskSitePreviewOf("https://good\\@evil.example").usable)
    }

    @Test
    fun anUnusablePreviewCarriesNoOriginToDisplay() {
        val preview = kioskSitePreviewOf("http://portal.school.example")

        assertTrue(preview.entered)
        assertFalse(preview.usable)
        assertEquals("", preview.origin)
        assertEquals("", preview.normalizedUrl)
    }
}
