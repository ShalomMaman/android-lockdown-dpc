package com.example.lockdowndpc.ui

import com.example.lockdowndpc.kiosk.KioskController
import com.example.lockdowndpc.kiosk.KioskUrl
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.function.Consumer

/** A transition result plus its independently reported serialized policy pass. */
internal data class KioskActionAttempt(
    val result: KioskController.Result,
    val reconciliationCompleted: Boolean,
    val reconciliationVerified: Boolean,
)

/** Blocking test seam used from an IO dispatcher, never from the main thread. */
internal fun awaitKioskAction(
    timeout: Long,
    unit: TimeUnit,
    request: (Consumer<Boolean>) -> KioskController.Result,
): KioskActionAttempt {
    val reconciled = CountDownLatch(1)
    var verified = false
    val outcome = request(Consumer { passVerified ->
        verified = passVerified
        reconciled.countDown()
    })
    val completed = reconciled.await(timeout, unit)
    return KioskActionAttempt(outcome, completed, completed && verified)
}

/**
 * Pure decisions and formatting for the kiosk administration flow.
 *
 * Free of Android APIs on purpose, exactly like [UiLogic]: the interesting parts
 * of this flow are "which refusal is this, and what should an operator do about
 * it", and those are worth proving on the JVM rather than on a device that has
 * to be re-provisioned after every wrong answer.
 *
 * The controller and the state machine speak stable machine reasons
 * (`admin-authentication-required`, `site:scheme-not-https`, …). Mapping them to
 * an enum here, and the enum to a string resource in the composable, keeps this
 * file testable and keeps every operator-facing word in `strings.xml` where the
 * locale parity check can see it.
 */

/** Why a kiosk request was refused, in terms an operator can act on. */
internal enum class KioskFailure {
    AUTH_REQUIRED,
    INVALID_CONFIGURATION,
    NOT_CONFIGURED,
    NOT_ACTIVE,
    NOT_DEVICE_OWNER,
    UNKNOWN,
}

/**
 * Classifies a [com.example.lockdowndpc.kiosk.KioskController.Result] reason.
 *
 * An unrecognised reason deliberately becomes [KioskFailure.UNKNOWN] rather than
 * anything reassuring: the console then shows the raw code, which is what a
 * support call actually needs.
 */
internal fun kioskFailureOf(reason: String?): KioskFailure = when (reason?.trim()) {
    "admin-authentication-required" -> KioskFailure.AUTH_REQUIRED
    "invalid-configuration" -> KioskFailure.INVALID_CONFIGURATION
    "not-configured" -> KioskFailure.NOT_CONFIGURED
    "not-active", "not-active-before-restart" -> KioskFailure.NOT_ACTIVE
    "not-device-owner" -> KioskFailure.NOT_DEVICE_OWNER
    else -> KioskFailure.UNKNOWN
}

/**
 * The reasons {@code KioskStateMachine} reports for a transition it *allowed*.
 *
 * A `KioskController.Result` that carries one of these was authorized and
 * recorded; `allowed()` may still be false, which means the device did not
 * confirm every enforcement step. The console has to tell those two apart,
 * because "refused" and "applied but unverified" need opposite next steps.
 */
private val KIOSK_SUCCESS_REASONS =
    setOf("configured", "entered", "exited", "cleared", "restored")

internal fun isKioskSuccessReason(reason: String?): Boolean =
    reason?.trim() in KIOSK_SUCCESS_REASONS

/** One concrete reason a stored kiosk configuration cannot be used. */
internal enum class KioskConfigProblem {
    TARGET_NOT_SELECTED,
    TARGET_INVALID_NAME,
    TARGET_UNRESOLVED,
    TARGET_MISMATCH,
    TARGET_DEVICE_GUARD,
    TARGET_PROTECTED,
    TARGET_NOT_INSTALLED,
    TARGET_NOT_ENABLED,
    TARGET_NOT_LAUNCHABLE,
    SITE_MISSING,
    SITE_SCHEME,
    SITE_CREDENTIALS,
    SITE_HOST,
    SITE_PORT,
    SITE_MALFORMED,
    UNKNOWN,
}

/**
 * Classifies one entry of `KioskConfigValidator.Validation.errors()`.
 *
 * Every shape `KioskUrl` can reject collapses into one of five site problems.
 * The narrow ones — scheme, credentials, host, port — are the ones an operator
 * can fix by editing what they typed; everything else (an opaque URI, a relative
 * URL, a control character, a dot segment, an over-long value) reads as "this is
 * not one absolute HTTPS address", which is the only useful thing to say.
 */
internal fun kioskConfigProblemOf(code: String?): KioskConfigProblem {
    val trimmed = code?.trim().orEmpty()
    return if (trimmed.isEmpty()) KioskConfigProblem.UNKNOWN else classifyProblem(trimmed)
}

private fun classifyProblem(code: String): KioskConfigProblem = when (code) {
    "target:not-selected" -> KioskConfigProblem.TARGET_NOT_SELECTED
    "target:invalid-package-name" -> KioskConfigProblem.TARGET_INVALID_NAME
    "target:unresolved" -> KioskConfigProblem.TARGET_UNRESOLVED
    "target:selection-mismatch" -> KioskConfigProblem.TARGET_MISMATCH
    "target:is-device-guard" -> KioskConfigProblem.TARGET_DEVICE_GUARD
    "target:essential-system-component" -> KioskConfigProblem.TARGET_PROTECTED
    "target:not-installed" -> KioskConfigProblem.TARGET_NOT_INSTALLED
    "target:not-enabled" -> KioskConfigProblem.TARGET_NOT_ENABLED
    "target:not-launchable" -> KioskConfigProblem.TARGET_NOT_LAUNCHABLE
    "missing-config", "unknown-mode" -> KioskConfigProblem.UNKNOWN
    else -> if (code.startsWith("site:")) siteProblem(code.removePrefix("site:")) else
        KioskConfigProblem.UNKNOWN
}

private fun siteProblem(code: String): KioskConfigProblem = when (code) {
    "missing-url" -> KioskConfigProblem.SITE_MISSING
    "scheme-not-https" -> KioskConfigProblem.SITE_SCHEME
    "credentials-in-url" -> KioskConfigProblem.SITE_CREDENTIALS
    "missing-host", "invalid-host" -> KioskConfigProblem.SITE_HOST
    "invalid-port" -> KioskConfigProblem.SITE_PORT
    else -> KioskConfigProblem.SITE_MALFORMED
}

/**
 * What the site editor shows under the address field while it is being typed.
 *
 * [entered] is false for an empty field, which is why the editor stays quiet
 * before an operator has typed anything instead of greeting them with an error.
 */
internal data class KioskSitePreview(
    val entered: Boolean,
    val normalizedUrl: String,
    val origin: String,
    val problem: KioskConfigProblem?,
) {
    val usable: Boolean get() = entered && problem == null
}

/**
 * Normalizes [raw] with the same rule the device applies, so the operator sees
 * the address that will actually be opened and the origin navigation is confined
 * to before anything is stored.
 */
internal fun kioskSitePreviewOf(raw: String): KioskSitePreview {
    if (raw.isBlank()) {
        return KioskSitePreview(entered = false, normalizedUrl = "", origin = "", problem = null)
    }
    val result = KioskUrl.normalize(raw)
    if (!result.ok()) {
        return KioskSitePreview(
            entered = true,
            normalizedUrl = "",
            origin = "",
            problem = siteProblem(result.error().orEmpty()),
        )
    }
    return KioskSitePreview(
        entered = true,
        normalizedUrl = result.value().url(),
        origin = result.value().origin().value(),
        problem = null,
    )
}
