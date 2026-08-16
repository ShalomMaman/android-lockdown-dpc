package com.example.lockdowndpc.ui

import java.util.Locale

/**
 * Pure helpers shared by the console screens. Everything here is free of Android
 * dependencies so it can be covered by plain JVM unit tests.
 */

/** Longest admin PIN accepted by `AdminPinStore.isValidPin`. */
internal const val MAX_PIN_LENGTH = 12

/**
 * Fallback scrim for system bars on API levels that cannot draw dark icons.
 * Same value the AndroidX default uses.
 */
internal val SYSTEM_BAR_DARK_SCRIM: Int = 0x801B1B1BL.toInt()

/** U+2066 LEFT-TO-RIGHT ISOLATE. */
internal const val LTR_ISOLATE = '⁦'

/** U+2068 FIRST STRONG ISOLATE. */
internal const val FIRST_STRONG_ISOLATE = '⁨'

/** U+2069 POP DIRECTIONAL ISOLATE. */
internal const val POP_ISOLATE = '⁩'

/**
 * Wraps [this] in Unicode isolate marks so known left-to-right content such as a
 * package name, a URL, a version identifier or a hash keeps its own direction and
 * its own punctuation order when it is rendered inside a right-to-left paragraph.
 *
 * This is the platform equivalent of HTML `<span dir="ltr">`; the marks are
 * formatting characters, so they neither print nor affect a text-to-speech pass.
 */
internal fun String.ltrIsolated(): String =
    if (isEmpty()) this else "$LTR_ISOLATE$this$POP_ISOLATE"

/**
 * Isolates [this] without forcing a direction: the Unicode bidi algorithm picks
 * the base direction from the first strong character, and the result cannot leak
 * into the surrounding paragraph either way.
 *
 * This is the platform equivalent of HTML `<bdi>`, and it is the right tool for
 * values whose language is not known at build time: third-party app labels, policy
 * failure details, and update messages, which mix Hebrew prose with Latin class and
 * package names.
 */
internal fun String.bidiIsolated(): String =
    if (isEmpty()) this else "$FIRST_STRONG_ISOLATE$this$POP_ISOLATE"

/** Every isolate mark this app inserts, so tests and callers can strip them. */
internal val ISOLATE_MARKS = charArrayOf(LTR_ISOLATE, FIRST_STRONG_ISOLATE, POP_ISOLATE)

/**
 * Isolates each line of a multi-line listing on its own. The audit log mixes
 * timestamps with entries recorded in whichever language was active at the time,
 * and isolating the block as a whole would let the first entry decide the
 * direction of every line below it.
 */
internal fun bidiIsolatedLines(text: String): String =
    text.lineSequence().joinToString("\n") { it.bidiIsolated() }

/** The display languages Device Guard ships a complete translation for. */
internal enum class LanguageChoice { SYSTEM, ENGLISH, HEBREW }

/**
 * Resolves the persisted display language from a comma-separated BCP-47 list, the
 * form `LocaleListCompat.toLanguageTags()` returns. An empty list means "follow the
 * system", which is the shipped default, so an already-Hebrew device keeps Hebrew.
 *
 * Hebrew is accepted under both its modern tag `he` and the legacy code `iw` that
 * `java.util.Locale` still reports; a tag this build has no translation for falls
 * back to the system locale rather than pinning a language the operator never chose.
 */
internal fun languageChoiceOf(languageTags: String): LanguageChoice {
    val primary = languageTags.substringBefore(',').trim()
    if (primary.isEmpty()) {
        return LanguageChoice.SYSTEM
    }
    return when (primary.substringBefore('-').lowercase(Locale.ROOT)) {
        "en" -> LanguageChoice.ENGLISH
        "he", "iw" -> LanguageChoice.HEBREW
        else -> LanguageChoice.SYSTEM
    }
}

/** The BCP-47 tag to persist for [choice], or `null` to follow the system. */
internal fun languageTagOf(choice: LanguageChoice): String? = when (choice) {
    LanguageChoice.SYSTEM -> null
    LanguageChoice.ENGLISH -> "en"
    LanguageChoice.HEBREW -> "he"
}

/** Mirrors the digit-only, max-12 input filter of the previous `EditText`. */
internal fun sanitizePin(raw: String): String =
    raw.filter { it in '0'..'9' }.take(MAX_PIN_LENGTH)

internal enum class LockoutUnit { SECONDS, MINUTES }

internal data class LockoutDelay(val amount: Long, val unit: LockoutUnit)

/**
 * Rounds a remaining lockout window up to whole seconds, and to whole minutes
 * once it no longer fits in a minute. Matches the wording rules of the shipped
 * build so operators see the same retry guidance.
 */
internal fun lockoutDelayOf(remainingMillis: Long): LockoutDelay {
    val seconds = maxOf(1L, (remainingMillis + 999L) / 1_000L)
    return if (seconds < 60L) {
        LockoutDelay(seconds, LockoutUnit.SECONDS)
    } else {
        LockoutDelay((seconds + 59L) / 60L, LockoutUnit.MINUTES)
    }
}

/** Free-text search over an app row; matches the label or the package name. */
internal fun matchesAppQuery(label: String, packageName: String, query: String): Boolean {
    val trimmed = query.trim()
    return trimmed.isEmpty() ||
        label.contains(trimmed, ignoreCase = true) ||
        packageName.contains(trimmed, ignoreCase = true)
}

/**
 * Whether a direct apply failure has become stale because a later reconciliation
 * proved the requested protection active.
 *
 * Other error banners are never candidates: the caller supplies true only when
 * the banner still on screen is the exact failure object produced by that apply.
 */
internal fun shouldDismissReconciledApplyFailure(
    isCurrentApplyFailure: Boolean,
    policyActive: Boolean,
    protectionEnabled: Boolean,
): Boolean = isCurrentApplyFailure && policyActive && protectionEnabled
