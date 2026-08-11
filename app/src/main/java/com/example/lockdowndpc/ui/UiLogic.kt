package com.example.lockdowndpc.ui

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

/** U+2069 POP DIRECTIONAL ISOLATE. */
internal const val POP_ISOLATE = '⁩'

/**
 * Wraps [this] in Unicode isolate marks so Latin content such as a package name
 * or a recovery code keeps its own direction when it is rendered inside a
 * right-to-left paragraph.
 */
internal fun String.ltrIsolated(): String = "$LTR_ISOLATE$this$POP_ISOLATE"

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
