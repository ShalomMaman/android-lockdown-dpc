package com.example.lockdowndpc.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UiLogicTest {

    @Test
    fun sanitizePin_dropsNonDigits() {
        assertEquals("123456", sanitizePin("1a2 3-4b5\n6"))
    }

    @Test
    fun sanitizePin_capsAtTwelveDigits() {
        assertEquals("123456789012", sanitizePin("12345678901234567890"))
    }

    @Test
    fun lockoutDelay_roundsPartialSecondsUp() {
        val delay = lockoutDelayOf(1_200L)
        assertEquals(LockoutUnit.SECONDS, delay.unit)
        assertEquals(2L, delay.amount)
    }

    @Test
    fun lockoutDelay_neverReportsZero() {
        assertEquals(1L, lockoutDelayOf(0L).amount)
        assertEquals(LockoutUnit.SECONDS, lockoutDelayOf(0L).unit)
    }

    @Test
    fun lockoutDelay_switchesToMinutesAtOneMinute() {
        val delay = lockoutDelayOf(60_000L)
        assertEquals(LockoutUnit.MINUTES, delay.unit)
        assertEquals(1L, delay.amount)
    }

    @Test
    fun lockoutDelay_roundsPartialMinutesUp() {
        val delay = lockoutDelayOf(5 * 60_000L - 1L)
        assertEquals(LockoutUnit.MINUTES, delay.unit)
        assertEquals(5L, delay.amount)
    }

    @Test
    fun appQuery_blankMatchesEverything() {
        assertTrue(matchesAppQuery("Signal", "org.thoughtcrime.securesms", "   "))
    }

    @Test
    fun appQuery_matchesLabelIgnoringCase() {
        assertTrue(matchesAppQuery("Signal", "org.thoughtcrime.securesms", "sig"))
    }

    @Test
    fun appQuery_matchesPackageName() {
        assertTrue(matchesAppQuery("Signal", "org.thoughtcrime.securesms", "thoughtcrime"))
    }

    @Test
    fun appQuery_rejectsUnrelatedTerm() {
        assertFalse(matchesAppQuery("Signal", "org.thoughtcrime.securesms", "telegram"))
    }

    @Test
    fun reconciledApplyFailure_isDismissedOnlyAfterVerifiedActiveReadBack() {
        assertTrue(shouldDismissReconciledApplyFailure(true, true, true))
        assertFalse(shouldDismissReconciledApplyFailure(true, false, true))
        assertFalse(shouldDismissReconciledApplyFailure(true, true, false))
    }

    @Test
    fun reconciledPolicy_neverDismissesAnUnrelatedBanner() {
        assertFalse(shouldDismissReconciledApplyFailure(false, true, true))
    }

    @Test
    fun ltrIsolated_wrapsInIsolateMarks() {
        val isolated = "com.example.app".ltrIsolated()
        assertEquals(LTR_ISOLATE, isolated.first())
        assertEquals(POP_ISOLATE, isolated.last())
        assertEquals("com.example.app", isolated.substring(1, isolated.length - 1))
    }

    @Test
    fun ltrIsolated_leavesAnEmptyValueAlone() {
        // An empty package name or code would otherwise become two stray marks
        // that a screen reader still has to walk over.
        assertEquals("", "".ltrIsolated())
    }

    @Test
    fun bidiIsolated_wrapsInFirstStrongIsolate() {
        val isolated = "מדיניות com.example.app".bidiIsolated()
        assertEquals(FIRST_STRONG_ISOLATE, isolated.first())
        assertEquals(POP_ISOLATE, isolated.last())
        assertEquals("מדיניות com.example.app", isolated.trim(*ISOLATE_MARKS))
    }

    @Test
    fun bidiIsolated_leavesAnEmptyValueAlone() {
        assertEquals("", "".bidiIsolated())
    }

    @Test
    fun bidiIsolatedLines_isolatesEachLineSeparately() {
        val isolated = bidiIsolatedLines("12/08/26 — הופעלה\n12/08/26 — SecurityException")
        val lines = isolated.split("\n")
        assertEquals(2, lines.size)
        lines.forEach { line ->
            assertEquals(FIRST_STRONG_ISOLATE, line.first())
            assertEquals(POP_ISOLATE, line.last())
        }
    }

    @Test
    fun languageChoice_defaultsToTheSystemLocale() {
        // The shipped default follows the system, so a Hebrew device is never
        // silently switched to English.
        assertEquals(LanguageChoice.SYSTEM, languageChoiceOf(""))
        assertEquals(LanguageChoice.SYSTEM, languageChoiceOf("   "))
    }

    @Test
    fun languageChoice_readsEnglishAndHebrewTags() {
        assertEquals(LanguageChoice.ENGLISH, languageChoiceOf("en"))
        assertEquals(LanguageChoice.ENGLISH, languageChoiceOf("en-US"))
        assertEquals(LanguageChoice.HEBREW, languageChoiceOf("he"))
        assertEquals(LanguageChoice.HEBREW, languageChoiceOf("he-IL"))
    }

    @Test
    fun languageChoice_acceptsTheLegacyHebrewCode() {
        // java.util.Locale still reports Hebrew as "iw", which is also why the
        // resource folder is res/values-iw.
        assertEquals(LanguageChoice.HEBREW, languageChoiceOf("iw"))
        assertEquals(LanguageChoice.HEBREW, languageChoiceOf("iw-IL"))
    }

    @Test
    fun languageChoice_usesTheFirstTagOfAList() {
        assertEquals(LanguageChoice.HEBREW, languageChoiceOf("he-IL,en-US"))
    }

    @Test
    fun languageChoice_fallsBackToTheSystemForAnUntranslatedLanguage() {
        assertEquals(LanguageChoice.SYSTEM, languageChoiceOf("ar"))
        assertEquals(LanguageChoice.SYSTEM, languageChoiceOf("fr-CA"))
    }

    @Test
    fun languageTag_roundTripsEveryChoice() {
        LanguageChoice.entries.forEach { choice ->
            assertEquals(choice, languageChoiceOf(languageTagOf(choice).orEmpty()))
        }
    }

    @Test
    fun languageTag_followsTheSystemWithoutATag() {
        assertNull(languageTagOf(LanguageChoice.SYSTEM))
        assertEquals("en", languageTagOf(LanguageChoice.ENGLISH))
        assertEquals("he", languageTagOf(LanguageChoice.HEBREW))
    }
}
