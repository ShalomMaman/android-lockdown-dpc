package com.example.lockdowndpc.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
    fun ltrIsolated_wrapsInIsolateMarks() {
        val isolated = "com.example.app".ltrIsolated()
        assertEquals(LTR_ISOLATE, isolated.first())
        assertEquals(POP_ISOLATE, isolated.last())
        assertEquals("com.example.app", isolated.substring(1, isolated.length - 1))
    }
}
