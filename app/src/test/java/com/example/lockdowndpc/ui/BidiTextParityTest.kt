package com.example.lockdowndpc.ui

import com.example.lockdowndpc.kiosk.BidiText
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The kiosk host is Java and cannot see the `internal` Kotlin helpers the console
 * isolates its text with, so it has a twin in `kiosk/BidiText.java`. Two
 * implementations of the same Unicode rule drift silently — the marks are
 * invisible, and the failure only shows up as a scrambled app name on a Hebrew
 * device — so they are pinned to each other here.
 */
class BidiTextParityTest {

    @Test
    fun theJavaAndKotlinFirstStrongIsolationAgree() {
        listOf("סרטונים (בטא)", "כיתה 5-ב", "Videos (beta)", "com.example.app").forEach {
            assertEquals(it.bidiIsolated(), BidiText.bidiIsolated(it))
        }
    }

    @Test
    fun theJavaAndKotlinLeftToRightIsolationAgree() {
        listOf("https://portal.school.example:8443/a", "com.example.app").forEach {
            assertEquals(it.ltrIsolated(), BidiText.ltrIsolated(it))
        }
    }

    @Test
    fun bothLeaveAnEmptyValueAlone() {
        assertEquals("", BidiText.bidiIsolated(""))
        assertEquals("", BidiText.ltrIsolated(""))
        assertEquals("", "".bidiIsolated())
        assertEquals("", "".ltrIsolated())
    }

    @Test
    fun firstStrongIsolationIsNotTheLeftToRightOne() {
        // The distinction is the whole point: U+2068 takes the direction from the
        // first strong character, U+2066 forces L. Using the second on a Hebrew
        // app label is what rendered `סרטונים (בטא)` with its parentheses placed
        // as if the run were English.
        assertEquals(BidiText.FIRST_STRONG_ISOLATE, BidiText.bidiIsolated("x")[0])
        assertEquals(BidiText.LTR_ISOLATE, BidiText.ltrIsolated("x")[0])
        assertEquals(BidiText.POP_ISOLATE, BidiText.bidiIsolated("x").last())
    }
}
