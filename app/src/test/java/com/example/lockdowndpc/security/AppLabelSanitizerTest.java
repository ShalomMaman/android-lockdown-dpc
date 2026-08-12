package com.example.lockdowndpc.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

public final class AppLabelSanitizerTest {

    @Test
    public void stripsLegacyBidiEmbeddingAndOverrideControls() {
        assertEquals("Trustedexe.live", AppLabelSanitizer.sanitize(
                "Trusted\u202Eexe.live\u202C"));
        assertEquals("abc", AppLabelSanitizer.sanitize(
                "\u202A\u202B\u202D\u202Eabc\u202C"));
    }

    @Test
    public void stripsMalformedAndNestedIsolateControls() {
        assertEquals("TrustedSettings", AppLabelSanitizer.sanitize(
                "Trusted\u2069\u2067Settings\u2066"));
        assertEquals("abc", AppLabelSanitizer.sanitize(
                "\u2066a\u2067b\u2068c\u2069"));
    }

    @Test
    public void ordinaryHebrewEnglishAndPunctuationRemainUntouched() {
        for (String label : new String[]{"School Portal", "פורטל בית ספר", "כיתה 5-ב (Beta)"}) {
            assertEquals(label, AppLabelSanitizer.sanitize(label));
        }
    }

    @Test
    public void nullAndEmptyRemainUntouched() {
        assertNull(AppLabelSanitizer.sanitize(null));
        assertEquals("", AppLabelSanitizer.sanitize(""));
    }
}
