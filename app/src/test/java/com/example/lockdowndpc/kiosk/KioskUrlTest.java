package com.example.lockdowndpc.kiosk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class KioskUrlTest {

    private static KioskUrl.Normalized normalized(String raw) {
        KioskUrl.Result result = KioskUrl.normalize(raw);
        assertTrue("expected " + raw + " to normalize, got " + result.error(), result.ok());
        return result.value();
    }

    private static void rejects(String raw, String expectedError) {
        KioskUrl.Result result = KioskUrl.normalize(raw);
        assertFalse("expected " + raw + " to be rejected", result.ok());
        assertEquals(expectedError, result.error());
    }

    @Test
    public void addsRootPathAndKeepsDefaultPortImplicit() {
        KioskUrl.Normalized value = normalized("https://portal.school.example");

        assertEquals("https://portal.school.example/", value.url());
        assertEquals(443, value.port());
        assertEquals("https://portal.school.example", value.origin().value());
    }

    @Test
    public void lowerCasesSchemeAndHostButNotPath() {
        KioskUrl.Normalized value = normalized("HTTPS://Portal.School.Example/Grades?Term=A");

        assertEquals("https://portal.school.example/Grades?Term=A", value.url());
        assertEquals("portal.school.example", value.host());
    }

    @Test
    public void acceptsPunycodeHostAndRejectsNonAsciiHomographs() {
        assertEquals("xn--bcher-kva.example", normalized("https://xn--bcher-kva.example/katalog").host());

        KioskUrl.Result unicode = KioskUrl.normalize("https://bücher.example/katalog");
        assertFalse(unicode.ok());
    }

    @Test
    public void keepsExplicitNonDefaultPort() {
        KioskUrl.Normalized value = normalized("https://portal.school.example:8443/app");

        assertEquals(8443, value.port());
        assertEquals("https://portal.school.example:8443/app", value.url());
        assertEquals("https://portal.school.example:8443", value.origin().value());
    }

    @Test
    public void dropsRedundantDefaultPort() {
        assertEquals("https://portal.school.example/", normalized("https://portal.school.example:443").url());
    }

    @Test
    public void rejectsPlainHttp() {
        rejects("http://portal.school.example/", "scheme-not-https");
    }

    @Test
    public void rejectsNonWebSchemes() {
        rejects("intent://portal.school.example#Intent;scheme=https;end", "scheme-not-https");
        rejects("file:///sdcard/index.html", "scheme-not-https");
        rejects("content://media/external/file/1", "scheme-not-https");
        rejects("javascript:alert(1)", "opaque-url");
        rejects("data:text/plain,hello", "opaque-url");
        rejects("blob:https://portal.school.example/1234", "opaque-url");
        rejects("myschoolapp://open", "scheme-not-https");
    }

    @Test
    public void rejectsEmbeddedCredentials() {
        rejects("https://admin:secret@portal.school.example/", "credentials-in-url");
        rejects("https://portal.school.example@evil.example/", "credentials-in-url");
    }

    @Test
    public void rejectsWhitespaceAndBackslashTricks() {
        rejects("https://portal.school.example/a b", "illegal-character");
        rejects("https://portal.school.example\\@evil.example", "illegal-character");
        rejects("https://portal.school.example/\nGET /", "illegal-character");
    }

    @Test
    public void rejectsMissingOrUnusableHost() {
        rejects("https:///path", "missing-host");
        rejects("https://portal", "invalid-host");
        rejects("", "missing-url");
        rejects(null, "missing-url");
        rejects("/relative/path", "relative-url");
    }

    @Test
    public void rejectsDotSegmentPaths() {
        rejects("https://portal.school.example/a/../../etc", "relative-path-segment");
        rejects("https://portal.school.example/a/%2e%2e/b", "relative-path-segment");
    }

    @Test
    public void schemeOfIsCaseInsensitiveAndSafeOnGarbage() {
        assertEquals("intent", KioskUrl.schemeOf("Intent://x"));
        assertEquals("javascript", KioskUrl.schemeOf("JavaScript:alert(1)"));
        assertEquals("", KioskUrl.schemeOf("no-scheme-here"));
        assertEquals("", KioskUrl.schemeOf("://x"));
        assertEquals("", KioskUrl.schemeOf(null));
    }
}
