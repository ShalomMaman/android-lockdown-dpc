package com.example.lockdowndpc.kiosk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class KioskNavigationGuardTest {

    private static final KioskOrigin ORIGIN =
            new KioskOrigin("https", "portal.school.example", 443);

    private static void blocks(String url, String expectedReason) {
        KioskNavigationGuard.Verdict verdict = KioskNavigationGuard.evaluate(ORIGIN, url);
        assertFalse("expected " + url + " to be blocked", verdict.allowed());
        assertEquals(expectedReason, verdict.reason());
    }

    private static void allows(String url) {
        assertTrue("expected " + url + " to be allowed",
                KioskNavigationGuard.evaluate(ORIGIN, url).allowed());
    }

    @Test
    public void allowsExactOriginRegardlessOfPathQueryOrFragment() {
        allows("https://portal.school.example/");
        allows("https://portal.school.example/grades/2026?term=spring#top");
        allows("HTTPS://PORTAL.SCHOOL.EXAMPLE/login");
    }

    @Test
    public void blocksOtherHostsIncludingSubdomainsAndSuffixTricks() {
        blocks("https://mail.school.example/", "external-origin");
        blocks("https://school.example/", "external-origin");
        blocks("https://portal.school.example.evil.test/", "external-origin");
        blocks("https://evil.test/portal.school.example", "external-origin");
    }

    @Test
    public void blocksPortChangesOnTheSameHost() {
        blocks("https://portal.school.example:8443/", "external-origin");
    }

    @Test
    public void blocksMixedContentDowngrade() {
        blocks("http://portal.school.example/", "insecure-scheme:http");
    }

    @Test
    public void blocksAppLaunchAndLocalContentSchemes() {
        blocks("intent://portal.school.example#Intent;scheme=https;end", "blocked-scheme:intent");
        blocks("android-app://com.android.chrome/https/portal.school.example", "blocked-scheme:android-app");
        blocks("market://details?id=org.mozilla.firefox", "blocked-scheme:market");
        blocks("file:///sdcard/Download/page.html", "blocked-scheme:file");
        blocks("content://com.android.providers.downloads/1", "blocked-scheme:content");
        blocks("javascript:document.location='https://evil.test'", "blocked-scheme:javascript");
        blocks("data:text/plain,hello", "blocked-scheme:data");
        blocks("blob:https://portal.school.example/abcd", "blocked-scheme:blob");
        blocks("about:blank", "blocked-scheme:about");
        blocks("tel:+15551234", "blocked-scheme:tel");
    }

    @Test
    public void blocksUnknownCustomSchemes() {
        blocks("myschoolapp://open/grades", "scheme-not-https");
    }

    @Test
    public void blocksCredentialBearingUrlsOnTheConfiguredHost() {
        blocks("https://admin:secret@portal.school.example/", "credentials-in-url");
    }

    @Test
    public void failsClosedWithoutAConfiguredOrigin() {
        KioskNavigationGuard.Verdict verdict =
                KioskNavigationGuard.evaluate(null, "https://portal.school.example/");

        assertFalse(verdict.allowed());
        assertEquals("no-origin-configured", verdict.reason());
    }

    @Test
    public void failsClosedOnGarbage() {
        blocks("", "missing-url");
        blocks(null, "missing-url");
        blocks("https://portal.school.example/a b", "illegal-character");
    }
}
