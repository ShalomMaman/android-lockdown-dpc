package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.policy.BuiltInBlockExemptions.BrowserState;
import com.example.lockdowndpc.policy.BuiltInBlockExemptions.FilterEvidence;
import com.example.lockdowndpc.policy.BuiltInBlockExemptions.LinkRoute;
import com.example.lockdowndpc.policy.BuiltInBlockExemptions.Settings;

import org.junit.Test;

import java.util.Set;

public final class BuiltInBlockExemptionsTest {

    private static final String CHROME = "com.android.chrome";
    private static final String FIREFOX = "org.mozilla.firefox";
    private static final String WHATSAPP = "com.whatsapp";
    private static final String TELEGRAM = "org.telegram.messenger";
    private static final String PLAY_STORE = "com.android.vending";

    private static final FilterEvidence CONFIRMED_NO_CANARY = new FilterEvidence(true, false, false);
    private static final FilterEvidence CONFIRMED_CANARY_PASSED = new FilterEvidence(true, true, true);
    private static final FilterEvidence CONFIRMED_CANARY_FAILED = new FilterEvidence(true, true, false);
    private static final FilterEvidence FILTER_OFF = new FilterEvidence(false, false, false);
    private static final FilterEvidence FILTER_FAILING_CANARY_PASSED = new FilterEvidence(false, true, true);

    private static String exemptBrowserFor(Settings settings, FilterEvidence evidence) {
        return BuiltInBlockExemptions.exemptBrowser(
                settings, BuiltInBlockExemptions.browserState(settings, true, evidence));
    }

    // --- Defaults -----------------------------------------------------------

    @Test
    public void nothingIsExemptByDefault() {
        Settings none = Settings.NONE;
        assertFalse(none.any());
        assertEquals(BrowserState.OFF,
                BuiltInBlockExemptions.browserState(none, true, CONFIRMED_NO_CANARY));
        for (String packageName : LockdownPackages.ALWAYS_BLOCKED) {
            assertFalse(packageName, BuiltInBlockExemptions.keepsAvailable(packageName, none, null));
        }
        for (String packageName : LockdownPackages.KNOWN_BROWSER_AND_SOCIAL) {
            assertFalse(packageName, BuiltInBlockExemptions.keepsAvailable(packageName, none, null));
        }
    }

    // --- Browser through the filter -----------------------------------------

    @Test
    public void browserIsBlockedWhenTheHomeFilterIsOff() {
        Settings settings = Settings.NONE.withBrowser(CHROME);
        assertEquals(BrowserState.FILTER_UNVERIFIED,
                BuiltInBlockExemptions.browserState(settings, true, FILTER_OFF));
        assertNull(exemptBrowserFor(settings, FILTER_OFF));
        assertFalse(BuiltInBlockExemptions.keepsAvailable(CHROME, settings, null));
    }

    @Test
    public void browserIsBlockedWhenTheHomeFilterFailsReadBackEvenIfTheCanaryPassed() {
        Settings settings = Settings.NONE.withBrowser(CHROME);
        assertEquals(BrowserState.FILTER_UNVERIFIED,
                BuiltInBlockExemptions.browserState(settings, true, FILTER_FAILING_CANARY_PASSED));
        assertNull(exemptBrowserFor(settings, FILTER_FAILING_CANARY_PASSED));
    }

    @Test
    public void browserIsBlockedWhileAConfiguredCanaryHasNotPassed() {
        Settings settings = Settings.NONE.withBrowser(CHROME);
        assertEquals(BrowserState.CANARY_UNVERIFIED,
                BuiltInBlockExemptions.browserState(settings, true, CONFIRMED_CANARY_FAILED));
        assertNull(exemptBrowserFor(settings, CONFIRMED_CANARY_FAILED));
    }

    @Test
    public void browserIsAvailableOnlyWhenTheFilterIsConfirmed() {
        Settings settings = Settings.NONE.withBrowser(CHROME);
        assertEquals(BrowserState.ACTIVE,
                BuiltInBlockExemptions.browserState(settings, true, CONFIRMED_NO_CANARY));
        assertEquals(CHROME, exemptBrowserFor(settings, CONFIRMED_NO_CANARY));
        assertEquals(CHROME, exemptBrowserFor(settings, CONFIRMED_CANARY_PASSED));
        assertTrue(BuiltInBlockExemptions.keepsAvailable(
                CHROME, settings, exemptBrowserFor(settings, CONFIRMED_NO_CANARY)));
    }

    @Test
    public void browserIsBlockedAgainOnTheFirstPassAfterTheFilterLapses() {
        Settings settings = Settings.NONE.withBrowser(CHROME);
        String before = exemptBrowserFor(settings, CONFIRMED_CANARY_PASSED);
        String after = exemptBrowserFor(settings, CONFIRMED_CANARY_FAILED);
        assertEquals(CHROME, before);
        assertNull(after);
        assertFalse(BuiltInBlockExemptions.keepsAvailable(CHROME, settings, after));
    }

    @Test
    public void aMissingBrowserIsReportedAndNotExempted() {
        Settings settings = Settings.NONE.withBrowser(FIREFOX);
        BrowserState state = BuiltInBlockExemptions.browserState(settings, false, CONFIRMED_NO_CANARY);
        assertEquals(BrowserState.NOT_INSTALLED, state);
        assertNull(BuiltInBlockExemptions.exemptBrowser(settings, state));
    }

    @Test
    public void onlyOneBrowserIsEverAvailable() {
        Settings settings = Settings.NONE.withBrowser(CHROME).withBrowser(FIREFOX);
        assertEquals(FIREFOX, settings.browserPackage());
        String exempt = exemptBrowserFor(settings, CONFIRMED_NO_CANARY);
        int available = 0;
        for (String browser : BuiltInBlockExemptions.FILTERABLE_BROWSERS) {
            if (BuiltInBlockExemptions.keepsAvailable(browser, settings, exempt)) {
                available++;
                assertEquals(FIREFOX, browser);
            }
        }
        assertEquals(1, available);
    }

    @Test
    public void aBrowserCannotBeExemptedThroughTheSocialList() {
        assertThrows(IllegalArgumentException.class,
                () -> new Settings(null, Set.of(FIREFOX)));
        assertThrows(IllegalArgumentException.class,
                () -> Settings.NONE.withSocial(CHROME, true));
    }

    @Test
    public void aPackageOutsideTheBrowserCatalogueIsRefusedAsBrowser() {
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> Settings.NONE.withBrowser("org.example.notabrowser"));
        assertEquals("browser-not-filterable", refused.getMessage());
        assertThrows(IllegalArgumentException.class, () -> Settings.NONE.withBrowser(WHATSAPP));
        assertThrows(IllegalArgumentException.class,
                () -> Settings.NONE.withBrowser("com.google.android.googlequicksearchbox"));
    }

    // --- Stores -------------------------------------------------------------

    @Test
    public void storesAreNeverExemptable() {
        for (String store : BuiltInBlockExemptions.APP_STORES) {
            assertTrue(store, LockdownPackages.ALWAYS_BLOCKED.contains(store));
            assertFalse(store, BuiltInBlockExemptions.isFilterableBrowser(store));
            assertFalse(store, BuiltInBlockExemptions.isExemptableSocial(store));
            assertThrows(IllegalArgumentException.class, () -> Settings.NONE.withBrowser(store));
            assertThrows(IllegalArgumentException.class, () -> Settings.NONE.withSocial(store, true));
            // Even a caller that passed the store as "the exempt browser" gets nothing.
            assertFalse(store, BuiltInBlockExemptions.keepsAvailable(store, Settings.NONE, store));
        }
        assertTrue(BuiltInBlockExemptions.isAppStore(PLAY_STORE));
    }

    @Test
    public void catalogueHalvesAreDisjointAndCoverTheBuiltInLists() {
        for (String browser : BuiltInBlockExemptions.FILTERABLE_BROWSERS) {
            assertTrue(browser, LockdownPackages.ALWAYS_BLOCKED.contains(browser)
                    || LockdownPackages.KNOWN_BROWSER_AND_SOCIAL.contains(browser));
            assertFalse(browser, BuiltInBlockExemptions.EXEMPTABLE_SOCIAL.contains(browser));
            assertFalse(browser, BuiltInBlockExemptions.APP_STORES.contains(browser));
        }
        for (String social : BuiltInBlockExemptions.EXEMPTABLE_SOCIAL) {
            assertTrue(social, LockdownPackages.KNOWN_BROWSER_AND_SOCIAL.contains(social));
        }
        for (String known : LockdownPackages.KNOWN_BROWSER_AND_SOCIAL) {
            assertTrue(known, BuiltInBlockExemptions.isFilterableBrowser(known)
                    || BuiltInBlockExemptions.isExemptableSocial(known));
        }
        for (String essential : LockdownPackages.ESSENTIAL_SYSTEM) {
            assertFalse(essential, BuiltInBlockExemptions.isFilterableBrowser(essential));
            assertFalse(essential, BuiltInBlockExemptions.isExemptableSocial(essential));
        }
    }

    // --- Social and messaging -----------------------------------------------

    @Test
    public void socialPackageIsExemptOnlyWhenListed() {
        Settings settings = Settings.NONE.withSocial(WHATSAPP, true);
        assertTrue(BuiltInBlockExemptions.keepsAvailable(WHATSAPP, settings, null));
        assertFalse(BuiltInBlockExemptions.keepsAvailable(TELEGRAM, settings, null));
        assertFalse(BuiltInBlockExemptions.keepsAvailable("com.instagram.android", settings, null));
        // A social exemption never opens a browser.
        assertFalse(BuiltInBlockExemptions.keepsAvailable(CHROME, settings, null));
    }

    @Test
    public void aSocialExemptionDoesNotDependOnTheHomeFilter() {
        Settings settings = Settings.NONE.withSocial(WHATSAPP, true).withBrowser(CHROME);
        String exempt = exemptBrowserFor(settings, FILTER_OFF);
        assertNull(exempt);
        assertTrue(BuiltInBlockExemptions.keepsAvailable(WHATSAPP, settings, exempt));
        assertFalse(BuiltInBlockExemptions.keepsAvailable(CHROME, settings, exempt));
    }

    @Test
    public void packagesOutsideTheSocialCatalogueAreRefused() {
        assertThrows(IllegalArgumentException.class,
                () -> Settings.NONE.withSocial("org.example.reader", true));
    }

    // --- Removal ------------------------------------------------------------

    @Test
    public void removalIsImmediate() {
        Settings with = Settings.NONE.withSocial(WHATSAPP, true).withBrowser(CHROME);
        Settings without = with.withSocial(WHATSAPP, false).withBrowser(null);
        assertFalse(BuiltInBlockExemptions.keepsAvailable(WHATSAPP, without, null));
        assertNull(exemptBrowserFor(without, CONFIRMED_NO_CANARY));
        assertEquals(BrowserState.OFF,
                BuiltInBlockExemptions.browserState(without, true, CONFIRMED_NO_CANARY));
        assertFalse(without.any());
    }

    @Test
    public void onlyAddingAnExemptionIsLoosening() {
        Settings none = Settings.NONE;
        Settings whatsapp = none.withSocial(WHATSAPP, true);
        Settings chrome = whatsapp.withBrowser(CHROME);
        assertTrue(none.loosensTo(whatsapp));
        assertTrue(whatsapp.loosensTo(chrome));
        assertTrue("switching browsers opens a new one", chrome.loosensTo(chrome.withBrowser(FIREFOX)));
        assertFalse(chrome.loosensTo(whatsapp));
        assertFalse(whatsapp.loosensTo(none));
        assertFalse(chrome.loosensTo(chrome));
    }

    // --- Link routing and Trusted Web Activities ------------------------------

    @Test
    public void linksGoToTheBlockedScreenWithoutAnExemptBrowser() {
        assertEquals(LinkRoute.BLOCKED_BROWSER, BuiltInBlockExemptions.route(null, null));
        assertEquals(LinkRoute.BLOCKED_BROWSER, BuiltInBlockExemptions.route(CHROME, null));
    }

    @Test
    public void aTrustedWebActivityBackedByTheExemptBrowserIsNotRoutedToTheBlockedScreen() {
        Settings settings = Settings.NONE.withBrowser(CHROME);
        String exempt = exemptBrowserFor(settings, CONFIRMED_NO_CANARY);
        assertEquals(LinkRoute.EXEMPT_BROWSER, BuiltInBlockExemptions.route(CHROME, exempt));
        assertEquals(LinkRoute.EXEMPT_BROWSER, BuiltInBlockExemptions.route(null, exempt));
    }

    @Test
    public void aTrustedWebActivityBackedByAnotherBrowserStaysBlocked() {
        String exempt = exemptBrowserFor(Settings.NONE.withBrowser(CHROME), CONFIRMED_NO_CANARY);
        assertEquals(LinkRoute.BLOCKED_BROWSER, BuiltInBlockExemptions.route(FIREFOX, exempt));
    }

    @Test
    public void aTrustedWebActivityIsBlockedAgainWhenTheFilterLapses() {
        String exempt = exemptBrowserFor(Settings.NONE.withBrowser(CHROME), FILTER_OFF);
        assertEquals(LinkRoute.BLOCKED_BROWSER, BuiltInBlockExemptions.route(CHROME, exempt));
    }

    // --- WebView provider -----------------------------------------------------

    @Test
    public void theExemptBrowserIsNotSuspendedAsWebViewProvider() {
        String exempt = exemptBrowserFor(Settings.NONE.withBrowser(CHROME), CONFIRMED_NO_CANARY);
        assertTrue(BuiltInBlockExemptions.keepsWebViewProviderUnsuspended(CHROME, exempt));
        assertFalse(BuiltInBlockExemptions.keepsWebViewProviderUnsuspended(CHROME, null));
        assertFalse(BuiltInBlockExemptions.keepsWebViewProviderUnsuspended(CHROME, FIREFOX));
        assertFalse(BuiltInBlockExemptions.keepsWebViewProviderUnsuspended(null, null));
    }
}
