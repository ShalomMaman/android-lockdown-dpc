package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.policy.BuiltInBlockExemptions.FilterEvidence;
import com.example.lockdowndpc.policy.BuiltInBlockExemptions.Settings;

import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/** Pure rules of the exemptions: catalogues, signer binding and Chrome's configuration. */
public final class BuiltInBlockExemptionsTest {

    private static final String WHATSAPP = "com.whatsapp";
    private static final String TELEGRAM = "org.telegram.messenger";
    private static final String SIGNER_A = "aa".repeat(32);
    private static final String SIGNER_B = "bb".repeat(32);
    private static final String PAC = "https://filter.example.org/proxy.pac";

    @Test
    public void nothingIsExemptByDefault() {
        assertFalse(Settings.NONE.any());
        assertFalse(Settings.NONE.chromeThroughFilter());
        for (String packageName : BuiltInBlockExemptions.EXEMPTABLE_SOCIAL) {
            assertFalse(packageName,
                    BuiltInBlockExemptions.keepsSocialAvailable(packageName, Settings.NONE, SIGNER_A));
        }
    }

    // --- Catalogues -------------------------------------------------------------

    @Test
    public void theSocialCatalogueIsPositiveAndExcludesBrowsersAndStores() {
        for (String social : BuiltInBlockExemptions.EXEMPTABLE_SOCIAL) {
            assertTrue(social, LockdownPackages.KNOWN_BROWSER_AND_SOCIAL.contains(social));
            assertFalse(social, LockdownPackages.ALWAYS_BLOCKED.contains(social));
            assertFalse(social, BuiltInBlockExemptions.isAppStore(social));
            assertFalse(social, BuiltInBlockExemptions.CHROME.equals(social));
        }
        for (String browser : new String[]{"org.mozilla.firefox", "com.brave.browser",
                "com.microsoft.emmx", "com.opera.browser", BuiltInBlockExemptions.CHROME}) {
            assertFalse(browser, BuiltInBlockExemptions.isExemptableSocial(browser));
        }
    }

    @Test
    public void storesAreNeverExemptable() {
        for (String store : BuiltInBlockExemptions.APP_STORES) {
            assertTrue(store, LockdownPackages.ALWAYS_BLOCKED.contains(store));
            assertFalse(store, BuiltInBlockExemptions.isExemptableSocial(store));
            assertThrows(IllegalArgumentException.class, () -> Settings.NONE.withSocial(store, SIGNER_A));
            assertFalse(store, BuiltInBlockExemptions.keepsSocialAvailable(store, Settings.NONE, SIGNER_A));
        }
    }

    @Test
    public void builtInBlockedPackagesCannotServeAsTheVpn() {
        assertTrue(BuiltInBlockExemptions.isBuiltInBlocked(BuiltInBlockExemptions.CHROME));
        assertTrue(BuiltInBlockExemptions.isBuiltInBlocked("org.mozilla.firefox"));
        assertTrue(BuiltInBlockExemptions.isBuiltInBlocked("com.android.vending"));
        assertFalse(BuiltInBlockExemptions.isBuiltInBlocked(HomeFilterPolicy.DEFAULT_VPN_PACKAGE));
    }

    @Test
    public void aBuiltInBlockedVpnPackageDoesNotInheritVpnVisibility() {
        HomeFilterPolicy.Settings chromeAsVpn = new HomeFilterPolicy.Settings(
                new HomeFilterPolicy.Config(BuiltInBlockExemptions.CHROME, PAC), true, null, false);
        assertFalse(chromeAsVpn.keepsVpnVisible(BuiltInBlockExemptions.CHROME));
        assertTrue(chromeAsVpn.packageShouldBeHidden(BuiltInBlockExemptions.CHROME, true));
    }

    // --- Social exemptions: signer binding ---------------------------------------

    @Test
    public void socialPackageIsExemptOnlyWhenListedAndSignedByThePinnedSigner() {
        Settings settings = Settings.NONE.withSocial(WHATSAPP, SIGNER_A);
        assertTrue(BuiltInBlockExemptions.keepsSocialAvailable(WHATSAPP, settings, SIGNER_A));
        assertTrue("digest format is normalized",
                BuiltInBlockExemptions.keepsSocialAvailable(WHATSAPP, settings, SIGNER_A.toUpperCase()));
        assertFalse("another signer under the same name is not the approved app",
                BuiltInBlockExemptions.keepsSocialAvailable(WHATSAPP, settings, SIGNER_B));
        assertFalse("an unreadable signer fails closed",
                BuiltInBlockExemptions.keepsSocialAvailable(WHATSAPP, settings, ""));
        assertFalse(BuiltInBlockExemptions.keepsSocialAvailable(TELEGRAM, settings, SIGNER_A));
    }

    @Test
    public void approvalsRequireAPinnedSignerAndACataloguePackage() {
        assertThrows(IllegalArgumentException.class, () -> Settings.NONE.withSocial(WHATSAPP, ""));
        assertThrows(IllegalArgumentException.class,
                () -> Settings.NONE.withSocial("org.example.reader", SIGNER_A));
        assertThrows(IllegalArgumentException.class,
                () -> new Settings(false, Map.of("com.whatsapp.evil", SIGNER_A)));
    }

    @Test
    public void onlyAddingOrRepinningIsLoosening() {
        Settings none = Settings.NONE;
        Settings whatsapp = none.withSocial(WHATSAPP, SIGNER_A);
        Settings chrome = whatsapp.withChrome(true);
        assertTrue(none.loosensTo(whatsapp));
        assertTrue(whatsapp.loosensTo(chrome));
        assertTrue("re-pinning to another signer", whatsapp.loosensTo(none.withSocial(WHATSAPP, SIGNER_B)));
        assertFalse(chrome.loosensTo(whatsapp));
        assertFalse(whatsapp.loosensTo(none));
        assertFalse(chrome.loosensTo(chrome));
    }

    @Test
    public void removalsAreListedForDurableRevocation() {
        Settings both = Settings.NONE.withSocial(WHATSAPP, SIGNER_A).withChrome(true);
        assertEquals(Set.of(BuiltInBlockExemptions.CHROME, WHATSAPP),
                both.revokedBy(Settings.NONE));
        assertEquals(Set.of(WHATSAPP), both.revokedBy(both.withSocial(WHATSAPP, SIGNER_B)));
        assertEquals(Set.of(), both.revokedBy(both));
    }

    // --- Chrome --------------------------------------------------------------------

    @Test
    public void onlyGooglesChromeSignerIsAccepted() {
        assertTrue(BuiltInBlockExemptions.chromeSignerVerified(
                BuiltInBlockExemptions.CHROME_RELEASE_SIGNER_SHA256));
        assertFalse(BuiltInBlockExemptions.chromeSignerVerified(SIGNER_A));
        assertFalse(BuiltInBlockExemptions.chromeSignerVerified(""));
        assertFalse(BuiltInBlockExemptions.chromeSignerVerified(null));
    }

    @Test
    public void filterEvidenceNeedsEveryCondition() {
        assertTrue(new FilterEvidence(true, true, true).verified());
        assertFalse(new FilterEvidence(false, true, true).verified());
        assertFalse(new FilterEvidence(true, false, true).verified());
        assertFalse(new FilterEvidence(true, true, false).verified());
        assertFalse(FilterEvidence.NONE.verified());
    }

    @Test
    public void theCaConditionRejectsAPendingRemoval() {
        assertTrue("no CA in the profile", BuiltInBlockExemptions.caSatisfied(false, false, false));
        assertTrue(BuiltInBlockExemptions.caSatisfied(true, false, true));
        assertFalse(BuiltInBlockExemptions.caSatisfied(true, false, false));
        assertFalse("a confirmed removal is not a present CA",
                BuiltInBlockExemptions.caSatisfied(true, true, true));
    }

    @Test
    public void chromeConfigurationForcesTheFilterAndClosesBypasses() {
        Map<String, Object> required = BuiltInBlockExemptions.chromeRestrictions(PAC);
        assertEquals("pac_script", required.get("ProxyMode"));
        assertEquals(PAC, required.get("ProxyPacUrl"));
        assertEquals(Boolean.FALSE, required.get("QuicAllowed"));
        assertEquals("off", required.get("DnsOverHttpsMode"));
        assertEquals(1, required.get("IncognitoModeAvailability"));
        assertEquals(Boolean.TRUE, required.get("ForceGoogleSafeSearch"));
        assertEquals(2, required.get("ForceYouTubeRestrict"));
        assertEquals(0, required.get("BrowserSignin"));
        assertEquals(2, required.get("DeveloperToolsAvailability"));
        assertArrayEquals(new String[]{"chrome://flags", "chrome://net-internals", "chrome://proxy"},
                (String[]) required.get("URLBlocklist"));
        assertThrows(IllegalArgumentException.class, () -> BuiltInBlockExemptions.chromeRestrictions(""));
    }

    @Test
    public void readBackMustMatchValuesAndTypes() {
        Map<String, Object> required = BuiltInBlockExemptions.chromeRestrictions(PAC);
        LinkedHashMap<String, Object> readBack = new LinkedHashMap<>(required);
        assertTrue(BuiltInBlockExemptions.restrictionsSatisfied(readBack, required));
        readBack.put("IncognitoModeAvailability", "1");
        assertFalse("a string is not the integer Chrome expects",
                BuiltInBlockExemptions.restrictionsSatisfied(readBack, required));
        readBack.put("IncognitoModeAvailability", 1);
        readBack.put("ProxyPacUrl", "https://other.example.org/proxy.pac");
        assertFalse(BuiltInBlockExemptions.restrictionsSatisfied(readBack, required));
        readBack.put("ProxyPacUrl", PAC);
        readBack.put("URLBlocklist", new String[]{"chrome://flags"});
        assertFalse(BuiltInBlockExemptions.restrictionsSatisfied(readBack, required));
        readBack.remove("URLBlocklist");
        assertFalse(BuiltInBlockExemptions.restrictionsSatisfied(readBack, required));
        assertFalse(BuiltInBlockExemptions.restrictionsSatisfied(null, required));
    }

    @Test
    public void mergingKeepsStricterAdministratorEntries() {
        Map<String, Object> required = BuiltInBlockExemptions.chromeRestrictions(PAC);
        LinkedHashMap<String, Object> current = new LinkedHashMap<>();
        current.put("URLBlocklist", new String[]{"example.org"});
        current.put("PasswordManagerEnabled", Boolean.FALSE);
        Map<String, Object> merged = BuiltInBlockExemptions.mergeRestrictions(current, required);
        assertTrue(BuiltInBlockExemptions.restrictionsSatisfied(merged, required));
        assertEquals(Boolean.FALSE, merged.get("PasswordManagerEnabled"));
        assertTrue(Set.of((String[]) merged.get("URLBlocklist")).contains("example.org"));
    }
}
