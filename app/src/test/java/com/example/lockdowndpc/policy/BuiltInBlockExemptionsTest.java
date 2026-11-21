package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.kiosk.KioskAppCatalog;
import com.example.lockdowndpc.policy.BuiltInBlockExemptions.Settings;

import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/** Pure rules of the exemptions: catalogues, signer binding, Chrome's configuration, kiosk. */
public final class BuiltInBlockExemptionsTest {

    private static final String WHATSAPP = "com.whatsapp";
    private static final String TELEGRAM = "org.telegram.messenger";
    private static final String SIGNER_A = "aa".repeat(32);
    private static final String SIGNER_B = "bb".repeat(32);
    private static final String PAC = "https://filter.example.org/proxy.pac";

    @Test
    public void nothingIsExemptByDefault() {
        assertFalse(Settings.NONE.chrome());
        for (String packageName : BuiltInBlockExemptions.EXEMPTABLE_SOCIAL) {
            assertFalse(packageName, BuiltInBlockExemptions.socialVisible(packageName, Settings.NONE, SIGNER_A));
        }
    }

    // --- Catalogues ---------------------------------------------------------------

    @Test
    public void theSocialCatalogueIsPositiveAndExcludesBrowsersAndStores() {
        for (String social : BuiltInBlockExemptions.EXEMPTABLE_SOCIAL) {
            assertTrue(social, LockdownPackages.KNOWN_BROWSER_AND_SOCIAL.contains(social));
            assertFalse(social, LockdownPackages.ALWAYS_BLOCKED.contains(social));
        }
        for (String browser : new String[]{"org.mozilla.firefox", "com.brave.browser",
                "com.microsoft.emmx", BuiltInBlockExemptions.CHROME}) {
            assertFalse(browser, BuiltInBlockExemptions.isExemptableSocial(browser));
        }
    }

    @Test
    public void storesAreNeverExemptable() {
        for (String store : BuiltInBlockExemptions.APP_STORES) {
            assertTrue(store, LockdownPackages.ALWAYS_BLOCKED.contains(store));
            assertFalse(store, BuiltInBlockExemptions.isExemptableSocial(store));
            assertThrows(IllegalArgumentException.class, () -> Settings.NONE.withSocial(store, SIGNER_A));
        }
    }

    @Test
    public void builtInBlockedPackagesDoNotInheritVpnVisibility() {
        assertTrue(BuiltInBlockExemptions.isBuiltInBlocked(BuiltInBlockExemptions.CHROME));
        assertFalse(BuiltInBlockExemptions.isBuiltInBlocked(HomeFilterPolicy.DEFAULT_VPN_PACKAGE));
        HomeFilterPolicy.Settings chromeAsVpn = new HomeFilterPolicy.Settings(
                new HomeFilterPolicy.Config(BuiltInBlockExemptions.CHROME, PAC), true, null, false);
        assertFalse(chromeAsVpn.keepsVpnVisible(BuiltInBlockExemptions.CHROME));
    }

    // --- Social: signer binding ---------------------------------------------------

    @Test
    public void socialPackageIsVisibleOnlyWhenListedAndSignedByThePinnedSigner() {
        Settings settings = Settings.NONE.withSocial(WHATSAPP, SIGNER_A);
        assertTrue(BuiltInBlockExemptions.socialVisible(WHATSAPP, settings, SIGNER_A));
        assertTrue(BuiltInBlockExemptions.socialVisible(WHATSAPP, settings, SIGNER_A.toUpperCase()));
        assertFalse(BuiltInBlockExemptions.socialVisible(WHATSAPP, settings, SIGNER_B));
        assertFalse(BuiltInBlockExemptions.socialVisible(TELEGRAM, settings, SIGNER_A));
    }

    @Test
    public void anUnreadableSignerKeepsTheApplicationHidden() {
        // PackageIdentity reports "" when the read throws or there is not
        // exactly one current signer.
        Settings settings = Settings.NONE.withSocial(WHATSAPP, SIGNER_A);
        assertFalse(BuiltInBlockExemptions.socialVisible(WHATSAPP, settings, ""));
        assertFalse(BuiltInBlockExemptions.socialVisible(WHATSAPP, settings, null));
    }

    @Test
    public void approvalsRequireAPinnedSignerAndACataloguePackage() {
        assertThrows(IllegalArgumentException.class, () -> Settings.NONE.withSocial(WHATSAPP, ""));
        assertThrows(IllegalArgumentException.class,
                () -> Settings.NONE.withSocial("org.example.reader", SIGNER_A));
        assertThrows(IllegalArgumentException.class,
                () -> new Settings(false, Map.of("com.whatsapp.other", SIGNER_A)));
    }

    @Test
    public void onlyAddingOrRepinningIsLoosening() {
        Settings whatsapp = Settings.NONE.withSocial(WHATSAPP, SIGNER_A);
        Settings both = whatsapp.withChrome(true);
        assertTrue(Settings.NONE.loosensTo(whatsapp));
        assertTrue(whatsapp.loosensTo(both));
        assertTrue(whatsapp.loosensTo(Settings.NONE.withSocial(WHATSAPP, SIGNER_B)));
        assertFalse(both.loosensTo(whatsapp));
        assertFalse(whatsapp.loosensTo(whatsapp.withoutSocial(WHATSAPP)));
        assertFalse(both.loosensTo(both));
    }

    // --- Chrome ---------------------------------------------------------------------

    @Test
    public void onlyGooglesChromeSignerIsAccepted() {
        assertTrue(BuiltInBlockExemptions.chromeSignerVerified(
                BuiltInBlockExemptions.CHROME_RELEASE_SIGNER_SHA256));
        assertFalse(BuiltInBlockExemptions.chromeSignerVerified(SIGNER_A));
        assertFalse(BuiltInBlockExemptions.chromeSignerVerified(""));
    }

    @Test
    public void chromeConfigurationHasAMandatoryPacInProxySettingsAndNoSeparateProxyKeys() {
        Map<String, Object> required = BuiltInBlockExemptions.chromeRestrictions(PAC);
        assertEquals("{\"ProxyMode\":\"pac_script\",\"ProxyPacUrl\":\"" + PAC
                        + "\",\"ProxyPacMandatory\":true}",
                required.get("ProxySettings"));
        for (String separate : BuiltInBlockExemptions.SEPARATE_PROXY_POLICIES) {
            assertFalse(separate, required.containsKey(separate));
        }
        assertEquals(1, required.get("IncognitoModeAvailability"));
        assertEquals("off", required.get("DnsOverHttpsMode"));
        assertEquals(2, required.get("DeveloperToolsAvailability"));
        assertEquals(0, required.get("BrowserSignin"));
        assertThrows(IllegalArgumentException.class, () -> BuiltInBlockExemptions.chromeRestrictions(""));
    }

    @Test
    public void thePacUrlIsJsonEscaped() {
        assertTrue(BuiltInBlockExemptions.proxySettingsJson("https://x.example/a\"b\\c.pac")
                .contains("\"ProxyPacUrl\":\"https://x.example/a\\\"b\\\\c.pac\""));
    }

    @Test
    public void aSeparateProxyKeyFailsTheReadBack() {
        LinkedHashMap<String, Object> readBack =
                new LinkedHashMap<>(BuiltInBlockExemptions.chromeRestrictions(PAC));
        assertTrue(BuiltInBlockExemptions.restrictionsSatisfied(readBack, PAC));
        readBack.put("ProxyMode", "direct");
        assertFalse(BuiltInBlockExemptions.restrictionsSatisfied(readBack, PAC));
    }

    @Test
    public void readBackMustMatchValuesAndTypes() {
        LinkedHashMap<String, Object> readBack =
                new LinkedHashMap<>(BuiltInBlockExemptions.chromeRestrictions(PAC));
        readBack.put("IncognitoModeAvailability", "1");
        assertFalse(BuiltInBlockExemptions.restrictionsSatisfied(readBack, PAC));
        readBack.put("IncognitoModeAvailability", 1);
        readBack.put("ProxySettings", BuiltInBlockExemptions.proxySettingsJson("https://other.example/p.pac"));
        assertFalse(BuiltInBlockExemptions.restrictionsSatisfied(readBack, PAC));
        readBack.remove("ProxySettings");
        assertFalse(BuiltInBlockExemptions.restrictionsSatisfied(readBack, PAC));
        assertFalse(BuiltInBlockExemptions.restrictionsSatisfied(null, PAC));
    }

    @Test
    public void mergingRemovesSeparateProxyKeysAndKeepsOtherAdministratorKeys() {
        LinkedHashMap<String, Object> current = new LinkedHashMap<>();
        current.put("ProxyMode", "direct");
        current.put("ProxyServer", "198.51.100.1:3128");
        current.put("PasswordManagerEnabled", Boolean.FALSE);
        Map<String, Object> merged = BuiltInBlockExemptions.mergeRestrictions(current, PAC);
        assertTrue(BuiltInBlockExemptions.restrictionsSatisfied(merged, PAC));
        assertFalse(merged.containsKey("ProxyMode"));
        assertFalse(merged.containsKey("ProxyServer"));
        assertEquals(Boolean.FALSE, merged.get("PasswordManagerEnabled"));
    }

    // --- Kiosk ------------------------------------------------------------------------

    @Test
    public void kioskCannotTargetAnUnexemptedSocialApplication() {
        assertTrue(KioskAppCatalog.isProtectedFromKiosk(TELEGRAM));
        assertTrue(KioskAppCatalog.isProtectedFromKiosk(TELEGRAM, Set.of()));
        assertTrue("an exemption for another app does not count",
                KioskAppCatalog.isProtectedFromKiosk(TELEGRAM, Set.of(WHATSAPP)));
        assertFalse(KioskAppCatalog.isProtectedFromKiosk(TELEGRAM, Set.of(TELEGRAM)));
        KioskAppCatalog.Candidate telegram = new KioskAppCatalog.Candidate(
                TELEGRAM, "Telegram", true, true, true, false);
        assertFalse(KioskAppCatalog.isSelectable(telegram));
        assertTrue(KioskAppCatalog.isSelectable(telegram, Set.of(TELEGRAM)));
    }

    @Test
    public void aVerifiedSocialExemptionNeverOpensAStoreOrEscapeSurfaceToKiosk() {
        assertTrue(KioskAppCatalog.isProtectedFromKiosk("com.android.vending", Set.of("com.android.vending")));
        assertTrue(KioskAppCatalog.isProtectedFromKiosk("com.android.documentsui",
                Set.of("com.android.documentsui")));
    }
}
