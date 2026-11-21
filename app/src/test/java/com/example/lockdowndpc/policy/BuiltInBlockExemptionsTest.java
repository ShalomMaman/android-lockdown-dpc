package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.kiosk.KioskAppCatalog;
import com.example.lockdowndpc.policy.BuiltInBlockExemptions.Observed;
import com.example.lockdowndpc.policy.BuiltInBlockExemptions.Settings;

import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.List;
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

    // --- Home filter teardown guard (live facts, fail closed) -----------------------

    private static HomeFilterPolicy.Settings enabledFilter(String ca) {
        return new HomeFilterPolicy.Settings(
                new HomeFilterPolicy.Config(HomeFilterPolicy.DEFAULT_VPN_PACKAGE, PAC), true, ca, false);
    }

    @Test
    public void turningOffOrRemovingTheCertificateIsATeardown() {
        HomeFilterPolicy.Settings before = enabledFilter("MIIB");
        assertTrue(BuiltInBlockExemptions.isFilterTeardown(before, before.requestDisable()));
        assertTrue(BuiltInBlockExemptions.isFilterTeardown(before, before.requestRemoveCa()));
        assertFalse("retry", BuiltInBlockExemptions.isFilterTeardown(before, before));
        assertFalse("first enable", BuiltInBlockExemptions.isFilterTeardown(HomeFilterPolicy.Settings.OFF, before));
    }

    @Test
    public void aSavedOrUnreadableApprovalRefusesTeardown() {
        for (Observed observed : Observed.values()) {
            for (boolean active : new boolean[]{true, false}) {
                assertEquals(BuiltInBlockExemptions.TeardownVerdict.CHROME_APPROVED,
                        BuiltInBlockExemptions.teardownVerdict(
                                BuiltInBlockExemptions.ChromeFlag.PRESENT, observed, active));
                assertEquals(BuiltInBlockExemptions.TeardownVerdict.APPROVAL_UNREADABLE,
                        BuiltInBlockExemptions.teardownVerdict(
                                BuiltInBlockExemptions.ChromeFlag.UNREADABLE, observed, active));
            }
        }
    }

    @Test
    public void withoutAnApprovalTeardownNeedsChromeObservedContainedWhileProtected() {
        BuiltInBlockExemptions.ChromeFlag absent = BuiltInBlockExemptions.ChromeFlag.ABSENT;
        for (Observed contained : new Observed[]{Observed.HIDDEN, Observed.SUSPENDED, Observed.NOT_INSTALLED}) {
            assertEquals(contained.name(), BuiltInBlockExemptions.TeardownVerdict.ALLOWED,
                    BuiltInBlockExemptions.teardownVerdict(absent, contained, true));
        }
        for (Observed open : new Observed[]{Observed.VISIBLE, Observed.DISABLED, Observed.UNKNOWN}) {
            assertEquals(open.name(), BuiltInBlockExemptions.TeardownVerdict.CHROME_NOT_CONTAINED,
                    BuiltInBlockExemptions.teardownVerdict(absent, open, true));
        }
        assertEquals("paused shows every app by design; only the approval counts then",
                BuiltInBlockExemptions.TeardownVerdict.ALLOWED,
                BuiltInBlockExemptions.teardownVerdict(absent, Observed.VISIBLE, false));
    }

    @Test
    public void theChromeFlagIsReadOnItsOwnAndAMalformedRecordIsUnreadable() {
        assertEquals(BuiltInBlockExemptions.ChromeFlag.ABSENT, BuiltInBlockExemptions.chromeFlag(null, null));
        assertEquals(BuiltInBlockExemptions.ChromeFlag.ABSENT, BuiltInBlockExemptions.chromeFlag(false, Set.of()));
        assertEquals(BuiltInBlockExemptions.ChromeFlag.PRESENT,
                BuiltInBlockExemptions.chromeFlag(true, Set.of(WHATSAPP + "=" + SIGNER_A)));
        assertEquals("a malformed social pin no longer hides a saved Chrome flag",
                BuiltInBlockExemptions.ChromeFlag.UNREADABLE,
                BuiltInBlockExemptions.chromeFlag(true, Set.of("not-a-pin")));
        assertEquals(BuiltInBlockExemptions.ChromeFlag.UNREADABLE,
                BuiltInBlockExemptions.chromeFlag(false, Set.of("org.example.reader=" + SIGNER_A)));
        assertEquals(BuiltInBlockExemptions.ChromeFlag.UNREADABLE, BuiltInBlockExemptions.chromeFlag("true", null));
        assertEquals(BuiltInBlockExemptions.ChromeFlag.UNREADABLE, BuiltInBlockExemptions.chromeFlag(false, "pins"));
    }

    @Test
    public void aPendingTeardownIsHeldWithTheFilterOnAndItsCertificateKept() {
        HomeFilterPolicy.Settings pendingDisable = enabledFilter("MIIB").requestDisable();
        HomeFilterPolicy.Settings pendingRemoval = enabledFilter("MIIB").requestRemoveCa();
        assertTrue(BuiltInBlockExemptions.hasPendingTeardown(pendingDisable));
        assertTrue(BuiltInBlockExemptions.hasPendingTeardown(pendingRemoval));
        assertFalse(BuiltInBlockExemptions.hasPendingTeardown(enabledFilter("MIIB")));
        for (HomeFilterPolicy.Settings pending : List.of(pendingDisable, pendingRemoval)) {
            HomeFilterPolicy.Settings held = BuiltInBlockExemptions.withTeardownHeld(pending);
            assertTrue(held.enabled());
            assertFalse(held.removeCa());
            assertEquals("MIIB", held.ca());
        }
    }

    @Test
    public void chromeIsApprovedOnlyOverASteadyFilter() {
        HomeFilterPolicy.Settings steady = enabledFilter("MIIB");
        assertTrue(BuiltInBlockExemptions.filterSteadyForChrome(steady, HomeFilterPolicy.State.CONFIRMED));
        assertTrue("no certificate in the profile",
                BuiltInBlockExemptions.filterSteadyForChrome(enabledFilter(null), HomeFilterPolicy.State.NOT_REQUESTED));
        assertFalse("certificate not installed",
                BuiltInBlockExemptions.filterSteadyForChrome(steady, HomeFilterPolicy.State.UNCONFIRMED));
        assertFalse("pending certificate removal",
                BuiltInBlockExemptions.filterSteadyForChrome(steady.requestRemoveCa(), HomeFilterPolicy.State.CONFIRMED));
        assertFalse("pending disable",
                BuiltInBlockExemptions.filterSteadyForChrome(steady.requestDisable(), HomeFilterPolicy.State.CONFIRMED));
        assertFalse(BuiltInBlockExemptions.filterSteadyForChrome(HomeFilterPolicy.Settings.OFF, null));
    }

    // --- One settled filter for the whole pass -----------------------------------------

    @Test
    public void aHeldDisableLooksEnabledAndKeepsTheRequiredControls() {
        HomeFilterPolicy.Settings pendingDisable = enabledFilter("MIIB").requestDisable();
        BuiltInBlockExemptions.PassFilter pass = BuiltInBlockExemptions.PassFilter.forPass(
                pendingDisable, () -> BuiltInBlockExemptions.TeardownVerdict.CHROME_NOT_CONTAINED);
        assertTrue(pass.held());
        assertTrue(pass.effective().enabled());
        Map<SystemPolicyControl, Boolean> choices = HomeFilterPolicy.choicesFor(Map.of(), pass.effective().enabled());
        for (SystemPolicyControl required : HomeFilterPolicy.REQUIRED_CONTROLS) {
            assertEquals(required.name(), Boolean.TRUE, choices.get(required));
        }
        assertEquals("install lock (DISALLOW_INSTALL_APPS) stays required",
                Boolean.TRUE, choices.get(SystemPolicyControl.APP_STORES_AND_INSTALLERS));
    }

    @Test
    public void maintenanceAndPauseSeeTheSameSettledStateAsThePass() {
        // The one answer every policy writer uses outside a pass too.
        HomeFilterPolicy.Settings pendingDisable = enabledFilter("MIIB").requestDisable();
        assertTrue("held turn-off is on", BuiltInBlockExemptions.PassFilter.enforcedEnabled(
                BuiltInBlockExemptions.PassFilter.forPass(pendingDisable,
                        () -> BuiltInBlockExemptions.TeardownVerdict.CHROME_APPROVED)));
        assertFalse("allowed turn-off is off", BuiltInBlockExemptions.PassFilter.enforcedEnabled(
                BuiltInBlockExemptions.PassFilter.forPass(pendingDisable,
                        () -> BuiltInBlockExemptions.TeardownVerdict.ALLOWED)));
        assertTrue("unreadable settings fail closed", BuiltInBlockExemptions.PassFilter.enforcedEnabled(null));
        assertFalse("never configured", BuiltInBlockExemptions.PassFilter.enforcedEnabled(
                BuiltInBlockExemptions.PassFilter.forPass(HomeFilterPolicy.Settings.OFF,
                        () -> BuiltInBlockExemptions.TeardownVerdict.ALLOWED)));
        assertEquals("maintenance restore keeps the install lock while a turn-off is held",
                Boolean.TRUE, HomeFilterPolicy.choicesFor(Map.of(), BuiltInBlockExemptions.PassFilter.enforcedEnabled(
                        BuiltInBlockExemptions.PassFilter.forPass(pendingDisable,
                                () -> BuiltInBlockExemptions.TeardownVerdict.CHROME_NOT_CONTAINED)))
                        .get(SystemPolicyControl.APP_STORES_AND_INSTALLERS));
    }

    @Test
    public void anAllowedTeardownIsEnforcedAsStored() {
        HomeFilterPolicy.Settings pendingDisable = enabledFilter("MIIB").requestDisable();
        BuiltInBlockExemptions.PassFilter pass = BuiltInBlockExemptions.PassFilter.forPass(
                pendingDisable, () -> BuiltInBlockExemptions.TeardownVerdict.ALLOWED);
        assertFalse(pass.held());
        assertFalse(pass.effective().enabled());
        int[] asked = {0};
        BuiltInBlockExemptions.PassFilter steady = BuiltInBlockExemptions.PassFilter.forPass(enabledFilter(null), () -> {
            asked[0]++;
            return BuiltInBlockExemptions.TeardownVerdict.CHROME_APPROVED;
        });
        assertFalse(steady.held());
        assertEquals("the guard is consulted only for a pending teardown", 0, asked[0]);
    }

    // --- Credentials lock -------------------------------------------------------------

    private static final class FakeLock implements BuiltInBlockExemptions.CredentialsLock {
        boolean set;
        boolean refuse;

        @Override public boolean isSet() { return set; }

        @Override
        public void set(boolean locked) {
            if (!refuse) {
                set = locked;
            }
        }
    }

    @Test
    public void theCredentialsLockFollowsTheApprovalAndIsReleasedOnlyWhenTheGuardAllows() {
        BuiltInBlockExemptions.TeardownVerdict allowed = BuiltInBlockExemptions.TeardownVerdict.ALLOWED;
        BuiltInBlockExemptions.TeardownVerdict notContained = BuiltInBlockExemptions.TeardownVerdict.CHROME_NOT_CONTAINED;
        assertEquals(Boolean.TRUE, BuiltInBlockExemptions.credentialsLockTarget(
                BuiltInBlockExemptions.ChromeFlag.PRESENT, allowed));
        assertEquals(Boolean.TRUE, BuiltInBlockExemptions.credentialsLockTarget(
                BuiltInBlockExemptions.ChromeFlag.UNREADABLE, allowed));
        assertEquals(Boolean.FALSE, BuiltInBlockExemptions.credentialsLockTarget(
                BuiltInBlockExemptions.ChromeFlag.ABSENT, allowed));
        assertNull("a refused hide keeps the lock as it is", BuiltInBlockExemptions.credentialsLockTarget(
                BuiltInBlockExemptions.ChromeFlag.ABSENT, notContained));
        FakeLock lock = new FakeLock();
        java.util.List<String> errors = new java.util.ArrayList<>();
        assertTrue(BuiltInBlockExemptions.reconcileCredentialsLock(true, lock, errors));
        assertTrue("set while Chrome is approved", lock.set);
        assertTrue(BuiltInBlockExemptions.reconcileCredentialsLock(false, lock, errors));
        assertFalse("released when the approval is removed", lock.set);
        assertTrue(errors.isEmpty());
    }

    @Test
    public void aLockAndroidRefusesIsReported() {
        FakeLock lock = new FakeLock();
        lock.refuse = true;
        java.util.List<String> errors = new java.util.ArrayList<>();
        assertFalse(BuiltInBlockExemptions.reconcileCredentialsLock(true, lock, errors));
        assertEquals(List.of("credentials-lock-unverified:true"), errors);
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
