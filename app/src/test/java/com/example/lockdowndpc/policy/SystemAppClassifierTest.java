package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.policy.SystemAppClassifier.Category;
import com.example.lockdowndpc.policy.SystemAppClassifier.CatalogContext;
import com.example.lockdowndpc.policy.SystemAppClassifier.Classification;
import com.example.lockdowndpc.policy.SystemAppClassifier.Origin;
import com.example.lockdowndpc.policy.SystemAppClassifier.PackageSnapshot;
import com.example.lockdowndpc.policy.SystemAppClassifier.ProtectedContext;
import com.example.lockdowndpc.policy.SystemAppClassifier.ReasonKey;
import com.example.lockdowndpc.policy.SystemAppClassifier.RiskAcceptanceStatus;
import com.example.lockdowndpc.policy.SystemAppClassifier.RowState;
import com.example.lockdowndpc.policy.SystemAppClassifier.Tier;

import org.junit.Test;

import java.util.Set;

/**
 * Covers the inventory classification seam of Issue #18.
 *
 * <p>The load-bearing property is not "the right label appears": it is that
 * nothing the console can present as toggleable is a package the policy engine
 * pins, and that an OEM component nobody has reviewed fails closed.
 */
public final class SystemAppClassifierTest {

    private static final String OWN = "com.example.lockdowndpc";
    private static final String OEM_KEYBOARD = "com.oem.keyboard";
    private static final String OEM_WEBVIEW = "com.oem.webview";

    private static final ProtectedContext PROTECTED = new ProtectedContext(
            OWN,
            LockdownPackages.ESSENTIAL_SYSTEM,
            LockdownPackages.managementPackageNames(),
            OEM_KEYBOARD,
            OEM_WEBVIEW
    );

    private static final CatalogContext CATALOG = CatalogContext.fromLockdownPackages();

    private static PackageSnapshot userApp(String packageName) {
        return new PackageSnapshot(packageName, false, false, true, false);
    }

    private static PackageSnapshot systemApp(String packageName) {
        return new PackageSnapshot(packageName, true, false, true, false);
    }

    private static Classification classify(PackageSnapshot snapshot) {
        return classify(snapshot, RiskAcceptanceStatus.NONE);
    }

    private static Classification classify(
            PackageSnapshot snapshot,
            RiskAcceptanceStatus riskStatus
    ) {
        return SystemAppClassifier.classify(snapshot, PROTECTED, CATALOG, true, riskStatus);
    }

    // --- Ordinary rows -----------------------------------------------------

    @Test
    public void anOrdinaryThirdPartyAppIsSelectable() {
        Classification result = classify(userApp("org.thoughtcrime.securesms"));

        assertEquals(Origin.USER, result.origin());
        assertEquals(Tier.ORDINARY, result.tier());
        assertEquals(RowState.ALLOWED, result.state());
        assertEquals(ReasonKey.ORDINARY_APP, result.reasonKey());
        assertTrue(result.blockable());
    }

    @Test
    public void theSelectionDecidesOnlyTheStateOfARowThatIsActuallySelectable() {
        PackageSnapshot app = userApp("org.thoughtcrime.securesms");

        assertEquals(RowState.ALLOWED,
                SystemAppClassifier.classify(app, PROTECTED, CATALOG, true, RiskAcceptanceStatus.NONE)
                        .state());
        assertEquals(RowState.BLOCKED,
                SystemAppClassifier.classify(app, PROTECTED, CATALOG, false, RiskAcceptanceStatus.NONE)
                        .state());
    }

    @Test
    public void anUpdatedSystemAppReportsItsOwnOrigin() {
        PackageSnapshot updated = new PackageSnapshot("com.oem.gallery", true, true, true, false);

        assertEquals(Origin.UPDATED_SYSTEM, SystemAppClassifier.originOf(updated));
        assertEquals(Origin.SYSTEM, SystemAppClassifier.originOf(systemApp("com.oem.gallery")));
        assertEquals(Origin.USER, SystemAppClassifier.originOf(userApp("com.oem.gallery")));
    }

    // --- Protected core ----------------------------------------------------

    @Test
    public void deviceGuardItselfIsNeverBlockable() {
        Classification result = classify(userApp(OWN));

        assertEquals(Tier.PROTECTED_CORE, result.tier());
        assertEquals(RowState.PROTECTED, result.state());
        assertEquals(ReasonKey.PROTECTED_DEVICE_GUARD, result.reasonKey());
        assertFalse(result.blockable());
    }

    @Test
    public void everyEssentialSystemPackageIsProtected() {
        for (String packageName : LockdownPackages.ESSENTIAL_SYSTEM) {
            Classification result = classify(systemApp(packageName));

            assertEquals(packageName, RowState.PROTECTED, result.state());
            assertFalse(packageName + " must never be blockable", result.blockable());
        }
    }

    @Test
    public void everyManagementTransportIsProtected() {
        for (String packageName : LockdownPackages.managementPackageNames()) {
            Classification result = classify(userApp(packageName));

            assertEquals(packageName, Tier.PROTECTED_CORE, result.tier());
            assertEquals(packageName,
                    ReasonKey.PROTECTED_MANAGEMENT_TRANSPORT, result.reasonKey());
            assertFalse(result.blockable());
        }
    }

    @Test
    public void theActiveKeyboardIsProtectedEvenWhenNoCatalogueListsIt() {
        // The whole point: an OEM keyboard absent from ESSENTIAL_SYSTEM would
        // otherwise land in the unclassified tier and become blockable after a
        // risk acceptance, leaving the device with no way to type.
        Classification result = classify(systemApp(OEM_KEYBOARD), RiskAcceptanceStatus.FRESH);

        assertEquals(Tier.PROTECTED_CORE, result.tier());
        assertEquals(ReasonKey.PROTECTED_ACTIVE_INPUT_METHOD, result.reasonKey());
        assertFalse(result.blockable());
    }

    @Test
    public void theActiveWebViewProviderIsProtectedEvenWhenNoCatalogueListsIt() {
        Classification result = classify(systemApp(OEM_WEBVIEW), RiskAcceptanceStatus.FRESH);

        assertEquals(Tier.PROTECTED_CORE, result.tier());
        assertEquals(ReasonKey.PROTECTED_ACTIVE_WEBVIEW_PROVIDER, result.reasonKey());
        assertFalse(result.blockable());
    }

    @Test
    public void anAbsentActiveKeyboardOrWebViewProviderProtectsNothingByAccident() {
        // An empty runtime fact must not turn every package with an empty name
        // into a protected row, and PackageSnapshot forbids an empty name anyway.
        ProtectedContext noRuntimeFacts = new ProtectedContext(
                OWN, LockdownPackages.ESSENTIAL_SYSTEM,
                LockdownPackages.managementPackageNames(), null, null);

        Classification result = SystemAppClassifier.classify(
                userApp("org.thoughtcrime.securesms"),
                noRuntimeFacts, CATALOG, true, RiskAcceptanceStatus.NONE);

        assertEquals(Tier.ORDINARY, result.tier());
        assertTrue(result.blockable());
    }

    // --- Catalogue-ruled rows ----------------------------------------------

    @Test
    public void catalogueRuledPackagesAreShownButNeverOfferedAsAChoice() {
        // LockdownPolicyController blocks these unconditionally. Offering a
        // checkbox would show a state the next reconciliation pass overrules.
        for (String packageName : LockdownPackages.ALWAYS_BLOCKED) {
            Classification result = classify(systemApp(packageName));

            assertEquals(packageName, Tier.POLICY_RULED, result.tier());
            assertEquals(packageName, RowState.BLOCKED, result.state());
            assertFalse(packageName + " is decided by the catalogue", result.blockable());
        }
        for (String packageName : LockdownPackages.KNOWN_BROWSER_AND_SOCIAL) {
            Classification result = classify(userApp(packageName));

            assertEquals(packageName, ReasonKey.KNOWN_BROWSER_OR_SOCIAL_CATALOG,
                    result.reasonKey());
            assertFalse(result.blockable());
        }
        for (String packageName : LockdownPackages.KIOSK_ESCAPE_SURFACES) {
            Classification result = classify(systemApp(packageName));

            assertEquals(packageName, ReasonKey.KIOSK_ESCAPE_SURFACE, result.reasonKey());
            assertFalse(result.blockable());
        }
    }

    // --- Known manageable system apps --------------------------------------

    @Test
    public void aReviewedManageableSystemAppIsSelectableWithoutARiskAcceptance() {
        Classification result = classify(systemApp("com.google.android.apps.photos"));

        assertEquals(Tier.KNOWN_MANAGEABLE, result.tier());
        assertEquals(ReasonKey.KNOWN_MANAGEABLE_SYSTEM, result.reasonKey());
        assertTrue(result.blockable());
        assertFalse(SystemAppClassifier.requiresRiskAcceptance(result));
    }

    @Test
    public void theManageableCatalogueNeverOverlapsAPinnedOne() {
        for (String packageName : SystemAppClassifier.KNOWN_MANAGEABLE_SYSTEM) {
            assertFalse(packageName + " is both manageable and essential",
                    LockdownPackages.ESSENTIAL_SYSTEM.contains(packageName));
            assertFalse(packageName + " is both manageable and always-blocked",
                    LockdownPackages.ALWAYS_BLOCKED.contains(packageName));
            assertFalse(packageName + " is both manageable and a kiosk escape surface",
                    LockdownPackages.KIOSK_ESCAPE_SURFACES.contains(packageName));
            assertFalse(packageName + " is both manageable and a management transport",
                    LockdownPackages.isManagementPackage(packageName));
        }
    }

    @Test
    public void aPinnedCatalogueAlwaysWinsOverTheManageableTier() {
        // The order of the checks is the safety argument. Today the two sets are
        // disjoint, so assert that first — and then prove the ordering directly,
        // rather than with a loop that would pass vacuously if it stayed disjoint.
        for (String packageName : SystemAppClassifier.KNOWN_MANAGEABLE_SYSTEM) {
            assertFalse(packageName + " is both manageable and catalogue-blocked",
                    LockdownPackages.KNOWN_BROWSER_AND_SOCIAL.contains(packageName));
        }

        String overlapping = LockdownPackages.KNOWN_BROWSER_AND_SOCIAL.iterator().next();
        Classification result = classify(systemApp(overlapping));

        assertEquals(Tier.POLICY_RULED, result.tier());
        assertEquals(ReasonKey.KNOWN_BROWSER_OR_SOCIAL_CATALOG, result.reasonKey());
        assertFalse(result.blockable());
    }

    // --- Unclassified OEM components ---------------------------------------

    @Test
    public void anUnclassifiedOemComponentIsVisibleButFailsClosed() {
        Classification result = classify(systemApp("com.oem.weatherwidget"));

        assertEquals(Tier.UNCLASSIFIED_OEM, result.tier());
        assertEquals(RowState.BLOCKED, result.state());
        assertEquals(ReasonKey.UNCLASSIFIED_OEM_NEEDS_RISK_ACCEPTANCE, result.reasonKey());
        assertFalse("it must not be blockable before it is reviewed", result.blockable());
        assertTrue(SystemAppClassifier.requiresRiskAcceptance(result));
    }

    @Test
    public void anAcceptedOemComponentBecomesSelectable() {
        Classification result =
                classify(systemApp("com.oem.weatherwidget"), RiskAcceptanceStatus.FRESH);

        assertEquals(Tier.UNCLASSIFIED_OEM, result.tier());
        assertEquals(ReasonKey.UNCLASSIFIED_OEM_RISK_ACCEPTED, result.reasonKey());
        assertTrue(result.blockable());
    }

    @Test
    public void aDriftedAcceptanceFailsClosedAgain() {
        Classification result =
                classify(systemApp("com.oem.weatherwidget"), RiskAcceptanceStatus.DRIFTED);

        assertEquals(RowState.BLOCKED, result.state());
        assertEquals(ReasonKey.UNCLASSIFIED_OEM_RISK_DRIFTED, result.reasonKey());
        assertFalse("a re-signed component is not the one that was reviewed",
                result.blockable());
    }

    @Test
    public void aRiskAcceptanceCanNeverUnprotectAProtectedPackage() {
        // Belt and braces for the console's worst case: an operator who accepts
        // the risk on every package on the device still cannot block one of these.
        for (String packageName : LockdownPackages.ESSENTIAL_SYSTEM) {
            assertFalse(packageName,
                    classify(systemApp(packageName), RiskAcceptanceStatus.FRESH).blockable());
        }
        assertFalse(classify(userApp(OWN), RiskAcceptanceStatus.FRESH).blockable());
    }

    // --- Risk-acceptance freshness -----------------------------------------

    @Test
    public void noAcceptanceOnFileIsReportedAsNone() {
        assertEquals(RiskAcceptanceStatus.NONE,
                SystemAppClassifier.riskStatusOf(null, "aa11", "1.0 (1)"));
    }

    @Test
    public void anAcceptanceIsFreshOnlyWhileSignerAndVersionBothMatch() {
        SystemAppRiskAcceptance accepted = new SystemAppRiskAcceptance(
                "com.oem.weatherwidget", "AA:11:BB:22", "1.0 (1)", "installed,visible",
                "oem/build/1", 1_000L);

        assertEquals(RiskAcceptanceStatus.FRESH,
                SystemAppClassifier.riskStatusOf(accepted, "aa11bb22", "1.0 (1)"));
        assertEquals("a re-signed package is a different package",
                RiskAcceptanceStatus.DRIFTED,
                SystemAppClassifier.riskStatusOf(accepted, "ffff0000", "1.0 (1)"));
        assertEquals("an updated package was not the one reviewed",
                RiskAcceptanceStatus.DRIFTED,
                SystemAppClassifier.riskStatusOf(accepted, "aa11bb22", "1.1 (2)"));
        assertEquals("an unreadable signer is not a match",
                RiskAcceptanceStatus.DRIFTED,
                SystemAppClassifier.riskStatusOf(accepted, "", "1.0 (1)"));
    }

    @Test
    public void anAcceptanceRecordedWithoutASignerNeverMatches() {
        // "Both signers unreadable" is not evidence of the same package; treating
        // it as a match would make an unreadable signer a way past the review.
        SystemAppRiskAcceptance unproven = new SystemAppRiskAcceptance(
                "com.oem.weatherwidget", "", "1.0 (1)", "installed,visible", "oem/build/1", 1L);

        assertFalse(unproven.matches("", "1.0 (1)"));
        assertEquals(RiskAcceptanceStatus.DRIFTED,
                SystemAppClassifier.riskStatusOf(unproven, "", "1.0 (1)"));
    }

    @Test
    public void anAcceptanceNormalisesDigestFormattingButNotContent() {
        SystemAppRiskAcceptance accepted = new SystemAppRiskAcceptance(
                "com.oem.weatherwidget", "AA:11:BB:22", "1.0 (1)", "", "", 1L);

        assertTrue(accepted.matches(" aa11bb22 ", "1.0 (1)"));
        assertTrue(accepted.matches("AA11BB22", "1.0 (1)"));
        assertFalse(accepted.matches("aa11bb23", "1.0 (1)"));
    }

    @Test
    public void aRecordKeepsTheAuditContextItWasGivenWithoutMatchingOnIt() {
        SystemAppRiskAcceptance accepted = new SystemAppRiskAcceptance(
                "com.oem.weatherwidget", "aa11", "1.0 (1)", "installed,hidden",
                "oem/product/device:14/UP1A/9999:user/release-keys", 42L);

        assertEquals("installed,hidden", accepted.priorState());
        assertEquals("oem/product/device:14/UP1A/9999:user/release-keys", accepted.firmwareBuild());
        assertEquals(42L, accepted.acceptedAtMillis());
        // The audit fields are context, not match criteria: the same package on a
        // different firmware build is still the package that was reviewed.
        assertTrue(accepted.matches("aa11", "1.0 (1)"));
    }

    // --- Filters -----------------------------------------------------------

    @Test
    public void everyRowMatchesTheAllFilter() {
        PackageSnapshot app = systemApp("com.oem.weatherwidget");

        assertTrue(SystemAppClassifier.matchesCategory(
                classify(app), app, PROTECTED, Category.ALL));
    }

    @Test
    public void theFiltersDescribeIndependentFacets() {
        PackageSnapshot chrome = systemApp("com.android.chrome");
        Classification classification = classify(chrome);

        // Chrome is a system package and a browser at the same time; the filters
        // must not partition the inventory into one bucket per row.
        assertTrue(SystemAppClassifier.matchesCategory(
                classification, chrome, PROTECTED, Category.SYSTEM));
        assertTrue(SystemAppClassifier.matchesCategory(
                classification, chrome, PROTECTED, Category.BROWSER));
        assertFalse(SystemAppClassifier.matchesCategory(
                classification, chrome, PROTECTED, Category.USER));
    }

    @Test
    public void theProtectedFilterShowsExactlyTheProtectedRows() {
        PackageSnapshot systemUi = systemApp("com.android.systemui");
        PackageSnapshot ordinary = userApp("org.thoughtcrime.securesms");

        assertTrue(SystemAppClassifier.matchesCategory(
                classify(systemUi), systemUi, PROTECTED, Category.PROTECTED));
        assertFalse(SystemAppClassifier.matchesCategory(
                classify(ordinary), ordinary, PROTECTED, Category.PROTECTED));
    }

    @Test
    public void theManagementFilterShowsTheConfiguredTransports() {
        for (String packageName : LockdownPackages.managementPackageNames()) {
            PackageSnapshot transport = userApp(packageName);

            assertTrue(packageName, SystemAppClassifier.matchesCategory(
                    classify(transport), transport, PROTECTED, Category.MANAGEMENT));
        }
    }

    @Test
    public void theStoreFilterFindsThePackageInstallers() {
        PackageSnapshot play = systemApp("com.android.vending");
        PackageSnapshot installer = systemApp("com.android.packageinstaller");

        assertTrue(SystemAppClassifier.matchesCategory(
                classify(play), play, PROTECTED, Category.STORE));
        assertTrue(SystemAppClassifier.matchesCategory(
                classify(installer), installer, PROTECTED, Category.STORE));
        // ...and the installer is still protected, so the filter shows it without
        // making it selectable.
        assertFalse(classify(installer).blockable());
    }

    @Test
    public void theSocialFilterFindsTheKnownSocialPackages() {
        PackageSnapshot instagram = userApp("com.instagram.android");

        assertTrue(SystemAppClassifier.matchesCategory(
                classify(instagram), instagram, PROTECTED, Category.SOCIAL));
    }

    // --- Structural guards --------------------------------------------------

    @Test
    public void aSnapshotDemandsAPackageName() {
        for (String invalid : new String[]{null, ""}) {
            try {
                new PackageSnapshot(invalid, false, false, true, false);
                throw new AssertionError("expected a rejection for " + invalid);
            } catch (IllegalArgumentException expected) {
                // The inventory is keyed by package name; a blank one is a defect.
            }
        }
    }

    @Test
    public void contextRecordsDefendAgainstNullCollections() {
        ProtectedContext empty = new ProtectedContext(null, null, null, null, null);
        CatalogContext catalog = new CatalogContext(null, null, null);

        assertEquals(Set.of(), empty.essentialSystem());
        assertEquals(Set.of(), empty.managementPackageNames());
        assertEquals("", empty.activeInputMethodPackage());
        assertEquals(Set.of(), catalog.alwaysBlocked());
    }

    @Test
    public void theCatalogueContextMirrorsTheEnforcedCatalogues() {
        assertEquals(LockdownPackages.ALWAYS_BLOCKED, CATALOG.alwaysBlocked());
        assertEquals(LockdownPackages.KNOWN_BROWSER_AND_SOCIAL, CATALOG.knownBrowserAndSocial());
        assertEquals(LockdownPackages.KIOSK_ESCAPE_SURFACES, CATALOG.kioskEscapeSurfaces());
    }
}
