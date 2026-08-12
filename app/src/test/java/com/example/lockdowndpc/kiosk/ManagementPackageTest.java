package com.example.lockdowndpc.kiosk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.policy.LockdownPackages;
import com.example.lockdowndpc.policy.LockdownPackages.ManagementPackage;
import com.example.lockdowndpc.policy.LockdownPackages.PackageClass;
import com.example.lockdowndpc.policy.LockdownPackages.SignerVerdict;

import org.junit.Test;

import java.util.Map;
import java.util.Set;

/**
 * Covers the management-package and essential-system-package models. These live
 * in {@code policy} but are exercised from the kiosk test package because kiosk
 * is the feature that introduced the classification seam.
 */
public final class ManagementPackageTest {

    private static final String DIGEST_A =
            "aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff0011223344";
    private static final String DIGEST_B =
            "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100f";

    @Test
    public void theTailscalePilotRecordExistsAndIsUnpinnedByDefault() {
        ManagementPackage tailscale = LockdownPackages.managementPackage("com.tailscale.ipn");

        assertNotNull(tailscale);
        assertFalse("the pilot must keep working unchanged", tailscale.hasPinnedCertificate());
        assertEquals(SignerVerdict.UNPINNED, LockdownPackages.verifySigner(tailscale, Set.of(DIGEST_A)));
        assertTrue(LockdownPackages.grantsManagementTrust(SignerVerdict.UNPINNED));
    }

    @Test
    public void aPinnedRecordMatchesOnlyItsApprovedDigest() {
        ManagementPackage pinned = new ManagementPackage("com.tailscale.ipn", Set.of(DIGEST_A));

        assertEquals(SignerVerdict.MATCH, LockdownPackages.verifySigner(pinned, Set.of(DIGEST_A)));
        assertEquals(SignerVerdict.MATCH,
                LockdownPackages.verifySigner(pinned, Set.of(DIGEST_B, DIGEST_A)));
        assertEquals(SignerVerdict.MISMATCH, LockdownPackages.verifySigner(pinned, Set.of(DIGEST_B)));
    }

    @Test
    public void aPinnedRecordFailsClosedWhenNoSignerCanBeRead() {
        ManagementPackage pinned = new ManagementPackage("com.tailscale.ipn", Set.of(DIGEST_A));

        assertEquals(SignerVerdict.UNKNOWN_SIGNER, LockdownPackages.verifySigner(pinned, Set.of()));
        assertEquals(SignerVerdict.UNKNOWN_SIGNER, LockdownPackages.verifySigner(pinned, null));
        assertFalse(LockdownPackages.grantsManagementTrust(SignerVerdict.UNKNOWN_SIGNER));
        assertFalse(LockdownPackages.grantsManagementTrust(SignerVerdict.MISMATCH));
    }

    @Test
    public void digestComparisonIgnoresFormattingButNotContent() {
        ManagementPackage pinned = new ManagementPackage(
                "com.tailscale.ipn", Set.of("AA:11:BB:22:CC:33:DD:44"));

        assertEquals(SignerVerdict.MATCH,
                LockdownPackages.verifySigner(pinned, Set.of("aa11bb22cc33dd44")));
        assertEquals(SignerVerdict.MATCH,
                LockdownPackages.verifySigner(pinned, Set.of(" AA11BB22CC33DD44 ")));
        assertEquals(SignerVerdict.MISMATCH,
                LockdownPackages.verifySigner(pinned, Set.of("aa11bb22cc33dd45")));
    }

    @Test
    public void aNullRecordNeverGrantsTrust() {
        assertEquals(SignerVerdict.MISMATCH, LockdownPackages.verifySigner(null, Set.of(DIGEST_A)));
    }

    @Test
    public void configurationCanOnlyTightenAnExistingRecordNeverAddOne() {
        var merged = LockdownPackages.managementPackages(Map.of(
                "com.tailscale.ipn", Set.of(DIGEST_A),
                "com.evil.backdoor", Set.of(DIGEST_B)
        ));

        assertEquals(LockdownPackages.MANAGEMENT_DEFAULTS.size(), merged.size());
        assertTrue(merged.get(0).hasPinnedCertificate());
        assertFalse(LockdownPackages.isManagementPackage("com.evil.backdoor"));
    }

    @Test
    public void emptyConfigurationLeavesTheDefaultsUntouched() {
        assertEquals(LockdownPackages.MANAGEMENT_DEFAULTS, LockdownPackages.managementPackages(Map.of()));
        assertEquals(LockdownPackages.MANAGEMENT_DEFAULTS, LockdownPackages.managementPackages(null));
    }

    @Test
    public void essentialSystemPackagesNeverOverlapTheBlockCatalogues() {
        for (String packageName : LockdownPackages.ESSENTIAL_SYSTEM) {
            assertFalse(packageName + " is both essential and always-blocked",
                    LockdownPackages.ALWAYS_BLOCKED.contains(packageName));
            assertFalse(packageName + " is both essential and browser/social-blocked",
                    LockdownPackages.KNOWN_BROWSER_AND_SOCIAL.contains(packageName));
            assertFalse(packageName + " is both essential and a kiosk escape surface",
                    LockdownPackages.KIOSK_ESCAPE_SURFACES.contains(packageName));
        }
    }

    @Test
    public void classificationIsConservativeByDefault() {
        assertEquals(PackageClass.ESSENTIAL_SYSTEM_PACKAGE,
                LockdownPackages.classify("com.android.systemui", Set.of()));
        assertEquals(PackageClass.MANAGEMENT,
                LockdownPackages.classify("com.tailscale.ipn", Set.of()));
        assertEquals(PackageClass.KIOSK_ESCAPE_SURFACE,
                LockdownPackages.classify("com.android.documentsui", Set.of()));
        // An arbitrary system package is NOT swept into management by default;
        // hiding every system package is what bricks OEM devices.
        assertEquals(PackageClass.ORDINARY,
                LockdownPackages.classify("com.oem.weatherwidget", Set.of()));
        assertEquals(PackageClass.ORDINARY, LockdownPackages.classify(null, Set.of()));
        assertEquals(PackageClass.ORDINARY, LockdownPackages.classify("", Set.of()));
    }

    @Test
    public void anAdministratorCanOptASystemAppIntoManagementButNotAnEssentialOne() {
        assertEquals(PackageClass.ADMIN_SELECTED_SYSTEM,
                LockdownPackages.classify("com.oem.weatherwidget", Set.of("com.oem.weatherwidget")));
        assertEquals(PackageClass.ESSENTIAL_SYSTEM_PACKAGE,
                LockdownPackages.classify("com.android.systemui", Set.of("com.android.systemui")));
    }

    @Test
    public void administratorSelectionCannotOverrideEscapeSurfaceClassification() {
        for (String packageName : LockdownPackages.KIOSK_ESCAPE_SURFACES) {
            assertEquals(
                    packageName,
                    PackageClass.KIOSK_ESCAPE_SURFACE,
                    LockdownPackages.classify(packageName, Set.of(packageName))
            );
        }
    }
}
