package com.example.lockdowndpc.kiosk;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.policy.LockdownPackages;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

/** The eligibility rule the console picker and the controller both apply. */
public final class KioskAppCatalogTest {

    private static KioskAppCatalog.Candidate healthy(String packageName, String label) {
        return new KioskAppCatalog.Candidate(packageName, label, true, true, true, false);
    }

    @Test
    public void acceptsAnInstalledEnabledLaunchableThirdPartyApp() {
        assertTrue(KioskAppCatalog.isSelectable(healthy("com.example.reader", "Reader")));
    }

    @Test
    public void rejectsDeviceGuardItself() {
        assertFalse(KioskAppCatalog.isSelectable(new KioskAppCatalog.Candidate(
                "com.example.lockdowndpc", "Device Guard", true, true, true, true)));
    }

    @Test
    public void rejectsEveryKnownKioskEscapeSurface() {
        // This is the case a picker built on "installed and launchable" alone
        // gets wrong: a documents picker or a file manager passes every device
        // check and is exactly the way out of a kiosk.
        for (String packageName : LockdownPackages.KIOSK_ESCAPE_SURFACES) {
            assertTrue(
                    packageName + " must never be a kiosk target",
                    KioskAppCatalog.isProtectedFromKiosk(packageName)
            );
            assertFalse(
                    packageName + " must not be selectable",
                    KioskAppCatalog.isSelectable(healthy(packageName, "Files"))
            );
        }
    }

    @Test
    public void rejectsEssentialSystemPackagesAndTheManagementTransport() {
        for (String packageName : LockdownPackages.ESSENTIAL_SYSTEM) {
            assertTrue(packageName, KioskAppCatalog.isProtectedFromKiosk(packageName));
        }
        for (String packageName : LockdownPackages.managementPackageNames()) {
            assertTrue(packageName, KioskAppCatalog.isProtectedFromKiosk(packageName));
        }
    }

    @Test
    public void rejectsUninstalledDisabledOrUnlaunchableCandidates() {
        assertFalse(KioskAppCatalog.isSelectable(new KioskAppCatalog.Candidate(
                "com.example.reader", "Reader", false, true, true, false)));
        assertFalse(KioskAppCatalog.isSelectable(new KioskAppCatalog.Candidate(
                "com.example.reader", "Reader", true, false, true, false)));
        assertFalse(KioskAppCatalog.isSelectable(new KioskAppCatalog.Candidate(
                "com.example.reader", "Reader", true, true, false, false)));
    }

    @Test
    public void rejectsAnEmptyOrNullPackageName() {
        assertTrue(KioskAppCatalog.isProtectedFromKiosk(null));
        assertTrue(KioskAppCatalog.isProtectedFromKiosk(""));
        assertFalse(KioskAppCatalog.isSelectable(null));
        assertFalse(KioskAppCatalog.isSelectable(healthy("", "Nameless")));
    }

    @Test
    public void anOrdinaryBrowserStaysSelectable() {
        // Kiosk eligibility is not the allow/block list. A browser an
        // administrator deliberately pins as the single kiosk app is a real
        // deployment, and lock task is what contains it.
        assertTrue(KioskAppCatalog.isSelectable(healthy("org.mozilla.firefox", "Firefox")));
    }

    @Test
    public void selectableFiltersDeduplicatesAndOrdersByLabel() {
        List<KioskAppCatalog.Candidate> candidates = new ArrayList<>(List.of(
                healthy("com.example.zebra", "zebra"),
                healthy("com.android.documentsui", "Files"),
                healthy("com.example.apple", "Apple"),
                healthy("com.example.zebra", "zebra"),
                new KioskAppCatalog.Candidate(
                        "com.example.gone", "Gone", false, true, true, false)
        ));

        List<KioskAppCatalog.Candidate> selectable = KioskAppCatalog.selectable(candidates);

        assertEquals(
                List.of("com.example.apple", "com.example.zebra"),
                selectable.stream().map(KioskAppCatalog.Candidate::packageName).toList()
        );
    }

    @Test
    public void selectableToleratesNoInput() {
        assertEquals(List.of(), KioskAppCatalog.selectable(null));
        assertEquals(List.of(), KioskAppCatalog.selectable(List.of()));
    }

    @Test
    public void aBlankLabelFallsBackToThePackageName() {
        assertEquals(
                "com.example.reader",
                new KioskAppCatalog.Candidate(
                        "com.example.reader", "  ", true, true, true, false).label()
        );
    }
}
