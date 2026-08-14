package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.policy.SystemAppSelection.InstalledIdentity;
import com.example.lockdowndpc.policy.SystemAppSelection.Revalidation;

import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * A stored selection is not an authorisation.
 *
 * <p>The case that matters is {@link #anOemUpdateThatResignsAPackageRevokesTheSelection()}:
 * an administrator accepts the risk of managing a specific OEM binary, the
 * vendor ships an update that re-signs it, and the package name — the only thing
 * the stored selection holds — does not change. Acting on the old acceptance
 * would hide a component nobody has reviewed, during an unattended reconciliation
 * pass, on a device nobody is holding.
 */
public final class SystemAppSelectionTest {

    private static final String PACKAGE = "com.oem.componentx";
    private static final String SIGNER =
            "aa11bb22cc33dd44ee55ff6677889900aa11bb22cc33dd44ee55ff6677889900";
    private static final String OTHER_SIGNER =
            "1111111111111111111111111111111111111111111111111111111111111111";

    @Test
    public void anUnchangedPackageStaysManaged() {
        Revalidation result = revalidate(
                acceptance(SIGNER, "1.0"), new InstalledIdentity(SIGNER, "1.0"));

        assertEquals(Set.of(PACKAGE), result.managed());
        assertTrue(result.revoked().isEmpty());
        assertFalse(result.anyRevoked());
    }

    @Test
    public void anOemUpdateThatResignsAPackageRevokesTheSelection() {
        Revalidation result = revalidate(
                acceptance(SIGNER, "1.0"), new InstalledIdentity(OTHER_SIGNER, "1.0"));

        assertTrue("a re-signed component must not stay managed", result.managed().isEmpty());
        assertEquals(Set.of(PACKAGE), result.revoked());
        assertEquals(PACKAGE, result.revokedSummary());
    }

    @Test
    public void anOemUpdateThatChangesTheVersionRevokesTheSelection() {
        // The signer can survive an update that replaces the binary entirely, so
        // the version is the second half of the identity, not decoration.
        Revalidation result = revalidate(
                acceptance(SIGNER, "1.0"), new InstalledIdentity(SIGNER, "1.1"));

        assertTrue(result.managed().isEmpty());
        assertEquals(Set.of(PACKAGE), result.revoked());
    }

    @Test
    public void aPackageThatCannotBeReadIsNotManaged() {
        // An unreadable identity is not evidence that the binary is unchanged.
        Revalidation result = revalidate(
                acceptance(SIGNER, "1.0"), InstalledIdentity.unreadable());

        assertTrue(result.managed().isEmpty());
        assertEquals(Set.of(PACKAGE), result.revoked());
    }

    @Test
    public void aSelectionWithNoRecordedAcceptanceIsNotManaged() {
        // A selection written before the acceptance record existed, or one whose
        // record was lost, has no risk that anyone is on record as accepting.
        Revalidation result = SystemAppSelection.revalidate(
                Set.of(PACKAGE),
                Map.of(),
                Map.of(PACKAGE, new InstalledIdentity(SIGNER, "1.0")));

        assertTrue(result.managed().isEmpty());
        assertEquals(Set.of(PACKAGE), result.revoked());
    }

    @Test
    public void anAcceptanceRecordedWithNoSignerNeverMatches() {
        // A signer that could not be read at acceptance time proves nothing, so
        // observing another unreadable signer later cannot reconfirm it.
        Revalidation result = revalidate(
                acceptance("", "1.0"), InstalledIdentity.unreadable());

        assertTrue(result.managed().isEmpty());
        assertEquals(Set.of(PACKAGE), result.revoked());
    }

    @Test
    public void digestFormattingDoesNotDecideTheOutcome() {
        // Operators paste colon-separated, spaced and upper-case digests. The
        // comparison normalises both sides, so formatting cannot silently revoke
        // a selection that is genuinely unchanged.
        Revalidation result = revalidate(
                acceptance("AA:11:BB:22:CC:33:DD:44:EE:55:FF:66:77:88:99:00"
                        + ":AA:11:BB:22:CC:33:DD:44:EE:55:FF:66:77:88:99:00", "1.0"),
                new InstalledIdentity(SIGNER, "1.0"));

        assertEquals(Set.of(PACKAGE), result.managed());
    }

    @Test
    public void severalPackagesAreJudgedIndependently() {
        Set<String> selected = new LinkedHashSet<>(java.util.List.of("com.a", "com.b", "com.c"));
        Map<String, SystemAppRiskAcceptance> acceptances = new LinkedHashMap<>();
        acceptances.put("com.a", new SystemAppRiskAcceptance("com.a", SIGNER, "1.0", "", "", 0L));
        acceptances.put("com.b", new SystemAppRiskAcceptance("com.b", SIGNER, "2.0", "", "", 0L));
        acceptances.put("com.c", new SystemAppRiskAcceptance("com.c", SIGNER, "3.0", "", "", 0L));
        Map<String, InstalledIdentity> installed = new LinkedHashMap<>();
        installed.put("com.a", new InstalledIdentity(SIGNER, "1.0"));
        installed.put("com.b", new InstalledIdentity(OTHER_SIGNER, "2.0"));
        installed.put("com.c", new InstalledIdentity(SIGNER, "3.0"));

        Revalidation result = SystemAppSelection.revalidate(selected, acceptances, installed);

        assertEquals(Set.of("com.a", "com.c"), result.managed());
        assertEquals(Set.of("com.b"), result.revoked());
    }

    @Test
    public void anEmptyOrNullSelectionIsNotAnError() {
        assertTrue(SystemAppSelection.revalidate(Set.of(), Map.of(), Map.of()).managed().isEmpty());
        assertTrue(SystemAppSelection.revalidate(null, null, null).managed().isEmpty());
        assertTrue(SystemAppSelection.revalidate(null, null, null).revoked().isEmpty());
    }

    @Test
    public void theResultCannotBeMutatedByItsCaller() {
        Revalidation result = revalidate(
                acceptance(SIGNER, "1.0"), new InstalledIdentity(SIGNER, "1.0"));

        org.junit.Assert.assertThrows(
                UnsupportedOperationException.class, () -> result.managed().add("com.other"));
        org.junit.Assert.assertThrows(
                UnsupportedOperationException.class, () -> result.revoked().add("com.other"));
    }

    private static SystemAppRiskAcceptance acceptance(String signer, String version) {
        return new SystemAppRiskAcceptance(PACKAGE, signer, version, "enabled", "build", 0L);
    }

    private static Revalidation revalidate(
            SystemAppRiskAcceptance acceptance,
            InstalledIdentity identity
    ) {
        return SystemAppSelection.revalidate(
                Set.of(PACKAGE),
                Map.of(PACKAGE, acceptance),
                Map.of(PACKAGE, identity));
    }
}
