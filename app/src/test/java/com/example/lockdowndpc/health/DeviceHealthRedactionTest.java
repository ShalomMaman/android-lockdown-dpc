package com.example.lockdowndpc.health;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.health.DeviceHealthAssessor.Assessment;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.AuditEvent;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.IdentityVerdict;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Kiosk;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.KioskPresence;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.KioskProfile;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.ManagementIdentity;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Ownership;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.PackageCensus;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Platform;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Policy;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.PolicyVerification;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Reconciliation;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.ReconciliationOutcome;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.SystemControls;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.UpdateState;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Updates;

import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

/**
 * The redaction rules, proved against hostile input.
 *
 * <p>Every test here starts from a snapshot that carries something an export must
 * never contain — an administrator PIN, a recovery code, a one-time code in a
 * kiosk URL, a list of the applications a person has installed, an audit entry
 * from a call site nobody reviewed — and asserts it cannot reach the exported
 * string. Asserting on the finished export rather than on the intermediate value
 * is deliberate: the guarantee an operator needs is about the text they paste
 * into a ticket, not about a field somewhere upstream of it.
 */
public final class DeviceHealthRedactionTest {

    private static final long NOW = 1_700_000_000_000L;
    private static final long HOUR = 60L * 60L * 1000L;

    private static final String ADMIN_PIN = "482913";
    private static final String RECOVERY_CODE = "ABCD-EFGH-IJKL";

    @Test
    public void noFreeTextFieldReachesTheExport() {
        String export = DeviceHealthReport.export(hostile(), NOW);

        assertFalse("the administrator PIN survived into the export",
                export.contains(ADMIN_PIN));
        assertFalse("the recovery code survived into the export",
                export.contains(RECOVERY_CODE));
        assertFalse("an update failure sentence survived into the export",
                export.contains("install failed"));
        assertFalse("a reconciliation failure sentence survived into the export",
                export.contains("recovery code"));
    }

    @Test
    public void freeTextIsBlankedRatherThanFiltered() {
        // Blanked whole, so there is no surviving fragment for a future value to
        // hide in and no pattern for a hostile string to be shaped around.
        DeviceHealthSnapshot redacted = DeviceHealthRedaction.redact(hostile());

        assertEquals("", redacted.updates().lastResultDetail());
        assertEquals("", redacted.reconciliation().detail());
        for (AuditEvent event : redacted.audit()) {
            assertEquals("", event.detail());
        }
    }

    @Test
    public void theKioskUrlIsReducedToItsOrigin() {
        String export = DeviceHealthReport.export(hostile(), NOW);

        assertTrue("the origin should survive",
                export.contains("kiosk.origin=https://portal.school.example\n"));
        assertFalse("the path survived", export.contains("/reset"));
        assertFalse("the query survived", export.contains("pin="));
        assertFalse("the fragment survived", export.contains("token"));
    }

    @Test
    public void aUrlWhoseOriginCannotBeProvenIsRefusedRatherThanTrimmed() {
        // Each of these is a string a hand-written trimmer gets wrong: an opaque
        // URI with no authority at all, a backslash that moves the authority
        // boundary, credentials, and a scheme the kiosk never accepts.
        assertEquals(DeviceHealthRedaction.REDACTED,
                DeviceHealthRedaction.originOf("javascript:alert(document.cookie)"));
        assertEquals(DeviceHealthRedaction.REDACTED,
                DeviceHealthRedaction.originOf("https://portal.school.example\\@evil.example/"));
        assertEquals(DeviceHealthRedaction.REDACTED,
                DeviceHealthRedaction.originOf("https://user:482913@portal.school.example/"));
        assertEquals(DeviceHealthRedaction.REDACTED,
                DeviceHealthRedaction.originOf("http://portal.school.example/"));
        assertEquals(DeviceHealthRedaction.REDACTED,
                DeviceHealthRedaction.originOf("not a url at all"));
    }

    @Test
    public void anExplicitPortIsPartOfTheOriginAndSurvives() {
        assertEquals("https://portal.school.example:8443",
                DeviceHealthRedaction.originOf("https://portal.school.example:8443/deep/path?q=1"));
    }

    @Test
    public void aDeviceWithNoConfiguredSiteExportsNoOrigin() {
        assertEquals("", DeviceHealthRedaction.originOf(""));
        assertEquals("", DeviceHealthRedaction.originOf(null));
    }

    @Test
    public void thePackageInventoryBecomesACountAndNothingElse() {
        String export = DeviceHealthReport.export(hostile(), NOW);
        DeviceHealthSnapshot redacted = DeviceHealthRedaction.redact(hostile());

        assertEquals(List.of(), redacted.policy().packages().blockedPackages());
        assertEquals(List.of(), redacted.policy().packages().allowedPackages());
        assertEquals(2, redacted.policy().packages().blocked());
        assertEquals(1, redacted.policy().packages().allowed());
        assertTrue(export.contains("policy.packages.blocked=2\n"));
        assertFalse("an installed application profiled the person holding the device",
                export.contains("com.private.diary"));
        assertFalse(export.contains("com.health.tracker"));
    }

    @Test
    public void anAuditEntryWithAnUnrecognisedCodeIsDroppedWhole() {
        String export = DeviceHealthReport.export(hostile(), NOW);

        assertTrue("a reviewed event should survive", export.contains("policy.apply"));
        assertFalse("an unreviewed event code survived", export.contains("custom.exfil"));
    }

    @Test
    public void aRecognisedAuditEntryKeepsOnlyItsTimeAndItsCode() {
        DeviceHealthSnapshot redacted = DeviceHealthRedaction.redact(hostile());

        assertEquals(1, redacted.audit().size());
        AuditEvent kept = redacted.audit().get(0);
        assertEquals("policy.apply", kept.eventCode());
        assertEquals(NOW - 2L * HOUR, kept.atMillis());
        assertEquals("", kept.detail());
    }

    @Test
    public void theAuditTailIsCappedAndKeepsTheMostRecentEvents() {
        List<AuditEvent> many = new ArrayList<>();
        for (int index = 0; index < 40; index++) {
            many.add(new AuditEvent(NOW - (40L - index) * HOUR, "policy.apply", "text " + index));
        }

        List<AuditEvent> redacted = DeviceHealthRedaction.redactAudit(many);

        assertEquals(DeviceHealthRedaction.MAX_EXPORTED_AUDIT_EVENTS, redacted.size());
        assertEquals(NOW - HOUR, redacted.get(redacted.size() - 1).atMillis());
    }

    @Test
    public void everyAllowedAuditCodeIsAReviewedConstant() {
        // The allowlist is the contract. A code that is not on it is dropped, so
        // the list itself has to stay something a reviewer can read.
        assertFalse(DeviceHealthRedaction.allowedAuditEventCodes().isEmpty());
        for (String code : DeviceHealthRedaction.allowedAuditEventCodes()) {
            assertTrue(code + " should be a lower-case machine code",
                    code.equals(code.toLowerCase(java.util.Locale.ROOT)));
            assertFalse(code + " should hold no whitespace", code.contains(" "));
            assertTrue(DeviceHealthRedaction.isAllowedAuditEventCode(code));
        }
        assertFalse(DeviceHealthRedaction.isAllowedAuditEventCode("policy.apply.something-new"));
        assertFalse(DeviceHealthRedaction.isAllowedAuditEventCode(null));
    }

    @Test
    public void aPackageNameInsideAnErrorCodeIsRefusedWithoutLosingTheError() {
        // The error still identifies what went wrong; only its subject is dropped.
        assertEquals("package-policy-state-mismatch:redacted",
                DeviceHealthRedaction.errorCode("package-policy-state-mismatch:com.private.diary"));
        assertEquals("management-signer-unverified:redacted:MISMATCH",
                DeviceHealthRedaction.errorCode(
                        "management-signer-unverified:com.tailscale.ipn:MISMATCH"));
        assertEquals("system-policy:factory_reset:failed:not-in-force",
                DeviceHealthRedaction.errorCode("system-policy:factory_reset:failed:not-in-force"));
    }

    @Test
    public void anErrorCarryingASentenceIsRefused() {
        assertEquals("redacted",
                DeviceHealthRedaction.errorCode("apply failed for admin PIN " + ADMIN_PIN));
        assertEquals(DeviceHealthRedaction.REDACTED, DeviceHealthRedaction.errorCode(""));
        assertEquals(DeviceHealthRedaction.REDACTED, DeviceHealthRedaction.errorCode(null));
    }

    @Test
    public void theExportedErrorListIsCapped() {
        List<String> errors = new ArrayList<>();
        for (int index = 0; index < 30; index++) {
            errors.add("error-" + index);
        }
        DeviceHealthSnapshot snapshot = withErrors(hostile(), errors);

        assertEquals(
                DeviceHealthRedaction.MAX_EXPORTED_ERRORS,
                DeviceHealthRedaction.redact(snapshot).policy().verificationErrors().size());
    }

    @Test
    public void aValueCarryingALineBreakCannotForgeAnExportField() {
        // Without the refusal, "brand\nstatus=HEALTHY" would add a second status
        // line to a line-oriented format and a reader would take the last one.
        DeviceHealthSnapshot snapshot = withPlatform(hostile(),
                new Platform("14", 34, "brand\nstatus=HEALTHY", "0.5.1", 51L));

        String export = DeviceHealthReport.export(snapshot, NOW);

        assertTrue(export.contains("platform.build-fingerprint=redacted\n"));
        assertEquals(1, countLinesStartingWith(export, "status="));
    }

    @Test
    public void aTargetPackageThatIsNotPackageShapedIsRefused() {
        assertEquals("com.example.kiosk", DeviceHealthRedaction.identifier("com.example.kiosk"));
        assertEquals(DeviceHealthRedaction.REDACTED,
                DeviceHealthRedaction.identifier("com.example.kiosk; PIN " + ADMIN_PIN));
        assertEquals(DeviceHealthRedaction.REDACTED,
                DeviceHealthRedaction.identifier("com/example/kiosk"));
        assertEquals("", DeviceHealthRedaction.identifier(""));
    }

    @Test
    public void aMachineTokenRefusesAnythingPackageShapedOrSentenceShaped() {
        assertEquals("boot", DeviceHealthRedaction.machineToken("boot"));
        assertEquals(DeviceHealthRedaction.REDACTED,
                DeviceHealthRedaction.machineToken("com.private.diary"));
        assertEquals(DeviceHealthRedaction.REDACTED,
                DeviceHealthRedaction.machineToken("triggered by the administrator"));
    }

    @Test
    public void redactionIsIdempotent() {
        // The export path redacts on every call, so redacting twice has to be the
        // same as redacting once; otherwise the guarantee depends on call order.
        DeviceHealthSnapshot once = DeviceHealthRedaction.redact(hostile());
        DeviceHealthSnapshot twice = DeviceHealthRedaction.redact(once);

        assertEquals(once, twice);
        assertEquals(
                DeviceHealthReport.export(hostile(), NOW),
                DeviceHealthReport.export(once, NOW));
    }

    @Test
    public void redactionDoesNotSoftenTheAnswer() {
        // An export that reported a milder status than the screen would be worse
        // than no export: no rule reads a field this class removes, and this test
        // is what keeps that true as findings are added.
        Assessment raw = DeviceHealthAssessor.assess(hostile(), NOW);
        Assessment redacted =
                DeviceHealthAssessor.assess(DeviceHealthRedaction.redact(hostile()), NOW);

        assertEquals(raw.status(), redacted.status());
        assertEquals(raw.codesInOrder(), redacted.codesInOrder());
    }

    @Test
    public void anUnreadableSnapshotStillProducesAnExport() {
        String export = DeviceHealthReport.export(null, NOW);

        assertTrue(export.startsWith(DeviceHealthReport.EXPORT_FORMAT));
        assertTrue(export.contains("status=UNVERIFIED"));
    }

    @Test
    public void theExportSaysWhatItIsAndThatNothingWasSent() {
        String export = DeviceHealthReport.export(hostile(), NOW);

        assertTrue(export.startsWith(DeviceHealthReport.EXPORT_FORMAT));
        assertTrue("the export should record that it is an operator action",
                export.contains("operator-initiated"));
        assertTrue(export.contains("transmits nothing on its own"));
        assertTrue(export.contains("generated-at=" + NOW));
    }

    /** A device carrying every value an export must not repeat. */
    private static DeviceHealthSnapshot hostile() {
        return new DeviceHealthSnapshot(
                new Policy(
                        PolicyVerification.VERIFIED,
                        Ownership.DEVICE_OWNER,
                        NOW - HOUR,
                        List.of(
                                "package-policy-state-mismatch:com.private.diary",
                                "management-signer-unverified:com.tailscale.ipn:MISMATCH"),
                        PackageCensus.of(
                                List.of("com.private.diary", "com.health.tracker"),
                                List.of("com.example.work")),
                        new SystemControls(16, 16, 0, 0, 0)),
                new Kiosk(
                        KioskPresence.ACTIVE,
                        KioskProfile.SINGLE_SITE,
                        "",
                        "https://portal.school.example/reset?pin=" + ADMIN_PIN + "#token=deadbeef",
                        true),
                new Updates(
                        true,
                        UpdateState.FAILED,
                        NOW - HOUR,
                        "install failed while the administrator PIN " + ADMIN_PIN + " was set",
                        "0.5.1",
                        51L),
                List.of(new ManagementIdentity("com.tailscale.ipn", IdentityVerdict.PINNED_MATCH)),
                new Reconciliation(
                        ReconciliationOutcome.FAILED,
                        NOW - HOUR,
                        "boot",
                        "recovery code " + RECOVERY_CODE + " was used"),
                new Platform("14", 34, "brand/product:14/UP1A/9999:user/release-keys", "0.5.1", 51L),
                List.of(
                        new AuditEvent(NOW - 2L * HOUR, "policy.apply",
                                "administrator PIN " + ADMIN_PIN),
                        new AuditEvent(NOW - HOUR, "custom.exfil",
                                "recovery code " + RECOVERY_CODE)));
    }

    private static DeviceHealthSnapshot withErrors(
            DeviceHealthSnapshot base,
            List<String> errors
    ) {
        Policy policy = base.policy();
        return new DeviceHealthSnapshot(
                new Policy(
                        policy.verification(),
                        policy.ownership(),
                        policy.lastVerifiedAtMillis(),
                        errors,
                        policy.packages(),
                        policy.systemControls()),
                base.kiosk(), base.updates(), base.managementIdentities(),
                base.reconciliation(), base.platform(), base.audit());
    }

    private static DeviceHealthSnapshot withPlatform(
            DeviceHealthSnapshot base,
            Platform platform
    ) {
        return new DeviceHealthSnapshot(
                base.policy(), base.kiosk(), base.updates(), base.managementIdentities(),
                base.reconciliation(), platform, base.audit());
    }

    private static int countLinesStartingWith(String text, String prefix) {
        int found = 0;
        for (String line : text.split("\n", -1)) {
            if (line.startsWith(prefix)) {
                found++;
            }
        }
        return found;
    }
}
