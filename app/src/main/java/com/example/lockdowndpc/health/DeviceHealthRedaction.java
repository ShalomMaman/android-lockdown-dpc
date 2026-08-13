package com.example.lockdowndpc.health;

import com.example.lockdowndpc.health.DeviceHealthSnapshot.AuditEvent;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Kiosk;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.ManagementIdentity;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.PackageCensus;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Platform;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Policy;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Reconciliation;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Updates;
import com.example.lockdowndpc.kiosk.KioskUrl;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Reduces a device health snapshot to the form an administrator may take off the
 * device.
 *
 * <p>The distinction this class draws is between what an administrator standing
 * in front of the device may read and what may be written into a file that will
 * be mailed, pasted into a ticket or stored in a fleet spreadsheet. Those are not
 * the same set. A local report may name every blocked application, because the
 * inventory screen already does; an export may not, because a list of every
 * application on a device describes the person holding it.
 *
 * <p>Two design rules do the actual work:
 *
 * <ul>
 *   <li><b>Allowlist by construction, not filter by inspection.</b> A field is
 *       exported because its type says what it is — an enum, a count, a
 *       timestamp, an origin — not because a scrubber failed to find anything
 *       objectionable in it. Free text is dropped whole, so there is no pattern
 *       for a hostile value to slip past.</li>
 *   <li><b>Refuse the value, do not repair it.</b> A string that does not match
 *       its expected shape becomes {@link #REDACTED} in full. Scrubbing the bad
 *       characters out of {@code https://portal.example/reset?pin=482913} leaves a
 *       string that still carries the secret; refusing it does not.</li>
 * </ul>
 *
 * <p>What is stripped or refused, in the words of the requirement:
 *
 * <ol>
 *   <li>Administrator PIN material and recovery codes. These have no field of
 *       their own and never will; they can only arrive inside free text, and no
 *       free-text field survives — {@code Updates.lastResultDetail},
 *       {@code Reconciliation.detail} and {@code AuditEvent.detail} are blanked
 *       unconditionally.</li>
 *   <li>The kiosk URL path, query and fragment. Only the origin survives, and
 *       only when {@code KioskUrl} can prove the URL parses to one.</li>
 *   <li>Package inventories. The counts survive; the names do not.</li>
 *   <li>Audit entries whose event code is not in
 *       {@link #ALLOWED_AUDIT_EVENT_CODES}. An unrecognised entry is dropped
 *       whole rather than exported with its text removed.</li>
 * </ol>
 *
 * <p>The honest boundary: this class cannot detect a secret an operator or an OEM
 * has placed inside a field whose shape is legitimate — a firmware fingerprint
 * containing a number, for instance. It guarantees that no field carrying
 * free-form, caller-supplied text is exported at all, which is where a PIN, a
 * recovery code or a URL secret can actually come from.
 *
 * <p>Nothing here transmits anything. {@link #redact} produces a value;
 * {@link DeviceHealthReport#export} turns it into a string; an administrator
 * decides what happens to that string.
 *
 * <h2>The audit tail is empty today, deliberately</h2>
 *
 * <p>Rule 4 above is enforced, but as of 0.5.2 nothing produces the codes it
 * allows: {@code AuditLog} stores localized prose with no machine code, so
 * {@code DeviceHealthCollector} passes an empty audit list and every export
 * carries no audit section at all. That is the fail-closed end of the
 * behaviour — nothing untrusted escapes — but it must not be read as "the export
 * carries a redacted audit trail", because it currently carries none. The
 * allowlist is the contract a future {@code AuditLog} event code has to satisfy
 * before an entry may travel; it is not evidence that entries are travelling.
 * The gap is recorded in {@code docs/production-roadmap.md}.
 */
public final class DeviceHealthRedaction {

    /** What a refused value becomes. Deliberately not empty, so a reader sees it. */
    public static final String REDACTED = "redacted";

    /** How many machine-readable policy errors an export carries. */
    public static final int MAX_EXPORTED_ERRORS = 10;

    /** How many audit events an export carries, most recent last. */
    public static final int MAX_EXPORTED_AUDIT_EVENTS = 25;

    private static final int MAX_TOKEN_LENGTH = 48;
    private static final int MAX_IDENTIFIER_LENGTH = 128;
    private static final int MAX_PLATFORM_TEXT_LENGTH = 160;
    private static final int MAX_ERROR_TOKENS = 6;

    /**
     * The audit event codes an export is allowed to carry.
     *
     * <p>An allowlist rather than a denylist, because the failure being prevented
     * is an event code nobody reviewed carrying whatever a future call site
     * interpolates into it. A code that is not here is dropped, which loses
     * information in the export and is the correct trade: the local report still
     * shows every entry to the administrator in front of the device.
     */
    public static final Set<String> ALLOWED_AUDIT_EVENT_CODES = Set.of(
            "policy.apply",
            "policy.apply.failed",
            "policy.pause",
            "policy.pause.failed",
            "policy.allowlist.saved",
            "policy.mode.changed",
            "policy.system-selection.saved",
            "policy.system-control.changed",
            "policy.system-control.unverified",
            "policy.reconciliation.failed",
            "policy.reconciliation.crashed",
            "kiosk.configured",
            "kiosk.entered",
            "kiosk.exited",
            "kiosk.cleared",
            "kiosk.faulted",
            "update.checked",
            "update.installed",
            "update.failed",
            "admin.pin.changed",
            "admin.recovery.rotated",
            "admin.session.locked",
            "admin.locale.changed",
            "device.boot",
            "health.exported"
    );

    private DeviceHealthRedaction() {}

    /**
     * The exportable form of a snapshot.
     *
     * <p>Returns the same type on purpose, so {@link DeviceHealthReport} can — and
     * does — run this over every snapshot it exports without the caller having to
     * remember to. The operation is idempotent, which is what makes that safe:
     * redacting an already-redacted snapshot changes nothing.
     *
     * <p>The assessment is unchanged by redaction. No rule in
     * {@link DeviceHealthAssessor} reads a field this class removes, so an export
     * reports exactly the status the local screen reports rather than a milder one
     * that the missing detail happened to produce.
     */
    public static DeviceHealthSnapshot redact(DeviceHealthSnapshot raw) {
        if (raw == null) {
            return DeviceHealthSnapshot.unreadable();
        }
        return new DeviceHealthSnapshot(
                redactPolicy(raw.policy()),
                redactKiosk(raw.kiosk()),
                redactUpdates(raw.updates()),
                redactIdentities(raw.managementIdentities()),
                redactReconciliation(raw.reconciliation()),
                redactPlatform(raw.platform()),
                redactAudit(raw.audit())
        );
    }

    private static Policy redactPolicy(Policy policy) {
        List<String> errors = new ArrayList<>();
        for (String error : policy.verificationErrors()) {
            if (errors.size() >= MAX_EXPORTED_ERRORS) {
                break;
            }
            errors.add(errorCode(error));
        }
        return new Policy(
                policy.verification(),
                policy.ownership(),
                policy.lastVerifiedAtMillis(),
                errors,
                // The counts are the fleet-relevant part; the names are the part
                // that profiles whoever uses the device.
                PackageCensus.counted(policy.packages().blocked(), policy.packages().allowed()),
                policy.systemControls()
        );
    }

    private static Kiosk redactKiosk(Kiosk kiosk) {
        return new Kiosk(
                kiosk.state(),
                kiosk.profile(),
                identifier(kiosk.targetPackage()),
                originOf(kiosk.siteUrl()),
                kiosk.targetResolved()
        );
    }

    private static Updates redactUpdates(Updates updates) {
        return new Updates(
                updates.channelEnabled(),
                updates.state(),
                updates.lastCheckedAtMillis(),
                // Free text from the update pipeline. The state enum already says
                // what happened; the sentence can say anything.
                "",
                platformText(updates.installedVersion()),
                updates.installedVersionCode()
        );
    }

    private static List<ManagementIdentity> redactIdentities(List<ManagementIdentity> identities) {
        List<ManagementIdentity> redacted = new ArrayList<>(identities.size());
        for (ManagementIdentity identity : identities) {
            redacted.add(new ManagementIdentity(
                    identifier(identity.packageName()), identity.verdict()));
        }
        return redacted;
    }

    private static Reconciliation redactReconciliation(Reconciliation reconciliation) {
        return new Reconciliation(
                reconciliation.outcome(),
                reconciliation.atMillis(),
                machineToken(reconciliation.trigger()),
                ""
        );
    }

    private static Platform redactPlatform(Platform platform) {
        return new Platform(
                platformText(platform.androidRelease()),
                platform.sdkInt(),
                platformText(platform.buildFingerprint()),
                platformText(platform.applicationVersion()),
                platform.applicationVersionCode()
        );
    }

    /**
     * Keeps the recognised audit events, without their text.
     *
     * <p>The most recent events are kept when the list is longer than the cap,
     * because the reason to read an exported audit tail is to see what happened
     * most recently before the device was reported.
     */
    public static List<AuditEvent> redactAudit(List<AuditEvent> raw) {
        List<AuditEvent> allowed = new ArrayList<>();
        for (AuditEvent event : DeviceHealthSnapshot.copyOf(raw)) {
            if (isAllowedAuditEventCode(event.eventCode())) {
                allowed.add(new AuditEvent(event.atMillis(), event.eventCode(), ""));
            }
        }
        int first = Math.max(0, allowed.size() - MAX_EXPORTED_AUDIT_EVENTS);
        return List.copyOf(allowed.subList(first, allowed.size()));
    }

    public static boolean isAllowedAuditEventCode(String eventCode) {
        return eventCode != null && ALLOWED_AUDIT_EVENT_CODES.contains(eventCode);
    }

    /**
     * The origin of a kiosk URL, and nothing else.
     *
     * <p>Delegates to {@code KioskUrl}, which is the same parser the kiosk itself
     * confines navigation with, so the export cannot disagree with the policy
     * about what the configured origin is. A URL that parser will not accept is
     * refused rather than trimmed by hand: the strings this has to survive —
     * {@code https://good\@evil.example}, an opaque {@code javascript:} URI, a
     * path holding a one-time code — are exactly the ones hand-written trimming
     * gets wrong.
     *
     * @return the origin, {@code ""} when there is no configured URL, or
     *         {@link #REDACTED} when no origin could be proven
     */
    public static String originOf(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) {
            return "";
        }
        KioskUrl.Result result = KioskUrl.normalize(rawUrl);
        if (!result.ok()) {
            return REDACTED;
        }
        String origin = result.value().origin().value();
        // Belt and braces: an origin is scheme, host and port. Anything that can
        // carry a path, a query or a fragment is not one, whatever the parser said.
        int authority = origin.indexOf("://");
        if (authority < 0
                || origin.indexOf('/', authority + 3) >= 0
                || origin.indexOf('?') >= 0
                || origin.indexOf('#') >= 0
                || origin.indexOf('@') >= 0) {
            return REDACTED;
        }
        return origin;
    }

    /**
     * One machine-readable error code, token by token.
     *
     * <p>The codes this project produces are colon-separated
     * ({@code system-policy:factory_reset:failed:not-in-force}) and the subject of
     * a failure is usually a package name in one of those positions. A token
     * containing a dot is therefore refused: that is what a package name, a host
     * name and a class name all look like, and none of the three belongs in a
     * fleet export.
     */
    public static String errorCode(String raw) {
        if (raw == null || raw.isBlank()) {
            return REDACTED;
        }
        String[] tokens = raw.trim().split(":", -1);
        StringBuilder result = new StringBuilder();
        for (int index = 0; index < tokens.length && index < MAX_ERROR_TOKENS; index++) {
            if (index > 0) {
                result.append(':');
            }
            result.append(tokens[index].isEmpty() ? REDACTED : machineToken(tokens[index]));
        }
        return result.length() == 0 ? REDACTED : result.toString();
    }

    /**
     * A short machine token: letters, digits, {@code -} and {@code _}.
     *
     * <p>No dot, so nothing package-shaped or host-shaped can pass, and no space,
     * so nothing sentence-shaped can.
     */
    public static String machineToken(String raw) {
        return refuseUnless(raw, MAX_TOKEN_LENGTH, DeviceHealthRedaction::isTokenCharacter);
    }

    /**
     * A configured identifier such as a package name.
     *
     * <p>A single configured target is not an inventory: it is the thing the
     * device was set up to do, and an export that cannot say what a kiosk points
     * at answers none of the questions it was written for.
     */
    public static String identifier(String raw) {
        return refuseUnless(raw, MAX_IDENTIFIER_LENGTH, DeviceHealthRedaction::isIdentifierCharacter);
    }

    /** A version or firmware string, which legitimately carries {@code /} and {@code :}. */
    public static String platformText(String raw) {
        return refuseUnless(raw, MAX_PLATFORM_TEXT_LENGTH, DeviceHealthRedaction::isPlatformCharacter);
    }

    /** Whole-value refusal: the value is exported as given, or not at all. */
    private static String refuseUnless(String raw, int maxLength, CharacterRule rule) {
        if (raw == null || raw.isEmpty()) {
            return "";
        }
        if (raw.length() > maxLength) {
            return REDACTED;
        }
        for (int index = 0; index < raw.length(); index++) {
            if (!rule.allows(raw.charAt(index))) {
                return REDACTED;
            }
        }
        return raw;
    }

    private static boolean isTokenCharacter(char character) {
        return isAsciiLetterOrDigit(character) || character == '-' || character == '_';
    }

    private static boolean isIdentifierCharacter(char character) {
        return isAsciiLetterOrDigit(character)
                || character == '.' || character == '_' || character == '-';
    }

    private static boolean isPlatformCharacter(char character) {
        return isAsciiLetterOrDigit(character)
                || character == '.' || character == '_' || character == '-'
                || character == '/' || character == ':' || character == '+'
                || character == ' ';
    }

    private static boolean isAsciiLetterOrDigit(char character) {
        return (character >= 'a' && character <= 'z')
                || (character >= 'A' && character <= 'Z')
                || (character >= '0' && character <= '9');
    }

    /** Every audit code an export may carry, sorted, for documentation and tests. */
    public static List<String> allowedAuditEventCodes() {
        return ALLOWED_AUDIT_EVENT_CODES.stream().sorted().collect(java.util.stream.Collectors.toList());
    }

    @FunctionalInterface
    private interface CharacterRule {
        boolean allows(char character);
    }
}
