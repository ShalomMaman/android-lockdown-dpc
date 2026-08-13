package com.example.lockdowndpc.health;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.health.DeviceHealthAssessor.DeviceHealthStatus;
import com.example.lockdowndpc.health.DeviceHealthAssessor.Finding;
import com.example.lockdowndpc.health.DeviceHealthAssessor.Severity;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.IdentityVerdict;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.KioskPresence;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.KioskProfile;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.Ownership;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.PolicyVerification;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.ReconciliationOutcome;
import com.example.lockdowndpc.health.DeviceHealthSnapshot.UpdateState;

import org.junit.Test;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilderFactory;

/**
 * Locale parity for {@code device_health_strings.xml}, and the tie between this
 * file and the enums the report renders.
 *
 * <p>The shared guards — {@code LocaleParityTest} and
 * {@code tools/check_locale_parity.py} — read {@code strings.xml} and only
 * {@code strings.xml}, so a feature-owned resource file is invisible to them.
 * The failure that actually happens is a key added to one locale and forgotten
 * in the other, which compiles and only surfaces on a device set to the other
 * language.
 *
 * <p>The second half of this test is the more valuable one: it walks every enum
 * constant the health report can display and asserts that both locales define a
 * sentence for it. An exhaustive {@code switch} in {@code DeviceHealthReport}
 * already refuses to compile when a constant has no branch; nothing but this
 * catches a branch pointing at a key that was never written.
 */
public final class DeviceHealthStringsParityTest {

    private static final String FILE_NAME = "device_health_strings.xml";
    private static final String PREFIX = "health_";
    private static final Pattern PLACEHOLDER = Pattern.compile("%(?:\\d+\\$)?[a-zA-Z]");
    private static final Pattern LATIN_RUN = Pattern.compile("[A-Za-z]{2,}");
    private static final char HEBREW_FIRST = '֐';
    private static final char HEBREW_LAST = '׿';
    private static final char LTR_ISOLATE = '⁦';
    private static final char POP_ISOLATE = '⁩';

    private final Map<String, String> english = read("values");
    private final Map<String, String> hebrew = read("values-iw");

    @Test
    public void everyKeyExistsInBothLocales() {
        assertEquals(
                "string keys differ between values/ and values-iw/",
                new TreeSet<>(english.keySet()),
                new TreeSet<>(hebrew.keySet()));
    }

    @Test
    public void everyKeyCarriesTheHealthPrefix() {
        // Android merges every values/*.xml into one resource table, so a key here
        // shares a namespace with strings.xml. The prefix is what keeps a health
        // string from silently overriding a console one.
        List<String> foreign = new ArrayList<>();
        english.keySet().forEach(key -> {
            if (!key.startsWith(PREFIX)) {
                foreign.add(key);
            }
        });
        assertEquals("every key in this file must carry the health_ prefix",
                List.of(), foreign);
    }

    @Test
    public void formatPlaceholdersMatch() {
        english.forEach((key, text) -> assertEquals(
                "format placeholders differ for string/" + key,
                placeholdersOf(text),
                placeholdersOf(hebrew.get(key))));
    }

    @Test
    public void noValueIsBlank() {
        english.forEach((key, text) ->
                assertFalse("values/" + key + " is blank", text.isBlank()));
        hebrew.forEach((key, text) ->
                assertFalse("values-iw/" + key + " is blank", text.isBlank()));
    }

    @Test
    public void theDefaultLocaleIsEnglish() {
        List<String> withHebrew = new ArrayList<>();
        english.forEach((key, text) -> {
            if (containsHebrew(text)) {
                withHebrew.add(key);
            }
        });
        assertEquals("values/ is the English default", List.of(), withHebrew);
    }

    @Test
    public void theHebrewTranslationIsActuallyHebrew() {
        // A key copied over from the default and never translated is the other
        // half of the same mistake, and it is invisible until a Hebrew device
        // shows it.
        List<String> untranslated = new ArrayList<>();
        hebrew.forEach((key, text) -> {
            if (hasTranslatableLetters(text) && !containsHebrew(text)) {
                untranslated.add(key);
            }
        });
        assertEquals("values-iw/ holds no Hebrew for these keys", List.of(), untranslated);
    }

    @Test
    public void hebrewIsolatesEveryLatinRunItEmbeds() {
        // A Latin word inside a Hebrew sentence drags the surrounding punctuation
        // to the wrong side unless it is isolated. Runtime values are isolated in
        // code; a Latin run baked into the translation carries its own marks.
        List<String> unisolated = new ArrayList<>();
        hebrew.forEach((key, text) -> {
            String stripped = PLACEHOLDER.matcher(text).replaceAll(" ");
            Matcher matcher = LATIN_RUN.matcher(stripped);
            while (matcher.find()) {
                if (!isIsolated(stripped, matcher.start(), matcher.end() - 1)) {
                    unisolated.add(key);
                    break;
                }
            }
        });
        assertEquals(
                "values-iw/ embeds a Latin run with no U+2066/U+2069 isolate around it",
                List.of(), unisolated);
    }

    @Test
    public void everyFindingHasASentenceInBothLocales() {
        for (Finding finding : Finding.values()) {
            requireKey(finding.resourceKey(), finding.name());
        }
    }

    @Test
    public void everyOverallStatusHasALabelAndAnExplanation() {
        for (DeviceHealthStatus status : DeviceHealthStatus.values()) {
            String key = PREFIX + "status_" + lower(status.name());
            requireKey(key, status.name());
            requireKey(key + "_body", status.name());
        }
    }

    @Test
    public void everySeverityHasALabel() {
        for (Severity severity : Severity.values()) {
            requireKey(PREFIX + "severity_" + lower(severity.name()), severity.name());
        }
    }

    @Test
    public void everyDeviceStateTheReportCanShowHasALabel() {
        for (Ownership ownership : Ownership.values()) {
            requireKey(PREFIX + "ownership_" + lower(ownership.name()), ownership.name());
        }
        for (PolicyVerification verification : PolicyVerification.values()) {
            requireKey(PREFIX + "policy_verification_" + lower(verification.name()),
                    verification.name());
        }
        for (KioskPresence presence : KioskPresence.values()) {
            requireKey(PREFIX + "kiosk_state_" + lower(presence.name()), presence.name());
        }
        for (KioskProfile profile : KioskProfile.values()) {
            requireKey(PREFIX + "kiosk_profile_" + lower(profile.name()), profile.name());
        }
        for (UpdateState state : UpdateState.values()) {
            requireKey(PREFIX + "update_state_" + lower(state.name()), state.name());
        }
        for (IdentityVerdict verdict : IdentityVerdict.values()) {
            requireKey(PREFIX + "identity_" + lower(verdict.name()), verdict.name());
        }
        for (ReconciliationOutcome outcome : ReconciliationOutcome.values()) {
            requireKey(PREFIX + "reconciliation_" + lower(outcome.name()), outcome.name());
        }
    }

    @Test
    public void theReportStatesThatNothingLeavesTheDeviceOnItsOwn() {
        // The privacy claim is a product promise, so it is pinned rather than left
        // to whoever edits the copy next.
        String notice = english.get("health_local_only").toLowerCase(Locale.ROOT);
        assertTrue("the report must say it is assembled on the device",
                notice.contains("on the device"));
        assertTrue("the report must deny collecting telemetry", notice.contains("telemetry"));
        assertTrue("the report must deny having an analytics endpoint",
                notice.contains("analytics endpoint"));
        assertTrue("the report must say an export is requested by an administrator",
                notice.contains("administrator asks"));
    }

    @Test
    public void theExportConfirmationNamesWhatItRemoves() {
        String body = english.get("health_export_body");
        assertTrue("the confirmation must name the administrator PIN", body.contains("PIN"));
        assertTrue("the confirmation must name the recovery code",
                body.contains("recovery code"));
        assertTrue("the confirmation must name the kiosk origin limit",
                body.contains("origin"));
        assertTrue("the confirmation must say where the export goes",
                body.contains("clipboard"));
    }

    private void requireKey(String key, String owner) {
        assertTrue("values/ is missing " + key + " for " + owner, english.containsKey(key));
        assertTrue("values-iw/ is missing " + key + " for " + owner, hebrew.containsKey(key));
    }

    private static String lower(String name) {
        return name.toLowerCase(Locale.ROOT);
    }

    private static List<String> placeholdersOf(String text) {
        List<String> found = new ArrayList<>();
        Matcher matcher = PLACEHOLDER.matcher(text == null ? "" : text);
        while (matcher.find()) {
            found.add(matcher.group());
        }
        found.sort(String::compareTo);
        return found;
    }

    private static boolean containsHebrew(String text) {
        return text.chars().anyMatch(c -> c >= HEBREW_FIRST && c <= HEBREW_LAST);
    }

    /** Whether the value holds a word at all once the placeholders are removed. */
    private static boolean hasTranslatableLetters(String text) {
        return PLACEHOLDER.matcher(text).replaceAll("").chars().anyMatch(Character::isLetter);
    }

    /** Whether the run between {@code first} and {@code last} sits in an isolate. */
    private static boolean isIsolated(String text, int first, int last) {
        int opening = text.lastIndexOf(LTR_ISOLATE, first);
        if (opening < 0) {
            return false;
        }
        int closing = text.indexOf(POP_ISOLATE, opening);
        return closing > last;
    }

    private static Map<String, String> read(String folder) {
        File file = new File(moduleDir(), "src/main/res/" + folder + "/" + FILE_NAME);
        assertTrue("missing resource file: " + file, file.isFile());
        try {
            NodeList nodes = DocumentBuilderFactory.newInstance()
                    .newDocumentBuilder()
                    .parse(file)
                    .getElementsByTagName("string");
            LinkedHashMap<String, String> strings = new LinkedHashMap<>();
            for (int index = 0; index < nodes.getLength(); index++) {
                Element element = (Element) nodes.item(index);
                strings.put(element.getAttribute("name"), element.getTextContent());
            }
            return strings;
        } catch (Exception exception) {
            throw new AssertionError("could not read " + file, exception);
        }
    }

    /** The {@code app} module directory, found from wherever the runner started. */
    private static File moduleDir() {
        File candidate = new File(System.getProperty("user.dir", ".")).getAbsoluteFile();
        while (candidate != null) {
            if (new File(candidate, "src/main/res/values/" + FILE_NAME).isFile()) {
                return candidate;
            }
            File module = new File(candidate, "app");
            if (new File(module, "src/main/res/values/" + FILE_NAME).isFile()) {
                return module;
            }
            candidate = candidate.getParentFile();
        }
        throw new AssertionError("could not locate the app module");
    }
}
