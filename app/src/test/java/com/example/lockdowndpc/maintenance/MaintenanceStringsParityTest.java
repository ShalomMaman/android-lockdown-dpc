package com.example.lockdowndpc.maintenance;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.example.lockdowndpc.maintenance.MaintenanceStateMachine.CloseReason;

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
 * Locale parity for {@code maintenance_strings.xml}, and the tie between the
 * resource file and the enums.
 *
 * <p>The shared guards — {@code LocaleParityTest} and
 * {@code tools/check_locale_parity.py} — read {@code strings.xml} and nothing
 * else, so a feature that ships its own resource file is invisible to them. That
 * matters more here than almost anywhere: this is the screen where an
 * administrator decides to expose a debugging transport, and a blank or
 * English-only warning on a Hebrew device is a warning nobody reads.
 */
public final class MaintenanceStringsParityTest {

    private static final String FILE_NAME = "maintenance_strings.xml";
    private static final Pattern PLACEHOLDER = Pattern.compile("%(?:\\d+\\$)?[a-zA-Z]");
    private static final char HEBREW_FIRST = '֐';
    private static final char HEBREW_LAST = '׿';

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
        List<String> untranslated = new ArrayList<>();
        hebrew.forEach((key, text) -> {
            if (hasTranslatableLetters(text) && !containsHebrew(text)) {
                untranslated.add(key);
            }
        });
        assertEquals("values-iw/ holds no Hebrew for these keys", List.of(), untranslated);
    }

    @Test
    public void everyCapabilityHasATitleAndAConsequenceInBothLocales() {
        // Ties the resource file to the enum: a capability added without operator
        // text would otherwise reach the console as a blank row that still opens
        // a real restriction.
        for (MaintenanceCapability capability : MaintenanceCapability.values()) {
            requireBothLocales("maint_capability_" + capability.storageKey() + "_title");
            requireBothLocales("maint_capability_" + capability.storageKey() + "_consequence");
        }
    }

    @Test
    public void everyCloseReasonHasAnAuditLineInBothLocales() {
        for (CloseReason reason : CloseReason.values()) {
            requireBothLocales("maint_audit_close_" + reason.token());
        }
    }

    @Test
    public void everyRefusalTheStateMachineCanReportIsExplained() {
        for (String reason : List.of(
                "admin_authentication_required",
                "already_open",
                "no_capability_selected",
                "unknown_capability",
                "non_positive_duration",
                "duration_above_maximum")) {
            requireBothLocales("maint_refused_" + reason);
        }
        // The fallback exists so a refusal added later is visibly untranslated
        // rather than invisible.
        requireBothLocales("maint_refused_generic");
    }

    @Test
    public void everyOfferedDurationHasALabel() {
        for (long duration : MaintenanceStateMachine.OFFERED_DURATIONS_MILLIS) {
            long minutes = duration / 60_000L;
            String key = minutes % 60 == 0
                    ? "maint_duration_" + (minutes / 60) + (minutes == 60 ? "_hour" : "_hours")
                    : "maint_duration_" + minutes + "_minutes";
            requireBothLocales(key);
        }
        requireBothLocales("maint_duration_custom_minutes");
    }

    @Test
    public void everyStateHasALabel() {
        requireBothLocales("maint_status_open");
        requireBothLocales("maint_status_closed");
    }

    @Test
    public void theBreakGlassCapabilityWarnsAboutWhatItExposes() {
        // The one capability that hands out a privileged transport rather than a
        // user-visible feature. If the console does not say so before the
        // confirmation, nothing else in the feature will.
        String consequence = english.get("maint_capability_adb_debugging_consequence");
        assertTrue("the break-glass consequence must exist", consequence != null);
        String lower = consequence.toLowerCase(Locale.ROOT);
        assertTrue(
                "the break-glass consequence must name ADB or debugging: " + consequence,
                lower.contains("adb") || lower.contains("debug"));
    }

    @Test
    public void noStringLeaksSomethingAnOperatorMustNotSee() {
        // Maintenance text is about capabilities and clocks. A PIN, a recovery
        // code or a kiosk address has no business being formatted into it.
        for (Map<String, String> locale : List.of(english, hebrew)) {
            locale.forEach((key, text) -> {
                String lower = text.toLowerCase(Locale.ROOT);
                assertFalse(key + " must not carry a URL", lower.contains("http://"));
                assertFalse(key + " must not carry a URL", lower.contains("https://"));
            });
        }
    }

    private void requireBothLocales(String key) {
        assertTrue("values/ is missing " + key, english.containsKey(key));
        assertTrue("values-iw/ is missing " + key, hebrew.containsKey(key));
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

    private static boolean hasTranslatableLetters(String text) {
        return PLACEHOLDER.matcher(text).replaceAll("").chars().anyMatch(Character::isLetter);
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
