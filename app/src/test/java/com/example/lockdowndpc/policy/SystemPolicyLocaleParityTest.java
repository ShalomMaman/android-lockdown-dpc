package com.example.lockdowndpc.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilderFactory;

/**
 * Locale parity for {@code system_policy_strings.xml}.
 *
 * <p>The shared guards — {@code LocaleParityTest} and
 * {@code tools/check_locale_parity.py} — both read {@code strings.xml} and only
 * {@code strings.xml}, so a second resource file is invisible to them. Without
 * this test the Hebrew console would silently fall back to English on exactly
 * the screen that explains how to withdraw a device recovery path, which is the
 * worst possible place to lose a translation.
 */
public final class SystemPolicyLocaleParityTest {

    private static final String FILE_NAME = "system_policy_strings.xml";
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
    public void everyControlHasATitleAndAConsequenceInBothLocales() {
        // Ties the resource file to the enum: a control added without operator
        // text would otherwise reach the console as a blank row.
        for (SystemPolicyControl control : SystemPolicyControl.values()) {
            String title = "system_policy_control_" + control.storageKey() + "_title";
            String consequence = "system_policy_control_" + control.storageKey() + "_consequence";
            assertTrue("values/ is missing " + title, english.containsKey(title));
            assertTrue("values/ is missing " + consequence, english.containsKey(consequence));
            assertTrue("values-iw/ is missing " + title, hebrew.containsKey(title));
            assertTrue("values-iw/ is missing " + consequence, hebrew.containsKey(consequence));
        }
    }

    @Test
    public void everyOutcomeAndProfileHasAStatusLabel() {
        for (SystemPolicyOutcome outcome : SystemPolicyOutcome.values()) {
            String key = "system_policy_status_" + outcome.name().toLowerCase(java.util.Locale.ROOT);
            assertTrue("values/ is missing " + key, english.containsKey(key));
            assertTrue("values-iw/ is missing " + key, hebrew.containsKey(key));
        }
        for (SystemPolicyProfile profile : SystemPolicyProfile.values()) {
            String key = "system_policy_profile_" + profile.name().toLowerCase(java.util.Locale.ROOT);
            assertTrue("values/ is missing " + key, english.containsKey(key));
            assertTrue("values-iw/ is missing " + key, hebrew.containsKey(key));
        }
    }

    @Test
    public void theConsequenceOfWithdrawingDebuggingIsSpeltOut() {
        // This is the one control that can remove the documented recovery path, so
        // the console is required to say so before an administrator confirms it.
        String consequence =
                english.get("system_policy_control_developer_options_and_adb_consequence");
        assertTrue("the ADB consequence must name ADB", consequence.contains("ADB"));
        assertTrue(
                "the ADB consequence must warn about recovery",
                consequence.toLowerCase(java.util.Locale.ROOT).contains("recover"));
    }

    @Test
    public void thePlayCompatibilityBoundaryIsStatedInBothLocales() {
        // The console must describe this mode honestly in both languages. An
        // operator reading the Hebrew screen has to learn the same thing: the
        // Store package stays available, installation is what is blocked, and
        // nobody is told the Store has been hidden.
        for (String key : List.of(
                "system_policy_section_play_compatibility",
                "system_policy_play_compat_row",
                "system_policy_play_compat_body",
                "system_policy_play_compat_state_strict",
                "system_policy_play_compat_state_active",
                "system_policy_play_compat_state_maintenance",
                "system_policy_play_compat_state_unverified",
                "system_policy_play_compat_locked_control",
                "system_policy_play_compat_confirm_enable_title",
                "system_policy_play_compat_confirm_enable_body",
                "system_policy_play_compat_confirm_disable_title",
                "system_policy_play_compat_confirm_disable_body")) {
            assertTrue("values/ is missing " + key, english.containsKey(key));
            assertTrue("values-iw/ is missing " + key, hebrew.containsKey(key));
        }
        String body = english.get("system_policy_play_compat_body")
                .toLowerCase(java.util.Locale.ROOT);
        assertTrue(
                "the compatibility text must say that installation is what is blocked",
                body.contains("installation"));
        assertTrue(
                "the compatibility text must not claim the Store is hidden",
                body.contains("may stay visible"));
    }

    private static List<String> placeholdersOf(String text) {
        List<String> found = new ArrayList<>();
        Matcher matcher = PLACEHOLDER.matcher(text);
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
