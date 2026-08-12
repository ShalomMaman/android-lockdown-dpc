package com.example.lockdowndpc.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

/**
 * Locale parity guard. It reads the resource XML directly instead of going through
 * the generated `R` class, because the failure that actually happens is a key added
 * to one locale and forgotten in the other, which still compiles and only shows up
 * on a device set to the other language.
 *
 * The same rules are implemented by `tools/check_locale_parity.py`, which runs
 * without a Gradle build. The two are kept in step deliberately, so a translation
 * can be checked from an editor and from CI.
 */
class LocaleParityTest {

    private val default = LocaleResources.read(stringsFile("values"))
    private val hebrew = LocaleResources.read(stringsFile("values-iw"))

    @Test
    fun everyTranslatableStringExistsInHebrew() {
        assertEquals(
            "translatable <string> keys differ between values/ and values-iw/",
            default.translatableStrings.keys.sorted(),
            hebrew.strings.keys.sorted(),
        )
    }

    @Test
    fun everyPluralExistsInHebrew() {
        assertEquals(
            "<plurals> keys differ between values/ and values-iw/",
            default.plurals.keys.sorted(),
            hebrew.plurals.keys.sorted(),
        )
    }

    @Test
    fun hebrewNeverTranslatesAnUntranslatableString() {
        // Language autonyms read the same on every locale, so translating them is a
        // bug rather than a missing translation, and aapt rejects it outright.
        val leaked = default.untranslatableKeys.filter { it in hebrew.strings }
        assertEquals(
            "translatable=\"false\" keys must not appear in values-iw/",
            emptyList<String>(),
            leaked,
        )
    }

    @Test
    fun stringPlaceholdersMatch() {
        default.translatableStrings.forEach { (key, text) ->
            assertEquals(
                "format placeholders differ for string/$key",
                placeholdersOf(text),
                placeholdersOf(hebrew.strings.getValue(key)),
            )
        }
    }

    @Test
    fun pluralPlaceholdersMatch() {
        default.plurals.forEach { (key, items) ->
            val translation = hebrew.plurals.getValue(key)
            assertEquals(
                "format placeholders differ for plurals/$key",
                declaredPlaceholders(items),
                declaredPlaceholders(translation),
            )
        }
    }

    @Test
    fun otherQuantityCanShowEveryArgument() {
        // `other` is the branch every count outside the named categories selects,
        // so it is the one that has to be able to show every argument the call site
        // passes; a narrower `one` or `two` branch is a translator's choice.
        forEachLocale { folder, resources ->
            resources.plurals.forEach { (key, items) ->
                val fallback = items["other"]
                assertTrue("$folder plurals/$key has no other quantity", fallback != null)
                assertTrue(
                    "$folder plurals/$key quantity=other cannot show every argument the " +
                        "other quantities use",
                    placeholdersOf(fallback!!).containsAll(declaredPlaceholders(items)),
                )
            }
        }
    }

    @Test
    fun defaultLocaleDeclaresEnglishPluralCategories() {
        default.plurals.forEach { (key, items) ->
            assertEquals(
                "English CLDR plural categories for plurals/$key",
                setOf("one", "other"),
                items.keys.toSet(),
            )
        }
    }

    @Test
    fun hebrewDeclaresOneTwoAndOther() {
        // CLDR gives Hebrew one (n=1), two (n=2) and other. The `many` category was
        // removed in CLDR 42, so a `many` branch would never be selected at runtime.
        hebrew.plurals.forEach { (key, items) ->
            assertEquals(
                "Hebrew CLDR plural categories for plurals/$key",
                setOf("one", "two", "other"),
                items.keys.toSet(),
            )
        }
    }

    @Test
    fun defaultLocaleHasNoHebrewText() {
        val untranslated = default.translatableStrings.filterValues { containsHebrew(it) }.keys +
            default.plurals.filterValues { items -> items.values.any { containsHebrew(it) } }.keys
        assertEquals(
            "values/strings.xml is the English default; these keys still hold Hebrew",
            emptySet<String>(),
            untranslated,
        )
    }

    @Test
    fun hebrewTranslationIsActuallyHebrew() {
        // A key copied over from the default and never translated is the other half
        // of the same mistake, and it is invisible until a Hebrew device shows it.
        // A value that holds no word at all — `%1$s · %2$s`, the separator the
        // kiosk summary is assembled from — is exempt: there is nothing in it to
        // translate, so "holds no Hebrew" says nothing about it.
        val latinOnly = hebrew.strings
            .filterValues { hasTranslatableLetters(it) && !containsHebrew(it) }.keys +
            hebrew.plurals.filterValues { items ->
                items.values.any { hasTranslatableLetters(it) } &&
                    items.values.none { containsHebrew(it) }
            }.keys
        assertEquals(
            "values-iw/strings.xml holds no Hebrew for these keys",
            emptySet<String>(),
            latinOnly,
        )
    }

    @Test
    fun noValueIsBlank() {
        forEachLocale { folder, resources ->
            assertEquals(
                "$folder holds blank strings",
                emptySet<String>(),
                resources.strings.filterValues { it.isBlank() }.keys,
            )
            assertEquals(
                "$folder holds blank plural items",
                emptySet<String>(),
                resources.plurals.filterValues { items -> items.values.any { it.isBlank() } }.keys,
            )
        }
    }

    @Test
    fun localesConfigListsExactlyTheShippedLanguages() {
        val document = DocumentBuilderFactory.newInstance()
            .newDocumentBuilder()
            .parse(File(moduleDir(), "src/main/res/xml/locales_config.xml"))
        val nodes = document.getElementsByTagName("locale")
        val declared = (0 until nodes.length)
            .map { (nodes.item(it) as Element).getAttribute("android:name") }
            .toSet()
        // "he" is the BCP-47 tag the platform locale picker parses; res/values-iw is
        // the folder Android resolves it to, because Locale#getLanguage() still
        // reports the legacy code for Hebrew.
        assertEquals(setOf("en", "he"), declared)
    }

    private fun forEachLocale(action: (String, LocaleResources) -> Unit) {
        action("values", default)
        action("values-iw", hebrew)
    }

    private fun stringsFile(folder: String) = File(moduleDir(), "src/main/res/$folder/strings.xml")
}

/** `%s`, `%1$d`, … — the tokens `Resources.getString` substitutes at runtime. */
private val PLACEHOLDER = Regex("""%(?:\d+\$)?[a-zA-Z]""")

private val HEBREW_BLOCK = '֐'..'׿'

// `findAll` yields a Sequence, and `Sequence.sorted()` returns another Sequence
// rather than a List. It has to be collected before it is sorted, otherwise this
// file does not compile and the whole parity guard is silently absent from the
// test run.
private fun placeholdersOf(text: String): List<String> =
    PLACEHOLDER.findAll(text).map { it.value }.toList().sorted()

/** Every placeholder any quantity of one plural declares. */
private fun declaredPlaceholders(items: Map<String, String>): Set<String> =
    items.values.flatMapTo(sortedSetOf<String>()) { placeholdersOf(it) }

private fun containsHebrew(text: String): Boolean = text.any { it in HEBREW_BLOCK }

/**
 * Whether [text] holds a word at all. The placeholders are removed first, because
 * `%1$s` itself contains a letter; what is left of a pure separator is punctuation
 * and spacing, which no translator can act on.
 */
private fun hasTranslatableLetters(text: String): Boolean =
    PLACEHOLDER.replace(text, "").any { it.isLetter() }

/** The `app` module directory, found from wherever the test runner was started. */
private fun moduleDir(): File {
    var candidate: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
    while (candidate != null) {
        if (File(candidate, "src/main/res/values/strings.xml").isFile) {
            return candidate
        }
        val module = File(candidate, "app")
        if (File(module, "src/main/res/values/strings.xml").isFile) {
            return module
        }
        candidate = candidate.parentFile
    }
    throw AssertionError("could not locate the app module from ${System.getProperty("user.dir")}")
}

/** One parsed `strings.xml`. */
private class LocaleResources(
    val strings: Map<String, String>,
    val untranslatableKeys: Set<String>,
    val plurals: Map<String, Map<String, String>>,
) {

    /** The keys a translator is expected to deliver. */
    val translatableStrings: Map<String, String>
        get() = strings.filterKeys { it !in untranslatableKeys }

    companion object {

        fun read(file: File): LocaleResources {
            require(file.isFile) { "missing resource file: $file" }
            val document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file)

            val strings = LinkedHashMap<String, String>()
            val untranslatable = LinkedHashSet<String>()
            val stringNodes = document.getElementsByTagName("string")
            for (index in 0 until stringNodes.length) {
                val element = stringNodes.item(index) as Element
                val name = element.getAttribute("name")
                strings[name] = element.textContent
                if (element.getAttribute("translatable") == "false") {
                    untranslatable += name
                }
            }

            val plurals = LinkedHashMap<String, Map<String, String>>()
            val pluralNodes = document.getElementsByTagName("plurals")
            for (index in 0 until pluralNodes.length) {
                val element = pluralNodes.item(index) as Element
                val items = LinkedHashMap<String, String>()
                val itemNodes = element.getElementsByTagName("item")
                for (item in 0 until itemNodes.length) {
                    val itemElement = itemNodes.item(item) as Element
                    items[itemElement.getAttribute("quantity")] = itemElement.textContent
                }
                plurals[element.getAttribute("name")] = items
            }

            return LocaleResources(strings, untranslatable, plurals)
        }
    }
}
