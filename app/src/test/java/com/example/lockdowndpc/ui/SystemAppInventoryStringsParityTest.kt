package com.example.lockdowndpc.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

/**
 * Locale parity for `system_app_inventory_strings.xml`.
 *
 * `LocaleParityTest` reads `strings.xml` only, so the inventory's own resource
 * file would otherwise ship with no guard at all — and the failure that actually
 * happens is a key added to one locale and forgotten in the other, which still
 * compiles and only surfaces on a device set to the other language.
 *
 * The rules are the same ones `LocaleParityTest` applies, restated against this
 * file rather than shared, because the two suites have to be able to fail
 * independently: a break here is a translation gap in one screen, not a
 * console-wide one.
 */
class SystemAppInventoryStringsParityTest {

    private val default = InventoryResources.read(inventoryFile("values"))
    private val hebrew = InventoryResources.read(inventoryFile("values-iw"))

    @Test
    fun everyStringExistsInBothLocales() {
        assertEquals(
            "<string> keys differ between values/ and values-iw/",
            default.strings.keys.sorted(),
            hebrew.strings.keys.sorted(),
        )
    }

    @Test
    fun everyPluralExistsInBothLocales() {
        assertEquals(
            "<plurals> keys differ between values/ and values-iw/",
            default.plurals.keys.sorted(),
            hebrew.plurals.keys.sorted(),
        )
    }

    @Test
    fun everyKeyCarriesTheInventoryPrefix() {
        // Android merges every values/*.xml into one resource table, so a key here
        // shares a namespace with strings.xml. The prefix is what keeps a new
        // inventory string from silently overriding a console one.
        forEachLocale { folder, resources ->
            (resources.strings.keys + resources.plurals.keys).forEach { key ->
                assertTrue(
                    "$folder holds $key, which does not carry the sysinv_ prefix",
                    key.startsWith("sysinv_"),
                )
            }
        }
    }

    @Test
    fun stringPlaceholdersMatch() {
        default.strings.forEach { (key, text) ->
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
            assertEquals(
                "format placeholders differ for plurals/$key",
                declaredPlaceholders(items),
                declaredPlaceholders(hebrew.plurals.getValue(key)),
            )
        }
    }

    @Test
    fun otherQuantityCanShowEveryArgument() {
        // `other` is the branch every count outside the named categories selects,
        // so it is the one that has to be able to show every argument the call
        // site passes; a narrower `one` or `two` branch is a translator's choice.
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
        // CLDR gives Hebrew one (n=1), two (n=2) and other. `many` was removed in
        // CLDR 42, so such a branch would never be selected at runtime.
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
        val untranslated = default.strings.filterValues { containsHebrew(it) }.keys +
            default.plurals.filterValues { items -> items.values.any { containsHebrew(it) } }.keys

        assertEquals(
            "values/ is the English default; these keys still hold Hebrew",
            emptySet<String>(),
            untranslated,
        )
    }

    @Test
    fun hebrewTranslationIsActuallyHebrew() {
        // A key copied over from the default and never translated is the other
        // half of the same mistake, and it is invisible until a Hebrew device
        // shows it.
        val latinOnly = hebrew.strings
            .filterValues { hasTranslatableLetters(it) && !containsHebrew(it) }.keys +
            hebrew.plurals.filterValues { items ->
                items.values.any { hasTranslatableLetters(it) } &&
                    items.values.none { containsHebrew(it) }
            }.keys

        assertEquals(
            "values-iw/ holds no Hebrew for these keys",
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
    fun hebrewIsolatesEveryLatinRunItEmbeds() {
        // A Latin word inside a Hebrew sentence drags the surrounding punctuation
        // to the wrong side unless it is isolated. Runtime values are isolated in
        // code; a Latin run baked into the translation has to carry its own marks.
        val unisolated = hebrew.strings.filterValues { text ->
            LATIN_RUN.findAll(stripPlaceholders(text)).any { match ->
                !isIsolated(stripPlaceholders(text), match.range)
            }
        }.keys

        assertEquals(
            "values-iw/ embeds a Latin run with no U+2066/U+2069 isolate around it",
            emptySet<String>(),
            unisolated,
        )
    }

    @Test
    fun theInventoryScreenResolvesEveryReasonAndFilterItCanShow() {
        // The screen maps every classifier enum constant to a resource. A new
        // constant with no `when` branch is a compile error; a new constant
        // pointing at a key that was never added to the resource file is not, so
        // it is checked here.
        val source = File(moduleDir(), SCREEN_SOURCE).readText()
        val referenced = RESOURCE_REFERENCE.findAll(source)
            .map { it.groupValues[1] }
            .filter { it.startsWith("sysinv_") }
            .toSet()

        val missing = referenced.filterNot {
            it in default.strings || it in default.plurals
        }
        assertEquals(
            "$SCREEN_SOURCE references resources that values/ does not define",
            emptyList<String>(),
            missing.sorted(),
        )
        assertTrue(
            "the screen should resolve at least every row state, origin and reason",
            referenced.size >= 30,
        )
    }

    private fun forEachLocale(action: (String, InventoryResources) -> Unit) {
        action("values", default)
        action("values-iw", hebrew)
    }

    private fun inventoryFile(folder: String) =
        File(moduleDir(), "src/main/res/$folder/system_app_inventory_strings.xml")
}

private const val SCREEN_SOURCE =
    "src/main/java/com/example/lockdowndpc/ui/AllowedAppsActivity.kt"

/** `%s`, `%1$d`, … — the tokens `Resources.getString` substitutes at runtime. */
private val PLACEHOLDER = Regex("""%(?:\d+\$)?[a-zA-Z]""")

/** `R.string.foo` / `R.plurals.foo`. */
private val RESOURCE_REFERENCE = Regex("""R\.(?:string|plurals)\.(\w+)""")

/** Two or more Latin letters in a row; a single letter is not a word. */
private val LATIN_RUN = Regex("""[A-Za-z]{2,}""")

private val HEBREW_BLOCK = '֐'..'׿'

private const val LTR_ISOLATE_MARK = '⁦'
private const val POP_ISOLATE_MARK = '⁩'

private fun placeholdersOf(text: String): List<String> =
    PLACEHOLDER.findAll(text).map { it.value }.toList().sorted()

private fun declaredPlaceholders(items: Map<String, String>): Set<String> =
    items.values.flatMapTo(sortedSetOf()) { placeholdersOf(it) }

private fun containsHebrew(text: String): Boolean = text.any { it in HEBREW_BLOCK }

/**
 * Whether [text] holds a word at all. Placeholders are removed first, because
 * `%1$s` itself contains a letter; what is left of a pure separator is
 * punctuation, which no translator can act on.
 */
private fun hasTranslatableLetters(text: String): Boolean =
    PLACEHOLDER.replace(text, "").any { it.isLetter() }

private fun stripPlaceholders(text: String): String = PLACEHOLDER.replace(text, " ")

/** Whether the run at [range] sits inside a balanced LTR isolate. */
private fun isIsolated(text: String, range: IntRange): Boolean {
    val opening = text.lastIndexOf(LTR_ISOLATE_MARK, range.first)
    if (opening < 0) return false
    val closing = text.indexOf(POP_ISOLATE_MARK, opening)
    return closing > range.last
}

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

/** One parsed resource file. */
private class InventoryResources(
    val strings: Map<String, String>,
    val plurals: Map<String, Map<String, String>>,
) {
    companion object {
        fun read(file: File): InventoryResources {
            require(file.isFile) { "missing resource file: $file" }
            val document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file)

            val strings = LinkedHashMap<String, String>()
            val stringNodes = document.getElementsByTagName("string")
            for (index in 0 until stringNodes.length) {
                val element = stringNodes.item(index) as Element
                strings[element.getAttribute("name")] = element.textContent
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
            return InventoryResources(strings, plurals)
        }
    }
}
