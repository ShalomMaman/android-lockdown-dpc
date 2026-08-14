package com.example.lockdowndpc.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

/**
 * Locale parity for `management_identity_strings.xml`.
 *
 * `LocaleParityTest` reads `strings.xml` only, so this screen's own resource file
 * would otherwise ship with no guard at all — and the failure that actually
 * happens is a key added to one locale and forgotten in the other, which still
 * compiles and only surfaces on a device set to the other language.
 *
 * The rules are the ones `SystemAppInventoryStringsParityTest` applies, restated
 * against this file rather than shared, because the two suites have to be able to
 * fail independently: a break here is a translation gap in one screen, not a
 * console-wide one.
 */
class ManagementIdentityStringsParityTest {

    private val default = ManagementIdentityResources.read(resourceFile("values"))
    private val hebrew = ManagementIdentityResources.read(resourceFile("values-iw"))

    @Test
    fun everyStringExistsInBothLocales() {
        assertEquals(
            "<string> keys differ between values/ and values-iw/",
            default.strings.keys.sorted(),
            hebrew.strings.keys.sorted(),
        )
    }

    @Test
    fun everyKeyCarriesTheManagementIdentityPrefix() {
        // Android merges every values/*.xml into one resource table, so a key
        // here shares a namespace with strings.xml. The prefix is what keeps a
        // new key from silently overriding a console one.
        forEachLocale { folder, resources ->
            resources.strings.keys.forEach { key ->
                assertTrue(
                    "$folder holds $key, which does not carry the mgmtid_ prefix",
                    key.startsWith("mgmtid_"),
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
    fun defaultLocaleHasNoHebrewText() {
        assertEquals(
            "values/ is the English default; these keys still hold Hebrew",
            emptySet<String>(),
            default.strings.filterValues { containsHebrew(it) }.keys,
        )
    }

    @Test
    fun hebrewTranslationIsActuallyHebrew() {
        // A key copied over from the default and never translated is the other
        // half of the same mistake, and it is invisible until a Hebrew device
        // shows it.
        assertEquals(
            "values-iw/ holds no Hebrew for these keys",
            emptySet<String>(),
            hebrew.strings
                .filterValues { hasTranslatableLetters(it) && !containsHebrew(it) }.keys,
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
        }
    }

    @Test
    fun hebrewIsolatesEveryLatinRunItEmbeds() {
        // A Latin word inside a Hebrew sentence drags the surrounding punctuation
        // to the wrong side unless it is isolated. Runtime values — package
        // names, digests, verdict names — are isolated in code; a Latin run baked
        // into the translation has to carry its own marks.
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
    fun theScreenResolvesEveryStateAndProblemItCanShow() {
        // The screen maps every identity state, severity and digest problem to a
        // resource. A missing `when` branch is a compile error; a branch pointing
        // at a key that was never added to the resource file is not, so it is
        // checked here.
        val referenced = SCREEN_SOURCES.flatMap { source ->
            RESOURCE_REFERENCE.findAll(File(moduleDir(), source).readText())
                .map { it.groupValues[1] }
        }.filter { it.startsWith("mgmtid_") }.toSet()

        val missing = referenced.filterNot { it in default.strings }
        assertEquals(
            "the console screens reference resources that values/ does not define",
            emptyList<String>(),
            missing.sorted(),
        )
        assertTrue(
            "the screen should resolve at least every state, severity and refusal reason",
            referenced.size >= 30,
        )
    }

    @Test
    fun noAuditStringCanCarryASecret() {
        // Audit entries are readable from the console by anyone holding the
        // administrator PIN. The three audit lines take the package name and the
        // verdict and nothing else, so a later edit cannot quietly add a digest,
        // a PIN or a recovery code by widening a placeholder list.
        val auditKeys = default.strings.keys.filter { it.startsWith("mgmtid_audit_") }
        assertEquals(
            "the audit lines this screen writes",
            listOf(
                "mgmtid_audit_pin_added",
                "mgmtid_audit_pin_removed",
                "mgmtid_audit_refused",
            ),
            auditKeys.sorted(),
        )
        auditKeys.forEach { key ->
            assertTrue(
                "$key takes more than a package name and a verdict",
                placeholdersOf(default.strings.getValue(key)).size <= 2,
            )
        }
    }

    private fun forEachLocale(action: (String, ManagementIdentityResources) -> Unit) {
        action("values", default)
        action("values-iw", hebrew)
    }

    private fun resourceFile(folder: String) =
        File(moduleDir(), "src/main/res/$folder/management_identity_strings.xml")
}

private val SCREEN_SOURCES = listOf(
    "src/main/java/com/example/lockdowndpc/ui/ManagementIdentityActivity.kt",
    "src/main/java/com/example/lockdowndpc/ui/ManagementIdentityLogic.kt",
)

/** `%s`, `%1$d`, … — the tokens `Resources.getString` substitutes at runtime. */
private val PLACEHOLDER = Regex("""%(?:\d+\$)?[a-zA-Z]""")

/** `R.string.foo`. */
private val RESOURCE_REFERENCE = Regex("""R\.string\.(\w+)""")

/** Two or more Latin letters in a row; a single letter is not a word. */
private val LATIN_RUN = Regex("""[A-Za-z]{2,}""")

private val HEBREW_LETTERS = '֐'..'׿'

private const val LEFT_TO_RIGHT_ISOLATE = '⁦'
private const val POP_DIRECTIONAL_ISOLATE = '⁩'

private fun placeholdersOf(text: String): List<String> =
    PLACEHOLDER.findAll(text).map { it.value }.toList().sorted()

private fun containsHebrew(text: String): Boolean = text.any { it in HEBREW_LETTERS }

/**
 * Whether [text] holds a word at all. Placeholders are removed first, because
 * `%1$s` itself contains a letter; what is left of a pure separator is
 * punctuation, which no translator can act on.
 */
private fun hasTranslatableLetters(text: String): Boolean =
    PLACEHOLDER.replace(text, "").any { it.isLetter() }

private fun stripPlaceholders(text: String): String = PLACEHOLDER.replace(text, " ")

/** Whether the run at [range] sits inside a balanced left-to-right isolate. */
private fun isIsolated(text: String, range: IntRange): Boolean {
    val opening = text.lastIndexOf(LEFT_TO_RIGHT_ISOLATE, range.first)
    if (opening < 0) return false
    val closing = text.indexOf(POP_DIRECTIONAL_ISOLATE, opening)
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
private class ManagementIdentityResources(val strings: Map<String, String>) {
    companion object {
        fun read(file: File): ManagementIdentityResources {
            require(file.isFile) { "missing resource file: $file" }
            val document = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file)
            val strings = LinkedHashMap<String, String>()
            val nodes = document.getElementsByTagName("string")
            for (index in 0 until nodes.length) {
                val element = nodes.item(index) as Element
                strings[element.getAttribute("name")] = element.textContent
            }
            return ManagementIdentityResources(strings)
        }
    }
}
