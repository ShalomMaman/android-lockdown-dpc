package com.example.lockdowndpc.ui

import android.app.LocaleManager
import android.content.Context
import android.os.Build
import android.os.LocaleList
import androidx.annotation.StringRes
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import com.example.lockdowndpc.R

/**
 * The persistent in-app display language.
 *
 * `AppCompatDelegate` is the single storage layer for the choice and it behaves
 * differently per platform release, which is exactly why it is used instead of a
 * private preference:
 *
 *  * API 33+ — the call is forwarded to the platform `LocaleManager`, so the value
 *    set here and the value set from Settings > System > Languages > App languages
 *    are the same value. `res/xml/locales_config.xml` is what makes Maakeh
 *    appear in that system list.
 *  * API 26-32 — AppCompat persists the locales itself and re-applies them to every
 *    `AppCompatActivity` at attach time. The `AppLocalesMetadataHolderService`
 *    declared in the manifest with `autoStoreLocales` is what enables that storage.
 *
 * An empty locale list is "follow the system", which is the default. Nothing here
 * writes a language at first launch, so a device already running in Hebrew keeps
 * showing Hebrew.
 */
internal object AppLocales {

    /** The language currently in force, resolved through the same tags Android stores. */
    fun current(): LanguageChoice =
        languageChoiceOf(AppCompatDelegate.getApplicationLocales().toLanguageTags())

    /**
     * Persists [choice] and re-applies it. Android recreates the visible activity,
     * which drops the administrator session; the picker warns about that before
     * the change is made.
     */
    fun apply(choice: LanguageChoice) {
        val tag = languageTagOf(choice)
        AppCompatDelegate.setApplicationLocales(
            if (tag == null) {
                LocaleListCompat.getEmptyLocaleList()
            } else {
                LocaleListCompat.forLanguageTags(tag)
            }
        )
    }

    /**
     * Applies a committed remote choice and reads it back from the platform.
     *
     * Only Android 13 and later store the choice in the system. Earlier releases
     * keep it inside AppCompat, whose answer is an echo of the request, so the
     * remote policy never carries a language for them and nothing is claimed here.
     */
    fun applyPolicyChoice(context: Context, choice: LanguageChoice): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return false
        val locales = context.getSystemService(LocaleManager::class.java) ?: return false
        val wanted = LocaleList.forLanguageTags(languageTagOf(choice).orEmpty())
        if (locales.applicationLocales != wanted) locales.applicationLocales = wanted
        return locales.applicationLocales == wanted
    }

    /**
     * The label for [choice]. The two language names are autonyms: they read the
     * same on every locale, so an operator can find their own language in the list
     * even when the console is currently in a language they cannot read.
     */
    @StringRes
    fun labelOf(choice: LanguageChoice): Int = when (choice) {
        LanguageChoice.SYSTEM -> R.string.language_option_system
        LanguageChoice.ENGLISH -> R.string.language_option_english
        LanguageChoice.HEBREW -> R.string.language_option_hebrew
    }
}
