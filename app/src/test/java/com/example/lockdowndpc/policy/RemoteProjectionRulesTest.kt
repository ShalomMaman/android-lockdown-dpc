package com.example.lockdowndpc.policy

import android.content.Context
import com.example.lockdowndpc.kiosk.KioskConfigStore
import com.example.lockdowndpc.kiosk.KioskController
import com.example.lockdowndpc.kiosk.KioskStateMachine.KioskState
import com.example.lockdowndpc.remote.Refused
import com.example.lockdowndpc.remote.RemoteFailure
import com.example.lockdowndpc.remote.RemoteOverride
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** What the remote pass refuses to take on trust: kiosk state, languages, hidden packages and a damaged journal. */
class RemoteProjectionRulesTest : RemotePassFixture() {

    /** A kiosk state in the store is never fleet intent. The pass does not enter lock task on it. */
    @Test fun storedKioskIsNeverEnteredAndProjectionKeepsItOff() {
        assertTrue(context.getSharedPreferences("kiosk_policy", Context.MODE_PRIVATE).edit()
            .putString("kiosk_state", "ACTIVE").putString("kiosk_mode", "SINGLE_SITE")
            .putString("kiosk_site_url", "https://example.com/").commit())
        val errors = mutableListOf<String>()
        assertFalse(KioskController.reconcileRemote(context, dpm, admin, errors))
        assertEquals(listOf("remote-kiosk-unsupported"), errors)
        assertFalse(dpm.isLockTaskPermitted(context.packageName))

        commit(policy())
        assertVerified()
        assertEquals(KioskState.OFF, KioskConfigStore.readState(context))
        assertFalse(dpm.isLockTaskPermitted(context.packageName))
    }

    /** A value outside what this build knows is refused. It is never read as the default. */
    @Test fun unknownLanguageOrKioskModeIsRefusedNotDefaulted() {
        fun refusal(extra: Map<String, Any?>): RemoteFailure? = try {
            projection.validate(policy(extra = extra))
            null
        } catch (refused: Refused) {
            refused.failure
        }
        assertEquals(RemoteFailure("doc-field-invalid", "/policy/locale"), refusal(mapOf("locale" to "fr")))
        assertEquals(RemoteFailure("doc-field-invalid", "/policy/kiosk/mode"),
            refusal(mapOf("kiosk" to mapOf("mode" to "MULTI_APP"))))
        assertNull(refusal(mapOf("locale" to "iw", "kiosk" to mapOf("mode" to "OFF"))))
    }

    /** Before Android 13 only AppCompat holds the language, and it can only repeat what it was asked. */
    @Test fun languageThatCannotBeReadBackLeavesTheGenerationUnverified() {
        commit(policy(extra = mapOf("locale" to "en")))
        assertFalse(pass().verified)
        assertEquals(listOf("remote-locale-unverified"), errors())
        assertEquals(previous, verified())

        // Asking for the device default afterwards cannot be read back either.
        replace(policy())
        assertFalse(pass().verified)
        assertEquals(listOf("remote-locale-unverified"), errors())
    }

    /** A system package the fleet accepted by signer and version can be hidden, verified again and shown again. */
    @Test fun hiddenSystemPackageKeepsItsAcceptedIdentity() {
        install(GALLERY, system = true, versionCode = 1234)
        val selection = mapOf("systemSelection" to listOf(mapOf(
            "package" to GALLERY, "signerSha256" to SIGNER_DIGEST, "versionCode" to 1234L)))
        fun apps(allowed: List<String>) = mapOf("apps" to
            (mapOf("mode" to "ALLOW_SELECTED", "allowed" to allowed) + selection))

        commit(policy(extra = apps(emptyList())))
        assertVerified()
        assertTrue(hidden(GALLERY))
        // The next pass reads the signer and version of the package it hid itself.
        assertVerified()
        assertTrue(hidden(GALLERY))

        replace(policy(extra = apps(listOf(GALLERY))))
        assertVerified()
        assertFalse(hidden(GALLERY))
    }

    /** The journal of an enrolled device reads back empty: no pass, no store write, and the device stays as it was. */
    @Test fun damagedJournalStopsEveryPassAndChangesNothingOnTheDevice() {
        install(READER)
        assertTrue(dpm.setApplicationHidden(admin, READER, true))
        commit(policy(allowed = listOf(READER)))
        harness.damageJournal(null)

        val pass = pass()

        assertEquals(RemoteFailure("journal-lost"), pass.failure)
        assertNull(projection.lastResult)
        assertTrue(hidden(READER))
        assertNull(dpm.getAlwaysOnVpnPackage(admin))
        assertTrue(AllowedAppsStore.getAllowedPackages(context).none { it == READER })
    }

    /** The same through the runtime entry points, with the real files: each one answers `journal-lost`. */
    @Test fun runtimeNamesALostJournalAndRefusesBindingPassesAndRecovery() {
        install(READER)
        assertTrue(dpm.setApplicationHidden(admin, READER, true))
        // A journal was stored once. Its file is now empty.
        assertTrue(context.getSharedPreferences(RemotePolicyRuntime.JOURNAL_MARKER_PREFS, Context.MODE_PRIVATE)
            .edit().putBoolean("journal_created", true).commit())

        assertTrue(RemotePolicyRuntime.journalLost(context))
        val result = onPolicyThread { RemotePolicyRuntime.reconcile(context) }
        assertEquals(listOf("journal-lost"), result.errors())
        assertFalse(result.applied())
        val root = f.keys.getValue("root") as Map<*, *>
        assertEquals("journal-lost", RemotePolicyRuntime.bindFleet(
            context, f.binding, root["keyId"] as String, root["spki"] as String)?.code)
        assertEquals("journal-lost", RemotePolicyRuntime.recover(
            context, setOf(RemoteOverride.NETWORK_OFF), "2222 2222 2222 2222 2222").failure?.code)
        assertEquals("journal-lost", RemotePolicyRuntime.dispatch(context, 1)?.code)
        assertTrue(hidden(READER))
        assertTrue(context.getSharedPreferences(RemotePolicyRuntime.JOURNAL_PREFS, Context.MODE_PRIVATE).all.isEmpty())

        // A device that never stored a journal is not lost. Before the baseline it stays contained.
        RemotePolicyRuntime.closeForTests()
        assertTrue(context.getSharedPreferences(RemotePolicyRuntime.JOURNAL_MARKER_PREFS, Context.MODE_PRIVATE)
            .edit().clear().commit())
        assertFalse(RemotePolicyRuntime.journalLost(context))
        assertFalse("journal-lost" in onPolicyThread { RemotePolicyRuntime.reconcile(context) }.errors())
    }

    private companion object {
        const val GALLERY = "com.oem.gallery"
    }
}
