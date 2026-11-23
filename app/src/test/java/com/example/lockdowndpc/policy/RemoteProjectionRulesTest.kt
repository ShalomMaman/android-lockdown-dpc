package com.example.lockdowndpc.policy

import android.app.ActivityManager
import android.app.Application
import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.provider.Settings
import com.example.lockdowndpc.kiosk.KioskConfigStore
import com.example.lockdowndpc.kiosk.KioskController
import com.example.lockdowndpc.kiosk.KioskHostActivity
import com.example.lockdowndpc.kiosk.KioskStateMachine.KioskState
import com.example.lockdowndpc.remote.DocumentType
import com.example.lockdowndpc.remote.JournalState
import com.example.lockdowndpc.remote.JsonObject
import com.example.lockdowndpc.remote.Refused
import com.example.lockdowndpc.remote.RemoteClientWire
import com.example.lockdowndpc.remote.RemoteCrypto
import com.example.lockdowndpc.remote.RemoteDocument
import com.example.lockdowndpc.remote.RemoteFailure
import com.example.lockdowndpc.remote.RemoteOverride
import com.example.lockdowndpc.remote.WireJson
import com.example.lockdowndpc.remote.asObject
import com.example.lockdowndpc.remote.obj
import java.io.File
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.robolectric.Robolectric
import org.robolectric.Shadows

/** What the remote pass refuses to take on trust: kiosk state, languages, hidden packages and a damaged journal. */
class RemoteProjectionRulesTest : RemotePassFixture() {

    @After fun restoreGuardMac() {
        RemotePolicyRuntime.setGuardMacForTests(null)
        RemotePolicyRuntime.setPinMacForTests(null)
    }

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

    /**
     * A device with remote intent and a kiosk left in its store starts: nothing
     * restores that kiosk, and the kiosk HOME screen neither locks the task nor
     * starts the target, ahead of the journal pass that turns the kiosk off.
     */
    @Test fun storedKioskIsNotReEnteredAtBootWhileRemoteIntentIsSet() {
        assertTrue(context.getSharedPreferences("kiosk_policy", Context.MODE_PRIVATE).edit()
            .putString("kiosk_state", "ACTIVE").putString("kiosk_mode", "SINGLE_SITE")
            .putString("kiosk_site_url", "https://example.com/").commit())
        val activityManager = context.getSystemService(ActivityManager::class.java)

        // What the boot receiver queues on the policy thread.
        val restored = onPolicyThread { KioskController.restoreAfterBoot(context) }
        assertFalse(restored.allowed())
        assertEquals("remote-kiosk-unsupported", restored.reason())
        assertFalse(dpm.isLockTaskPermitted(context.packageName))

        // What the system does at boot when the kiosk screen is HOME.
        context.packageManager.setComponentEnabledSetting(ComponentName(context, KioskHostActivity::class.java),
            PackageManager.COMPONENT_ENABLED_STATE_ENABLED, PackageManager.DONT_KILL_APP)
        Robolectric.buildActivity(KioskHostActivity::class.java).setup().use { host ->
            assertEquals(ActivityManager.LOCK_TASK_MODE_NONE, activityManager.lockTaskModeState)
            assertNull(Shadows.shadowOf(context as Application).nextStartedActivity)
            assertFalse(host.get().isFinishing)
        }
        assertFalse(dpm.isLockTaskPermitted(context.packageName))
        assertEquals(KioskState.ACTIVE, KioskConfigStore.readState(context))

        // The journal pass is what removes it.
        commit(policy())
        assertVerified()
        assertEquals(KioskState.OFF, KioskConfigStore.readState(context))
    }

    /** A value outside what this build knows is refused. It is never read as the default. */
    @Test fun unknownLanguageOrKioskModeIsRefusedNotDefaulted() {
        val android13 = RemotePolicyProjection(context, sdk = 33)
        fun refusal(extra: Map<String, Any?>): RemoteFailure? = try {
            android13.validate(policy(extra = extra))
            null
        } catch (refused: Refused) {
            refused.failure
        }
        assertEquals(RemoteFailure("doc-field-invalid", "/policy/locale"), refusal(mapOf("locale" to "fr")))
        assertEquals(RemoteFailure("doc-field-invalid", "/policy/kiosk/mode"),
            refusal(mapOf("kiosk" to mapOf("mode" to "MULTI_APP"))))
        assertNull(refusal(mapOf("locale" to "iw", "kiosk" to mapOf("mode" to "OFF"))))
    }

    /**
     * Before Android 13 only AppCompat holds the language, and it can only repeat
     * what it was asked. A policy with a language is refused there, so it can
     * never hold a device on an unverifiable generation.
     */
    @Test fun languageIsRefusedBeforeAndroid13AndAPolicyWithoutOneVerifies() {
        val fresh = f.harness(JournalState(), projection)
        for (language in listOf("en", "he", "iw")) {
            assertEquals(RemoteFailure(RemotePolicyProjection.LOCALE_UNSUPPORTED, "/policy/locale"),
                fresh.engine.commitBaseline(policy(extra = mapOf("locale" to language))))
        }
        assertNull(fresh.engine.state.policy)
        assertNull(f.harness(JournalState(), RemotePolicyProjection(context, sdk = 33)).engine
            .commitBaseline(policy(extra = mapOf("locale" to "iw"))))

        // A journal that already holds such a policy does not project it, and the next policy verifies.
        commit(policy(extra = mapOf("locale" to "en")))
        assertEquals(RemoteFailure(RemotePolicyProjection.LOCALE_UNSUPPORTED, "/policy/locale"), pass().failure)
        assertNull(projection.lastResult)
        replace(policy())
        assertVerified()
        assertEquals(setOf("choice"),
            context.getSharedPreferences("remote_policy_locale", Context.MODE_PRIVATE).all.keys)
    }

    @Test fun signedLocalePolicyIsRefusedBeforeCommitAndReportedToTheConsole() {
        RemotePolicyRuntime.setGuardMacForTests(f::mac)
        RemotePolicyRuntime.setPinMacForTests(f::mac)
        assertTrue(Settings.Global.putInt(context.contentResolver, Settings.Global.BOOT_COUNT, 9))
        val root = newKeyPair()
        val signer = newKeyPair()
        val rootSpki = RemoteCrypto.encode(root.public.encoded)
        val binding = f.binding.copy(deviceId = RemoteCrypto.encode(ByteArray(32)))
        assertNull(RemotePolicyRuntime.bindFleet(context, binding, RemoteCrypto.keyId(rootSpki), rootSpki))

        fun submit(type: DocumentType, document: JsonObject, key: KeyPair): RemoteFailure? {
            val exchange = requireNotNull(RemotePolicyRuntime.beginExchange(context))
            val signed = RemoteDocument(type, signedEnvelope(document, key))
            return RemotePolicyRuntime.receive(context, exchange, exchange.nonce, listOf(signed))
                .decisions.single().failure
        }

        val keySet = (f.doc("keyset-2-current-root") - "successorRoot") + mapOf(
            "fleetPolicyKeys" to listOf(RemoteCrypto.encode(signer.public.encoded)),
            "serverKey" to newRoot())
        assertNull(submit(DocumentType.KEY_SET, keySet, root))
        val prefs = context.getSharedPreferences(RemotePolicyRuntime.JOURNAL_PREFS, Context.MODE_PRIVATE)
        val before = prefs.getString("state", null)
        val document = f.doc("policy-6") + ("deviceIds" to listOf(binding.deviceId))
        val sync = "sync" to mapOf("pullMinutes" to 120L)
        val unsupported = document + ("policy" to policy(filter = null, extra = mapOf("locale" to "he", sync)))
        val code = RemotePolicyProjection.LOCALE_UNSUPPORTED
        assertEquals(RemoteFailure(code, "/policy/locale"), submit(DocumentType.POLICY, unsupported, signer))
        assertEquals(before, prefs.getString("state", null))
        assertEquals(code, RemotePolicyRuntime.policyRefusals.value)
        assertNull(RemotePolicyRuntime.committedPullMinutes(context))

        assertNull(submit(DocumentType.POLICY, document + ("policy" to policy(filter = null, extra = mapOf(sync))), signer))
        assertEquals(120L, RemotePolicyRuntime.committedPullMinutes(context))
        assertNull(RemotePolicyRuntime.policyRefusals.value)
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

        assertEquals(RemoteFailure("journal-lost"), RemotePolicyRuntime.journalFailure(context))
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
        assertTrue(context.deleteSharedPreferences(RemotePolicyRuntime.JOURNAL_MARKER_PREFS))
        assertNull(RemotePolicyRuntime.journalFailure(context))
        assertFalse("journal-lost" in onPolicyThread { RemotePolicyRuntime.reconcile(context) }.errors())
    }

    @Test fun malformedMarkerFileDoesNotLookLikeFreshEnrolment() {
        val marker = File(context.dataDir, "shared_prefs/${RemotePolicyRuntime.JOURNAL_MARKER_PREFS}.xml")
        marker.parentFile?.mkdirs()
        marker.writeText("<map>")

        val root = f.keys.getValue("root") as Map<*, *>
        assertEquals("journal-lost", RemotePolicyRuntime.journalFailure(context)?.code)
        assertEquals("journal-lost", RemotePolicyRuntime.bindFleet(
            context, f.binding, root["keyId"] as String, root["spki"] as String)?.code)
    }

    @Test fun committedRemoteModeWithNoJournalOrGuardRefusesBinding() {
        assertTrue(context.getSharedPreferences(ManagementModeStore.MODE_PREFS, Context.MODE_PRIVATE)
            .edit().putString(ManagementModeStore.MODE_KEY, ManagementMode.REMOTE.name).commit())

        val root = f.keys.getValue("root") as Map<*, *>
        assertEquals("journal-lost", RemotePolicyRuntime.journalFailure(context)?.code)
        assertEquals("journal-lost", RemotePolicyRuntime.bindFleet(
            context, f.binding, root["keyId"] as String, root["spki"] as String)?.code)
    }

    @Test fun runtimeWritesTheGuardAndSurfacesCorruptionBeforeAndAfterReopening() {
        RemotePolicyRuntime.setGuardMacForTests(f::mac)
        RemotePolicyRuntime.setPinMacForTests(f::mac)
        val spki = newRoot()
        val pinnedId = RemoteCrypto.keyId(spki)
        val binding = f.binding.copy(deviceId = RemoteCrypto.encode(ByteArray(32)))
        assertNull(RemotePolicyRuntime.bindFleet(context, binding, pinnedId, spki))
        assertNull(RemotePolicyRuntime.journalFailure(context))

        val file = File(context.noBackupFilesDir, RemotePolicyRuntime.JOURNAL_GUARD_FILE)
        assertTrue(file.isFile)
        file.writeText("corrupt")
        for (reopened in listOf(false, true)) {
            if (reopened) RemotePolicyRuntime.closeForTests()
            assertEquals("journal-guard-unreadable", RemotePolicyRuntime.journalFailure(context)?.code)
            assertEquals("journal-guard-unreadable", RemotePolicyRuntime.bindFleet(
                context, binding.copy(fleetId = "another-fleet"), pinnedId, spki)?.code)
            assertEquals(listOf("journal-guard-unreadable"), onPolicyThread { RemotePolicyRuntime.reconcile(context) }.errors())
        }
    }

    @Test fun successfulBindingCommitsRemoteModeAndRefusesRebindingAfterAllJournalStoresAreLost() {
        RemotePolicyRuntime.setGuardMacForTests(f::mac)
        RemotePolicyRuntime.setPinMacForTests(f::mac)
        val binding = f.binding.copy(deviceId = RemoteCrypto.encode(ByteArray(32)))
        val spki = newRoot()
        assertEquals(ManagementMode.ENROLLING, ManagementModeStore.read(context))
        assertNull(RemotePolicyRuntime.bindFleet(context, binding, RemoteCrypto.keyId(spki), spki))
        assertEquals(ManagementMode.REMOTE, ManagementModeStore.read(context))
        assertNull(RemotePolicyRuntime.journalFailure(context))

        RemotePolicyRuntime.closeForTests()
        assertTrue(context.deleteSharedPreferences(RemotePolicyRuntime.JOURNAL_PREFS))
        assertTrue(context.deleteSharedPreferences(RemotePolicyRuntime.JOURNAL_MARKER_PREFS))
        val guard = File(context.noBackupFilesDir, RemotePolicyRuntime.JOURNAL_GUARD_FILE)
        assertTrue(guard.delete())
        val otherRoot = newRoot()
        assertEquals("journal-lost", RemotePolicyRuntime.bindFleet(
            context, binding, RemoteCrypto.keyId(otherRoot), otherRoot)?.code)
        assertFalse(guard.exists())
        assertTrue(context.getSharedPreferences(RemotePolicyRuntime.JOURNAL_PREFS, Context.MODE_PRIVATE).all.isEmpty())
    }

    @Test fun sameBindingCanFinishAnInterruptedRemoteModeCommit() {
        RemotePolicyRuntime.setGuardMacForTests(f::mac)
        RemotePolicyRuntime.setPinMacForTests(f::mac)
        val binding = f.binding.copy(deviceId = RemoteCrypto.encode(ByteArray(32)))
        val spki = newRoot()
        val pinnedId = RemoteCrypto.keyId(spki)
        assertNull(RemotePolicyRuntime.bindFleet(context, binding, pinnedId, spki))
        assertTrue(context.deleteSharedPreferences(ManagementModeStore.MODE_PREFS))
        RemotePolicyRuntime.closeForTests()

        val otherRoot = newRoot()
        assertEquals("doc-version-rollback", RemotePolicyRuntime.bindFleet(
            context, binding, RemoteCrypto.keyId(otherRoot), otherRoot)?.code)
        assertEquals(ManagementMode.ENROLLING, ManagementModeStore.read(context))
        assertNull(RemotePolicyRuntime.bindFleet(context, binding, pinnedId, spki))
        assertEquals(ManagementMode.REMOTE, ManagementModeStore.read(context))
        assertEquals("doc-version-rollback", RemotePolicyRuntime.bindFleet(context, binding, pinnedId, spki)?.code)
    }

    @Test fun runtimeReanchorSyncsUntilAReplacementPolicyPassesReadBack() {
        RemotePolicyRuntime.setGuardMacForTests(f::mac)
        RemotePolicyRuntime.setPinMacForTests(f::mac)
        assertTrue(Settings.Global.putInt(context.contentResolver, Settings.Global.BOOT_COUNT, 9))
        install(READER)
        assertTrue(dpm.setApplicationHidden(admin, READER, true))
        val root = newKeyPair()
        val spki = RemoteCrypto.encode(root.public.encoded)
        val rootId = RemoteCrypto.keyId(spki)
        val binding = f.binding.copy(deviceId = RemoteCrypto.encode(ByteArray(32)))
        assertNull(RemotePolicyRuntime.bindFleet(context, binding, rootId, spki))
        assertEquals(ManagementMode.REMOTE, ManagementModeStore.read(context))
        assertTrue(context.getSharedPreferences(RemotePolicyRuntime.JOURNAL_PREFS, Context.MODE_PRIVATE)
            .edit().putString("state", "{").commit())
        RemotePolicyRuntime.closeForTests()
        val status = RemotePolicyRuntime.reanchorStatus(context)
        assertEquals("journal-lost", status.reason?.code)
        assertNull(RemotePolicyRuntime.prepareSync(context))
        val commandFloor = 7L
        val document = signedEnvelope(mapOf("schemaVersion" to 1L, "type" to "re-anchor",
            "fleetId" to binding.fleetId, "deviceId" to binding.deviceId, "nonce" to requireNotNull(status.nonce),
            "rootFingerprint" to rootId, "rootSpki" to spki,
            "floors" to DocumentType.entries.associate { it.wire to if (it == DocumentType.COMMAND) commandFloor else 0L }),
            root)

        assertNull(RemotePolicyRuntime.reanchor(context, document, null))
        RemotePolicyRuntime.closeForTests()
        assertNull(RemotePolicyRuntime.journalFailure(context))
        assertTrue(RemotePolicyRuntime.reanchorStatus(context).awaitingPolicy)
        assertEquals(ManagementMode.ENROLLING, ManagementModeStore.read(context))
        assertFalse(onPolicyThread { RemotePolicyRuntime.reconcile(context) }.applied())
        assertTrue(hidden(READER))

        fun prepare() = requireNotNull(RemotePolicyRuntime.prepareSync(context))
        fun reply(request: RemotePolicyRuntime.SyncRequest, vararg documents: RemoteDocument) =
            RemotePolicyRuntime.receiveAndApply(context, request.exchange,
                RemoteClientWire.SyncReply(request.exchange.nonce, documents.toList()))
        fun checkAwaiting(request: RemotePolicyRuntime.SyncRequest, keySetVersion: Long) {
            val body = WireJson.parse(request.body).asObject()
            for (field in listOf("fleetPolicyVersion", "committedSha256", "generationSha256", "verifiedGeneration")) {
                assertTrue(body.containsKey(field))
                assertNull(body[field])
            }
            assertEquals(emptyList<String>(), body["overrides"])
            assertEquals(binding.deviceId, body["deviceId"])
            assertEquals(keySetVersion, body["keySetVersion"])
            assertEquals(commandFloor, body["lastCommandSequence"])
        }

        val policyKey = newKeyPair()
        val commandKey = newKeyPair()
        val keySet = (f.doc("keyset-2-current-root") - "successorRoot") + mapOf(
            "fleetPolicyKeys" to listOf(RemoteCrypto.encode(policyKey.public.encoded)),
            "serverKey" to RemoteCrypto.encode(commandKey.public.encoded))
        val first = prepare()
        checkAwaiting(first, 0L)
        val withoutPolicy = reply(first, RemoteDocument(DocumentType.KEY_SET, signedEnvelope(keySet, root)))
        assertTrue(withoutPolicy.retry)
        assertTrue(RemotePolicyRuntime.reanchorStatus(context).awaitingPolicy)
        assertEquals(ManagementMode.ENROLLING, ManagementModeStore.read(context))
        assertTrue(hidden(READER))

        val second = prepare()
        checkAwaiting(second, 2L)
        val replacement = f.doc("policy-6") + mapOf(
            "deviceIds" to listOf(binding.deviceId),
            "policy" to policy(allowed = listOf(READER), filter = null))
        val command = f.doc("lock-2") + mapOf(
            "deviceId" to binding.deviceId, "nonce" to second.exchange.nonce, "sequence" to commandFloor + 1)
        val applied = reply(second,
            RemoteDocument(DocumentType.POLICY, signedEnvelope(replacement, policyKey)),
            RemoteDocument(DocumentType.COMMAND, signedEnvelope(command, commandKey)))
        assertFalse(applied.retry)
        assertTrue(applied.followUp)
        assertEquals(ManagementMode.REMOTE, ManagementModeStore.read(context))
        assertFalse(RemotePolicyRuntime.reanchorStatus(context).awaitingPolicy)
        assertFalse(hidden(READER))

        val reported = WireJson.parse(prepare().body).asObject()
        assertEquals(6L, reported["fleetPolicyVersion"])
        assertEquals(reported["generationSha256"], reported.obj("verifiedGeneration")["verifiedSha256"])
        assertEquals(commandFloor, reported["lastCommandSequence"])
        assertEquals(listOf("remote-policy-unavailable"), reported.obj("report")["syncErrors"])
    }

    private fun signedEnvelope(document: JsonObject, key: KeyPair): ByteArray {
        val payload = WireJson.canonical(document)
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(key.private)
            update(payload)
            sign()
        }
        return WireJson.canonical(mapOf("format" to "dg-signed/1",
            "keyId" to RemoteCrypto.keyId(RemoteCrypto.encode(key.public.encoded)),
            "payload" to RemoteCrypto.encode(payload), "signature" to RemoteCrypto.encode(signature)))
    }

    private fun newKeyPair() = KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    private fun newRoot() = RemoteCrypto.encode(newKeyPair().public.encoded)

    private companion object {
        const val GALLERY = "com.oem.gallery"
    }
}
