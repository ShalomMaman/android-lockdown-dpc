package com.example.lockdowndpc.remote

import com.example.lockdowndpc.security.PinLockoutPolicy
import com.example.lockdowndpc.testing.MemoryPreferences
import java.io.File
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.function.Consumer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class RemoteReanchorTest {
    @get:Rule val directory = TemporaryFolder()
    private val f = RemoteFixtures
    private val now = RemoteTime(4, 100)
    private val floors = mapOf(DocumentType.KEY_SET to 2L, DocumentType.POLICY to 6L,
        DocumentType.RECOVERY to 4L, DocumentType.COMMAND to 7L)

    private val floorHashes = mapOf(
        "keyset" to RemoteCrypto.hex(RemoteCrypto.sha256(WireJson.canonical(f.doc("keyset-2-current-root")))),
        "fleet-policy" to f.policy("policy-6").hash
    )

    private fun key() = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    private fun spki(key: KeyPair) = RemoteCrypto.encode(key.public.encoded)
    private fun id(key: KeyPair) = RemoteCrypto.keyId(spki(key))

    private fun sign(key: KeyPair, body: JsonObject): ByteArray {
        val payload = WireJson.canonical(body)
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(key.private)
            update(payload)
            sign()
        }
        return WireJson.canonical(mapOf("format" to "dg-signed/1", "keyId" to id(key),
            "payload" to RemoteCrypto.encode(payload), "signature" to RemoteCrypto.encode(signature)))
    }

    private class GuardKey(private val identity: Byte) {
        private var next = 0
        var present = false
        fun mac(payload: ByteArray, create: Boolean): ByteArray {
            if (!present && create) {
                present = true
                next++
            }
            check(present)
            return Mac.getInstance("HmacSHA256").run {
                init(SecretKeySpec(ByteArray(32) { if (it == 0) identity else next.toByte() }, "HmacSHA256"))
                doFinal(payload)
            }
        }
    }

    private inner class Device {
        val root = key()
        val guardKey = GuardKey(1)
        private val pinKey = GuardKey(2)
        val dir: File = directory.newFolder()
        val guard = File(dir, "guard")
        val pin = File(dir, "pin")
        val preferences = MemoryPreferences(emptyMap<String, Any>()).apply { failCommit = false }
        private val marker = MemoryPreferences(emptyMap<String, Any>()).apply { failCommit = false }
        private val projection = object : RemoteProjection {
            override fun validate(policy: JsonObject) { restrictionCalls.add("validate") }
            override fun project(policy: JsonObject, target: Generation): Boolean {
                restrictionCalls.add("project")
                return true
            }
            override fun apply(target: Generation, stillCurrent: () -> Boolean): Boolean {
                restrictionCalls.add("apply")
                return true
            }
            override fun revoke(packages: Set<String>): Set<String> {
                restrictionCalls.add("revoke")
                return emptySet()
            }
        }
        val restrictionCalls = mutableListOf<String>()
        var enrolling = false
        var journal = open()
        var engine = engine()
        private val keyset = RemoteDocument(DocumentType.KEY_SET, sign(root, f.doc("keyset-2-current-root")))

        init {
            assertNull(engine.bindFleet(f.verifier, f.binding, id(root), spki(root), 35))
            assertTrue(receive(keyset, f.document("policy-6"), f.document("recovery-2"),
                f.document("lock-2")).decisions.all { it.failure == null })
            assertTrue(journal.save(engine.state.copy(overrides = RemoteOverride.entries.toSet(),
                releases = setOf("test.previous.release"))))
            restrictionCalls.clear()
        }

        val pinStore get() = RecoveryPinFile(pin, pinKey::mac)
        private fun open() = RemoteJournal(preferences.preferences(), marker.preferences(),
            RemoteJournalGuardFile(guard, guardKey::mac), recoveryPinFile = pinStore)
        private fun engine() = RemoteEngine(journal, f.schema, projection, f::mac)
        fun restart() {
            preferences.restart()
            marker.restart()
            journal = open()
            engine = engine()
        }

        fun damageJournal() {
            assertTrue(preferences.preferences().edit().putString("state", "{").commit())
        }

        fun damageMarker() {
            assertTrue(marker.preferences().edit().putString("journal_created", "invalid").commit())
        }

        fun status(at: RemoteTime = now) = engine.reanchorStatus(at)
        fun challenge() = requireNotNull(status().nonce)
        fun document(nonce: String, key: KeyPair = root, binding: RemoteBinding = f.binding,
                     versions: Map<DocumentType, Long> = floors) = sign(key, mapOf(
            "schemaVersion" to 1L, "type" to "re-anchor", "fleetId" to binding.fleetId,
            "deviceId" to binding.deviceId, "nonce" to nonce, "rootFingerprint" to id(key),
            "rootSpki" to spki(key), "floors" to versions.mapKeys { it.key.wire },
            "floorPayloadSha256" to floorHashes
        ))

        fun submit(envelope: ByteArray, entered: String? = null, at: RemoteTime = now) =
            engine.reanchor(f.verifier, envelope, entered, at) {
                enrolling = true
                true
            }

        fun resendKeys() = receive(keyset)
        fun differentKeys(): RemoteDocument {
            val body = f.doc("keyset-2-current-root") + ("serverUrl" to "https://other.example")
            return RemoteDocument(DocumentType.KEY_SET, sign(root, body))
        }

        fun nominate(successor: KeyPair) {
            val body = f.doc("keyset-2-current-root") + mapOf("keySetVersion" to 3L, "successorRoot" to spki(successor))
            assertNull(receive(RemoteDocument(DocumentType.KEY_SET, sign(root, body))).decisions.single().failure)
        }

        fun rotation(successor: KeyPair): RemoteDocument {
            val body = (f.doc("keyset-2-current-root") - "successorRoot") + ("keySetVersion" to 4L)
            return RemoteDocument(DocumentType.KEY_SET, sign(successor, body))
        }

        fun receive(vararg docs: RemoteDocument): RemoteSync.Response {
            val sync = RemoteSync(f.verifier, f.binding)
            val exchange = requireNotNull(sync.begin(f.nonce, now))
            return engine.receive(sync, exchange, f.nonce, now, docs.toList())
        }
    }

    @Test fun eachRecognizedStorageRefusalCanRebuildWithoutCallingTheRestrictionGateway() {
        val failures: Map<RemoteFailure, Device.() -> Unit> = mapOf(
            RemoteJournal.JOURNAL_LOST to { damageJournal() },
            RemoteJournal.GUARD_MISSING to { assertTrue(guard.delete()) },
            RemoteJournal.GUARD_UNREADABLE to { guard.writeText("damaged") },
            RemoteJournal.GUARD_MISMATCH to {
                val changed = engine.state.copy(policy = f.policy("policy-5"))
                assertTrue(preferences.preferences().edit().putString("state", JournalCodec.encode(changed)).commit())
            },
            RemoteJournal.GUARD_REENROLMENT_NEEDED to {
                val payload = WireJson.canonical(mapOf("format" to 1L, "floors" to floors.mapKeys { it.key.wire }))
                guard.writeBytes(RemoteCrypto.sha256(payload) + payload)
            }
        )
        for ((reason, damage) in failures) {
            val device = Device()
            device.damage()
            device.restart()
            val status = device.status()
            assertEquals(reason, status.reason)
            assertFalse(status.needsRootFingerprint)
            val nonce = requireNotNull(status.nonce)
            if (reason == RemoteJournal.GUARD_REENROLMENT_NEEDED) {
                val older = device.document(nonce, versions = floors + (DocumentType.COMMAND to 6L))
                assertEquals("re-anchor-floor-rollback", device.submit(older)?.code)
            }
            val document = device.document(nonce)
            assertNull(device.submit(document))
            assertTrue(device.enrolling)
            assertTrue(device.status().awaitingPolicy)
            assertEquals("re-anchor-nonce-invalid", device.submit(document)?.code)
            device.restart()
            assertNull(device.engine.failure)
            assertEquals(floors, DocumentType.entries.associateWith(device.journal::floor))
            assertEquals(RemoteTrust(spki(device.root)), device.engine.state.trust)
            assertNull(device.engine.state.policy)
            assertNull(device.engine.state.recovery)
            assertTrue(device.engine.state.commands.isEmpty())
            assertTrue(device.engine.state.overrides.isEmpty())
            assertFalse(device.engine.reconcile().verified)
            assertEquals("doc-version-rollback", device.engine.commitBaseline(f.hashes.obj("baseline").obj("body"))?.code)
            assertTrue(device.restrictionCalls.isEmpty())
        }
    }

    @Test fun wrongDeviceFleetRootAndLoweredFloorsAreRefusedBeforeAnyWrites() {
        val device = Device()
        device.damageJournal()
        device.restart()
        val nonce = device.challenge()
        val copies = device.guard.readBytes() to device.pin.readBytes()
        assertEquals("re-anchor-binding-mismatch", device.submit(device.document(nonce,
            binding = f.binding.copy(deviceId = f.keys.obj("other-device").text("keyId"))))?.code)
        assertEquals("re-anchor-binding-mismatch", device.submit(device.document(nonce,
            binding = f.binding.copy(fleetId = "another-fleet")))?.code)
        assertEquals("re-anchor-root-mismatch", device.submit(device.document(nonce, key = key()))?.code)
        assertEquals("re-anchor-nonce-invalid", device.submit(device.document(f.nonce))?.code)
        assertEquals("doc-field-invalid", device.submit(device.document(nonce,
            versions = floors - DocumentType.RECOVERY))?.code)
        val envelope = WireJson.parse(device.document(nonce)).asObject()
        val signature = RemoteCrypto.decode(envelope.text("signature"))
        signature[signature.lastIndex] = (signature.last().toInt() xor 1).toByte()
        assertEquals("doc-signature-invalid", device.submit(WireJson.canonical(
            envelope + ("signature" to RemoteCrypto.encode(signature))))?.code)
        for ((type, belowStored) in mapOf(DocumentType.KEY_SET to 1L, DocumentType.POLICY to 5L,
            DocumentType.RECOVERY to 1L, DocumentType.COMMAND to 1L)) {
            assertEquals("re-anchor-floor-rollback", device.submit(device.document(nonce,
                versions = floors + (type to belowStored)))?.code)
        }
        assertTrue(copies.first.contentEquals(device.guard.readBytes()))
        assertTrue(copies.second.contentEquals(device.pin.readBytes()))
        assertFalse(device.enrolling)
        assertTrue(device.restrictionCalls.isEmpty())
        assertNull(device.submit(device.document(nonce)))
    }

    @Test fun onlyTheCommittedRootCanReanchorEvenWhenOnlyTheBindRecordSurvives() {
        for (loseGuard in listOf(false, true)) {
            val device = Device()
            val successor = key()
            device.nominate(successor)
            assertNull(device.receive(device.rotation(successor)).decisions.single().failure)
            assertEquals(id(successor), device.pinStore.read()?.pin?.rootFingerprint)
            val seal = RemoteJournalGuardFile(device.guard, device.guardKey::mac).read()?.current
            assertEquals(id(successor), seal?.bindingRootFingerprint)

            device.damageJournal()
            if (loseGuard) assertTrue(device.guard.delete())
            device.restart()
            assertEquals(loseGuard, device.status().needsRootFingerprint)
            val nonce = device.challenge()
            val latest = floors + (DocumentType.KEY_SET to 4L)
            val entered = id(successor).takeIf { loseGuard }
            assertEquals("re-anchor-root-mismatch",
                device.submit(device.document(nonce, versions = latest), entered)?.code)
            assertNull(device.submit(device.document(nonce, successor, versions = latest), entered))
            assertEquals(spki(successor), device.engine.state.trust?.root)
            assertEquals(4L, device.journal.floor(DocumentType.KEY_SET))
        }
    }

    @Test fun rotationRecoversOnBothSidesOfTheJournalWrite() {
        for (journalCommitted in listOf(false, true)) {
            val device = Device()
            val successor = key()
            device.nominate(successor)
            val rotation = device.rotation(successor)
            val crash = Consumer<Set<String>> { throw ProcessDeath() }
            if (journalCommitted) device.preferences.afterCommit = crash
            else device.preferences.beforeCommit = crash
            assertThrows(ProcessDeath::class.java) { device.receive(rotation) }
            device.preferences.beforeCommit = Consumer { }
            device.preferences.afterCommit = Consumer { }

            assertEquals(id(successor), device.pinStore.read()?.pending?.rootFingerprint)
            device.restart()
            assertNull(device.engine.failure)
            assertNull(device.pinStore.read()?.pending)
            val durable = if (journalCommitted) successor else device.root
            assertEquals(spki(durable), device.engine.state.trust?.root)
            assertEquals(id(durable), device.pinStore.read()?.pin?.rootFingerprint)
            if (!journalCommitted) {
                assertEquals(4L, device.journal.floor(DocumentType.KEY_SET))
                assertNull(device.receive(rotation).decisions.single().failure)
                assertEquals(id(successor), device.pinStore.read()?.pin?.rootFingerprint)
            }
        }
    }

    @Test fun disagreementBetweenAuthenticatedGuardAndBindRecordRequiresReset() {
        val device = Device()
        val prior = device.pin.readBytes()
        val successor = key()
        device.nominate(successor)
        assertNull(device.receive(device.rotation(successor)).decisions.single().failure)
        device.pin.writeBytes(prior)
        device.damageJournal()
        device.restart()
        assertEquals("re-anchor-pin-unavailable", device.status().error?.code)
        assertNull(device.status().nonce)
    }

    @Test fun bindRecordAloneCannotChooseASideOfAnInterruptedRotation() {
        val device = Device()
        val successor = key()
        device.nominate(successor)
        device.preferences.afterCommit = Consumer { throw ProcessDeath() }
        assertThrows(ProcessDeath::class.java) { device.receive(device.rotation(successor)) }
        device.preferences.afterCommit = Consumer { }
        assertTrue(device.guard.delete())
        device.damageJournal()
        device.restart()
        assertEquals("re-anchor-pin-unavailable", device.status().error?.code)
        assertNull(device.status().nonce)
    }

    @Test fun aJournalProofAloneCannotAuthorizeRecoveryAfterTheIndependentRecordsAreLost() {
        val device = Device()
        assertTrue(device.guard.delete())
        assertTrue(device.pin.delete())
        device.restart()
        assertEquals("re-anchor-pin-unavailable", device.status().error?.code)
        assertNull(device.status().nonce)
    }

    @Test fun thePinnedSpkiVerifiesTheSignatureBeforeParsingThePayload() {
        val device = Device()
        device.damageJournal()
        device.restart()
        val envelope = WireJson.parse(device.document(device.challenge())).asObject()
        assertEquals("doc-signature-invalid", device.submit(WireJson.canonical(
            envelope + ("payload" to RemoteCrypto.encode("{".toByteArray()))))?.code)
    }

    private class ProcessDeath : Error()

    @Test fun nonceExpiresAtTheDeadlineAndAfterReboot() {
        val device = Device()
        device.damageJournal()
        device.restart()
        val document = device.document(device.challenge())
        for (time in listOf(now.copy(elapsed = now.elapsed + RemoteReanchor.WINDOW_MS), now.copy(boot = now.boot + 1))) {
            assertEquals("re-anchor-nonce-invalid", device.submit(document, at = time)?.code)
        }
        assertFalse(device.enrolling)
        val after = now.copy(elapsed = now.elapsed + RemoteReanchor.WINDOW_MS)
        val newNonce = requireNotNull(device.status(after).nonce)
        assertEquals("re-anchor-nonce-invalid", device.submit(document, at = after)?.code)
        assertNull(device.submit(device.document(newNonce), at = after))
    }

    @Test fun guardKeyLossUsesIndependentPinWhenBothMainRecordsAreUnreadable() {
        val device = Device()
        device.damageJournal()
        device.guardKey.present = false
        device.restart()
        val fallback = device.status()
        assertFalse(device.guardKey.present)
        assertTrue(fallback.needsRootFingerprint)
        val envelope = device.document(requireNotNull(fallback.nonce))
        assertEquals("re-anchor-root-mismatch", device.submit(envelope, entered = id(key()))?.code)
        assertFalse(device.guardKey.present)
        assertNull(device.submit(envelope, entered = id(device.root)))
        assertTrue(device.guardKey.present)
        device.restart()
        assertNull(device.engine.failure)
        assertTrue(device.restrictionCalls.isEmpty())
    }

    @Test fun aReadableJournalCannotSubstituteItsOwnRootWhenTheGuardIsMissing() {
        val device = Device()
        val foreignRoot = key()
        val stored = device.engine.state
        val replaced = stored.copy(trust = RemoteTrust(spki(foreignRoot)),
            recoveryPin = requireNotNull(stored.recoveryPin).copy(rootFingerprint = id(foreignRoot)))
        assertTrue(device.preferences.preferences().edit().putString("state", JournalCodec.encode(replaced)).commit())
        assertTrue(device.guard.delete())
        device.restart()

        val status = device.status()
        assertEquals(RemoteJournal.GUARD_MISSING, status.reason)
        assertTrue(status.needsRootFingerprint)
        val nonce = requireNotNull(status.nonce)
        assertEquals("re-anchor-root-mismatch", device.submit(device.document(nonce, foreignRoot), id(foreignRoot))?.code)
        assertNull(device.submit(device.document(nonce), id(device.root)))
    }

    @Test fun losingAllIdentityEvidenceRequiresAReset() {
        val device = Device()
        device.damageJournal()
        device.guardKey.present = false
        assertTrue(device.pin.delete())
        device.restart()
        assertEquals("re-anchor-pin-unavailable", device.status().error?.code)
        assertNull(device.status().nonce)
        assertFalse(device.guardKey.present)
        assertTrue(device.restrictionCalls.isEmpty())
    }

    @Test fun partialWriteKeepsRestrictionsAndFloorsAndRequiresAnotherChallenge() {
        val device = Device()
        device.damageMarker()
        device.restart()
        val elevated = floors + (DocumentType.POLICY to 9L)
        val document = device.document(device.challenge(), versions = elevated)
        device.preferences.failCommit = true
        assertEquals("journal-write-failed", device.submit(document)?.code)
        assertEquals("re-anchor-nonce-invalid", device.submit(document)?.code)
        device.preferences.failCommit = false
        device.restart()
        assertTrue(device.engine.lost)
        assertEquals(9L, device.journal.floor(DocumentType.POLICY))
        val next = device.challenge()
        assertEquals("re-anchor-floor-rollback", device.submit(device.document(next))?.code)
        assertNull(device.submit(device.document(next, versions = elevated)))
        assertEquals(setOf("test.previous.release"), device.engine.state.releases)
        assertTrue(device.restrictionCalls.isEmpty())
    }

    @Test fun keysetAndPolicyCanBeResentAtTheFloorButAnOlderPolicyCannotApply() {
        val device = Device()
        device.damageJournal()
        device.restart()
        assertNull(device.submit(device.document(device.challenge())))
        assertEquals("doc-version-rollback", device.receive(device.differentKeys()).decisions.single().failure?.code)
        device.preferences.failCommit = true
        assertEquals("journal-write-failed", device.resendKeys().decisions.single().failure?.code)
        device.preferences.failCommit = false
        device.restart()
        assertEquals("doc-version-rollback", device.receive(device.differentKeys()).decisions.single().failure?.code)
        assertNull(device.resendKeys().decisions.single().failure)
        assertEquals("doc-version-rollback", device.resendKeys().decisions.single().failure?.code)
        assertEquals("doc-version-rollback", device.receive(f.document("policy-5")).decisions.single().failure?.code)
        assertTrue(device.restrictionCalls.isEmpty())
        assertNull(device.receive(f.document("policy-6")).decisions.single().failure)
        assertEquals(6L, device.engine.state.policy?.version)
        assertEquals("doc-version-rollback", device.receive(f.document("policy-6")).decisions.single().failure?.code)
    }

    @Test fun delegatedActionsWaitForFirstPolicyReadback() {
        val device = Device()
        device.damageJournal()
        device.restart()
        assertNull(device.submit(device.document(device.challenge())))

        val policyKey = key()
        val serverKey = key()
        val keyset = f.doc("keyset-2-current-root") + mapOf(
            "keySetVersion" to 3L, "fleetPolicyKeys" to listOf(spki(policyKey)), "serverKey" to spki(serverKey)
        )
        val policy = f.doc("policy-6") + mapOf("keySetVersion" to 3L, "fleetPolicyVersion" to 7L)
        val recovery = f.doc("recovery-2") + mapOf("keySetVersion" to 3L, "recoveryVersion" to 5L)
        val command = f.doc("lock-2") + mapOf("keySetVersion" to 3L, "sequence" to 8L)
        val recoveryDoc = RemoteDocument(DocumentType.RECOVERY, sign(policyKey, recovery))
        val commandDoc = RemoteDocument(DocumentType.COMMAND, sign(serverKey, command))

        val first = device.receive(RemoteDocument(DocumentType.KEY_SET, sign(device.root, keyset)),
            RemoteDocument(DocumentType.POLICY, sign(policyKey, policy)), recoveryDoc, commandDoc)
        assertEquals(listOf(null, null, "remote-policy-unavailable", "remote-policy-unavailable"),
            first.decisions.map { it.failure?.code })
        assertNull(device.engine.state.recovery)
        assertTrue(device.engine.state.commands.isEmpty())
        assertTrue(device.engine.reconcile().verified)

        device.restart()
        assertEquals(listOf(null, null), device.receive(recoveryDoc, commandDoc).decisions.map { it.failure?.code })
    }

    @Test fun publicReanchorVectorsVerifyAndProductionRefusesTheirKey() {
        val fixture = f.vectors("re-anchor")
        val envelope = WireJson.canonical(fixture.obj("envelope"))
        val signer = fixture.text("signer")
        for (value in fixture.items("cases")) {
            val case = value.asObject()
            val rootId = f.keys.obj(case["key"] as? String ?: signer).text("keyId")
            val binding = RemoteBinding(case["fleetId"] as? String ?: f.binding.fleetId,
                (case["deviceKey"] as? String)?.let { f.keys.obj(it).text("keyId") } ?: f.binding.deviceId)
            val pin = RecoveryPin(rootId, binding.fingerprint())
            val nonce = case["nonce"] as? String ?: f.nonce
            val result = runCatching { f.verifier.authenticateReanchor(envelope, pin, nonce) }
            assertEquals(case.text("id"), case["expectedFailure"],
                (result.exceptionOrNull() as? Refused)?.failure?.code)
            if (result.isSuccess) {
                val verified = result.getOrThrow()
                assertEquals(binding, verified.binding)
                assertEquals(floors, verified.floors)
                assertEquals(f.policy("policy-6").hash, verified.floorPayloadSha256[DocumentType.POLICY])
                val release = runCatching { RemoteVerifier(f.schema).authenticateReanchor(envelope, pin, nonce) }
                assertEquals("re-anchor-root-mismatch", (release.exceptionOrNull() as? Refused)?.failure?.code)
            } else assertTrue(result.exceptionOrNull() is Refused)
        }
    }

    @Test fun fullJournalRoundTripsAndSealsAllDurableFields() {
        val device = Device()
        val committed = f.policy("policy-6")
        val generation = Generation(committed.version, committed.hash, RemoteOverride.entries.toSet())
        val state = JournalState(
            trust = f.trust("keyset-1"), binding = f.binding, policy = committed,
            overrides = RemoteOverride.entries.toSet(), recoveryVersion = 3,
            recovery = RecoveryVerifier(RemoteCrypto.encode(ByteArray(16)), RemoteCrypto.encode(ByteArray(32))),
            recoveryUses = 2,
            lockout = PinLockoutPolicy.LockoutState(5, PinLockoutPolicy.BootId.ofBootCount(4), 30_100, 30_000, 424_242),
            commandFloor = 7,
            commands = mapOf(7L to CommandEntry(7, "reapply", now, CommandState.DONE, reapplyVerified = true,
                verified = generation)),
            verified = generation, releases = setOf("test.previous.release", "other.release"),
            recoveryPin = device.engine.state.recoveryPin, reanchorFloors = floors,
            floorPayloadSha256 = mapOf(DocumentType.POLICY to committed.hash)
        )
        assertNotNull(state.trust?.successor)
        val decoded = JournalCodec.decode(JournalCodec.encode(state))
        assertEquals(state, decoded)
        assertEquals(JournalCodec.encode(state), JournalCodec.encode(decoded))
        val seal = JournalSeal.from(decoded)
        val store = RemoteJournalGuardFile(device.guard, device.guardKey::mac)
        store.write(JournalGuard(seal))
        assertEquals(JournalSeal.from(state), store.read()?.current)
        assertNotEquals(seal, JournalSeal.from(decoded.copy(releases = emptySet())))
    }
}
