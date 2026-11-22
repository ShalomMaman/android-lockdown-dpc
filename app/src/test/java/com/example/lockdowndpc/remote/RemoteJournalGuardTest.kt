package com.example.lockdowndpc.remote

import com.example.lockdowndpc.testing.MemoryPreferences
import java.io.File
import java.io.IOException
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.function.Consumer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class RemoteJournalGuardTest {
    @get:Rule val directory = TemporaryFolder()
    private val f = RemoteFixtures

    private val file get() = File(directory.root, "remote-policy-guard")
    private val initial get() = JournalState(
        trust = f.trust("keyset-2", "successor"), binding = f.binding,
        policy = f.policy("policy-5"), recoveryVersion = 4, commandFloor = 7
    )

    private fun fileStore() = RemoteJournalGuardFile(file, f::mac)

    private fun harness(store: RemoteJournalGuardStore = fileStore()) = RemoteFixtures.Harness(
        MemoryPreferences(emptyMap<String, Any>()).apply { failCommit = false }, f.noProjection, store
    )

    private fun bind(harness: RemoteFixtures.Harness, binding: RemoteBinding = f.binding,
                     key: String = "root"): RemoteFailure? {
        val root = f.keys.obj(key)
        return harness.engine.bindFleet(f.verifier, binding, root.text("keyId"), root.text("spki"), 35)
    }

    private fun persistedJournal(harness: RemoteFixtures.Harness): JsonObject =
        WireJson.parse(requireNotNull(harness.memory.preferences().getString("state", null))
            .toByteArray(Charsets.UTF_8)).asObject()

    private fun replaceJournal(harness: RemoteFixtures.Harness, contents: JsonObject) =
        harness.damageJournal(WireJson.canonical(contents).toString(Charsets.UTF_8))

    @Test fun damagedOrEmptyJournalCannotBeTakenOverAndRetainsAllFloors() {
        val harness = harness()
        assertTrue(harness.journal.save(initial))
        for (damaged in listOf("{", null)) {
            harness.damageJournal(damaged)
            harness.restart()
            assertEquals("journal-lost", bind(harness, f.binding.copy(fleetId = "another-fleet"))?.code)
            assertEquals("journal-lost", harness.receive("policy-5").failure?.code)
            assertEquals(DocumentType.entries.map(initial::floor), DocumentType.entries.map(harness.journal::floor))
        }
        assertTrue(harness.marker.preferences().edit().clear().commit())
        harness.restart()
        assertEquals("journal-lost", bind(harness)?.code)
        assertEquals(5L, harness.journal.floor(DocumentType.POLICY))
    }

    @Test fun macFailureBlocksRemoteOperationsAndKeepsJournalFloors() {
        val harness = harness()
        assertTrue(harness.journal.save(initial))
        val record = file.readBytes()
        record[0] = (record[0].toInt() xor 1).toByte()
        file.writeBytes(record)

        assertEquals("journal-guard-unreadable", harness.journal.checkStores()?.code)
        harness.restart()
        assertEquals("journal-guard-unreadable", bind(harness)?.code)
        assertEquals("journal-guard-unreadable", harness.engine.reconcile().failure?.code)
        assertEquals(DocumentType.entries.map(initial::floor), DocumentType.entries.map(harness.journal::floor))
    }

    @Test fun replacingTheMacWithAPublicDigestDoesNotAuthenticateTheGuard() {
        val harness = harness()
        assertTrue(harness.journal.save(initial))
        val record = file.readBytes()
        val payload = record.copyOfRange(32, record.size)
        file.writeBytes(RemoteCrypto.sha256(payload) + payload)

        harness.restart()
        assertEquals(RemoteJournal.GUARD_UNREADABLE, harness.engine.failure)
    }

    @Test fun missingMacKeyCannotBeRecreatedWhenReadingAnExistingGuard() {
        var keyPresent = false
        val store = RemoteJournalGuardFile(file) { payload, create ->
            if (create) keyPresent = true
            check(keyPresent)
            f.mac(payload)
        }
        val harness = harness(store)
        assertTrue(harness.journal.save(initial))
        keyPresent = false

        harness.restart()
        assertEquals(RemoteJournal.GUARD_UNREADABLE, bind(harness))
        assertFalse(keyPresent)
    }

    @Test fun legacyGuardFormatsRequireReenrolmentWithoutRewritingEitherStore() {
        val harness = harness()
        assertTrue(harness.journal.save(initial))
        val current = requireNotNull(fileStore().read()).current
        val journal = persistedJournal(harness)
        val identity = mapOf("bindingFingerprint" to current.bindingFingerprint,
            "rootFingerprint" to current.rootFingerprint, "floors" to current.floors.mapKeys { it.key.wire })
        val legacyRecords = listOf(
            identity + ("format" to 1L),
            identity + ("format" to 2L),
            mapOf("format" to 3L, "previous" to null, "pending" to emptyMap<String, Any>(),
                "current" to identity + mapOf("policySha256" to current.policySha256,
                    "trustSha256" to RemoteCrypto.hex(RemoteCrypto.sha256(WireJson.canonical(journal.obj("trust"))))))
        )
        for (legacy in legacyRecords) {
            val format = legacy.number("format")
            val payload = WireJson.canonical(legacy)
            val tag = if (format == 1L) RemoteCrypto.sha256(payload) else f.mac(payload)
            val record = tag + payload
            file.writeBytes(record)
            harness.restart()

            assertEquals(RemoteJournal.GUARD_REENROLMENT_NEEDED, bind(harness))
            assertEquals(RemoteJournal.GUARD_REENROLMENT_NEEDED, harness.engine.reconcile().failure)
            assertFalse(harness.journal.save(initial))
            assertTrue(file.readBytes().contentEquals(record))
            assertEquals(journal, persistedJournal(harness))

            record[0] = (record[0].toInt() xor 1).toByte()
            file.writeBytes(record)
            harness.restart()
            assertEquals(RemoteJournal.GUARD_UNREADABLE, bind(harness))
        }
    }

    @Test fun absentStoresPermitBindingAndPersistTheIdentity() {
        val harness = harness()
        val longBinding = f.binding.copy(fleetId = "fleet/\"".repeat(800))
        assertNull(bind(harness, longBinding))
        assertTrue(file.isFile)
        harness.restart()
        assertFalse(harness.engine.lost)
        assertEquals(longBinding, harness.engine.state.binding)
        assertEquals("doc-version-rollback", bind(harness)?.code)
    }

    @Test fun disagreementsKeepTheMaximumOfEachChannelWithoutAuthorizingEitherCopy() {
        val store = fileStore()
        val harness = harness(store)
        assertTrue(harness.journal.save(initial))
        val original = requireNotNull(store.read())
        store.write(original.copy(current = original.current.copy(floors = mapOf(
            DocumentType.KEY_SET to 1L, DocumentType.POLICY to 6L,
            DocumentType.RECOVERY to 3L, DocumentType.COMMAND to 9L
        ))))
        harness.restart()

        assertEquals("journal-guard-mismatch", bind(harness)?.code)
        assertEquals(listOf(2L, 6L, 4L, 9L), DocumentType.entries.map(harness.journal::floor))
        assertFalse(harness.journal.save(initial))
    }

    @Test fun sameFloorsWithDifferentBindingOrRootStillDisagree() {
        val store = fileStore()
        val harness = harness(store)
        assertTrue(harness.journal.save(initial))
        for (changed in listOf(
            initial.copy(binding = f.binding.copy(fleetId = "another-fleet")),
            initial.copy(trust = f.trust("keyset-2", "root"))
        )) {
            store.write(JournalGuard.from(changed))
            harness.restart()
            assertEquals("journal-guard-mismatch", bind(harness)?.code)
        }
    }

    @Test fun sealedTrustPinsDelegatedKeysSuccessorAndServerUrl() {
        val harness = harness()
        assertTrue(harness.journal.save(initial))
        val journal = persistedJournal(harness)
        val trust = journal.obj("trust")
        for (change in listOf(
            "policies" to listOf(f.keys.obj("policy").text("spki")),
            "server" to f.keys.obj("server").text("spki"),
            "successor" to f.keys.obj("root").text("spki"),
            "serverUrl" to "https://other.example/"
        )) {
            replaceJournal(harness, journal + ("trust" to (trust + change)))
            assertEquals(change.first, RemoteJournal.GUARD_MISMATCH, harness.engine.reconcile().failure)
        }
    }

    @Test fun anAddedNetworkOverrideFailsClosedBeforeProjection() {
        val harness = harness()
        assertTrue(harness.journal.save(initial))
        val changed = persistedJournal(harness) + ("overrides" to listOf(RemoteOverride.NETWORK_OFF.code))
        assertTrue(harness.memory.preferences().edit()
            .putString("state", WireJson.canonical(changed).toString(Charsets.UTF_8)).commit())

        assertEquals(RemoteJournal.GUARD_MISMATCH, harness.journal.checkStores())
        harness.restart()
        assertEquals(RemoteJournal.GUARD_MISMATCH, harness.engine.ensureProjected().failure)
    }

    @Test fun removingAnUnverifiedReleaseFailsClosedOnRestart() {
        val harness = harness()
        assertTrue(harness.journal.save(initial.copy(releases = setOf("example.test.released"))))
        replaceJournal(harness, persistedJournal(harness) + ("releases" to emptyList<String>()))

        assertEquals(RemoteJournal.GUARD_MISMATCH, harness.engine.reconcile().failure)
    }

    @Test fun recoveryStateCannotChangeAtTheSameFloors() {
        val harness = harness()
        val recovery = RecoveryVerifier(RemoteCrypto.encode(ByteArray(16)), RemoteCrypto.encode(ByteArray(32)))
        assertTrue(harness.journal.save(initial.copy(recovery = recovery, recoveryUses = 1)))
        val journal = persistedJournal(harness)
        for (change in listOf("recovery" to null, "uses" to 0L,
            "lockout" to (journal.obj("lockout") + ("failures" to 1L)))) {
            replaceJournal(harness, journal + change)
            assertEquals(change.first, RemoteJournal.GUARD_MISMATCH, harness.engine.failure)
        }
    }

    @Test fun commandHistoryAndReportGenerationCanChangeWithoutRewritingTheGuard() {
        val store = fileStore()
        val harness = harness(store)
        val command = CommandEntry(initial.commandFloor, "reapply", RemoteTime(1, 100), CommandState.DONE)
        assertTrue(harness.journal.save(initial.copy(commands = mapOf(command.sequence to command),
            verified = initial.generation())))
        val guard = store.read()
        val journal = persistedJournal(harness)
        for (change in listOf("commands" to emptyList<Any>(), "verified" to null)) {
            replaceJournal(harness, journal + change)
            assertNull(change.first, harness.journal.checkStores())
            assertEquals(guard, store.read())
        }
        assertEquals(initial.commandFloor, harness.journal.floor(DocumentType.COMMAND))
    }

    @Test fun rewrittenPolicyBytesAreRefusedEvenWithARecomputedHash() {
        val harness = harness()
        assertTrue(harness.journal.save(initial))
        val journal = persistedJournal(harness)
        val policy = journal.obj("policy")
        val newBytes = WireJson.canonical(f.doc("policy-5") + ("auditNote" to "TEST ONLY"))
        val changed = policy + ("bytes" to RemoteCrypto.encode(newBytes))
        replaceJournal(harness, journal + ("policy" to changed))
        assertEquals(RemoteJournal.JOURNAL_LOST, harness.engine.failure)

        val matchingHash = changed + ("hash" to RemoteCrypto.hex(RemoteCrypto.sha256(newBytes)))
        replaceJournal(harness, journal + ("policy" to matchingHash))
        assertEquals(RemoteJournal.GUARD_MISMATCH, harness.engine.reconcile().failure)
    }

    @Test fun anInvalidFloorDoesNotEraseOtherReadableFloors() {
        val store = fileStore()
        val harness = harness(store)
        assertTrue(harness.journal.save(initial.copy(policy = f.policy("policy-6"))))
        store.write(JournalGuard.from(initial))
        val encoded = requireNotNull(harness.memory.preferences().getString("state", null))
        val journal = WireJson.parse(encoded.toByteArray(Charsets.UTF_8)).asObject()
        harness.damageJournal(WireJson.canonical(journal + ("recoveryVersion" to -1L)).toString(Charsets.UTF_8))

        assertEquals("journal-lost", bind(harness)?.code)
        assertEquals(6L, harness.journal.floor(DocumentType.POLICY))
        assertEquals(4L, harness.journal.floor(DocumentType.RECOVERY))
    }

    @Test fun committedJournalMarkerWithEmptyStoresRefusesBinding() {
        val harness = harness()
        assertTrue(harness.marker.preferences().edit().putBoolean("journal_created", true).commit())
        harness.restart()
        assertEquals("journal-lost", bind(harness)?.code)
        assertFalse(file.exists())
    }

    @Test fun olderSignedPolicyIsRejectedAfterRestartAndAfterLosingTheJournal() {
        val harness = harness()
        assertTrue(harness.journal.save(initial))
        assertNull(harness.receive("policy-6").decisions.single().failure)
        harness.restart()
        assertEquals("doc-version-rollback", harness.receive("policy-5").decisions.single().failure?.code)
        assertFalse(harness.journal.save(initial))
        harness.damageJournal(null)
        harness.restart()
        assertEquals(6L, harness.journal.floor(DocumentType.POLICY))
        assertEquals("journal-lost", harness.receive("policy-5").failure?.code)
    }

    @Test fun failedGuardWriteStopsTheLiveBatchWithoutAdvancingTheJournal() {
        val fileStore = fileStore()
        var fail = false
        val harness = harness(object : RemoteJournalGuardStore by fileStore {
            override fun write(guard: JournalGuard, createKey: Boolean) {
                if (fail) throw IOException("Simulated guard write failure")
                fileStore.write(guard, createKey)
            }
        })
        assertTrue(harness.journal.save(initial.copy(commandFloor = 0)))
        fail = true
        assertEquals(listOf("journal-guard-write-failed", "journal-guard-write-failed"),
            harness.receive("policy-6", "lock-2").decisions.map { it.failure?.code })
        assertEquals(5L, harness.engine.state.policy?.version)
        assertEquals(5L, harness.journal.floor(DocumentType.POLICY))
        assertEquals(0L, harness.journal.floor(DocumentType.COMMAND))
        assertEquals("journal-guard-write-failed", bind(harness)?.code)
        harness.restart()
        assertNull(harness.engine.failure)
        fail = false
        assertNull(harness.receive("policy-6").decisions.single().failure)
        assertEquals(6L, harness.journal.floor(DocumentType.POLICY))
    }

    @Test fun crashBeforeFirstJournalWriteCanOnlyResumeWithTheGuardedIdentity() {
        val harness = harness()
        harness.memory.beforeCommit = Consumer { throw ProcessDeath() }
        assertThrows(ProcessDeath::class.java) { bind(harness) }
        harness.memory.beforeCommit = Consumer { }

        harness.restart()
        assertNull(harness.engine.failure)
        assertNull(harness.engine.state.binding)
        assertEquals("journal-write-failed", bind(harness, f.binding.copy(fleetId = "another-fleet"))?.code)
        assertEquals("journal-write-failed", bind(harness, key = "successor")?.code)
        assertNull(bind(harness))
        harness.restart()
        assertEquals(f.binding, harness.engine.state.binding)
        assertNull(harness.engine.failure)
    }

    @Test fun pendingPolicySurvivesCrashAndUnrelatedSavesUntilTheExactDocumentCommits() {
        val store = fileStore()
        val harness = harness()
        assertTrue(harness.journal.save(initial.copy(commandFloor = 0)))
        harness.memory.beforeCommit = Consumer { throw ProcessDeath() }
        assertThrows(ProcessDeath::class.java) { harness.receive("policy-6") }
        harness.memory.beforeCommit = Consumer { }

        harness.restart()
        assertNull(harness.engine.failure)
        assertEquals(5L, harness.engine.state.policy?.version)
        assertEquals(6L, harness.journal.floor(DocumentType.POLICY))
        assertTrue(harness.engine.reconcile().verified)
        assertEquals("doc-version-rollback", harness.receive("policy-5").decisions.single().failure?.code)
        assertNull(harness.receive("lock-2").decisions.single().failure)
        harness.restart()
        assertEquals(6L, store.read()?.pending?.get(DocumentType.POLICY)?.version)
        assertNull(harness.receive("policy-6").decisions.single().failure)
        assertEquals(6L, harness.journal.floor(DocumentType.POLICY))
        assertEquals(2L, harness.journal.floor(DocumentType.COMMAND))
        assertTrue(requireNotNull(store.read()).pending.isEmpty())
        assertEquals("doc-version-rollback", harness.receive("policy-6").decisions.single().failure?.code)
    }

    @Test fun pendingVersionRejectsDifferentSignedContentAndMatchesCanonicalPolicy() {
        val pair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair()
        val spki = RemoteCrypto.encode(pair.public.encoded)
        fun sign(payload: ByteArray): RemoteDocument {
            val signature = Signature.getInstance("SHA256withECDSA").run {
                initSign(pair.private)
                update(payload)
                sign()
            }
            val envelope = f.envelope("policy-5") + mapOf("keyId" to RemoteCrypto.keyId(spki),
                "payload" to RemoteCrypto.encode(payload), "signature" to RemoteCrypto.encode(signature))
            return RemoteDocument(DocumentType.POLICY, WireJson.canonical(envelope))
        }
        val harness = harness()
        val trust = requireNotNull(initial.trust).copy(policyKeys = listOf(spki))
        assertTrue(harness.journal.save(initial.copy(trust = trust, policy = f.policy("policy-1"))))
        fun receive(document: RemoteDocument): String? {
            val sync = RemoteSync(f.verifier, f.binding)
            val now = RemoteTime(1, 100)
            val exchange = requireNotNull(sync.begin(f.nonce, now))
            return harness.engine.receive(sync, exchange, f.nonce, now, listOf(document))
                .decisions.single().failure?.code
        }

        harness.memory.failCommit = true
        assertEquals("journal-write-failed", receive(sign(f.payload("policy-5"))))
        harness.restart()
        val different = WireJson.canonical(f.doc("policy-5") + ("auditNote" to "TEST ONLY"))
        assertEquals("doc-version-rollback", receive(sign(different)))
        assertEquals(1L, harness.engine.state.policy?.version)
        assertNull(receive(sign(f.payload("policy-5-spaced"))))
        assertEquals(f.policy("policy-5-spaced"), harness.engine.state.policy)
    }

    @Test fun interruptedRotationAuthenticatesTheOldSnapshotAndPinsTheNewSigner() {
        val store = fileStore()
        val harness = harness(store)
        val previous = initial.copy(trust = f.trust(), policy = f.policy("policy-1"))
        assertTrue(harness.journal.save(previous))
        val journal = persistedJournal(harness)
        harness.memory.beforeCommit = Consumer { throw ProcessDeath() }
        assertThrows(ProcessDeath::class.java) { harness.receive("keyset-2") }
        harness.memory.beforeCommit = Consumer { }

        assertEquals(RemoteCrypto.keyId(requireNotNull(previous.trust).root), store.read()?.previousRootFingerprint)
        replaceJournal(harness, journal + ("trust" to (journal.obj("trust") +
            ("server" to f.keys.obj("server-next").text("spki")))))
        assertEquals(RemoteJournal.GUARD_MISMATCH, harness.engine.failure)

        replaceJournal(harness, journal)
        assertNull(harness.engine.failure)
        assertEquals(previous.trust, harness.engine.state.trust)
        assertEquals("doc-version-rollback", harness.receive("lock-5-old-key").decisions.single().failure?.code)
        assertEquals("doc-version-rollback", harness.receive("keyset-2-current-root").decisions.single().failure?.code)
        assertNull(harness.receive("keyset-2").decisions.single().failure)
        assertEquals(f.trust("keyset-2", "successor"), harness.engine.state.trust)
        assertNull(store.read()?.previousRootFingerprint)
        replaceJournal(harness, journal)
        assertEquals(RemoteJournal.GUARD_MISMATCH, harness.engine.failure)
    }

    @Test fun restartFinalizesRotationAfterJournalCommitBeforeDroppingTheOldSnapshot() {
        val store = fileStore()
        val harness = harness(store)
        assertTrue(harness.journal.save(initial.copy(trust = f.trust())))
        val previous = persistedJournal(harness)
        harness.memory.afterCommit = Consumer { throw ProcessDeath() }
        assertThrows(ProcessDeath::class.java) { harness.receive("keyset-2") }
        harness.memory.afterCommit = Consumer { }
        assertTrue(store.read()?.previousRootFingerprint != null)

        harness.restart()
        assertNull(harness.engine.failure)
        assertEquals(f.trust("keyset-2", "successor"), harness.engine.state.trust)
        assertNull(store.read()?.previousRootFingerprint)
        assertTrue(requireNotNull(store.read()).pending.isEmpty())
        replaceJournal(harness, previous)
        assertEquals(RemoteJournal.GUARD_MISMATCH, harness.engine.failure)
    }

    @Test fun releaseLedgerWriteRecoversOnEitherSideOfTheJournalCommit() {
        val store = fileStore()
        val harness = harness(store)
        val next = initial.copy(releases = setOf("example.test.released"))
        assertTrue(harness.journal.save(initial))
        val previous = persistedJournal(harness)

        harness.memory.beforeCommit = Consumer { throw ProcessDeath() }
        assertThrows(ProcessDeath::class.java) { harness.journal.save(next) }
        harness.memory.beforeCommit = Consumer { }
        assertEquals(JournalSeal.from(initial), store.read()?.previous)
        assertEquals(JournalSeal.from(next), store.read()?.current)
        harness.restart()
        assertNull(harness.engine.failure)
        assertTrue(harness.engine.state.releases.isEmpty())

        harness.memory.afterCommit = Consumer { throw ProcessDeath() }
        assertThrows(ProcessDeath::class.java) { harness.journal.save(next) }
        harness.memory.afterCommit = Consumer { }
        harness.restart()
        assertNull(harness.engine.failure)
        assertEquals(next.releases, harness.engine.state.releases)
        assertEquals(JournalGuard.from(next), store.read())
        replaceJournal(harness, previous)
        assertEquals(RemoteJournal.GUARD_MISMATCH, harness.engine.failure)
    }

    @Test fun ambiguousCommitBlocksTheLiveJournalAndIsCoveredOnRestart() {
        val store = fileStore()
        val harness = harness(store)
        val next = initial.copy(overrides = setOf(RemoteOverride.NETWORK_OFF))
        assertTrue(harness.journal.save(initial))

        harness.memory.afterCommit = Consumer {
            // The new value reached disk, but the editor reports failure and cannot roll it back.
            harness.memory.throwBeforeCommit = true
            throw IllegalStateException("Simulated ambiguous commit")
        }
        assertFalse(harness.journal.save(next))
        harness.memory.afterCommit = Consumer { }
        harness.memory.throwBeforeCommit = false

        assertTrue(harness.journal.state.overrides.isEmpty())
        assertEquals(RemoteJournal.GUARD_MISMATCH, harness.journal.checkStores())
        assertEquals(RemoteJournal.GUARD_MISMATCH, harness.engine.reconcile().failure)
        assertEquals(JournalSeal.from(initial), store.read()?.previous)
        harness.restart()
        assertNull(harness.journal.checkStores())
        assertEquals(next.overrides, harness.journal.state.overrides)
        assertEquals(JournalGuard.from(next), store.read())
    }

    @Test fun baselineWriteCanRetryWithVersionZeroAndPinsItsBytes() {
        val harness = harness()
        assertNull(bind(harness))
        val baseline = f.hashes.obj("baseline").obj("body")
        harness.memory.failCommit = true
        assertEquals("journal-write-failed", harness.engine.commitBaseline(baseline)?.code)

        harness.restart()
        assertNull(harness.engine.failure)
        assertNull(harness.engine.state.policy)
        assertNull(harness.engine.commitBaseline(baseline))
        harness.restart()
        assertEquals(f.policy("baseline"), harness.engine.state.policy)
    }

    @Test fun bindingAfterTheBaselineStaysPinnedThroughFailureAndUnrelatedSaves() {
        val store = fileStore()
        val harness = harness(store)
        val baseline = f.hashes.obj("baseline").obj("body")
        assertNull(harness.engine.commitBaseline(baseline))
        harness.memory.failCommit = true
        assertEquals("journal-write-failed", bind(harness)?.code)

        harness.restart()
        assertNull(harness.engine.failure)
        assertNull(harness.engine.state.binding)
        val reservation = requireNotNull(store.read())
        assertTrue(harness.engine.reconcile().verified)
        assertFalse(harness.journal.save(harness.engine.state.copy(releases = setOf("example.test.released"))))
        assertEquals(reservation, store.read())
        assertEquals("journal-write-failed", bind(harness, f.binding.copy(fleetId = "another-fleet"))?.code)
        assertEquals("journal-write-failed", bind(harness, key = "successor")?.code)
        assertNull(bind(harness))
        harness.restart()
        assertEquals(f.binding, harness.engine.state.binding)
        assertEquals(f.policy("baseline"), harness.engine.state.policy)
        assertNull(harness.engine.failure)
    }

    @Test fun guardCleanupFailureBlocksUseOfTheCommittedRotationUntilRecovery() {
        val fileStore = fileStore()
        var failCleanup = false
        val store = object : RemoteJournalGuardStore by fileStore {
            override fun write(guard: JournalGuard, createKey: Boolean) {
                if (failCleanup && guard.previous == null) throw IOException("Simulated cleanup failure")
                fileStore.write(guard, createKey)
            }
        }
        val harness = harness(store)
        assertTrue(harness.journal.save(initial.copy(trust = f.trust())))
        failCleanup = true
        assertEquals(RemoteJournal.GUARD_WRITE_FAILED, harness.receive("keyset-2").decisions.single().failure)
        assertEquals(RemoteJournal.GUARD_WRITE_FAILED, harness.engine.reconcile().failure)
        harness.restart()
        assertEquals(RemoteJournal.GUARD_WRITE_FAILED, harness.engine.failure)

        failCleanup = false
        harness.restart()
        assertNull(harness.engine.failure)
        assertEquals(f.trust("keyset-2", "successor"), harness.engine.state.trust)
        assertNull(store.read()?.previousRootFingerprint)
    }

    @Test fun aJournalAheadOfTheGuardFailsClosed() {
        val store = fileStore()
        val harness = harness(store)
        assertTrue(harness.journal.save(initial))
        assertNull(harness.receive("policy-6").decisions.single().failure)
        store.write(JournalGuard.from(initial))

        harness.restart()
        assertEquals(RemoteJournal.GUARD_MISMATCH, bind(harness))
        assertEquals(RemoteJournal.GUARD_MISMATCH, harness.engine.reconcile().failure)
        assertEquals(6L, harness.journal.floor(DocumentType.POLICY))
    }

    @Test fun missingGuardCannotBeRecreatedFromTheJournalAlone() {
        val harness = harness()
        assertTrue(harness.journal.save(initial))
        assertTrue(file.delete())
        harness.restart()
        assertEquals("journal-guard-missing", bind(harness)?.code)
        assertEquals(5L, harness.journal.floor(DocumentType.POLICY))
        assertFalse(file.exists())
    }

    private class ProcessDeath : Error()
}
