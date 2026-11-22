package com.example.lockdowndpc.remote

import com.example.lockdowndpc.testing.MemoryPreferences
import java.io.File
import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
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

    private fun harness(store: RemoteJournalGuardStore = RemoteJournalGuardFile(file)) = RemoteFixtures.Harness(
        MemoryPreferences(emptyMap<String, Any>()).apply { failCommit = false }, f.noProjection, store
    )

    private fun bind(harness: RemoteFixtures.Harness, binding: RemoteBinding = f.binding): RemoteFailure? {
        val root = f.keys.obj("root")
        return harness.engine.bindFleet(f.verifier, binding, root.text("keyId"), root.text("spki"), 35)
    }

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

    @Test fun checksumFailureBlocksRemoteOperationsAndKeepsJournalFloors() {
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
        val store = RemoteJournalGuardFile(file)
        val harness = harness(store)
        assertTrue(harness.journal.save(initial))
        val original = requireNotNull(store.read())
        store.write(original.copy(floors = mapOf(
            DocumentType.KEY_SET to 1L, DocumentType.POLICY to 6L,
            DocumentType.RECOVERY to 3L, DocumentType.COMMAND to 9L
        )))
        harness.restart()

        assertEquals("journal-guard-mismatch", bind(harness)?.code)
        assertEquals(listOf(2L, 6L, 4L, 9L), DocumentType.entries.map(harness.journal::floor))
        assertFalse(harness.journal.save(initial))
    }

    @Test fun sameFloorsWithDifferentBindingOrRootStillDisagree() {
        val store = RemoteJournalGuardFile(file)
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

    @Test fun anInvalidFloorDoesNotEraseOtherReadableFloors() {
        val store = RemoteJournalGuardFile(file)
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

    @Test fun failedSecondWriteStopsTheLiveBatchAndRetainsTheHigherJournalFloorAfterRestart() {
        val fileStore = RemoteJournalGuardFile(file)
        var fail = false
        val harness = harness(object : RemoteJournalGuardStore by fileStore {
            override fun write(guard: JournalGuard) {
                if (fail) throw IOException("Simulated guard write failure")
                fileStore.write(guard)
            }
        })
        assertTrue(harness.journal.save(initial.copy(commandFloor = 0)))
        fail = true
        assertEquals(listOf("journal-guard-write-failed", "journal-guard-write-failed"),
            harness.receive("policy-6", "lock-2").decisions.map { it.failure?.code })
        assertEquals(5L, harness.engine.state.policy?.version)
        assertEquals(6L, harness.journal.floor(DocumentType.POLICY))
        assertEquals(0L, harness.journal.floor(DocumentType.COMMAND))
        assertEquals("journal-guard-write-failed", bind(harness)?.code)
        harness.restart()
        assertEquals("journal-guard-mismatch", bind(harness)?.code)
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
}
