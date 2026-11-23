package com.example.lockdowndpc.remote

import com.example.lockdowndpc.BuildConfig
import com.example.lockdowndpc.policy.RemoteProvisioning
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class RemoteDeviceClientTest {
    private val fixtures = RemoteFixtures
    private val wire = RemoteClientWire

    @Test fun onlyRemoteTestOpensTheBuildGate() {
        assertEquals(BuildConfig.BUILD_TYPE == "remoteTest", BuildConfig.REMOTE_ENROLMENT_ENABLED)
        if (BuildConfig.BUILD_TYPE == "remoteTest") {
            assertFalse(BuildConfig.DEBUG)
            assertTrue(BuildConfig.APPLICATION_ID.endsWith(".remotetest"))
            assertTrue(BuildConfig.UPDATE_MANIFEST_URL.isEmpty())
            assertTrue(BuildConfig.UPDATE_PUBLIC_KEY.isEmpty())
        }
    }

    @Test fun matchesReferenceServerTranscriptsAndDerSignatures() {
        val vector = fixtures.vectors("client-wire")
        val signer = RemoteCrypto.publicKey(vector.text("signerSpki"))
        val enrol = vector.obj("enrolment")
        val transcript = wire.enrolTranscript(enrol.text("challenge"), enrol.text("ticket"),
            enrol.items("chain").map { it as String }, enrol.obj("facts"))
        assertArrayEquals(enrol.text("transcriptUtf8").toByteArray(), transcript)
        assertTrue(RemoteCrypto.verifies(signer, transcript, RemoteCrypto.decode(enrol.text("signature"))))

        val sync = vector.obj("sync")
        val body = sync.obj("body")
        val journal = JournalState(
            binding = RemoteBinding("fixture", body.text("deviceId")),
            trust = fixtures.trust("keyset-2", "successor"),
            policy = CommittedPolicy("", body.text("committedSha256"), 0),
            overrides = setOf(RemoteOverride.NETWORK_OFF),
            recoveryVersion = 1,
            commandFloor = 3,
        )
        val exchange = RemoteSync.Exchange(body.text("nonce"), RemoteTime(1, 50))
        val request = wire.syncBody(exchange, journal, body.obj("report"))
        assertArrayEquals(sync.text("bodyUtf8").toByteArray(), request)
        val signed = wire.syncTranscript(sync.number("timestamp"), request)
        val signature = RemoteCrypto.decode(sync.text("signature"))
        assertArrayEquals(sync.text("transcriptUtf8").toByteArray(), signed)
        assertTrue(RemoteCrypto.verifies(signer, signed, signature))
        assertFalse(RemoteCrypto.verifies(signer, wire.syncTranscript(sync.number("timestamp") + 1, request), signature))
    }

    @Test fun bootstrapCommitsOnlyThePinnedKeySetAfterTheVerifiedBaseline() {
        val harness = fixtures.harness(JournalState())
        val engine = harness.engine
        val root = fixtures.keys.obj("root")
        val keyset = fixtures.document("keyset-1").envelope
        fun install(pin: String) = engine.installEnrolmentKeySet(fixtures.verifier, fixtures.binding,
            pin, root.text("spki"), keyset, 35)

        assertNull(engine.commitBaseline(RemoteProvisioning.baseline()))
        assertEquals(fixtures.hashes.obj("baseline").text("baselineSha256"), engine.state.policy?.hash)
        assertEquals("remote-policy-unavailable", install(root.text("keyId"))?.code)
        assertTrue(engine.ensureProjected().verified)
        assertEquals("doc-key-unknown", install(fixtures.nonce)?.code)
        assertNull(engine.state.binding)
        assertNull(install(root.text("keyId")))
        assertEquals(1L, engine.state.trust?.version)
        assertNull(install(root.text("keyId")))
        harness.restart()
        assertEquals(fixtures.trust().server, harness.engine.state.trust?.server)
        assertEquals(fixtures.binding, harness.engine.state.binding)
    }

    @Test fun rotationUsesTheNewServerKeyForTheNextSyncAndDispatchesTheSequenceOnce() {
        val initial = JournalState(trust = fixtures.trust(), binding = fixtures.binding,
            policy = fixtures.policy("baseline"))
        val harness = fixtures.harness(initial)
        val engine = harness.engine
        val sync = RemoteSync(fixtures.verifier, fixtures.binding)
        val now = RemoteTime(1, 100)
        val commandNonce = fixtures.doc("lock-2").text("nonce")
        val otherNonce = fixtures.sync.obj("nonces").text("b")
        var calls = 0
        val platform = object : RemoteEngine.CommandPlatform {
            override fun isDeviceSecure() = false
            override fun lockNow() { calls++ }
        }

        fun apply(exchange: RemoteSync.Exchange, vararg names: String): RemoteSync.Response {
            val reply = wire.syncReply(WireJson.canonical(mapOf("nonce" to exchange.nonce,
                "documents" to names.map { mapOf("type" to fixtures.doc(it).text("type"), "envelope" to fixtures.envelope(it)) })))
            return engine.receive(sync, exchange, reply.nonce, now, reply.documents)
        }

        val rotation = requireNotNull(sync.begin(otherNonce, now))
        assertNull(apply(rotation, "keyset-2").decisions.single().failure)
        assertEquals(2L, engine.state.trust?.version)
        assertTrue(engine.state.commands.isEmpty())

        val command = requireNotNull(sync.begin(commandNonce, now))
        assertNull(apply(command, "lock-2").decisions.single().failure)
        assertEquals("lock-screen-off-only", engine.dispatch(2, { now }, platform)?.code)
        engine.dispatch(2, { now }, platform)
        assertEquals(1, calls)
        assertEquals(false, engine.state.commands[2L]?.secureLock)
        assertEquals("sync-response-stale", apply(command, "lock-2").failure?.code)
        val differentExchange = requireNotNull(sync.begin(otherNonce, now))
        assertEquals("doc-version-rollback", apply(differentExchange, "lock-2").decisions.single().failure?.code)
        harness.restart()
        harness.engine.dispatch(2, { now }, platform)
        assertEquals(1, calls)
    }

    @Test fun failedExchangeCannotBeReusedAndDoesNotDelayTheNextNonce() {
        val sync = RemoteSync(fixtures.verifier, fixtures.binding)
        val now = RemoteTime(1, 100)
        val failed = requireNotNull(sync.begin(fixtures.nonce, now))
        sync.discard(failed)
        val fresh = requireNotNull(sync.begin(fixtures.sync.obj("nonces").text("b"), now))
        // A late cleanup from the old exchange cannot discard the new one.
        sync.discard(failed)
        val harness = fixtures.harness(JournalState(trust = fixtures.trust(), binding = fixtures.binding))
        assertEquals("sync-response-stale", harness.engine.receive(sync, failed, failed.nonce, now, emptyList()).failure?.code)
        assertNull(harness.engine.receive(sync, fresh, fresh.nonce, now, emptyList()).failure)
    }

    @Test fun requiresCleanHttpsServerUrl() {
        assertEquals("https://example.invalid/bench", wire.serverUrl("https://example.invalid/bench/"))
        for (url in listOf("http://example.invalid", "https://a@example.invalid", "https://example.invalid/?ticket=x",
            "https://example.invalid/#fragment", "https://example.invalid/%2e%2e", "https://example.invalid:99999")) {
            assertThrows(IllegalArgumentException::class.java) { wire.serverUrl(url) }
        }
    }
}
