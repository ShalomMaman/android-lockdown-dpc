package com.example.lockdowndpc.remote

import com.example.lockdowndpc.testing.MemoryPreferences
import java.io.File
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

internal object RemoteFixtures {
    private val contract = generateSequence(File(requireNotNull(System.getProperty("user.dir"))).absoluteFile) { it.parentFile }
        .map { File(it, "docs/remote-contract") }.first { it.isDirectory }

    fun vectors(name: String) = read(File(contract, "vectors/$name.json"))
    fun vectorFiles(): Set<String> = requireNotNull(File(contract, "vectors").list()).toSet()
    val mainSources: File = File(contract.parentFile.parentFile, "app/src/main/java")
    val readme: String get() = File(contract, "README.md").readText()
    val contractSchema: File = File(contract, "v1.schema.json")
    val packagedSchema: File = File(mainSources.parentFile, "assets/v1.schema.json")
    private fun read(file: File) = convertFixture(JSONObject(file.readText())).asObject()

    private fun convertFixture(value: Any?): Any? = when {
        value === JSONObject.NULL -> null
        // keys() exists in every org.json implementation the tests can load.
        value is JSONObject -> value.keys().asSequence().toList().associateWith { convertFixture(value.get(it)) }
        value is JSONArray -> (0 until value.length()).map { convertFixture(value.get(it)) }
        value is Int -> value.toLong()
        else -> value
    }
    val schema = RemoteSchema(contractSchema.readBytes())
    val signed = vectors("signed-documents")
    val keys = signed.obj("keys")
    val signedDocs = signed.obj("documents")
    val sync = vectors("sync")
    val hashes = vectors("hashes")
    val verifier = RemoteVerifier(schema, allowFixtureKeys = true)
    val binding = RemoteBinding(sync.text("fleetId"), keys.obj(sync.text("deviceKey")).text("keyId"))
    val nonce = sync.obj("nonces").text("a")

    fun envelope(name: String) = signedDocs.obj(name).obj("envelope")
    fun payload(name: String) = RemoteCrypto.decode(envelope(name).text("payload"))
    fun doc(name: String) = WireJson.parse(payload(name)).asObject()
    fun document(name: String, tamper: Boolean = false): RemoteDocument {
        var envelope = envelope(name)
        if (tamper) {
            val signature = RemoteCrypto.decode(envelope.text("signature"))
            val last = signature.lastIndex
            signature[last] = (signature[last].toInt() xor 1).toByte()
            envelope = envelope + ("signature" to RemoteCrypto.encode(signature))
        }
        return RemoteDocument(DocumentType.entries.single { it.wire == doc(name)["type"] }, WireJson.canonical(envelope))
    }

    fun trust(keyset: String = "keyset-1", root: String = "root"): RemoteTrust {
        val doc = doc(keyset)
        return RemoteTrust(keys.obj(root).text("spki"), doc["successorRoot"] as String?,
            doc.number("keySetVersion"), doc.items("fleetPolicyKeys").map { it as String },
            doc.text("serverKey"), doc.text("serverUrl"))
    }

    fun mac(bytes: ByteArray, create: Boolean = false): ByteArray =
        Mac.getInstance("HmacSHA256").run {
            // Public fixture MAC key. The runtime uses a device-specific Keystore key.
            init(SecretKeySpec(ByteArray(32), "HmacSHA256"))
            doFinal(bytes)
        }

    val noProjection = object : RemoteProjection {
        override fun project(policy: JsonObject, target: Generation) = true
        override fun apply(target: Generation, stillCurrent: () -> Boolean) = true
    }

    fun harness(initial: JournalState, projection: RemoteProjection = noProjection): Harness {
        val memory = MemoryPreferences(emptyMap<String, Any>()).apply { failCommit = false }
        return Harness(memory, projection).also { assertTrue(it.journal.save(initial)) }
    }

    class Harness(
        val memory: MemoryPreferences, private val projection: RemoteProjection,
        private val guardStore: RemoteJournalGuardStore = MemoryGuardStore()
    ) {
        /** The separate file that records that a journal was ever stored. */
        val marker = MemoryPreferences(emptyMap<String, Any>()).apply { failCommit = false }
        private var journalFile = memory
        private var damagedFilePresent = false
        var journal = openJournal()
            private set
        var engine = engineFor(journal)
            private set

        fun restart() {
            memory.failCommit = false
            journalFile.failCommit = false
            journalFile.restart()
            marker.restart()
            reopen()
        }

        /** The journal file comes back empty or unreadable, as Android does with a damaged preferences file. */
        fun damageJournal(content: String?) {
            damagedFilePresent = true
            journalFile = MemoryPreferences(if (content == null) emptyMap() else mapOf("state" to content))
                .apply { failCommit = false }
            reopen()
        }

        private fun reopen() {
            journal = openJournal()
            engine = engineFor(journal)
        }

        private fun openJournal() = RemoteJournal(journalFile.preferences(), marker.preferences(), guardStore,
            journalFileAbsent = { !damagedFilePresent })

        fun receive(vararg names: String): RemoteSync.Response {
            val sync = RemoteSync(verifier, binding)
            val time = RemoteTime(1, 100)
            val exchange = requireNotNull(sync.begin(nonce, time))
            return engine.receive(sync, exchange, nonce, time, names.map { document(it) })
        }

        private fun engineFor(journal: RemoteJournal) = RemoteEngine(journal, schema, projection, ::mac)
    }

    private class MemoryGuardStore : RemoteJournalGuardStore {
        private var guard: JournalGuard? = null
        override fun read() = guard
        override fun write(guard: JournalGuard, createKey: Boolean) { this.guard = guard }
    }

    fun policy(name: String): CommittedPolicy = if (name == "baseline") {
        CommittedPolicy.fromBytes(WireJson.canonical(hashes.obj("baseline").obj("body")), 0)
    } else CommittedPolicy.fromBytes(payload(name), doc(name).number("fleetPolicyVersion"))

    fun overrides(codes: List<*>) = codes.map { RemoteOverride.fromCode(it as String) }.toSet()

    fun generation(name: String): Generation {
        val record = hashes.obj("generations").obj(name).obj("value")
        return Generation(record["fleetPolicyVersion"] as? Long ?: 0L, record.text("committedSha256"),
            overrides(record.items("overrides")))
    }

    fun result(outcome: String, failure: String? = null, vararg facts: Pair<String, Any?>): JsonObject =
        mapOf("outcome" to outcome, "failureCode" to failure, *facts)

    fun check(case: JsonObject, actual: JsonObject) =
        assertEquals(case["id"] as? String ?: case["source"] as? String, case.obj("expected"), actual)
}

class RemoteContractTest {
    private val f = RemoteFixtures

    @Test fun allSignedDocumentVectorsAndReleaseKeyRefusals() {
        val release = RemoteVerifier(f.schema)
        assertEquals(f.keys.values.map { it.asObject().text("keyId") }.toSet(), RemoteVerifier.TEST_KEY_IDS)
        for (raw in f.keys.values) {
            val key = raw.asObject()
            assertEquals(key.text("keyId"), RemoteCrypto.keyId(key.text("spki")))
            assertFalse(release.permitsKeyId(key.text("keyId")))
        }
        for ((name, raw) in f.signedDocs) {
            val case = raw.asObject()
            val envelope = f.schema.envelope(WireJson.canonical(f.envelope(name)))
            val payload = f.payload(name)
            val key = f.keys.obj(case.text("signer"))
            assertEquals(name, key.text("keyId"), envelope.text("keyId"))
            assertTrue(name, RemoteCrypto.verifies(RemoteCrypto.publicKey(key.text("spki")), payload,
                RemoteCrypto.decode(envelope.text("signature"))))
            assertEquals(name, case["canonicalPayload"], payload.contentEquals(WireJson.canonical(f.doc(name))))
            f.check(case, validate { f.schema.payload(f.doc(name)) })
        }
        val refused = failure { release.authenticate(f.document("keyset-1"), f.trust(), f.binding) }
        assertEquals("doc-key-unknown", refused?.code)
    }

    /** A vector file or section added to the contract fails here until a Kotlin test replays it. */
    @Test fun everyVectorFileAndSectionIsReplayedByTheKotlinTests() {
        val replayed = mapOf(
            "signed-documents" to setOf("notice", "keys", "documents"),
            "document-shapes" to setOf("payloads", "envelopes", "rawPayloads"),
            "hashes" to setOf("example", "canonicalJson", "baseline", "generations", "verifiedGeneration",
                "invalidOverrides", "exactBytes", "canonicalStrings"),
            "sync" to setOf("fleetId", "deviceKey", "nonces", "nonceCases", "batches"),
            "journal" to setOf("cases", "readBackCases"),
            "dispatch" to setOf("initial", "cases"),
            "re-anchor" to setOf("signer", "envelope", "cases"),
            "recovery" to setOf("testCode", "boot", "elapsedMs", "callsMadeOnPolicyThread", "initial", "cases")
        )
        assertEquals(replayed.keys.map { "$it.json" }.toSet(), f.vectorFiles())
        for ((name, sections) in replayed) assertEquals(name, sections, f.vectors(name).keys)
    }

    /** The APK carries its own copy of the schema; it must be the reviewed contract, byte for byte. */
    @Test fun packagedSchemaIsTheReviewedContract() {
        assertTrue(f.contractSchema.readBytes().contentEquals(f.packagedSchema.readBytes()))
    }

    /** Nothing in the application can open the build gate: the test switch is declared, read once and never written. */
    @Test fun productionCodeNeverOpensTheEnrolmentGate() {
        val mentions = f.mainSources.walkTopDown().filter { it.isFile && it.readText().contains("openedByTest") }
            .map { it.name }.toList()
        assertEquals(listOf("RemoteEnrolmentGate.java"), mentions)
        val gate = File(f.mainSources, "com/example/lockdowndpc/policy/RemoteEnrolmentGate.java").readText()
        assertEquals(listOf("private static boolean openedByTest;",
            "return BuildConfig.REMOTE_ENROLMENT_ENABLED || openedByTest;"),
            gate.lines().map { it.trim() }.filter { "openedByTest" in it })
        assertFalse(gate.contains("setAccessible") || gate.contains("getDeclaredField"))
    }

    /** Only tests may trust the published fixture keys: no production caller can switch the refusal off. */
    @Test fun productionCodeNeverAllowsFixtureKeys() {
        val mentions = f.mainSources.walkTopDown().filter { it.isFile && it.readText().contains("allowFixtureKeys") }
            .map { it.name }.toList()
        assertEquals(listOf("RemoteVerifier.kt"), mentions)
        val verifier = File(f.mainSources, "com/example/lockdowndpc/remote/RemoteVerifier.kt").readText()
        assertTrue(verifier.contains("private val allowFixtureKeys: Boolean = false"))
        assertEquals(13, RemoteVerifier.TEST_KEY_IDS.size)
        val readme = f.readme
        for (id in RemoteVerifier.TEST_KEY_IDS) assertTrue(id, readme.contains("`$id`"))
    }

    @Test fun malformedAuthenticatedInputIsRefusedAsOneDocument() {
        val failure = failure {
            f.verifier.authenticate(RemoteDocument(DocumentType.KEY_SET, "{".toByteArray()), f.trust(), f.binding)
        }
        assertEquals("doc-field-invalid", failure?.code)
    }

    @Test fun releaseRejectsEveryFixtureKeyInEveryIncomingKeyRole() {
        val generator = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
        val root = generator.generateKeyPair()
        val rootSpki = RemoteCrypto.encode(root.public.encoded)
        val rootId = RemoteCrypto.keyId(rootSpki)
        val server = RemoteCrypto.encode(generator.generateKeyPair().public.encoded)
        val policy = RemoteCrypto.encode(generator.generateKeyPair().public.encoded)
        val release = RemoteVerifier(f.schema)
        val body = mapOf("schemaVersion" to 1L, "type" to "keyset", "fleetId" to f.binding.fleetId,
            "keySetVersion" to 1L, "serverKey" to server, "serverUrl" to "https://sync.example.org",
            "fleetPolicyKeys" to listOf(policy))
        for (raw in f.keys.values) {
            val key = raw.asObject()
            val spki = key.text("spki")
            assertEquals("doc-key-unknown", failure {
                release.bootstrap(key.text("keyId"), spki, RemoteBinding(f.binding.fleetId, rootId))
            }?.code)
            for ((field, value) in mapOf("successorRoot" to spki, "serverKey" to spki, "fleetPolicyKeys" to listOf(spki))) {
                val payload = WireJson.canonical(body + (field to value))
                val signature = Signature.getInstance("SHA256withECDSA").run {
                    initSign(root.private)
                    update(payload)
                    sign()
                }
                val envelope = WireJson.canonical(mapOf("format" to "dg-signed/1", "keyId" to rootId,
                    "payload" to RemoteCrypto.encode(payload), "signature" to RemoteCrypto.encode(signature)))
                val denied = failure {
                    release.authenticate(RemoteDocument(DocumentType.KEY_SET, envelope), RemoteTrust(rootSpki), f.binding)
                }
                val path = if (field == "fleetPolicyKeys") "/fleetPolicyKeys/0" else "/$field"
                assertEquals(key.text("keyId"), RemoteFailure("doc-field-invalid", path), denied)
            }
        }
    }

    @Test fun everyClosedShapeAndMalformedWireVector() {
        val cases = f.vectors("document-shapes")
        for (raw in cases.items("payloads")) {
            val case = raw.asObject()
            val path = case.text("path").removePrefix("/").split('/').map { it.replace("~1", "/").replace("~0", "~") }
            val updated = update(f.doc(case.text("document")), path, case)
            f.check(case, validate { f.schema.payload(updated) })
        }
        for (raw in cases.items("envelopes")) {
            val case = raw.asObject()
            val bytes = WireJson.canonical(f.envelope(case.text("document")) + case["set"]?.asObject().orEmpty())
            val padded = (case["wireBytes"] as? Long)?.toInt()?.let { count ->
                bytes + ByteArray(count - bytes.size) { ' '.code.toByte() }
            } ?: bytes
            f.check(case, validate { f.schema.envelope(padded) })
        }
        for (raw in cases.items("rawPayloads")) {
            val case = raw.asObject()
            val bytes = (case["bytesHex"] as? String)?.chunked(2)?.map { it.toInt(16).toByte() }?.toByteArray()
                ?: case.text("utf8").toByteArray()
            f.check(case, validate { f.schema.payload(f.schema.decode(bytes)) })
        }
    }

    @Test fun canonicalBytesAndAllGenerationHashes() {
        val data = f.hashes
        val canonical = data.obj("canonicalJson")
        assertEquals(canonical.text("canonicalUtf8"), WireJson.canonical(canonical["value"]).toString(Charsets.UTF_8))
        f.check(canonical, f.result("reproduced"))
        for (raw in data.items("canonicalStrings")) {
            val case = raw.asObject()
            f.check(case, f.result("reproduced", null,
                "canonicalUtf8" to WireJson.canonical(case["value"]).toString(Charsets.UTF_8)))
        }
        val baseline = data.obj("baseline")
        f.schema.requireValid("policy", baseline["body"])
        val baselineBytes = WireJson.canonical(baseline["body"])
        assertEquals(baseline.text("canonicalUtf8"), baselineBytes.toString(Charsets.UTF_8))
        assertEquals(baseline.text("baselineSha256"), f.policy("baseline").hash)
        f.check(baseline, f.result("reproduced"))

        val verified = data.obj("verifiedGeneration")
        for ((name, raw) in data.obj("generations") + ("verifiedGeneration" to verified)) {
            val case = raw.asObject()
            val value = case.obj("value")
            val source = case.text("source")
            val policy = if (source == "example") CommittedPolicy.fromBytes(data.text("example").toByteArray(), 0)
                else f.policy(source)
            val overrides = f.overrides((case["hashInputOverrides"] as? List<*>) ?: value.items("overrides"))
            val generation = Generation(policy.version, policy.hash, overrides)
            assertEquals(name, if (policy.version == 0L) "baseline" else policy.version, value["fleetPolicyVersion"])
            assertEquals(name, value["committedSha256"], policy.hash)
            assertEquals(name, value["overrides"], overrides.map { it.code }.sorted())
            assertEquals(name, value[if (name == "verifiedGeneration") "verifiedSha256" else "generationSha256"],
                generation.sha256)
            f.check(case, f.result("reproduced"))
        }
        assertNotEquals(f.generation(verified.text("current")).sha256, verified.obj("value").text("verifiedSha256"))
        val exact = data.obj("exactBytes")
        assertEquals(f.doc(exact.text("canonical")), f.doc(exact.text("alternative")))
        assertNotEquals(f.policy(exact.text("canonical")).hash, f.policy(exact.text("alternative")).hash)
        f.check(exact, f.result("equal-json-different-committed-hashes"))
        for (raw in data.items("invalidOverrides")) {
            val case = raw.asObject()
            f.check(case, f.result("refused", failure { f.schema.requireValid("overrides", case["overrides"]) }?.code))
        }
    }

    @Test fun allSyncBatchesAndNonceEvents() {
        for (raw in f.sync.items("batches")) {
            val case = raw.asObject()
            val initial = case.obj("initial")
            val policy = initial.number("policyVersion").takeIf { it > 0 }?.let { version ->
                val stored = f.doc("policy-1") + ("fleetPolicyVersion" to version)
                CommittedPolicy.fromBytes(WireJson.canonical(stored), version)
            }
            val state = JournalState(trust = f.trust(initial.text("keyset"), initial.text("root")),
                policy = policy, recoveryVersion = initial.number("recoveryVersion"), commandFloor = initial.number("commandFloor"))
            val harness = f.harness(state)
            val sync = RemoteSync(f.verifier, f.binding)
            val now = RemoteTime(3, 100)
            val exchange = requireNotNull(sync.begin(f.nonce, now))
            val (names, docs) = documents(case.items("documents"))
            val response = harness.engine.receive(sync, exchange, f.nonce, now, docs)
            assertNull(response.failure)
            val expected = case.obj("expected")
            assertEquals(case.text("id"), expected["processed"], decisions(names, response))
            val final = expected.obj("final")
            // Key rotation and its server URL must survive a restart.
            harness.restart()
            assertEquals(case.text("id"), f.trust(final.text("keyset"), final.text("root")), harness.engine.state.trust)
            for ((type, key) in listOf(DocumentType.POLICY to "policyVersion", DocumentType.RECOVERY to "recoveryVersion",
                DocumentType.COMMAND to "commandFloor")) {
                assertEquals(case.text("id"), final[key], harness.engine.state.floor(type))
            }
        }
        for (raw in f.sync.items("nonceCases")) {
            val case = raw.asObject()
            var sync = RemoteSync(f.verifier, f.binding)
            val harness = f.harness(JournalState(trust = f.trust()))
            val exchanges = mutableMapOf<String, RemoteSync.Exchange>()
            val results = case.items("events").map { item ->
                val event = item.asObject()
                val now = RemoteTime(event["boot"] as? Long ?: 0L, event["elapsedMs"] as? Long ?: 0L)
                val nonce = (event["nonce"] as? String)?.let { f.sync.obj("nonces").text(it) }.orEmpty()
                when (event.text("event")) {
                    "send" -> {
                        val exchange = sync.begin(nonce, now)
                        if (exchange != null) exchanges[event.text("exchange")] = exchange
                        f.result(if (exchange != null) "sent" else "not-sent")
                    }
                    "response" -> {
                        val exchange = exchanges[event.text("exchange")]
                            ?: RemoteSync.Exchange(nonce, now)
                        val (names, docs) = documents((event["documents"] as? List<*>).orEmpty())
                        val response = harness.engine.receive(sync, exchange, nonce, now, docs)
                        f.result(if (response.failure == null) "processed" else "dropped", response.failure?.code) +
                            if ("documents" in event) mapOf("processedDocuments" to decisions(names, response)) else emptyMap()
                    }
                    "timeout" -> { sync.expire(now); f.result("discarded") }
                    else -> { sync = RemoteSync(f.verifier, f.binding); harness.restart(); f.result("discarded") }
                }
            }
            assertEquals(case.text("id"), case["expected"], results)
        }
    }

    @Test fun signaturePrecedesPayloadSchemaAndFleet() {
        val raw = f.envelope("lock-2")
        val changed = raw + ("payload" to RemoteCrypto.encode("{\"fleetId\":\"elsewhere\"}".toByteArray()))
        val failure = failure {
            f.verifier.authenticate(RemoteDocument(DocumentType.COMMAND, WireJson.canonical(changed)), f.trust("keyset-2", "successor"), f.binding)
        }
        assertEquals(RemoteFailure("doc-signature-invalid"), failure)
        val foreign = f.signedDocs.keys.first { name ->
            f.doc(name)["type"] == "fleet-policy" && f.doc(name)["fleetId"] != f.binding.fleetId
        }
        assertEquals(RemoteFailure("doc-field-invalid", "/fleetId"), failure {
            f.verifier.authenticate(f.document(foreign), f.trust("review-keyset-1", "review-root"), f.binding)
        })
    }

    private fun documents(refs: List<*>): Pair<List<String>, List<RemoteDocument>> {
        val entries = refs.map { if (it is String) mapOf("document" to it) else it.asObject() }
        return entries.map { it.text("document") } to entries.map {
            f.document(it.text("document"), it["tamper"] == "signature")
        }
    }

    private fun decisions(names: List<String>, response: RemoteSync.Response) = response.decisions.map {
        mapOf("document" to names[it.index]) + f.result(if (it.failure == null) "accepted" else "refused", it.failure?.code)
    }

    private fun update(value: Any?, path: List<String>, case: JsonObject): Any? {
        val key = path.first()
        val rest = path.drop(1)
        fun replacement(old: Any?): Any? {
            if (rest.isNotEmpty()) return update(old, rest, case)
            return when (case.text("op")) {
                "set" -> case["value"]
                "device-id-range" -> (0L until case.number("value")).map { index ->
                    val bytes = ByteArray(32)
                    for (i in 0..7) bytes[31 - i] = (index ushr (i * 8)).toByte()
                    RemoteCrypto.encode(bytes)
                }
                else -> error("Unknown fixture mutation")
            }
        }
        val remove = rest.isEmpty() && case["op"] == "remove"
        if (value is List<*>) {
            return value.toMutableList().apply {
                if (remove) removeAt(key.toInt()) else set(key.toInt(), replacement(get(key.toInt())))
            }
        }
        val obj = value.asObject()
        return if (remove) obj - key else obj + (key to replacement(obj[key]))
    }

    private fun validate(block: () -> Unit): JsonObject = failure(block)?.let {
        f.result("refused", it.code, "path" to it.path)
    } ?: f.result("valid")

    private fun failure(block: () -> Unit): RemoteFailure? = try {
        block()
        null
    } catch (error: Refused) {
        error.failure
    }
}
