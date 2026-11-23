package com.example.lockdowndpc.remote

import java.net.URI

/** Framing for the reference server. Signed document payload bytes stay inside their envelopes. */
internal object RemoteClientWire {
    const val START = "/v1/enrol/start"
    const val FINISH = "/v1/enrol/finish"
    const val SYNC = "/v1/sync"
    const val KEY_SET = "/v1/keyset"
    const val TIMESTAMP_HEADER = "X-DG-Timestamp"
    const val SIGNATURE_HEADER = "X-DG-Signature"

    fun serverUrl(value: String): String {
        val uri = URI.create(value)
        require(uri.scheme == "https" && uri.host != null && uri.rawUserInfo == null &&
            uri.rawQuery == null && uri.rawFragment == null && (uri.port == -1 || uri.port in 1..65535))
        require(uri.rawPath.split('/').none { it.replace("%2e", ".", ignoreCase = true) in setOf(".", "..") })
        return uri.toASCIIString().trimEnd('/')
    }

    fun ticketDigest(ticket: String): String {
        val raw = if (ticket.matches(Regex("[A-Z2-7]{16}"))) ticket.toByteArray(Charsets.US_ASCII)
            else RemoteCrypto.decode(ticket).also { require(it.size == 24) }
        return hash(raw)
    }

    fun challenge(bytes: ByteArray): String = fields(bytes, "challenge").text("challenge").also {
        require(RemoteCrypto.decode(it).size == 32)
    }

    fun enrolTranscript(challenge: String, ticket: String, chain: List<String>, facts: JsonObject): ByteArray =
        WireJson.canonical(listOf("dg-enrol/1", challenge, ticketDigest(ticket),
            hash(WireJson.canonical(chain)), hash(WireJson.canonical(facts))))

    fun syncTranscript(timestamp: Long, body: ByteArray): ByteArray =
        WireJson.canonical(listOf("dg-sync/1", "POST", SYNC, timestamp, hash(body)))

    data class Enrolled(val deviceId: String, val fleetId: String, val keySet: ByteArray)

    fun enrolled(bytes: ByteArray): Enrolled {
        val response = fields(bytes, "deviceId", "keyset")
        val wrapped = response.obj("keyset")
        val payload = WireJson.parse(RemoteCrypto.decode(wrapped.text("payload"))).asObject()
        // An untrusted routing hint for GET /v1/keyset. The engine authenticates
        // the original finish envelope against the provisioning digest.
        val fleet = payload.text("fleetId").also { require(it.isNotBlank() && it.length <= 128) }
        return Enrolled(response.text("deviceId"), fleet, WireJson.canonical(wrapped))
    }

    fun root(bytes: ByteArray, fleet: String): String {
        val response = fields(bytes, "fleetId", "rootSpki", "keyset")
        require(response.text("fleetId") == fleet)
        return response.text("rootSpki")
    }

    data class SyncReply(val nonce: String, val documents: List<RemoteDocument>)

    fun syncReply(bytes: ByteArray): SyncReply {
        val response = fields(bytes, "nonce", "documents")
        val documents = response.items("documents").mapNotNull {
            val slot = it.asObject()
            val type = DocumentType.entries.firstOrNull { type -> type.wire == slot["type"] }
                ?: return@mapNotNull null
            require(slot.keys == setOf("type", "envelope"))
            RemoteDocument(type, WireJson.canonical(slot.getValue("envelope")))
        }
        return SyncReply(response.text("nonce"), documents)
    }

    fun syncBody(exchange: RemoteSync.Exchange, state: JournalState, report: JsonObject): ByteArray {
        val generation = requireNotNull(state.generation())
        return WireJson.canonical(generation.fields("generationSha256") + mapOf(
            "deviceId" to requireNotNull(state.binding).deviceId,
            "nonce" to exchange.nonce,
            "keySetVersion" to requireNotNull(state.trust).version,
            "recoveryVersion" to state.recoveryVersion,
            "verifiedGeneration" to state.verified?.fields("verifiedSha256"),
            "lastCommandSequence" to state.floor(DocumentType.COMMAND),
            "report" to report,
        ))
    }

    fun Generation.fields(hashField: String): JsonObject = mapOf(
        "fleetPolicyVersion" to if (version == 0L) "baseline" else version,
        "committedSha256" to committedSha256,
        "overrides" to overrides.map { it.code }.sorted(),
        hashField to sha256,
    )

    private fun fields(bytes: ByteArray, vararg keys: String): JsonObject =
        WireJson.parse(bytes).asObject().also { require(it.keys == keys.toSet()) }

    private fun hash(bytes: ByteArray) = RemoteCrypto.hex(RemoteCrypto.sha256(bytes))
}
