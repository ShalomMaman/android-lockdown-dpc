package com.example.lockdowndpc.remote

import java.io.DataInputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.security.MessageDigest

/** The protected fields of one durable journal state. */
internal data class JournalSeal(
    val bindingFingerprint: String?,
    val rootFingerprint: String?,
    val floors: Map<DocumentType, Long>,
    val policySha256: String?,
    val stateSha256: String,
    val bindingRootFingerprint: String? = null,
    val reanchored: Boolean = false
) {
    init {
        require(floors.keys == DocumentType.entries.toSet())
        require(floors.values.all { it in 0..WireJson.MAX_INTEGER })
        require(bindingFingerprint == null || RemoteCrypto.decode(bindingFingerprint).size == 32)
        require(rootFingerprint == null || RemoteCrypto.decode(rootFingerprint).size == 32)
        require(bindingRootFingerprint == null ||
            (bindingFingerprint != null && RemoteCrypto.decode(bindingRootFingerprint).size == 32))
        policySha256?.let(RemoteCrypto::unhex)
        RemoteCrypto.unhex(stateSha256)
    }

    companion object {
        fun from(state: JournalState) = JournalSeal(state.binding?.fingerprint(),
            state.trust?.root?.let(RemoteCrypto::keyId),
            DocumentType.entries.associateWith {
                require(state.appliedFloor(it) in 0..WireJson.MAX_INTEGER)
                state.floor(it)
            },
            state.policy?.let {
                it.verifiedBytes()
                it.hash
            }, RemoteCrypto.hex(RemoteCrypto.sha256(JournalCodec.sealBytes(state))),
            state.recoveryPin?.rootFingerprint, state.reanchored)
    }
}

internal data class PendingDocument(val version: Long, val sha256: String, val keySetSigner: String?) {
    init {
        require(version in 1..WireJson.MAX_INTEGER)
        RemoteCrypto.unhex(sha256)
        require(keySetSigner == null || RemoteCrypto.decode(keySetSigner).size == 32)
    }

    companion object {
        fun from(doc: RemoteVerifier.Authenticated) = PendingDocument(
            doc.version, RemoteCrypto.hex(RemoteCrypto.sha256(WireJson.canonical(doc.body))),
            doc.signer.takeIf { doc.type == DocumentType.KEY_SET }?.let(RemoteCrypto::keyId)
        )
    }
}

/** One authenticated transition, plus retry reservations that survive unrelated saves. */
internal data class JournalGuard(
    val current: JournalSeal,
    val previous: JournalSeal? = null,
    val pending: Map<DocumentType, PendingDocument> = emptyMap(),
    /** Evidence for retaining unfinished releases across an interrupted re-anchor. Never covers a journal. */
    val reanchorSource: JournalSeal? = null
) {
    val isBindingTransition: Boolean get() = previous != null && previous.bindingFingerprint == null &&
        current.bindingFingerprint != null

    init {
        require(reanchorSource == null ||
            (current.reanchored && previous == null && pending.isEmpty() &&
                reanchorSource.bindingFingerprint == current.bindingFingerprint))
        require(pending.all { (type, doc) ->
            (doc.keySetSigner != null) == (type == DocumentType.KEY_SET) &&
                doc.version >= current.floors.getValue(type)
        })
        if (previous != null) {
            require(DocumentType.entries.all { previous.floors.getValue(it) <= current.floors.getValue(it) })
            if (isBindingTransition) {
                require(previous.rootFingerprint == null && current.rootFingerprint != null &&
                    previous.floors == current.floors && current.floors.values.all { it == 0L } &&
                    previous.policySha256 == current.policySha256 && pending.isEmpty())
            } else {
                require(previous.bindingFingerprint == current.bindingFingerprint)
                require(previous.bindingRootFingerprint == current.bindingRootFingerprint)
                require(previous.reanchored == current.reanchored)
                require(previous.rootFingerprint == current.rootFingerprint ||
                    (pending[DocumentType.KEY_SET]?.version == current.floors.getValue(DocumentType.KEY_SET) &&
                        pending[DocumentType.KEY_SET]?.keySetSigner == current.rootFingerprint))
            }
        }
    }

    val floors: Map<DocumentType, Long> get() = current.floors.mapValues { (type, version) ->
        maxOf(version, pending[type]?.version ?: 0L)
    }

    val previousRootFingerprint: String? get() =
        previous?.rootFingerprint?.takeUnless { it == current.rootFingerprint }

    // Require one whole protected snapshot, including during a root transition.
    fun covers(journal: JournalSeal): Boolean = journal == current || journal == previous

    fun outstanding(journal: JournalState): Map<DocumentType, PendingDocument> =
        pending.filter { (type, doc) -> journal.appliedFloor(type) < doc.version }

    fun isInitialBinding(): Boolean =
        !current.reanchored && previous == null && pending.isEmpty() && current.bindingFingerprint != null &&
            current.rootFingerprint != null && current.policySha256 == null && current.floors.values.all { it == 0L }

    companion object {
        fun from(state: JournalState) = JournalGuard(JournalSeal.from(state))
    }
}

internal class LegacyJournalGuardFormat(
    val floors: Map<DocumentType, Long> = emptyMap(),
    val pin: RecoveryPin? = null
) : IllegalArgumentException()

internal interface RemoteJournalGuardStore {
    /** Returns null only when the file is absent. Unreadable or invalid contents throw. */
    fun read(): JournalGuard?
    fun write(guard: JournalGuard, createKey: Boolean = false)
}

/** One authenticated record in no-backup storage, replaced on the same filesystem. */
internal class RemoteJournalGuardFile(
    private val file: File, private val mac: (ByteArray, Boolean) -> ByteArray
) : RemoteJournalGuardStore {
    override fun read(): JournalGuard? {
        if (Files.notExists(file.toPath(), NOFOLLOW_LINKS)) return null
        val record = FileInputStream(file).use { input ->
            val size = input.channel.size()
            require(size in (MAC_SIZE + 1L)..MAX_RECORD_SIZE)
            ByteArray(size.toInt()).also {
                DataInputStream(input).readFully(it)
                require(input.read() == -1)
            }
        }
        val payload = record.copyOfRange(MAC_SIZE, record.size)
        val json = WireJson.parse(payload).asObject()
        val format = json.number("format")
        require(format in 1L..FORMAT)
        // Format 1 had a public checksum. Older records do not seal the whole
        // protected state, so recognized legacy records require re-enrolment.
        val tag = if (format == 1L) RemoteCrypto.sha256(payload) else mac(payload, false)
        require(MessageDigest.isEqual(record.copyOf(MAC_SIZE), tag))
        if (format != FORMAT) throw legacyEvidence(format, json)
        val pending = json.obj("pending").map { (wire, value) ->
            val type = DocumentType.entries.single { it.wire == wire }
            val doc = value.asObject()
            type to PendingDocument(doc.number("version"), doc.text("sha256"), doc.getValue("keySetSigner") as String?)
        }.toMap()
        return JournalGuard(decodeSeal(json.obj("current")),
            json.getValue("previous")?.asObject()?.let(::decodeSeal), pending,
            json["reanchorSource"]?.asObject()?.let(::decodeSeal))
    }

    override fun write(guard: JournalGuard, createKey: Boolean) {
        val payload = WireJson.canonical(mapOf(
            "format" to FORMAT,
            "current" to encodeSeal(guard.current),
            "previous" to guard.previous?.let(::encodeSeal),
            "pending" to guard.pending.entries.associate { (type, doc) ->
                type.wire to mapOf("version" to doc.version, "sha256" to doc.sha256, "keySetSigner" to doc.keySetSigner)
            }
        ) + listOfNotNull(guard.reanchorSource?.let { "reanchorSource" to encodeSeal(it) }))
        require(MAC_SIZE + payload.size <= MAX_RECORD_SIZE)
        val tag = mac(payload, createKey)
        require(tag.size == MAC_SIZE)
        val staged = File.createTempFile(file.name, ".pending", file.parentFile)
        try {
            FileOutputStream(staged).use {
                it.write(tag)
                it.write(payload)
                it.fd.sync()
            }
            Files.move(staged.toPath(), file.toPath(), ATOMIC_MOVE, REPLACE_EXISTING)
        } finally {
            // A successful move consumes the staged file. The previous record survives a failed move.
            staged.delete()
        }
    }

    private fun legacyEvidence(format: Long, json: JsonObject): LegacyJournalGuardFormat {
        // Readable floors can only raise the lower bound. The public v1
        // checksum cannot prove identity, and no legacy guard covers a journal.
        return runCatching {
            val current = if (format < 3L) json else json.obj("current")
            val versions = current.obj("floors")
            val pending = if (format == 3L) json.obj("pending") else emptyMap()
            val floors = DocumentType.entries.associateWith { type ->
                val version = versions.number(type.wire)
                val reserved = pending[type.wire]?.asObject()?.number("version") ?: 0L
                require(version >= 0 && reserved >= 0)
                maxOf(version, reserved)
            }
            val root = current["rootFingerprint"] as String?
            val binding = current["bindingFingerprint"] as String?
            val pin = if (format >= 2L && root != null && binding != null &&
                versions.number(DocumentType.KEY_SET.wire) == 0L) {
                RecoveryPin(root, binding)
            } else null
            LegacyJournalGuardFormat(floors, pin)
        }.getOrElse { LegacyJournalGuardFormat() }
    }

    private fun encodeSeal(seal: JournalSeal) = mapOf(
        "bindingFingerprint" to seal.bindingFingerprint, "rootFingerprint" to seal.rootFingerprint,
        "floors" to seal.floors.mapKeys { it.key.wire }, "policySha256" to seal.policySha256,
        "stateSha256" to seal.stateSha256
    ) + listOfNotNull(
        seal.bindingRootFingerprint?.let { "bindingRootFingerprint" to it },
        if (seal.reanchored) "reanchored" to true else null
    )

    private fun decodeSeal(seal: JsonObject): JournalSeal {
        val floors = seal.obj("floors")
        return JournalSeal(seal.getValue("bindingFingerprint") as String?, seal.getValue("rootFingerprint") as String?,
            DocumentType.entries.associateWith { floors.number(it.wire) },
            seal.getValue("policySha256") as String?, seal.text("stateSha256"),
            seal["bindingRootFingerprint"] as String?, seal["reanchored"] == true)
    }

    companion object {
        private const val FORMAT = 4L
        private const val MAC_SIZE = 32
        private const val MAX_RECORD_SIZE = 4096L
    }
}
