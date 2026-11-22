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

/** The small part of the journal that must survive losing either store. */
internal data class JournalGuard(
    val bindingFingerprint: String?, val rootFingerprint: String?, val floors: Map<DocumentType, Long>
) {
    init {
        require(floors.keys == DocumentType.entries.toSet())
        require(floors.values.all { it in 0..WireJson.MAX_INTEGER })
        require(bindingFingerprint == null || RemoteCrypto.decode(bindingFingerprint).size == 32)
        require(rootFingerprint == null || RemoteCrypto.decode(rootFingerprint).size == 32)
    }

    companion object {
        // Canonicalize the fleet ID and device key fingerprint together. The
        // wire contract allows long fleet IDs, so store a fixed-size digest.
        fun from(state: JournalState) = JournalGuard(state.binding?.let {
            require(it.fleetId.isNotEmpty() && RemoteCrypto.decode(it.deviceId).size == 32)
            RemoteCrypto.encode(RemoteCrypto.sha256(WireJson.canonical(listOf(it.fleetId, it.deviceId))))
        }, state.trust?.root?.let(RemoteCrypto::keyId),
            DocumentType.entries.associateWith(state::floor))
    }
}

internal interface RemoteJournalGuardStore {
    /** Returns null only when the file is absent. Unreadable or invalid contents throw. */
    fun read(): JournalGuard?
    fun write(guard: JournalGuard)
}

/** One checksummed record in no-backup storage, replaced on the same filesystem. */
internal class RemoteJournalGuardFile(private val file: File) : RemoteJournalGuardStore {
    override fun read(): JournalGuard? {
        if (Files.notExists(file.toPath(), NOFOLLOW_LINKS)) return null
        val record = FileInputStream(file).use { input ->
            val size = input.channel.size()
            require(size in (CHECKSUM_SIZE + 1L)..MAX_RECORD_SIZE)
            ByteArray(size.toInt()).also {
                DataInputStream(input).readFully(it)
                require(input.read() == -1)
            }
        }
        val payload = record.copyOfRange(CHECKSUM_SIZE, record.size)
        require(MessageDigest.isEqual(record.copyOf(CHECKSUM_SIZE), RemoteCrypto.sha256(payload)))
        val json = WireJson.parse(payload).asObject()
        require(json.number("format") == 1L)
        val floors = json.obj("floors")
        return JournalGuard(json.getValue("bindingFingerprint") as String?, json.getValue("rootFingerprint") as String?,
            DocumentType.entries.associateWith { floors.number(it.wire) })
    }

    override fun write(guard: JournalGuard) {
        val payload = WireJson.canonical(mapOf(
            "format" to 1L,
            "bindingFingerprint" to guard.bindingFingerprint,
            "rootFingerprint" to guard.rootFingerprint,
            "floors" to guard.floors.mapKeys { it.key.wire }
        ))
        require(CHECKSUM_SIZE + payload.size <= MAX_RECORD_SIZE)
        val staged = File.createTempFile(file.name, ".pending", file.parentFile)
        try {
            FileOutputStream(staged).use {
                it.write(RemoteCrypto.sha256(payload))
                it.write(payload)
                it.fd.sync()
            }
            Files.move(staged.toPath(), file.toPath(), ATOMIC_MOVE, REPLACE_EXISTING)
        } finally {
            // A successful move consumes the staged file. The previous record survives a failed move.
            staged.delete()
        }
    }

    companion object {
        private const val CHECKSUM_SIZE = 32
        private const val MAX_RECORD_SIZE = 4096L
    }
}
