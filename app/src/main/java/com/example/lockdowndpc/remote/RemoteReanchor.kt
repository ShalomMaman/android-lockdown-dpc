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
import java.security.SecureRandom

internal data class RecoveryPin(
    val rootFingerprint: String, val bindingFingerprint: String, val rootSpki: String? = null
) {
    init {
        require(RemoteCrypto.decode(rootFingerprint).size == 32)
        require(RemoteCrypto.decode(bindingFingerprint).size == 32)
        require(rootSpki == null || RemoteCrypto.keyId(rootSpki) == rootFingerprint)
    }

    fun bytes() = RemoteCrypto.decode(rootFingerprint) + RemoteCrypto.decode(bindingFingerprint)

    fun sameIdentity(other: RecoveryPin) =
        rootFingerprint == other.rootFingerprint && bindingFingerprint == other.bindingFingerprint
}

internal fun RemoteBinding.fingerprint(): String {
    require(fleetId.isNotEmpty() && RemoteCrypto.decode(deviceId).size == 32)
    return RemoteCrypto.encode(RemoteCrypto.sha256(WireJson.canonical(listOf(fleetId, deviceId))))
}

internal data class JournalRecoveryPin(val rootFingerprint: String, val tag: String)

/** Independent from the guard and usable even if the journal and guard are both lost. */
internal class RecoveryPinFile(
    private val file: File, private val mac: (ByteArray, Boolean) -> ByteArray
) {
    // A pending replacement disables standalone recovery until the guarded
    // journal proves which side of the commit survived.
    data class Record(val pin: RecoveryPin?, val pending: RecoveryPin? = null)

    fun exists(): Boolean = !Files.notExists(file.toPath(), NOFOLLOW_LINKS)

    fun read(): Record? {
        if (!exists()) return null
        val record = FileInputStream(file).use { input ->
            val size = input.channel.size()
            require(size in 33L..1024L)
            ByteArray(size.toInt()).also {
                DataInputStream(input).readFully(it)
                require(input.read() == -1)
            }
        }
        if (record.size == 96) {
            val pin = RecoveryPin(RemoteCrypto.encode(record.copyOfRange(0, 32)),
                RemoteCrypto.encode(record.copyOfRange(32, 64)))
            require(verifies(pin, RemoteCrypto.encode(record.copyOfRange(64, 96))))
            return Record(pin)
        }
        val payload = record.copyOfRange(32, record.size)
        require(MessageDigest.isEqual(mac(payload, false), record.copyOf(32)))
        val json = WireJson.parse(payload).asObject()
        require(json.number("format") == 2L)
        return Record(decodePin(json["pin"]), decodePin(json["pending"]))
    }

    fun verifies(pin: RecoveryPin, tag: String): Boolean =
        MessageDigest.isEqual(mac(pin.bytes(), false), RemoteCrypto.decode(tag))

    fun proof(pin: RecoveryPin): JournalRecoveryPin =
        JournalRecoveryPin(pin.rootFingerprint, RemoteCrypto.encode(mac(pin.bytes(), true)))

    fun write(record: Record) {
        val bytes = WireJson.canonical(mapOf("format" to 2L,
            "pin" to encodePin(record.pin), "pending" to encodePin(record.pending)))
        val tag = mac(bytes, true)
        require(tag.size == 32)
        val staged = File.createTempFile(file.name, ".pending", file.parentFile)
        try {
            FileOutputStream(staged).use {
                it.write(tag)
                it.write(bytes)
                it.fd.sync()
            }
            Files.move(staged.toPath(), file.toPath(), ATOMIC_MOVE, REPLACE_EXISTING)
        } finally {
            staged.delete()
        }
    }

    private fun encodePin(pin: RecoveryPin?) = pin?.let {
        mapOf("root" to it.rootFingerprint, "binding" to it.bindingFingerprint, "spki" to it.rootSpki)
    }

    private fun decodePin(value: Any?) = value?.asObject()?.let {
        RecoveryPin(it.text("root"), it.text("binding"), it["spki"] as String?)
    }
}

internal object RemoteReanchor {
    const val TYPE = "re-anchor"
    const val WINDOW_MS = 15 * 60 * 1000L
    const val MAX_ENVELOPE_BYTES = WireJson.MAX_ENVELOPE

    private val reasons = setOf(RemoteJournal.JOURNAL_LOST, RemoteJournal.GUARD_MISSING,
        RemoteJournal.GUARD_UNREADABLE, RemoteJournal.GUARD_MISMATCH, RemoteJournal.GUARD_REENROLMENT_NEEDED)

    fun supports(failure: RemoteFailure?) = failure in reasons

    data class Challenge(val nonce: String, val issued: RemoteTime) {
        fun fresh(now: RemoteTime) = now.known && now.boot == issued.boot &&
            now.elapsed >= issued.elapsed && now.elapsed - issued.elapsed < WINDOW_MS
    }

    data class Status(
        val reason: RemoteFailure? = null,
        val nonce: String? = null,
        val needsRootFingerprint: Boolean = false,
        val error: RemoteFailure? = null,
        val awaitingPolicy: Boolean = false
    )

    fun issue(now: RemoteTime) =
        Challenge(RemoteCrypto.encode(ByteArray(32).also { SecureRandom().nextBytes(it) }), now)

    val resendableTypes = setOf(DocumentType.KEY_SET, DocumentType.POLICY)
}
