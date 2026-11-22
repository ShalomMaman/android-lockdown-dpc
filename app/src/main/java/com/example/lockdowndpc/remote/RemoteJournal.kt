package com.example.lockdowndpc.remote

import android.content.SharedPreferences
import com.example.lockdowndpc.security.DurablePreferences
import com.example.lockdowndpc.security.PinLockoutPolicy
import java.security.MessageDigest
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

internal data class Generation(
    val version: Long, val committedSha256: String, val overrides: Set<RemoteOverride>
) {
    val sha256: String = RemoteCrypto.generation(committedSha256, overrides)
}

internal data class CommittedPolicy(val encodedPayload: String, val hash: String, val version: Long) {
    fun verifiedBytes(): ByteArray = RemoteCrypto.decode(encodedPayload).also {
        require(RemoteCrypto.hex(RemoteCrypto.sha256(it)) == hash)
    }

    fun body(schema: RemoteSchema): JsonObject {
        val bytes = verifiedBytes()
        val json = schema.decode(bytes).asObject()
        if (version == 0L) {
            schema.requireValid("policy", json)
            require(bytes.contentEquals(WireJson.canonical(json)))
            return json
        }
        require(schema.payload(json) == DocumentType.POLICY && json.number("fleetPolicyVersion") == version)
        return json.obj("policy")
    }

    companion object {
        fun fromBytes(bytes: ByteArray, version: Long) =
            CommittedPolicy(RemoteCrypto.encode(bytes), RemoteCrypto.hex(RemoteCrypto.sha256(bytes)), version)
    }
}

internal data class RecoveryVerifier(val salt: String, val mac: String)
internal enum class CommandState {
    ACCEPTED, DISPATCHING, DONE, EXPIRED, CANCELLED, OUTCOME_UNKNOWN;

    val finished: Boolean get() = this != ACCEPTED && this != DISPATCHING
}
internal data class CommandEntry(
    val sequence: Long, val kind: String, val sent: RemoteTime,
    val state: CommandState = CommandState.ACCEPTED, val code: String? = null,
    val secureLock: Boolean? = null, val reapplyVerified: Boolean? = null, val verified: Generation? = null
) {
    val cutoff: Long get() = Math.addExact(sent.elapsed, RemoteSync.WINDOW_MS)
    val shouldReport: Boolean get() = kind == "reapply" && state == CommandState.DONE
    fun fresh(now: RemoteTime) = now.boot == sent.boot && now.elapsed in sent.elapsed until cutoff
}

internal data class JournalState(
    val trust: RemoteTrust? = null,
    val binding: RemoteBinding? = null,
    val policy: CommittedPolicy? = null,
    val overrides: Set<RemoteOverride> = emptySet(),
    val recoveryVersion: Long = 0,
    val recovery: RecoveryVerifier? = null,
    val recoveryUses: Long = 0,
    val lockout: PinLockoutPolicy.LockoutState = PinLockoutPolicy.LockoutState.CLEARED,
    val commandFloor: Long = 0,
    val commands: Map<Long, CommandEntry> = emptyMap(),
    val verified: Generation? = null,
    /** Packages a pass made visible before its generation was verified. */
    val releases: Set<String> = emptySet()
) {
    /** Replay protection needs only the floor. A short tail of outcomes is kept for the next report. */
    fun bounded(): JournalState {
        val finished = commands.values.filter { it.state.finished }.map { it.sequence }.sorted()
        val dropped = finished.dropLast(MAX_FINISHED_COMMANDS).toSet()
        return if (dropped.isEmpty()) this else copy(commands = commands - dropped)
    }

    fun generation() = policy?.let { Generation(it.version, it.hash, overrides) }
    fun floor(type: DocumentType): Long = when (type) {
        DocumentType.KEY_SET -> trust?.version ?: 0
        DocumentType.POLICY -> policy?.version ?: 0
        DocumentType.RECOVERY -> recoveryVersion
        DocumentType.COMMAND -> commandFloor
    }
}

internal const val MAX_FINISHED_COMMANDS = 16

/** One live instance on the policy thread. The guard bounds what the journal can authorize. */
internal class RemoteJournal(
    private val preferences: SharedPreferences,
    private val marker: SharedPreferences,
    private val guardStore: RemoteJournalGuardStore,
    private val journalFileAbsent: () -> Boolean = { true },
    private val markerFileAbsent: () -> Boolean = { true },
    private val remoteCommitted: () -> Boolean = { false }
) {
    private var marked: Boolean
    private var stateSeal: JournalSeal?
    private var guard: JournalGuard?
    private var floors: Map<DocumentType, Long>
    var state: JournalState
        private set
    var failure: RemoteFailure?
        private set
    val lost: Boolean get() = failure != null

    init {
        val initial = read()
        marked = initial.marked
        stateSeal = initial.seal
        guard = initial.secondary
        floors = DocumentType.entries.associateWith(initial::floor)
        state = initial.state ?: JournalState()
        failure = initial.failure
        if (!lost) finishGuardCommit()
    }

    fun floor(type: DocumentType): Long = floors.getValue(type)

    fun canRetry(doc: RemoteVerifier.Authenticated): Boolean {
        val pending = guard?.pending?.get(doc.type) ?: return false
        return state.floor(doc.type) < doc.version && doc.version == floor(doc.type) &&
            pending == PendingDocument.from(doc)
    }

    /** Refresh at runtime entry points, keeping every observed floor and any prior failure. */
    fun checkStores(): RemoteFailure? {
        val stored = read()
        floors = DocumentType.entries.associateWith { maxOf(floor(it), stored.floor(it)) }
        if (!lost) failure = stored.failure ?: when {
            stateSeal != null && stored.seal == null -> JOURNAL_LOST
            stored.secondary != guard || stored.seal != stateSeal -> GUARD_MISMATCH
            else -> null
        }
        return failure
    }

    internal fun save(next: JournalState, doc: RemoteVerifier.Authenticated? = null): Boolean {
        if (lost) return false
        val bounded = next.bounded()
        val nextSeal = try {
            JournalSeal.from(bounded)
        } catch (_: Exception) {
            return false
        }
        val (nextGuard, encoded) = try {
            guardFor(nextSeal, doc) to JournalCodec.encode(bounded)
        } catch (_: Exception) {
            return false
        }
        // Reserve floors before the journal write. A failed write leaves the
        // old snapshot usable and the exact authenticated document retryable.
        if (!mark() || !writeGuard(nextGuard) || !write(STATE, encoded)) return false
        state = bounded
        stateSeal = nextSeal
        return finishGuardCommit()
    }

    private fun guardFor(next: JournalSeal, doc: RemoteVerifier.Authenticated?): JournalGuard {
        val before = stateSeal
        val existing = guard
        if (existing != null) {
            // A failed first bind pins the bootstrap identity whether it was
            // preceded by a version-zero baseline or by an empty journal.
            if (before == null) {
                require(doc == null && existing == JournalGuard(next))
                return existing
            }
            if (existing.isBindingTransition && before == existing.previous) {
                require(doc == null && (next == before || next == existing.current))
                return existing
            }
            val binding = existing.current.bindingFingerprint
            require(binding == null || binding == next.bindingFingerprint)
        }
        val pending = if (before != null) existing?.outstanding(before).orEmpty() else emptyMap()
        val reservations = if (doc == null) {
            require(before == null || next.floors == before.floors)
            pending
        } else {
            require(before != null && next.floors.getValue(doc.type) == doc.version)
            require(doc.version > floor(doc.type) || canRetry(doc))
            require(DocumentType.entries.all { it == doc.type || next.floors.getValue(it) == state.floor(it) })
            pending + (doc.type to PendingDocument.from(doc))
        }
        return JournalGuard(next, before?.takeUnless { it == next }, reservations)
    }

    /** If the journal did commit, remove the old snapshot before using the new one. */
    private fun finishGuardCommit(): Boolean {
        val current = guard ?: return true
        if (current.current != stateSeal) return true
        return writeGuard(current.copy(previous = null, pending = current.outstanding(current.current)))
    }

    private fun writeGuard(next: JournalGuard): Boolean {
        if (guard == next) return true
        try {
            guardStore.write(next, createKey = guard == null)
        } catch (_: Exception) {
            failure = GUARD_WRITE_FAILED
            return false
        }
        guard = next
        floors = next.floors
        return true
    }

    fun stamp(target: Generation): Boolean = !lost && mark() && write(STAMP, target.sha256)
    fun stamped(target: Generation): Boolean = try {
        !lost && preferences.getString(STAMP, null) == target.sha256
    } catch (_: RuntimeException) {
        false
    }

    /** Stored once, before any journal write. Until it is, nothing is written to the journal. */
    private fun mark(): Boolean {
        if (!marked) {
            marked = try {
                DurablePreferences.commit(marker, marker.edit().putBoolean(CREATED, true), CREATED)
            } catch (_: RuntimeException) {
                false
            }
        }
        return marked
    }

    private fun write(key: String, value: String): Boolean = try {
        DurablePreferences.commit(preferences, preferences.edit().putString(key, value), key)
    } catch (_: RuntimeException) {
        false
    }

    private class Read(
        val marked: Boolean, val state: JournalState?, val seal: JournalSeal?,
        val secondary: JournalGuard?, val failure: RemoteFailure?
    ) {
        fun floor(type: DocumentType): Long {
            val journalFloor = state?.floor(type)?.takeIf { it in 0..WireJson.MAX_INTEGER } ?: 0L
            return maxOf(journalFloor, secondary?.floors?.getValue(type) ?: 0L)
        }
    }

    private fun read(): Read {
        val marked = runCatching {
            val value = marker.all[CREATED]
            // A malformed marker XML can also appear as an empty map.
            require(value == true || (value == null && markerFileAbsent()))
            value == true
        }
        val journal = runCatching {
            val stored = preferences.getString(STATE, null)
            if (stored == null) {
                // SharedPreferences can return an empty map after a malformed XML read.
                require(!preferences.contains(STAMP) && journalFileAbsent() && !remoteCommitted())
                null
            } else {
                JournalCodec.decode(stored)
            }
        }
        val secondary = runCatching(guardStore::read)
        val state = journal.getOrNull()
        val primary = runCatching { state?.let(JournalSeal::from) }
        val expected = primary.getOrNull()
        val copy = secondary.getOrNull()
        val hasMarker = marked.getOrDefault(false)
        val failure = when {
            secondary.exceptionOrNull() is LegacyJournalGuardFormat -> GUARD_REENROLMENT_NEEDED
            marked.isFailure || journal.isFailure || primary.isFailure -> JOURNAL_LOST
            !hasMarker && (expected != null || copy != null) -> JOURNAL_LOST
            secondary.isFailure -> GUARD_UNREADABLE
            expected == null && hasMarker && copy?.isInitialBinding() != true -> JOURNAL_LOST
            expected != null && copy == null -> GUARD_MISSING
            expected != null && copy?.covers(expected) != true -> GUARD_MISMATCH
            else -> null
        }
        return Read(hasMarker, state, expected, copy, failure)
    }

    companion object {
        private const val STATE = "state"
        private const val STAMP = "projection_generation"
        private const val CREATED = "journal_created"
        val JOURNAL_LOST = RemoteFailure("journal-lost")
        val GUARD_UNREADABLE = RemoteFailure("journal-guard-unreadable")
        val GUARD_MISSING = RemoteFailure("journal-guard-missing")
        val GUARD_MISMATCH = RemoteFailure("journal-guard-mismatch")
        val GUARD_WRITE_FAILED = RemoteFailure("journal-guard-write-failed")
        val GUARD_REENROLMENT_NEEDED = RemoteFailure("journal-guard-reenrolment-needed")
    }
}

/** Shared by the journal encoding and the guard's canonical trust digest. */
internal fun RemoteTrust.journalFields() = mapOf(
    "root" to root, "successor" to successor, "version" to version,
    "policies" to policyKeys, "server" to server, "serverUrl" to serverUrl
)

private object JournalCodec {
    private fun overrides(values: Set<RemoteOverride>) = values.map { it.code }.sorted()
    private fun overrides(values: List<*>) = values.map { RemoteOverride.fromCode(it as String) }.toSet()

    private fun encodeGeneration(value: Generation?) = value?.let {
        mapOf("version" to it.version, "hash" to it.committedSha256, "overrides" to overrides(it.overrides))
    }

    private fun decodeGeneration(value: Any?) = value?.asObject()?.let {
        Generation(it.number("version"), it.text("hash"), overrides(it.items("overrides")))
    }

    fun encode(state: JournalState): String = WireJson.canonical(mapOf(
        "trust" to state.trust?.journalFields(),
        "binding" to state.binding?.let { mapOf("fleet" to it.fleetId, "device" to it.deviceId) },
        "policy" to state.policy?.let { mapOf("bytes" to it.encodedPayload, "hash" to it.hash, "version" to it.version) },
        "overrides" to overrides(state.overrides),
        "recoveryVersion" to state.recoveryVersion,
        "recovery" to state.recovery?.let { mapOf("salt" to it.salt, "mac" to it.mac) },
        "uses" to state.recoveryUses,
        "lockout" to state.lockout.run {
            mapOf("failures" to failures().toLong(), "bootKind" to armedBoot().kind().name,
                "boot" to armedBoot().value(), "until" to armedElapsedDeadline(),
                "penalty" to penaltyMillis())
        },
        "floor" to state.commandFloor,
        "commands" to state.commands.values.map {
            mapOf("sequence" to it.sequence, "kind" to it.kind, "boot" to it.sent.boot, "cutoffElapsed" to it.cutoff,
                "state" to it.state.name, "code" to it.code, "secure" to it.secureLock, "reapply" to it.reapplyVerified,
                "verified" to encodeGeneration(it.verified))
        },
        "verified" to encodeGeneration(state.verified),
        "releases" to state.releases.sorted()
    )).toString(Charsets.UTF_8)

    fun decode(value: String): JournalState {
        val json = WireJson.parse(value.toByteArray(Charsets.UTF_8)).asObject()
        val lockout = json.obj("lockout")
        return JournalState(
            trust = json.getValue("trust")?.asObject()?.let {
                RemoteTrust(it.text("root"), it.getValue("successor") as String?, it.number("version"),
                    it.items("policies").map { key -> key as String }, it.getValue("server") as String?,
                    it.getValue("serverUrl") as String?)
            },
            binding = json.getValue("binding")?.asObject()?.let { RemoteBinding(it.text("fleet"), it.text("device")) },
            policy = json.getValue("policy")?.asObject()?.let {
                CommittedPolicy(it.text("bytes"), it.text("hash"), it.number("version"))
            },
            overrides = overrides(json.items("overrides")),
            recoveryVersion = json.number("recoveryVersion"),
            recovery = json.getValue("recovery")?.asObject()?.let { RecoveryVerifier(it.text("salt"), it.text("mac")) },
            recoveryUses = json.number("uses"),
            lockout = PinLockoutPolicy.LockoutState(
                Math.toIntExact(lockout.number("failures")),
                PinLockoutPolicy.BootId(PinLockoutPolicy.BootKind.valueOf(lockout.text("bootKind")), lockout.number("boot")),
                lockout.number("until"), lockout.number("penalty"), 0
            ),
            commandFloor = json.number("floor"),
            commands = json.items("commands").map { it.asObject() }.associate {
                val sequence = it.number("sequence")
                sequence to CommandEntry(sequence, it.text("kind"), RemoteTime(it.number("boot"), it.number("cutoffElapsed") - RemoteSync.WINDOW_MS),
                    CommandState.valueOf(it.text("state")), it.getValue("code") as String?,
                    it.getValue("secure") as Boolean?, it.getValue("reapply") as Boolean?, decodeGeneration(it.getValue("verified")))
            },
            verified = decodeGeneration(json.getValue("verified")),
            releases = (json["releases"] as List<*>?).orEmpty().map { it as String }.toSet()
        )
    }
}

internal object RecoveryCode {
    fun derive(code: String, salt: ByteArray): ByteArray? {
        val compact = code.replace(" ", "")
        if (compact.length != 20 || compact.any { it !in 'A'..'Z' && it !in '2'..'7' }) return null
        val spec = PBEKeySpec(compact.toCharArray(), salt, 210_000, 256)
        return try {
            SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }

    fun matches(code: String, stored: RecoveryVerifier, mac: (ByteArray) -> ByteArray): Boolean {
        val salt = RemoteCrypto.decode(stored.salt)
        val derived = derive(code, salt) ?: return false
        return try {
            MessageDigest.isEqual(mac(salt + derived), RemoteCrypto.decode(stored.mac))
        } finally {
            derived.fill(0)
        }
    }
}
