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
    val releases: Set<String> = emptySet(),
    val recoveryPin: JournalRecoveryPin? = null,
    /** A nonempty map marks a rebuilt journal and retains its independent minimum versions. */
    val reanchorFloors: Map<DocumentType, Long> = emptyMap(),
    val floorPayloadSha256: Map<DocumentType, String> = emptyMap()
) {
    /** Replay protection needs only the floor. A short tail of outcomes is kept for the next report. */
    fun bounded(): JournalState {
        val finished = commands.values.filter { it.state.finished }.map { it.sequence }.sorted()
        val dropped = finished.dropLast(MAX_FINISHED_COMMANDS).toSet()
        return if (dropped.isEmpty()) this else copy(commands = commands - dropped)
    }

    fun generation() = policy?.let { Generation(it.version, it.hash, overrides) }
    val reanchored: Boolean get() = reanchorFloors.isNotEmpty()

    fun floor(type: DocumentType): Long {
        val applied = appliedFloor(type)
        return reanchorFloors[type]?.let { maxOf(applied, it) } ?: applied
    }

    fun appliedFloor(type: DocumentType): Long = when (type) {
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
    private val remoteCommitted: () -> Boolean = { false },
    private val recoveryPinFile: RecoveryPinFile? = null
) {
    private var marked: Boolean
    private var stateSeal: JournalSeal?
    private var guard: JournalGuard?
    private val legacyPin: RecoveryPin?
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
        legacyPin = initial.legacy?.pin
        floors = DocumentType.entries.associateWith(initial::floor)
        state = initial.state ?: JournalState()
        failure = initial.failure
        if (!lost) finishGuardCommit()
    }

    fun floor(type: DocumentType): Long = floors.getValue(type)

    fun canRetry(doc: RemoteVerifier.Authenticated): Boolean {
        if (state.appliedFloor(doc.type) >= doc.version || doc.version != floor(doc.type)) return false
        val pending = guard?.pending?.get(doc.type)
        // At the rebuilt floor, only the exact bytes authorized by the root may be resent.
        if (doc.version == state.reanchorFloors[doc.type] &&
            state.floorPayloadSha256[doc.type] != doc.committedSha256) return false
        return if (pending != null) pending == PendingDocument.from(doc)
        else doc.version == state.reanchorFloors[doc.type]
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

    fun bindPin(binding: RemoteBinding, root: String): JournalRecoveryPin? =
        recoveryPinFile?.write(RecoveryPin(root, binding.fingerprint()))

    /** A healthy pre-upgrade binding at version zero still proves its original root. */
    fun preserveLegacyPin() {
        val binding = state.binding ?: return
        val trust = state.trust ?: return
        if (lost || state.recoveryPin != null || trust.version != 0L || stateSeal == null) return
        runCatching { bindPin(binding, RemoteCrypto.keyId(trust.root)) }
    }

    data class ReanchorPin(val pin: RecoveryPin, val needsRootFingerprint: Boolean)

    fun reanchorPin(): ReanchorPin? {
        val stored = read()
        fun JournalSeal.pin(): RecoveryPin? {
            val binding = bindingFingerprint ?: return null
            // In a legacy seal, version zero proves that no root rotation has taken place.
            val root = bindingRootFingerprint ?: rootFingerprint?.takeIf {
                floors.getValue(DocumentType.KEY_SET) == 0L
            } ?: return null
            return RecoveryPin(root, binding)
        }
        fun JournalState.pin(): RecoveryPin? = runCatching {
            val proof = recoveryPin ?: return null
            val pin = RecoveryPin(proof.rootFingerprint, requireNotNull(binding).fingerprint())
            pin.takeIf { recoveryPinFile?.verifies(pin, proof.tag) == true }
        }.getOrNull()
        val known = listOfNotNull(guard?.current?.pin(), stored.secondary?.current?.pin(),
            legacyPin, stored.legacy?.pin, state.pin(), stored.state?.pin()).distinct()
        if (known.size > 1) return null
        known.singleOrNull()?.let { return ReanchorPin(it, false) }
        return runCatching { recoveryPinFile?.read() }.getOrNull()?.let { ReanchorPin(it, true) }
    }

    /** The guard reserves the recovered floors before the new journal can authorize anything. */
    fun reanchor(verified: RemoteVerifier.AuthenticatedReanchor, enterEnrolling: () -> Boolean): Boolean {
        if (!RemoteReanchor.supports(failure)) return false
        return try {
            val minFloors = DocumentType.entries.associateWith { maxOf(floor(it), verified.floors.getValue(it)) }
            if (!writeMarker() || !enterEnrolling()) return false
            val pin = RecoveryPin(RemoteCrypto.keyId(verified.trust.root), verified.binding.fingerprint())
            val proof = requireNotNull(recoveryPinFile).write(pin, restoring = true)
            val (releases, source) = authenticatedReleases()
            val next = JournalState(trust = verified.trust, binding = verified.binding,
                recoveryPin = proof, reanchorFloors = minFloors, floorPayloadSha256 = verified.floorPayloadSha256,
                releases = releases)
            val seal = JournalSeal.from(next)
            val nextGuard = JournalGuard(seal, reanchorSource = source)
            guardStore.write(nextGuard, createKey = true)
            guard = nextGuard
            floors = nextGuard.floors
            val update = preferences.edit().putString(STATE, JournalCodec.encode(next)).remove(STAMP)
            if (!DurablePreferences.commit(preferences, update, STATE, STAMP)) return false
            state = next
            stateSeal = seal
            failure = null
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun authenticatedReleases(): Pair<Set<String>, JournalSeal?> {
        val stored = read()
        fun JournalGuard?.authenticates(seal: JournalSeal): Boolean =
            this != null && (covers(seal) || reanchorSource == seal)

        val source = stored.seal?.takeIf {
            stored.state?.releases?.isNotEmpty() == true &&
                (stored.secondary.authenticates(it) || guard.authenticates(it))
        }
        val disk = if (source != null) stored.state?.releases.orEmpty() else emptySet()
        val memory = if (stateSeal?.let { guard.authenticates(it) } == true) state.releases else emptySet()
        return (disk + memory) to source
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
                // Preserve both sealed snapshots until the reserved binding commits.
                require(doc == null && (next == before || next == existing.current))
                return existing
            }
            val binding = existing.current.bindingFingerprint
            require(binding == null || binding == next.bindingFingerprint)
        }
        val pending = if (before != null) existing?.outstanding(state).orEmpty() else emptyMap()
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
        return writeGuard(current.copy(previous = null, pending = current.outstanding(state), reanchorSource = null))
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
        return marked || writeMarker()
    }

    private fun writeMarker(): Boolean {
        marked = try {
            DurablePreferences.commit(marker, marker.edit().putBoolean(CREATED, true), CREATED)
        } catch (_: RuntimeException) {
            false
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
        val secondary: JournalGuard?, val legacy: LegacyJournalGuardFormat?, val failure: RemoteFailure?
    ) {
        fun floor(type: DocumentType): Long {
            val journalFloor = state?.floor(type)?.takeIf { it in 0..WireJson.MAX_INTEGER } ?: 0L
            return maxOf(journalFloor, secondary?.floors?.getValue(type) ?: 0L, legacy?.floors?.get(type) ?: 0L)
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
        val legacy = secondary.exceptionOrNull() as? LegacyJournalGuardFormat
        val hasMarker = marked.getOrDefault(false)
        val failure = when {
            legacy != null -> GUARD_REENROLMENT_NEEDED
            marked.isFailure || journal.isFailure || primary.isFailure -> JOURNAL_LOST
            !hasMarker && (expected != null || copy != null) -> JOURNAL_LOST
            secondary.isFailure -> GUARD_UNREADABLE
            expected == null && copy?.isInitialBinding() != true &&
                (hasMarker || recoveryPinFile?.exists() == true) -> JOURNAL_LOST
            expected != null && copy == null -> GUARD_MISSING
            expected != null && copy?.covers(expected) != true -> GUARD_MISMATCH
            else -> null
        }
        return Read(hasMarker, state, expected, copy, legacy, failure)
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

private fun RemoteTrust.journalFields() = mapOf(
    "root" to root, "successor" to successor, "version" to version,
    "policies" to policyKeys, "server" to server, "serverUrl" to serverUrl
)

internal object JournalCodec {
    private fun overrides(values: Set<RemoteOverride>) = values.map { it.code }.sorted()
    private fun overrides(values: List<*>) = values.map { RemoteOverride.fromCode(it as String) }.toSet()

    private fun encodeGeneration(value: Generation?) = value?.let {
        mapOf("version" to it.version, "hash" to it.committedSha256, "overrides" to overrides(it.overrides))
    }

    private fun decodeGeneration(value: Any?) = value?.asObject()?.let {
        Generation(it.number("version"), it.text("hash"), overrides(it.items("overrides")))
    }

    fun sealBytes(state: JournalState): ByteArray =
        // Command history is updated and trimmed independently. Commands can
        // dispatch only with a live acceptance in this process.
        // A rebuilt journal also uses verified to gate commands and code recovery.
        // Use the persisted fields so new durable fields are sealed by default.
        WireJson.canonical((fields(state) - "commands").let { if (state.reanchored) it else it - "verified" })

    fun encode(state: JournalState): String = WireJson.canonical(fields(state)).toString(Charsets.UTF_8)

    private fun fields(state: JournalState): JsonObject = mapOf(
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
                "penalty" to penaltyMillis()) + listOfNotNull(
                wallDeadline().takeIf { it != 0L }?.let { "wallDeadline" to it }
            )
        },
        "floor" to state.commandFloor,
        "commands" to state.commands.values.map {
            mapOf("sequence" to it.sequence, "kind" to it.kind, "boot" to it.sent.boot, "cutoffElapsed" to it.cutoff,
                "state" to it.state.name, "code" to it.code, "secure" to it.secureLock, "reapply" to it.reapplyVerified,
                "verified" to encodeGeneration(it.verified))
        },
        "verified" to encodeGeneration(state.verified),
        "releases" to state.releases.sorted()
    ) + listOfNotNull(
        state.recoveryPin?.let { "recoveryPin" to mapOf("rootFingerprint" to it.rootFingerprint, "tag" to it.tag) },
        state.reanchorFloors.takeIf { it.isNotEmpty() }?.let { floors -> "reanchorFloors" to floors.mapKeys { it.key.wire } },
        state.floorPayloadSha256.takeIf { it.isNotEmpty() }?.let { hashes ->
            "floorPayloadSha256" to hashes.mapKeys { it.key.wire }
        }
    )

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
                lockout.number("until"), lockout.number("penalty"), lockout["wallDeadline"] as? Long ?: 0L
            ),
            commandFloor = json.number("floor"),
            commands = json.items("commands").map { it.asObject() }.associate {
                val sequence = it.number("sequence")
                sequence to CommandEntry(sequence, it.text("kind"), RemoteTime(it.number("boot"), it.number("cutoffElapsed") - RemoteSync.WINDOW_MS),
                    CommandState.valueOf(it.text("state")), it.getValue("code") as String?,
                    it.getValue("secure") as Boolean?, it.getValue("reapply") as Boolean?, decodeGeneration(it.getValue("verified")))
            },
            verified = decodeGeneration(json.getValue("verified")),
            releases = (json["releases"] as List<*>?).orEmpty().map { it as String }.toSet(),
            recoveryPin = json["recoveryPin"]?.asObject()?.let {
                JournalRecoveryPin(it.text("rootFingerprint"), it.text("tag"))
            },
            reanchorFloors = json["reanchorFloors"]?.asObject()?.let { floors ->
                require(floors.keys == DocumentType.entries.map { it.wire }.toSet())
                DocumentType.entries.associateWith { floors.number(it.wire).also { value -> require(value >= 0) } }
            }.orEmpty(),
            floorPayloadSha256 = json["floorPayloadSha256"]?.asObject()?.map { (wire, value) ->
                val type = RemoteReanchor.resendableTypes.single { it.wire == wire }
                type to (value as String).also { RemoteCrypto.unhex(it) }
            }?.toMap().orEmpty()
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
