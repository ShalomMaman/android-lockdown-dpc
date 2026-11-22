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
    fun body(schema: RemoteSchema): JsonObject {
        val bytes = RemoteCrypto.decode(encodedPayload)
        require(RemoteCrypto.hex(RemoteCrypto.sha256(bytes)) == hash)
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
internal enum class CommandState { ACCEPTED, DISPATCHING, DONE, EXPIRED, CANCELLED, OUTCOME_UNKNOWN }
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
    val verified: Generation? = null
) {
    fun generation() = policy?.let { Generation(it.version, it.hash, overrides) }
    fun floor(type: DocumentType): Long = when (type) {
        DocumentType.KEY_SET -> trust?.version ?: 0
        DocumentType.POLICY -> policy?.version ?: 0
        DocumentType.RECOVERY -> recoveryVersion
        DocumentType.COMMAND -> commandFloor
    }
}

/** One credential-protected file and one live instance on the policy thread. */
internal class RemoteJournal(private val preferences: SharedPreferences) {
    var state: JournalState = preferences.getString(STATE, null)?.let(JournalCodec::decode) ?: JournalState()
        private set

    internal fun save(next: JournalState): Boolean {
        val encoded = JournalCodec.encode(next)
        if (!write(STATE, encoded)) return false
        state = next
        return true
    }

    fun stamp(target: Generation): Boolean = write(STAMP, target.sha256)
    fun stamped(target: Generation): Boolean = preferences.getString(STAMP, null) == target.sha256

    private fun write(key: String, value: String): Boolean = try {
        DurablePreferences.commit(preferences, preferences.edit().putString(key, value), key)
    } catch (_: RuntimeException) {
        false
    }

    private companion object {
        const val STATE = "state"
        const val STAMP = "projection_generation"
    }
}

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
        "trust" to state.trust?.let {
            mapOf("root" to it.root, "successor" to it.successor, "version" to it.version,
                "policies" to it.policyKeys, "server" to it.server, "serverUrl" to it.serverUrl)
        },
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
        "verified" to encodeGeneration(state.verified)
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
            verified = decodeGeneration(json.getValue("verified"))
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
