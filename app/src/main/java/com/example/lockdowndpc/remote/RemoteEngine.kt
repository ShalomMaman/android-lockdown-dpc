package com.example.lockdowndpc.remote

import com.example.lockdowndpc.security.PinLockoutPolicy

/** The journal's record of what a pass is about to make visible, written before the first such call. */
internal fun interface ReleaseLedger {
    fun record(packages: Set<String>): Boolean
}

internal interface RemoteProjection {
    /** Throws when the device stores cannot hold a schema-valid policy. Runs before the journal commit. */
    fun validate(policy: JsonObject) {}

    /** Persist the full effective policy. A refused write aborts the current pass. */
    fun project(policy: JsonObject, target: Generation): Boolean
    fun apply(target: Generation, stillCurrent: () -> Boolean): Boolean = false

    /** A pass that makes a hidden package visible records it in [releases] first. */
    fun apply(target: Generation, stillCurrent: () -> Boolean, releases: ReleaseLedger): Boolean =
        apply(target, stillCurrent)

    /** Hides again what an unverified pass made visible. Returns the packages not proven hidden. */
    fun revoke(packages: Set<String>): Set<String> = emptySet()
}

/** All entry points, including recovery and dispatch, run on the same policy thread. */
internal class RemoteEngine(
    private val journal: RemoteJournal,
    private val schema: RemoteSchema,
    private val projection: RemoteProjection,
    private val recoveryMac: (ByteArray, Boolean) -> ByteArray,
    private val commandProcess: CommandProcess = CommandProcess()
) {
    internal class CommandProcess {
        val liveDispatches = mutableSetOf<Long>()
        val callsStarted = mutableSetOf<Long>()
        /** Outcomes this process knows and could not store yet. */
        val unsaved = mutableMapOf<Long, CommandEntry>()
    }

    private val liveDispatches get() = commandProcess.liveDispatches
    private val callsStarted get() = commandProcess.callsStarted
    private val unsaved get() = commandProcess.unsaved
    private val ledger = ReleaseLedger { packages -> save(state.copy(releases = state.releases + packages)) == null }
    private var reconciling = false
    val state: JournalState get() = journal.state
    /** The journal existed and cannot be read. Every entry point refuses with `journal-lost`. */
    val lost: Boolean get() = journal.lost

    data class Pass(val verified: Boolean, val failure: RemoteFailure? = null)
    enum class RecoveryOutcome { UNCHANGED, REFUSED, COMMITTED }
    data class RecoveryResult(
        val outcome: RecoveryOutcome, val failure: RemoteFailure? = null,
        val codeChecked: Boolean? = null, val remainingMillis: Long = 0,
        val projection: Pass? = null
    )

    fun bindFleet(
        verifier: RemoteVerifier, binding: RemoteBinding, pinnedId: String, rootSpki: String, sdk: Int
    ): RemoteFailure? {
        if (journal.lost) return LOST
        // Below Android 10 the default controls cannot all be enforced, so no generation could verify.
        if (sdk < MIN_SDK) return RemoteFailure("enrolment-sdk-unsupported")
        if (state.trust != null || state.binding != null) return RemoteFailure("doc-version-rollback")
        return try {
            val trust = verifier.bootstrap(pinnedId, rootSpki, binding)
            save(state.copy(trust = trust, binding = binding))
        } catch (error: Refused) {
            error.failure
        } catch (_: Exception) {
            RemoteFailure("doc-field-invalid")
        }
    }

    fun commitBaseline(policy: JsonObject): RemoteFailure? {
        if (journal.lost) return LOST
        if (state.policy != null) return RemoteFailure("doc-version-rollback")
        return try {
            schema.requireValid("policy", policy)
            unprojectable(policy)
                ?: save(state.copy(policy = CommittedPolicy.fromBytes(WireJson.canonical(policy), 0)))
        } catch (error: Refused) {
            error.failure
        }
    }

    /** A policy that could never be projected is refused while the previous one is still the target. */
    private fun unprojectable(policy: JsonObject): RemoteFailure? = try {
        projection.validate(policy)
        null
    } catch (error: Refused) {
        error.failure
    } catch (_: RuntimeException) {
        RemoteFailure("doc-field-invalid", "/policy")
    }

    fun receive(sync: RemoteSync, exchange: RemoteSync.Exchange, nonce: String, now: RemoteTime,
                documents: List<RemoteDocument>): RemoteSync.Response {
        if (journal.lost) return RemoteSync.Response(LOST)
        return sync.respond(exchange, nonce, now, documents, { requireNotNull(state.trust) }, { state.floor(it) }, ::accept)
    }

    private fun accept(doc: RemoteVerifier.Authenticated, exchange: RemoteSync.Exchange): RemoteFailure? {
        val next = when (doc.type) {
            DocumentType.KEY_SET -> state.copy(trust = doc.rotatedTrust())
            DocumentType.POLICY -> {
                unprojectable(doc.body.obj("policy"))?.let { return it }
                state.copy(
                    policy = CommittedPolicy(RemoteCrypto.encode(doc.payload), doc.committedSha256, doc.version),
                    overrides = emptySet()
                )
            }
            DocumentType.RECOVERY -> {
                val salt = doc.body.text("salt")
                val mac = try {
                    recoveryMac(RemoteCrypto.decode(salt) + RemoteCrypto.decode(doc.body.text("verifier")), true)
                } catch (_: Exception) {
                    return WRITE_FAILED
                }
                state.copy(recoveryVersion = doc.version, recovery = RecoveryVerifier(salt, RemoteCrypto.encode(mac)))
            }
            DocumentType.COMMAND -> {
                if (RemoteOverride.COMMANDS_OFF in state.overrides) return RemoteFailure("commands-suspended-by-recovery")
                val entry = CommandEntry(doc.version, doc.body.text("kind"), exchange.sent)
                state.copy(commandFloor = doc.version, commands = state.commands + (entry.sequence to entry))
            }
        }
        val failure = save(next)
        if (failure == null && doc.type == DocumentType.COMMAND) liveDispatches.add(doc.version)
        return failure
    }

    fun ensureProjected(): Pass {
        if (journal.lost) return Pass(false, LOST)
        if (reconciling) return Pass(false)
        reconciling = true
        return try {
            // Nothing an earlier, unverified pass exposed survives into this one.
            revokeReleases()
            val target = state.generation() ?: return Pass(false, RemoteFailure("remote-policy-unavailable"))
            val body = try {
                requireNotNull(state.policy).body(schema)
            } catch (error: Refused) {
                return Pass(false, error.failure)
            } catch (_: IllegalArgumentException) {
                return Pass(false, RemoteFailure("doc-field-invalid"))
            }
            val effective = if (RemoteOverride.NETWORK_OFF in target.overrides) {
                body + ("homeFilter" to mapOf("enabled" to false))
            } else body
            if (!projection.project(effective, target)) return Pass(false, WRITE_FAILED)
            if (state.generation() != target) return Pass(false)
            if (!journal.stamp(target)) return Pass(false, WRITE_FAILED)
            val stillCurrent = { state.generation() == target && journal.stamped(target) }
            if (!stillCurrent()) return Pass(false)
            val verified = try {
                projection.apply(target, stillCurrent, ledger)
            } catch (_: RuntimeException) {
                false
            }
            if (verified && stillCurrent()) {
                // The verified hash and the end of the release record are one commit.
                val failure = save(state.copy(verified = target, releases = emptySet()))
                if (failure == null) return Pass(true)
                revokeReleases()
                return Pass(false, failure)
            }
            revokeReleases()
            Pass(false)
        } catch (error: Refused) {
            Pass(false, error.failure)
        } catch (_: RuntimeException) {
            Pass(false, WRITE_FAILED)
        } finally {
            reconciling = false
        }
    }

    /** A package stays in the record until it is proven hidden or a pass verifies. */
    private fun revokeReleases() {
        val exposed = state.releases
        if (exposed.isEmpty()) return
        val stuck = try {
            projection.revoke(exposed)
        } catch (_: RuntimeException) {
            exposed
        }
        if (stuck != exposed) save(state.copy(releases = stuck))
    }

    fun recover(choices: Set<RemoteOverride>, code: String, now: RemoteTime): RecoveryResult {
        if (journal.lost) return RecoveryResult(RecoveryOutcome.REFUSED, LOST)
        val stored = state.recovery ?: return RecoveryResult(RecoveryOutcome.UNCHANGED)
        if (choices.isEmpty()) return RecoveryResult(RecoveryOutcome.UNCHANGED)
        if (!now.known) return RecoveryResult(RecoveryOutcome.REFUSED, codeChecked = false)
        val boot = PinLockoutPolicy.BootId.ofBootCount(now.boot)
        // BOOT_COUNT is required so the shared schedule never falls back to wall time.
        val evaluated = PinLockoutPolicy.evaluate(state.lockout, boot, now.elapsed, 0)
        if (evaluated.locked()) {
            if (evaluated.persistRequired() && !journal.save(state.copy(lockout = evaluated.state()))) {
                return RecoveryResult(RecoveryOutcome.REFUSED, RECOVERY_WRITE_FAILED, false)
            }
            return RecoveryResult(RecoveryOutcome.REFUSED, codeChecked = false, remainingMillis = evaluated.remainingMillis())
        }
        // The attempt is counted durably before the code is looked at. A store that
        // cannot count gives no answer, so it cannot be used to try codes for free.
        val counted = PinLockoutPolicy.afterFailure(evaluated.state(), boot, now.elapsed, 0)
        if (!journal.save(state.copy(lockout = counted))) {
            return RecoveryResult(RecoveryOutcome.REFUSED, RECOVERY_WRITE_FAILED)
        }
        val matches = try {
            RecoveryCode.matches(code, stored) { recoveryMac(it, false) }
        } catch (_: Exception) {
            return RecoveryResult(RecoveryOutcome.REFUSED, RECOVERY_WRITE_FAILED, false)
        }
        if (!matches) {
            return RecoveryResult(RecoveryOutcome.REFUSED, codeChecked = true, remainingMillis = counted.penaltyMillis())
        }

        val commands = state.commands.mapValues { (seq, entry) ->
            unsaved[seq] ?: when {
                entry.state == CommandState.DISPATCHING && seq !in liveDispatches ->
                    entry.copy(state = CommandState.OUTCOME_UNKNOWN, code = "dispatch-outcome-unknown")
                entry.state == CommandState.ACCEPTED ||
                    (entry.state == CommandState.DISPATCHING && seq !in callsStarted) ->
                    entry.copy(state = CommandState.CANCELLED, code = "cancelled-by-recovery")
                else -> entry
            }
        }
        val next = state.copy(recovery = null, recoveryUses = state.recoveryUses + 1,
            lockout = PinLockoutPolicy.LockoutState.CLEARED, overrides = state.overrides + choices, commands = commands)
        if (!journal.save(next)) return RecoveryResult(RecoveryOutcome.REFUSED, RECOVERY_WRITE_FAILED)
        settled()
        liveDispatches.retainAll(commands.filterValues { it.state == CommandState.DISPATCHING }.keys)
        return RecoveryResult(RecoveryOutcome.COMMITTED)
    }

    interface CommandPlatform {
        fun isDeviceSecure(): Boolean
        fun lockNow()
    }

    fun dispatch(sequence: Long, clock: () -> RemoteTime, platform: CommandPlatform): RemoteFailure? {
        if (journal.lost) return LOST
        if (sequence !in liveDispatches || sequence in unsaved) {
            return settleInterruptedCommands() ?: state.commands[sequence]?.code?.let { RemoteFailure(it) }
        }
        val accepted = state.commands.getValue(sequence)
        if (accepted.state == CommandState.DISPATCHING) return RemoteFailure("dispatch-outcome-unknown")
        if (accepted.state != CommandState.ACCEPTED) return accepted.code?.let { RemoteFailure(it) }
        val dispatching = accepted.copy(state = CommandState.DISPATCHING)
        val writeFailure = saveCommand(dispatching)
        if (writeFailure != null) return writeFailure

        val secure = try {
            if (dispatching.kind == "lock_now") platform.isDeviceSecure() else null
        } catch (_: RuntimeException) {
            return close(dispatching.copy(state = CommandState.OUTCOME_UNKNOWN, code = "dispatch-outcome-unknown"))
        }
        // A recovery may run re-entrantly before this final check. Re-read the entry and override.
        val now = clock()
        val current = state.commands.getValue(sequence)
        if (current.state != CommandState.DISPATCHING) return current.code?.let { RemoteFailure(it) }
        if (RemoteOverride.COMMANDS_OFF in state.overrides) {
            return close(current.copy(state = CommandState.CANCELLED, code = "cancelled-by-recovery"))
        }
        if (!current.fresh(now)) return close(current.copy(state = CommandState.EXPIRED, code = "command-expired"))

        callsStarted.add(sequence)
        val finished = try {
            if (secure != null) {
                platform.lockNow()
                current.copy(state = CommandState.DONE, secureLock = secure,
                    code = if (secure) null else "lock-screen-off-only")
            } else {
                val pass = ensureProjected()
                current.copy(state = CommandState.DONE, reapplyVerified = pass.verified,
                    verified = state.verified, code = pass.failure?.code)
            }
        } catch (_: RuntimeException) {
            current.copy(state = CommandState.OUTCOME_UNKNOWN, code = "dispatch-outcome-unknown")
        }
        return close(finished)
    }

    private fun close(entry: CommandEntry): RemoteFailure? {
        val failure = saveCommand(entry)
        if (failure == null) {
            liveDispatches.remove(entry.sequence)
            callsStarted.remove(entry.sequence)
            unsaved.remove(entry.sequence)
        } else {
            // The outcome is known here. It is stored as soon as the journal takes writes again.
            unsaved[entry.sequence] = entry
        }
        return failure ?: entry.code?.let { RemoteFailure(it) }
    }

    fun settleInterruptedCommands(): RemoteFailure? {
        if (journal.lost) return LOST
        val next = state.commands.mapValues { (sequence, entry) ->
            unsaved[sequence] ?: when {
                sequence in liveDispatches -> entry
                entry.state == CommandState.ACCEPTED -> entry.copy(state = CommandState.EXPIRED, code = "command-expired")
                entry.state == CommandState.DISPATCHING ->
                    entry.copy(state = CommandState.OUTCOME_UNKNOWN, code = "dispatch-outcome-unknown")
                else -> entry
            }
        }
        if (next == state.commands) return null
        return save(state.copy(commands = next)).also { if (it == null) settled() }
    }

    /** The stored journal now carries every outcome this process was holding. */
    private fun settled() {
        liveDispatches.removeAll(unsaved.keys)
        callsStarted.removeAll(unsaved.keys)
        unsaved.clear()
    }

    private fun saveCommand(entry: CommandEntry) = save(state.copy(commands = state.commands + (entry.sequence to entry)))
    private fun save(next: JournalState) = if (journal.save(next)) null else WRITE_FAILED

    companion object {
        /** Android 10: the first release that can enforce every default control and the home filter. */
        const val MIN_SDK = 29
        private val LOST = RemoteFailure("journal-lost")
        private val WRITE_FAILED = RemoteFailure("journal-write-failed")
        private val RECOVERY_WRITE_FAILED = RemoteFailure("recovery-commit-failed")
    }
}
