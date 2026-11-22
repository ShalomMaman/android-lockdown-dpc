package com.example.lockdowndpc.remote

import com.example.lockdowndpc.security.DurablePreferences
import com.example.lockdowndpc.security.PinLockoutPolicy
import com.example.lockdowndpc.testing.MemoryPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RemoteJournalTest {
    private val f = RemoteFixtures

    @Test fun everyJournalCrashAndWriteFailureVector() {
        val stores = listOf("apps-mode-selection", "apps-system-selection", "apps-system-risk-acceptance",
            "play-compatibility", "system-controls", "home-filter", "management-pins", "kiosk", "locale")
        for (raw in f.vectors("journal").items("cases")) {
            val case = raw.asObject()
            val phase = case.text("phase")
            val fault = case.text("fault")
            val initialName = case["initial"] as String?
            val targetName = case.text("target")
            val initial = initialName?.let(f::generation)
            val target = f.generation(targetName)
            val prefs = stores.associateWith {
                MemoryPreferences(initial?.let { mapOf("projected" to it.sha256) }.orEmpty()).apply { failCommit = false }
            }
            var passStarted = false
            var mixed = false
            var prematureRefused = false
            var injecting = true
            lateinit var harness: RemoteFixtures.Harness

            fun checkpoint(step: String) {
                if (!injecting || step != phase) return
                when (fault) {
                    "crash" -> throw ProcessDeath()
                    "replace-target" -> {
                        val replacement = case.text("replacement")
                        if (replacement == "policy-5-network-off") {
                            installRecovery(harness)
                            assertEquals(RemoteEngine.RecoveryOutcome.COMMITTED, harness.engine.recover(
                                setOf(RemoteOverride.NETWORK_OFF), code(), RemoteTime(4, 100)).outcome)
                        } else {
                            assertNull(harness.receive(replacement).decisions.single().failure)
                        }
                    }
                    "premature-pass" -> {
                        prematureRefused = !harness.engine.ensureProjected().verified
                    }
                }
            }

            val projection = object : RemoteProjection {
                override fun project(policy: JsonObject, target: Generation): Boolean {
                    for ((step, memory) in prefs) {
                        val store = memory.preferences()
                        memory.failCommit = injecting && phase == step && fault == "write-failed"
                        if (!DurablePreferences.commit(store, store.edit().putString("projected", target.sha256), "projected")) {
                            return false
                        }
                        checkpoint(step)
                        if (prematureRefused && injecting) return false
                    }
                    checkpoint("before-stamp")
                    return true
                }

                override fun apply(target: Generation, stillCurrent: () -> Boolean): Boolean {
                    passStarted = true
                    mixed = mixed || !stillCurrent() || prefs.values.any {
                        it.preferences().getString("projected", null) != target.sha256
                    }
                    checkpoint("pass")
                    checkpoint("read-back")
                    return true
                }
            }
            harness = f.harness(JournalState(trust = f.trust("keyset-2", "successor"),
                policy = initialName?.let(f::policy), verified = initial), projection)
            val initialStamp = (case["initialStamp"] as String?)?.let(f::generation) ?: initial
            if (phase == "matching-stamp") assertTrue(harness.journal.stamp(target))
            else if (initialStamp != null) assertTrue(harness.journal.stamp(initialStamp))
            val memory = harness.memory
            var writePhase = "journal"
            memory.beforeCommit = java.util.function.Consumer { keys ->
                val step = if ("projection_generation" in keys) "stamp" else writePhase
                memory.failCommit = injecting && fault == "write-failed" && phase == step
            }
            memory.afterCommit = java.util.function.Consumer { keys ->
                if ("projection_generation" in keys) checkpoint("stamp")
            }
            val (outcome, failure) = try {
                val policyFailure = if (targetName == "baseline") {
                    harness.engine.commitBaseline(f.hashes.obj("baseline").obj("body"))
                } else harness.receive(targetName).decisions.single().failure
                checkpoint("journal")
                writePhase = "verified"
                val passFailure = if (policyFailure == null) harness.engine.ensureProjected().failure else policyFailure
                if (prematureRefused) "refused" to null
                else if (passFailure != null) "refused" to passFailure.code
                else "reconciled" to null
            } catch (_: ProcessDeath) {
                "interrupted" to null
            }
            val before = generationName(harness.engine.state.generation())
            val verified = generationName(harness.engine.state.verified)
            val startedBefore = passStarted

            injecting = false
            if (fault == "crash") {
                harness.restart()
                prefs.values.forEach(MemoryPreferences::restart)
            }
            assertTrue(case.text("id"), harness.engine.ensureProjected().verified)
            val evidence = mutableMapOf<String, Any?>(
                "passStartedBeforeRetry" to startedBefore, "durableTargetBeforeRetry" to before,
                "verifiedBeforeRetry" to verified, "durableTargetAfterRetry" to generationName(harness.engine.state.generation()),
                "verifiedAfterRetry" to generationName(harness.engine.state.verified),
                "retryTrigger" to if (case["boot"] == true) "boot" else if (fault == "crash") "process-start" else "reconcile",
                "passReadsMixedGeneration" to mixed
            )
            if (phase == "matching-stamp") evidence["ranFullProjection"] = startedBefore
            if (fault == "premature-pass") evidence["prematurePassRefused"] = prematureRefused
            f.check(case, f.result(outcome, failure) + evidence)
        }
    }

    @Test fun failedNewestPolicyWritePreservesThePolicyAndDoesNotBlockCommandStep() {
        val old = f.generation("policy-1")
        val harness = f.harness(JournalState(trust = f.trust("keyset-2", "successor"),
            policy = f.policy("policy-1"), verified = old))
        var writes = 0
        harness.memory.beforeCommit = java.util.function.Consumer { harness.memory.failCommit = writes++ == 0 }

        val result = harness.receive("policy-5", "lock-2", "policy-6")
        assertEquals(listOf(2, 0, 1), result.decisions.map { it.index })
        assertEquals(listOf("journal-write-failed", "journal-write-failed", null), result.decisions.map { it.failure?.code })
        assertEquals(old, harness.engine.state.generation())
        assertEquals(old, harness.engine.state.verified)
        assertEquals(1L, harness.engine.state.floor(DocumentType.POLICY))
        assertEquals(6L, harness.journal.floor(DocumentType.POLICY))
        assertEquals(2L, harness.engine.state.floor(DocumentType.COMMAND))
    }

    @Test fun everyCommandDispatchVector() {
        val vectors = f.vectors("dispatch")
        val initial = vectors.obj("initial")
        val sent = RemoteTime(initial.number("boot"), initial.number("requestSentElapsedMs"))
        for (raw in vectors.items("cases")) {
            val case = raw.asObject()
            val fault = case["fault"] as String?
            val name = case.text("document")
            val sequence = f.doc(name).number("sequence")
            var calls = 0L
            val projection = object : RemoteProjection by f.noProjection {
                override fun apply(target: Generation, stillCurrent: () -> Boolean, releases: ReleaseLedger): Boolean {
                    calls++
                    return case["readBackVerified"] != false
                }
            }
            val harness = f.harness(JournalState(trust = f.trust("keyset-2", "successor"),
                policy = f.policy("policy-5"), verified = f.generation("policy-1"),
                overrides = f.overrides((case["overrides"] as? List<*>).orEmpty()),
                commandFloor = initial.number("sequenceFloor")), projection)
            installRecovery(harness)
            val sync = RemoteSync(f.verifier, f.binding)
            val exchange = requireNotNull(sync.begin(f.nonce, sent))
            harness.memory.failCommit = fault == "accept-write"
            val accepted = harness.engine.receive(sync, exchange, f.nonce, sent, listOf(f.document(name))).decisions.single()
            var failure = accepted.failure
            if (failure == null && fault != "crash-after-accepted") {
                val platform = object : RemoteEngine.CommandPlatform {
                    override fun isDeviceSecure(): Boolean {
                        if (fault == "crash-before-call") throw ProcessDeath()
                        return case["secureLock"] == true
                    }
                    override fun lockNow() {
                        calls++
                        if (case["recoveryAfterCall"] == true || fault == "done-write") {
                            assertEquals(CommandState.DISPATCHING, harness.engine.state.commands[sequence]?.state)
                            if (case["recoveryAfterCall"] == true) {
                                assertEquals(RemoteEngine.RecoveryOutcome.COMMITTED, harness.engine.recover(
                                    setOf(RemoteOverride.COMMANDS_OFF), code(), sent).outcome)
                                assertEquals(CommandState.DISPATCHING, harness.engine.state.commands[sequence]?.state)
                            }
                        }
                        if (fault == "crash-after-call") throw ProcessDeath()
                        if (fault == "done-write") harness.memory.failCommit = true
                    }
                }
                harness.memory.failCommit = fault == "dispatch-write"
                try {
                    failure = harness.engine.dispatch(sequence, {
                        (case["recoveryOverride"] as? String)?.let {
                            assertEquals(RemoteEngine.RecoveryOutcome.COMMITTED, harness.engine.recover(
                                setOf(RemoteOverride.fromCode(it)), code(), sent).outcome)
                        }
                        (case["dispatchOverrides"] as? List<*>)?.let {
                            assertTrue(harness.journal.save(harness.engine.state.copy(overrides = f.overrides(it))))
                        }
                        RemoteTime(case["dispatchBoot"] as? Long ?: sent.boot,
                            case["dispatchElapsedMs"] as? Long ?: exchange.cutoff - 1)
                    }, platform)
                } catch (_: ProcessDeath) {
                    // A new process has no live dispatch ticket.
                }
            }

            val afterRestart = if (fault == "dispatch-write") {
                assertEquals("journal-write-failed", failure?.code)
                val before = harness.engine.state.commands[sequence]
                assertEquals(CommandState.ACCEPTED, before?.state)
                harness.restart()
                assertNull(harness.engine.settleInterruptedCommands())
                val after = requireNotNull(harness.engine.state.commands[sequence])
                val evidence = dispatchResult(after, after.code, calls, sequence, case)
                f.check(case, dispatchResult(before, failure?.code, calls, sequence, case) + ("afterRestart" to evidence))
                true
            } else false
            if (afterRestart) continue
            if (fault in setOf("crash-after-accepted", "crash-before-call", "crash-after-call", "done-write")) {
                if (fault == "done-write") assertEquals("journal-write-failed", failure?.code)
                harness.restart()
                assertNull(harness.engine.settleInterruptedCommands())
                failure = harness.engine.state.commands[sequence]?.code?.let { RemoteFailure(it) }
            }
            f.check(case, dispatchResult(harness.engine.state.commands[sequence], failure?.code, calls,
                harness.engine.state.commandFloor, case))
            if (fault == "accept-write") {
                harness.restart()
                assertNull(harness.engine.failure)
                assertEquals(sequence, harness.journal.floor(DocumentType.COMMAND))
                assertNull(harness.engine.state.commands[sequence])
            }
        }
    }

    @Test fun everyRecoveryVector() {
        val data = f.vectors("recovery")
        val fixtureCode = data.obj("testCode")
        for (name in f.signedDocs.keys.filter { f.doc(it)["type"] == "recovery" }) {
            val doc = f.doc(name)
            assertEquals(name, doc.text("verifier"), RemoteCrypto.encode(requireNotNull(
                RecoveryCode.derive(fixtureCode.text("display"), RemoteCrypto.decode(doc.text("salt"))))))
        }
        f.check(fixtureCode, f.result("reproduced"))
        val initial = data.obj("initial")
        val identifiers = listOf("accepted", "dispatching", "done", "pending-dispatch")
            .withIndex().associate { it.value to (it.index + 1L) }
        for (raw in data.items("cases")) {
            val case = raw.asObject()
            val fault = case["fault"] as String?
            val merged = initial + case["initial"]?.asObject().orEmpty()
            val now = RemoteTime(case["boot"] as? Long ?: data.number("boot"),
                case["elapsedMs"] as? Long ?: data.number("elapsedMs"))
            val pending = identifiers.getValue("pending-dispatch")
            val commands = merged.obj("commandStates").map { (name, status) ->
                val seq = identifiers.getValue(name)
                seq to CommandEntry(seq, "lock_now", now, CommandState.valueOf(status as String))
            }.toMap()
            val harness = f.harness(JournalState(trust = f.trust("keyset-2", "successor"),
                policy = f.policy("policy-5"), overrides = f.overrides(merged.items("overrides")),
                commandFloor = merged.number("commandFloor"), commands = commands, recoveryUses = merged.number("uses"),
                lockout = PinLockoutPolicy.LockoutState(merged.obj("lockout").number("failures").toInt(),
                    PinLockoutPolicy.BootId.UNKNOWN, 0, 0, 0), recovery = storedRecovery()))
            val process = RemoteEngine.CommandProcess()
            if (case["restarted"] != true) {
                process.liveDispatches.addAll(commands.keys)
                val calls = (case["callsMadeOnPolicyThread"] as? List<*>) ?: data.items("callsMadeOnPolicyThread")
                process.callsStarted.addAll(calls.map { identifiers.getValue(it as String) })
            }
            var effective: JsonObject? = null
            val projection = object : RemoteProjection by f.noProjection {
                override fun project(policy: JsonObject, target: Generation): Boolean {
                    effective = policy
                    return true
                }
            }
            val engine = RemoteEngine(harness.journal, f.schema, projection, f::mac, process)
            val choices = f.overrides(case.items("choices"))
            harness.memory.failCommit = fault == "write-failed"
            val result = if (fault == "cancel-before-code" || fault == "crash-before") {
                RemoteEngine.RecoveryResult(RemoteEngine.RecoveryOutcome.UNCHANGED)
            } else engine.recover(choices, if (case["codeMatches"] == false) "2222 2222 2222 2222 2222" else code(), now)
            harness.memory.failCommit = false
            val evidence = mutableMapOf<String, Any?>()
            if (result.outcome == RemoteEngine.RecoveryOutcome.COMMITTED) {
                val entry = requireNotNull(engine.state.commands[pending])
                evidence["pendingCallOutcomeAtRecovery"] = if (pending in process.callsStarted) {
                    "command-already-executed"
                } else entry.code
            }
            if (fault == "crash-after") {
                harness.restart()
                assertNull(harness.engine.settleInterruptedCommands())
            }
            if (case["newerPolicy"] != null) {
                harness.memory.failCommit = case["newerPolicy"] == "write-failed"
                val sync = RemoteSync(f.verifier, f.binding)
                val exchange = requireNotNull(sync.begin(f.nonce, now))
                val failure = engine.receive(sync, exchange, f.nonce, now, listOf(f.document("policy-6")))
                    .decisions.single().failure
                if (harness.memory.failCommit) evidence["newerPolicyFailureCode"] = failure?.code
                else assertNull(failure)
                harness.memory.failCommit = false
            }
            val active = if (fault == "crash-after") harness.engine else engine
            if (fault == "retry") {
                val retry = active.recover(choices, code(), now)
                evidence["secondUse"] = f.result(retry.outcome.name.lowercase(), retry.failure?.code)
            }
            if (case["nextAttempt"] != null) {
                val next = active.recover(choices, code(), RemoteTime(now.boot, case.obj("nextAttempt").number("elapsedMs")))
                evidence["nextAttempt"] = recoveryResult(active.state, next, identifiers)
            }
            if (RemoteOverride.NETWORK_OFF in active.state.overrides && active === engine) {
                assertTrue(active.ensureProjected().verified)
                assertEquals(mapOf("enabled" to false), effective?.get("homeFilter"))
            }
            f.check(case, recoveryResult(active.state, result, identifiers) + evidence)
        }
    }

    @Test fun sixthWrongCodeRearmsFullPenaltyAfterRebootAndContinuesLadder() {
        val harness = f.harness(JournalState(recovery = storedRecovery()))
        val choice = setOf(RemoteOverride.NETWORK_OFF)
        val wrong = "2222 2222 2222 2222 2222"
        val expectedPenalties = listOf(0L, 0L, 0L, 0L, 60_000L, 300_000L, 1_800_000L, 3_600_000L, 3_600_000L)
        var elapsed = 100L
        for ((index, penalty) in expectedPenalties.withIndex()) {
            val boot = (index + 1).toLong()
            val result = harness.engine.recover(choice, wrong, RemoteTime(boot, elapsed))
            assertEquals(penalty, result.remainingMillis)
            assertEquals(true, result.codeChecked)
            assertEquals(index + 1, harness.engine.state.lockout.failures())
            harness.restart()
            if (penalty > 0) {
                // The right code inside a penalty is refused unread, in the next boot too.
                val blocked = harness.engine.recover(choice, code(), RemoteTime(boot + 1, 10))
                assertEquals(RemoteEngine.RecoveryOutcome.REFUSED, blocked.outcome)
                assertEquals(false, blocked.codeChecked)
                assertEquals(penalty, blocked.remainingMillis)
                assertEquals(storedRecovery(), harness.engine.state.recovery)
                assertTrue(harness.engine.state.overrides.isEmpty())
                harness.restart()
            }
            elapsed = 10 + penalty
        }
        // Once the last penalty is served, the right code works once and clears the count.
        val boot = (expectedPenalties.size + 1).toLong()
        val served = harness.engine.recover(choice, code(), RemoteTime(boot, elapsed))
        assertEquals(RemoteEngine.RecoveryOutcome.COMMITTED, served.outcome)
        harness.restart()
        assertEquals(PinLockoutPolicy.LockoutState.CLEARED, harness.engine.state.lockout)
        assertNull(harness.engine.state.recovery)
        assertEquals(choice, harness.engine.state.overrides)
    }

    @Test fun failedJournalWriteDuringRootRotationFailsClosedInProcessAndAfterRestart() {
        val initial = JournalState(trust = f.trust())
        val harness = f.harness(initial)
        harness.memory.failCommit = true
        assertEquals(RemoteJournal.GUARD_MISMATCH, harness.receive("keyset-2").decisions.single().failure)
        assertEquals(initial, harness.engine.state)
        harness.restart()
        assertEquals(initial, harness.engine.state)
        assertEquals(RemoteJournal.GUARD_MISMATCH, harness.receive("keyset-2").failure)
        assertEquals(2L, harness.journal.floor(DocumentType.KEY_SET))
    }

    @Test fun failedRecoveryWriteKeepsTheVerifierUnchangedAndRetainsTheGuardedFloor() {
        val initial = JournalState(trust = f.trust("keyset-2", "successor"))
        val harness = f.harness(initial)
        harness.memory.failCommit = true
        assertEquals("journal-write-failed", harness.receive("recovery-2").decisions.single().failure?.code)
        assertEquals(initial, harness.engine.state)
        harness.restart()
        assertEquals(initial, harness.engine.state)
        assertEquals(2L, harness.journal.floor(DocumentType.RECOVERY))
        assertEquals("doc-version-rollback", harness.receive("recovery-2").decisions.single().failure?.code)
    }

    @Test fun failedSameRootKeySetWriteKeepsTheOldKeysButRejectsHeadersBelowTheGuardedFloor() {
        val initial = JournalState(trust = f.trust(), binding = f.binding)
        val harness = f.harness(initial)
        harness.memory.failCommit = true
        assertEquals("journal-write-failed", harness.receive("keyset-2-current-root").decisions.single().failure?.code)

        harness.restart()
        assertNull(harness.engine.failure)
        assertEquals(initial.trust, harness.engine.state.trust)
        assertEquals(2L, harness.journal.floor(DocumentType.KEY_SET))
        assertEquals("doc-version-rollback", harness.receive("lock-1").decisions.single().failure?.code)
    }

    /** A5: a recovery that lands after the DISPATCHING commit still cancels the command. */
    @Test fun recoveryBetweenDispatchingCommitAndPlatformCallCancelsAndNeverLocks() {
        val harness = f.harness(JournalState(trust = f.trust("keyset-2", "successor"), policy = f.policy("policy-5")))
        installRecovery(harness)
        val sent = RemoteTime(4, 1_000)
        val sync = RemoteSync(f.verifier, f.binding)
        val exchange = requireNotNull(sync.begin(f.nonce, sent))
        assertNull(harness.engine.receive(sync, exchange, f.nonce, sent, listOf(f.document("lock-2")))
            .decisions.single().failure)
        val sequence = f.doc("lock-2").number("sequence")
        var locks = 0
        val platform = object : RemoteEngine.CommandPlatform {
            override fun isDeviceSecure() = true
            override fun lockNow() {
                locks++
            }
        }
        val failure = harness.engine.dispatch(sequence, {
            // The DISPATCHING commit is durable and the platform call has not been made.
            assertEquals(CommandState.DISPATCHING, harness.engine.state.commands[sequence]?.state)
            assertEquals(RemoteEngine.RecoveryOutcome.COMMITTED, harness.engine.recover(
                setOf(RemoteOverride.COMMANDS_OFF), code(), sent).outcome)
            sent
        }, platform)
        assertEquals("cancelled-by-recovery", failure?.code)
        assertEquals(0, locks)
        assertEquals(CommandState.CANCELLED, harness.engine.state.commands[sequence]?.state)

        harness.restart()
        assertNull(harness.engine.settleInterruptedCommands())
        assertEquals(CommandState.CANCELLED, harness.engine.state.commands[sequence]?.state)
        assertEquals("cancelled-by-recovery", harness.engine.dispatch(sequence, { sent }, platform)?.code)
        assertEquals(0, locks)
        assertEquals(setOf(RemoteOverride.COMMANDS_OFF), harness.engine.state.overrides)
    }

    /** The attempt is counted before the code is read, so a store that cannot count gives no answer. */
    @Test fun aStoreThatCannotCountAttemptsRefusesWithoutSayingWhetherTheCodeWasRight() {
        val harness = f.harness(JournalState(recovery = storedRecovery()))
        val choice = setOf(RemoteOverride.NETWORK_OFF)
        harness.memory.failCommit = true
        val wrong = harness.engine.recover(choice, "2222 2222 2222 2222 2222", RemoteTime(1, 100))
        val right = harness.engine.recover(choice, code(), RemoteTime(1, 100))
        assertEquals(wrong, right)
        assertEquals(RemoteEngine.RecoveryOutcome.REFUSED, right.outcome)
        assertEquals("recovery-commit-failed", right.failure?.code)
        assertNull(right.codeChecked)
        for (restarted in listOf(false, true)) {
            if (restarted) harness.restart()
            assertEquals(0, harness.engine.state.lockout.failures())
            assertEquals(storedRecovery(), harness.engine.state.recovery)
            assertTrue(harness.engine.state.overrides.isEmpty())
        }
        // A right code whose final commit fails has still used one counted attempt.
        var commits = 0
        harness.memory.beforeCommit = java.util.function.Consumer { harness.memory.failCommit = commits++ == 1 }
        val unsaved = harness.engine.recover(choice, code(), RemoteTime(1, 100))
        assertEquals("recovery-commit-failed", unsaved.failure?.code)
        assertEquals(1, harness.engine.state.lockout.failures())
        assertEquals(storedRecovery(), harness.engine.state.recovery)
    }

    /** A journal that existed and reads back empty or damaged is lost. It is never taken for a new one. */
    @Test fun damagedJournalOfAnEnrolledDeviceRefusesEverythingAndKeepsNoNewFloors() {
        val root = f.keys.obj("root")
        val platform = object : RemoteEngine.CommandPlatform {
            override fun isDeviceSecure() = true
            override fun lockNow() = throw AssertionError("A lost journal dispatches nothing")
        }
        for (content in listOf(null, "{", "{\"trust\":null}")) {
            var passes = 0
            val projection = object : RemoteProjection by f.noProjection {
                override fun project(policy: JsonObject, target: Generation): Boolean {
                    passes++
                    return true
                }
            }
            val harness = f.harness(JournalState(trust = f.trust("keyset-2", "successor"), binding = f.binding,
                policy = f.policy("policy-5"), verified = f.generation("policy-1"), recovery = storedRecovery(),
                commandFloor = 7), projection)
            assertFalse(harness.engine.lost)
            harness.damageJournal(content)
            for (restarted in listOf(false, true)) {
                if (restarted) harness.restart()
                val engine = harness.engine
                assertTrue(engine.lost)
                assertEquals("journal-lost", engine.bindFleet(
                    f.verifier, f.binding, root.text("keyId"), root.text("spki"), 35)?.code)
                assertEquals("journal-lost", engine.commitBaseline(f.hashes.obj("baseline").obj("body"))?.code)
                assertEquals("journal-lost", harness.receive("policy-1", "lock-2").failure?.code)
                assertEquals(RemoteFailure("journal-lost"), engine.ensureProjected().failure)
                assertEquals("journal-lost", engine.settleInterruptedCommands()?.code)
                assertEquals("journal-lost", engine.dispatch(8, { RemoteTime(1, 1) }, platform)?.code)
                val recovery = engine.recover(setOf(RemoteOverride.NETWORK_OFF), code(), RemoteTime(1, 100))
                assertEquals(RemoteEngine.RecoveryOutcome.REFUSED, recovery.outcome)
                assertEquals("journal-lost", recovery.failure?.code)
                assertFalse(harness.journal.save(JournalState()))
                assertFalse(harness.journal.stamp(f.generation("policy-1")))
            }
            assertEquals(0, passes)
        }
    }

    /** No journal write happens before its marker is stored, so a journal can never be lost without leaving one. */
    @Test fun journalIsNeverWrittenBeforeItsMarkerIsStored() {
        val root = f.keys.obj("root")
        val harness = RemoteFixtures.Harness(
            MemoryPreferences(emptyMap<String, Any>()).apply { failCommit = false }, f.noProjection)
        fun bind() = harness.engine.bindFleet(f.verifier, f.binding, root.text("keyId"), root.text("spki"), 35)

        // The marker cannot be stored. The save reports failure and the journal file is never touched.
        harness.marker.failCommit = true
        assertEquals("journal-write-failed", bind()?.code)
        assertFalse(harness.journal.save(JournalState(commandFloor = 5)))
        assertFalse(harness.journal.stamp(f.generation("policy-1")))
        assertTrue(harness.memory.preferences().all.isEmpty())
        assertEquals(JournalState(), harness.engine.state)
        // There is no journal to lose, so a device that reads as new here is new.
        harness.restart()
        assertFalse(harness.engine.lost)
        assertTrue(harness.memory.preferences().all.isEmpty())

        // With the marker stored the journal is written, and from then on an empty journal is a lost one.
        harness.marker.failCommit = false
        assertNull(bind())
        assertTrue(harness.marker.preferences().getBoolean("journal_created", false))
        harness.restart()
        assertEquals(f.binding, harness.engine.state.binding)
        harness.damageJournal(null)
        assertTrue(harness.engine.lost)
        assertEquals("journal-lost", bind()?.code)
    }

    /** The first journal write failed after the marker and guard were stored. */
    @Test fun failedFirstJournalWriteCanResumeOnlyTheRecordedBinding() {
        val root = f.keys.obj("root")
        val harness = RemoteFixtures.Harness(MemoryPreferences(emptyMap<String, Any>()), f.noProjection)
        fun bind() = harness.engine.bindFleet(f.verifier, f.binding, root.text("keyId"), root.text("spki"), 35)
        assertFalse(harness.engine.lost)
        harness.memory.failCommit = true
        assertEquals("journal-write-failed", bind()?.code)
        harness.restart()
        assertFalse(harness.engine.lost)
        assertEquals("journal-write-failed", harness.engine.bindFleet(f.verifier, f.binding.copy(fleetId = "other-fleet"),
            root.text("keyId"), root.text("spki"), 35)?.code)
        assertNull(harness.engine.state.binding)
        assertNull(bind())
        harness.restart()
        assertEquals(f.binding, harness.engine.state.binding)
    }

    @Test fun enrolmentIsRefusedBelowAndroid10() {
        val root = f.keys.obj("root")
        val harness = RemoteFixtures.Harness(
            MemoryPreferences(emptyMap<String, Any>()).apply { failCommit = false }, f.noProjection)
        for (sdk in listOf(26, 27, 28)) {
            assertEquals("enrolment-sdk-unsupported", harness.engine.bindFleet(
                f.verifier, f.binding, root.text("keyId"), root.text("spki"), sdk)?.code)
        }
        assertEquals(JournalState(), harness.engine.state)
        assertNull(harness.engine.bindFleet(f.verifier, f.binding, root.text("keyId"), root.text("spki"), 29))
        harness.restart()
        assertEquals(f.binding, harness.engine.state.binding)
    }

    @Test fun finishedCommandsArePrunedAndTheFloorAloneRefusesReplay() {
        val sent = RemoteTime(1, 100)
        val live = (1L..3L).associateWith { CommandEntry(it, "lock_now", sent) }
        val finished = (4L..43L).associateWith { CommandEntry(it, "lock_now", sent, CommandState.DONE) }
        val harness = f.harness(JournalState(trust = f.trust("keyset-2", "successor"),
            commandFloor = 43, commands = live + finished))
        for (restarted in listOf(false, true)) {
            if (restarted) harness.restart()
            val kept = harness.engine.state.commands
            assertEquals((1L..3L).toSet() + (28L..43L).toSet(), kept.keys)
            assertEquals(MAX_FINISHED_COMMANDS, kept.values.count { it.state.finished })
            assertEquals(43L, harness.engine.state.commandFloor)
        }
        // The pruned entries are gone and their sequences still cannot be replayed.
        assertEquals("doc-version-rollback", harness.receive("lock-2").decisions.single().failure?.code)
    }

    /** A known outcome is never downgraded to unknown just because its write failed once. */
    @Test fun outcomeThatCouldNotBeStoredIsRecordedOnceTheJournalTakesWritesAgain() {
        val harness = f.harness(JournalState(trust = f.trust("keyset-2", "successor"), policy = f.policy("policy-5")))
        val sent = RemoteTime(4, 1_000)
        val sync = RemoteSync(f.verifier, f.binding)
        val exchange = requireNotNull(sync.begin(f.nonce, sent))
        assertNull(harness.engine.receive(sync, exchange, f.nonce, sent, listOf(f.document("lock-2")))
            .decisions.single().failure)
        val sequence = f.doc("lock-2").number("sequence")
        var locks = 0
        val platform = object : RemoteEngine.CommandPlatform {
            override fun isDeviceSecure() = true
            override fun lockNow() {
                locks++
                harness.memory.failCommit = true
            }
        }
        assertEquals("journal-write-failed", harness.engine.dispatch(sequence, { sent }, platform)?.code)
        assertEquals(CommandState.DISPATCHING, harness.engine.state.commands[sequence]?.state)
        assertEquals("journal-write-failed", harness.engine.settleInterruptedCommands()?.code)
        assertEquals("journal-write-failed", harness.engine.dispatch(sequence, { sent }, platform)?.code)
        assertEquals(CommandState.DISPATCHING, harness.engine.state.commands[sequence]?.state)

        harness.memory.failCommit = false
        assertNull(harness.engine.settleInterruptedCommands())
        for (restarted in listOf(false, true)) {
            if (restarted) harness.restart()
            val entry = requireNotNull(harness.engine.state.commands[sequence])
            assertEquals(CommandState.DONE, entry.state)
            assertEquals(true, entry.secureLock)
            assertNull(entry.code)
            assertNull(harness.engine.settleInterruptedCommands())
            assertNull(harness.engine.dispatch(sequence, { sent }, platform))
        }
        assertEquals(1, locks)
    }

    /** What a pass made visible is in the journal first, and goes away again unless that pass verifies. */
    @Test fun releasesOfAnUnverifiedPassAreRevokedInProcessAndAfterACrash() {
        val visible = mutableSetOf<String>()
        var fault = "second-release-refused"
        var visibleAtPassStart: Set<String>? = null
        val projection = object : RemoteProjection by f.noProjection {
            override fun apply(target: Generation, stillCurrent: () -> Boolean, releases: ReleaseLedger): Boolean {
                visibleAtPassStart = visible.toSet()
                assertTrue(releases.record(setOf("org.example.one", "org.example.two")))
                visible.add("org.example.one")
                if (fault == "second-release-refused") return false
                if (fault == "process-death") throw ProcessDeath()
                visible.add("org.example.two")
                return true
            }

            override fun revoke(packages: Set<String>): Set<String> {
                visible.removeAll(packages)
                return emptySet()
            }
        }
        val old = f.generation("policy-1")
        val target = f.generation("policy-5")
        val harness = f.harness(JournalState(policy = f.policy("policy-5"), verified = old), projection)

        assertFalse(harness.engine.ensureProjected().verified)
        assertTrue(visible.isEmpty())
        assertTrue(harness.engine.state.releases.isEmpty())
        assertEquals(old, harness.engine.state.verified)

        fault = "process-death"
        try {
            harness.engine.ensureProjected()
            throw AssertionError("The pass must die after the first release")
        } catch (_: ProcessDeath) {
            // Nothing in this process can undo the release any more.
        }
        assertEquals(setOf("org.example.one"), visible)
        harness.restart()
        assertEquals(setOf("org.example.one", "org.example.two"), harness.engine.state.releases)
        assertEquals(old, harness.engine.state.verified)

        // The final verified write fails: the next pass starts by hiding the leftovers, and its own releases go too.
        fault = "none"
        var stateCommits = 0
        harness.memory.beforeCommit = java.util.function.Consumer { keys ->
            if ("state" in keys) harness.memory.failCommit = ++stateCommits == 3 else harness.memory.failCommit = false
        }
        val unsaved = harness.engine.ensureProjected()
        assertEquals(emptySet<String>(), visibleAtPassStart)
        assertEquals("journal-write-failed", unsaved.failure?.code)
        assertTrue(visible.isEmpty())
        assertEquals(old, harness.engine.state.verified)

        harness.memory.beforeCommit = java.util.function.Consumer { harness.memory.failCommit = false }
        assertTrue(harness.engine.ensureProjected().verified)
        assertEquals(setOf("org.example.one", "org.example.two"), visible)
        assertTrue(harness.engine.state.releases.isEmpty())
        harness.restart()
        assertEquals(target, harness.engine.state.verified)
        assertTrue(harness.engine.state.releases.isEmpty())
    }

    private fun dispatchResult(entry: CommandEntry?, code: String?, calls: Long, floor: Long, case: JsonObject): JsonObject {
        val outcome = when (entry?.state) {
            CommandState.DONE -> "executed"
            CommandState.CANCELLED -> "cancelled"
            CommandState.EXPIRED -> "expired"
            CommandState.OUTCOME_UNKNOWN -> "unknown"
            else -> "refused"
        }
        var result = f.result(outcome, code, "state" to entry?.state?.name, "sequenceFloor" to floor, "calls" to calls)
        if (entry == null) return result
        result += "cutoffElapsed" to entry.cutoff
        if (entry.state == CommandState.DONE) {
            val evidence = if (entry.kind == "lock_now") {
                mapOf("secureLock" to entry.secureLock, "effect" to "lockNow") +
                    if (case["recoveryAfterCall"] == true) mapOf("recoveryOutcome" to "command-already-executed") else emptyMap()
            } else mapOf("effect" to "ensureProjected+reconcile", "readBackVerified" to entry.reapplyVerified,
                "verifiedGeneration" to generationName(entry.verified), "syncEnqueued" to entry.shouldReport)
            result += "evidence" to evidence
        }
        return result
    }

    private fun recoveryResult(state: JournalState, result: RemoteEngine.RecoveryResult,
                               identifiers: Map<String, Long>): JsonObject {
        val networkOff = RemoteOverride.NETWORK_OFF in state.overrides
        val lockout = state.lockout
        val lock = mapOf("failures" to lockout.failures().toLong()) +
            if (lockout.penaltyArmed()) mapOf("boot" to lockout.armedBoot().value(), "untilElapsedMs" to lockout.armedElapsedDeadline())
            else emptyMap()
        var facts = f.result(result.outcome.name.lowercase(), result.failure?.code, "verifierPresent" to (state.recovery != null),
            "uses" to state.recoveryUses, "overrides" to state.overrides.map { it.code }.sorted(),
            "commandFloor" to state.commandFloor, "commandStates" to identifiers.mapValues { state.commands[it.value]?.state?.name },
            "lockout" to lock, "generation" to generationName(state.generation()),
            "cancellationCode" to if (result.outcome == RemoteEngine.RecoveryOutcome.COMMITTED) "cancelled-by-recovery" else null,
            "policyFieldsChanged" to if (networkOff) listOf("homeFilter", "homeFilterControlFloor") else emptyList<String>(),
            "rejectsNewCommands" to (RemoteOverride.COMMANDS_OFF in state.overrides))
        if (networkOff) facts += "networkReadBackTarget" to mapOf("vpnLockdown" to false, "proxy" to null, "caCertificate" to null)
        if (result.codeChecked != null) facts += "codeChecked" to result.codeChecked
        return facts
    }

    private fun generationName(generation: Generation?): String? = generation?.let { target ->
        f.hashes.obj("generations").keys.first { f.generation(it) == target }
    }

    private fun installRecovery(harness: RemoteFixtures.Harness) {
        // Install through the signed document verification and durable journal path.
        assertNull(harness.receive("recovery-2").decisions.single().failure)
    }

    private fun storedRecovery(): RecoveryVerifier {
        val doc = f.doc("recovery-2")
        val salt = doc.text("salt")
        return RecoveryVerifier(salt, RemoteCrypto.encode(f.mac(RemoteCrypto.decode(salt) + RemoteCrypto.decode(doc.text("verifier")))))
    }

    private fun code() = f.vectors("recovery").obj("testCode").text("display")
    private class ProcessDeath : Error()
}
