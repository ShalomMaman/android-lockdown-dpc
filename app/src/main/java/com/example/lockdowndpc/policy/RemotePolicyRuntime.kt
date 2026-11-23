package com.example.lockdowndpc.policy

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.Build
import android.os.SystemClock
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.KeyPermanentlyInvalidatedException
import com.example.lockdowndpc.BuildConfig
import com.example.lockdowndpc.health.DeviceHealthCollector
import com.example.lockdowndpc.health.DeviceHealthRedaction
import com.example.lockdowndpc.remote.DocumentType
import com.example.lockdowndpc.remote.JsonObject
import com.example.lockdowndpc.remote.RecoveryPinFile
import com.example.lockdowndpc.remote.RemoteReanchor
import com.example.lockdowndpc.remote.RemoteBinding
import com.example.lockdowndpc.remote.RemoteClientWire
import com.example.lockdowndpc.remote.RemoteClientWire.fields
import com.example.lockdowndpc.remote.RemoteCrypto
import com.example.lockdowndpc.remote.RemoteDocument
import com.example.lockdowndpc.remote.RemoteEngine
import com.example.lockdowndpc.remote.RemoteFailure
import com.example.lockdowndpc.remote.RemoteJournal
import com.example.lockdowndpc.remote.RemoteJournalGuardFile
import com.example.lockdowndpc.remote.RemoteOverride
import com.example.lockdowndpc.remote.RemoteSchema
import com.example.lockdowndpc.remote.RemoteSync
import com.example.lockdowndpc.remote.RemoteTime
import com.example.lockdowndpc.remote.RemoteVerifier
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.security.KeyStore
import java.security.SecureRandom
import java.security.UnrecoverableKeyException
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Policy-thread owner of the journal. Provisioning and sync entry points are gated separately. */
internal object RemotePolicyRuntime {
    private data class Open(
        val projection: RemotePolicyProjection, val engine: RemoteEngine, val verifier: RemoteVerifier,
        var sync: RemoteSync? = null, var syncErrors: List<String> = emptyList()
    )

    private var open: Open? = null
    private var guardMac: (ByteArray, Boolean) -> ByteArray = ::keystoreGuardMac
    private var pinMac: (ByteArray, Boolean) -> ByteArray = ::keystorePinMac
    private val policyRefusal = MutableStateFlow<String?>(null)
    val policyRefusals = policyRefusal.asStateFlow()

    @JvmStatic
    fun reconcile(context: Context): LockdownPolicyController.PolicyResult {
        if (!remoteEnabled(context)) {
            return RemotePolicyApplier.refusedLegacyPass()
        }
        return try {
            val current = open(context.applicationContext)
            // With a storage failure Android keeps the restrictions of the last pass.
            current.engine.checkStores()?.let { return failed(it) }
            if (!commitRemoteMode(context, current.engine)) {
                current.engine.revokeReleases()
                return failed(WRITE_FAILED)
            }
            // Before enrolment commits the baseline there is no generation to project.
            // The stores are still untouched, so the marker's containment pass applies.
            if (current.engine.state.policy == null) {
                // The live restrictions are the baseline after a re-anchor.
                if (current.engine.state.reanchored) return failed(DISABLED)
                if (!BuildConfig.REMOTE_ENROLMENT_ENABLED) return LockdownPolicyController.applyRemoteContainment(context)
                current.engine.commitBaseline(RemoteProvisioning.baseline())?.let { return failed(it) }
            }
            val pass = current.engine.reconcile()
            if (pass.failure != null) {
                if (isInlinePolicyRefusal(pass.failure.code)) policyRefusal.value = pass.failure.code
                return failed(pass.failure)
            }
            val result = current.projection.lastResult
            if (pass.verified && current.engine.state.reanchored && !ManagementModeStore.commitRemote(context)) {
                return failed(WRITE_FAILED)
            }
            if (pass.verified && result != null) result
            else if (result != null && !result.applied()) result
            else failed(RemoteFailure("remote-policy-unverified"))
        } catch (_: Exception) {
            failed(RemoteFailure("journal-write-failed"))
        }
    }

    fun baselineVerified(context: Context): Boolean = onRemoteThread(context, false) {
        if (engine.state.reanchored || engine.state.policy?.version?.let { it != 0L } == true) {
            return@onRemoteThread false
        }
        if (engine.state.policy == null && engine.commitBaseline(RemoteProvisioning.baseline()) != null) {
            return@onRemoteThread false
        }
        val generation = engine.state.generation()
        engine.failure == null && generation != null &&
            (engine.state.verified == generation || engine.reconcile().verified)
    }

    fun boundDevice(context: Context): String? = onRemoteThread(context, null, revoke = false) {
        if (engine.failure != null || (engine.state.trust?.version ?: 0L) == 0L) null
        else engine.state.binding?.deviceId
    }

    fun finishEnrolment(
        context: Context, device: RemoteClientWire.Enrolled, pin: String, root: String,
    ): RemoteFailure? = onRemoteThread(context, DISABLED, WRITE_FAILED, resumeMode = false) {
        engine.installEnrolmentKeySet(verifier, RemoteBinding(device.fleetId, device.deviceId), pin, root,
            device.keySet, Build.VERSION.SDK_INT)?.let { return@onRemoteThread it }
        WRITE_FAILED.takeUnless { ManagementModeStore.commitRemote(context) }
    }

    fun bindFleet(context: Context, binding: RemoteBinding, pinnedId: String, rootSpki: String): RemoteFailure? =
        onRemoteThread(context, DISABLED, WRITE_FAILED, resumeMode = false) {
            val app = context.applicationContext
            val sdk = Build.VERSION.SDK_INT
            val trust = engine.state.trust
            val interrupted = !engine.lost && !engine.state.reanchored && sdk >= RemoteEngine.MIN_SDK && engine.state.binding == binding &&
                trust != null && trust.version == 0L && trust.root == rootSpki && RemoteCrypto.keyId(rootSpki) == pinnedId &&
                ManagementModeStore.read(app) == ManagementMode.ENROLLING
            if (!interrupted) {
                engine.bindFleet(verifier, binding, pinnedId, rootSpki, sdk)?.let { return@onRemoteThread it }
            }
            WRITE_FAILED.takeUnless { ManagementModeStore.commitRemote(app) }
        }

    /** Read status on the writer's thread so an in-progress two-store write is never reported as damage. */
    fun journalFailure(context: Context): RemoteFailure? = try {
        PolicyReconciliationCoordinator.callOnPolicyThread {
            val app = context.applicationContext
            if (!remoteEnabled(app)) return@callOnPolicyThread null
            open?.let { return@callOnPolicyThread it.engine.checkStores() }
            openJournal(app).failure
        }
    } catch (_: Exception) {
        RemoteJournal.JOURNAL_LOST
    }

    fun reanchorStatus(context: Context): RemoteReanchor.Status =
        onRemoteThread(context, RemoteReanchor.Status(), RemoteReanchor.Status(RemoteJournal.JOURNAL_LOST,
            error = WRITE_FAILED), resumeMode = false, revoke = false) {
            engine.reanchorStatus(now(context))
        }

    fun reanchor(context: Context, envelope: ByteArray, rootFingerprint: String?): RemoteFailure? =
        onRemoteThread(context, DISABLED, WRITE_FAILED, resumeMode = false, revoke = false) {
            val result = engine.reanchor(verifier, envelope, rootFingerprint, now(context)) {
                ManagementModeStore.commitReanchorEnrolling(context.applicationContext)
            }
            if (result == null) {
                sync = null
                policyRefusal.value = null
            }
            result
        }

    fun beginExchange(context: Context): RemoteSync.Exchange? = onRemoteThread(context, null) {
        val binding = engine.state.binding ?: return@onRemoteThread null
        if (engine.settleInterruptedCommands() != null) return@onRemoteThread null
        val sync = this.sync ?: RemoteSync(verifier, binding).also { this.sync = it }
        val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
        sync.begin(RemoteCrypto.encode(nonce), now(context))
    }

    data class SyncRequest(val exchange: RemoteSync.Exchange, val body: ByteArray)

    fun prepareSync(context: Context): SyncRequest? = onRemoteThread(context, null) {
        val generation = engine.state.generation()
        if (generation == null || engine.state.verified != generation) engine.reconcile()
        if (engine.failure != null || engine.state.generation() == null) return@onRemoteThread null
        val report = report(context, this)
        val exchange = beginExchange(context) ?: return@onRemoteThread null
        SyncRequest(exchange, RemoteClientWire.syncBody(exchange, engine.state, report))
    }

    fun discardExchange(context: Context, exchange: RemoteSync.Exchange) {
        onRemoteThread(context, Unit, revoke = false) { sync?.discard(exchange) }
    }

    fun committedPullMinutes(context: Context): Long? =
        onRemoteThread(context, null, resumeMode = false, revoke = false) { engine.committedPullMinutes() }

    fun recordSyncError(context: Context, code: String) {
        onRemoteThread(context, Unit, resumeMode = false, revoke = false) {
            syncErrors = (syncErrors + code).distinct()
        }
    }

    /** Apply an arrived response through the live exchange and its journal, even if the job stopped. */
    fun receiveAndApply(
        context: Context, exchange: RemoteSync.Exchange, reply: RemoteClientWire.SyncReply,
    ): SyncResult = onRemoteThread(context, SyncResult(retry = true)) {
        val previous = engine.state
        val response = receive(context, exchange, reply.nonce, reply.documents)
        syncErrors = listOfNotNull(response.failure?.code) +
            response.decisions.mapNotNull { it.failure?.code }.distinct()
        if (response.failure != null) return@onRemoteThread SyncResult(retry = true)
        val accepted = engine.state
        (accepted.commands.keys - previous.commands.keys).sorted().forEach { dispatch(context, it) }
        val changed = accepted.generation() != previous.generation()
        val target = engine.state.generation()
        val verified = target != null && (engine.state.verified == target || engine.ensureProjected().verified)
        if (verified && engine.state.reanchored && !ManagementModeStore.commitRemote(context)) {
            return@onRemoteThread SyncResult(retry = true)
        }
        SyncResult(retry = !verified || WRITE_FAILED.code in syncErrors,
            followUp = changed || accepted.trust != previous.trust || accepted.recoveryVersion != previous.recoveryVersion ||
                accepted.commandFloor != previous.commandFloor)
    }

    data class SyncResult(val retry: Boolean, val followUp: Boolean = false)

    private fun report(context: Context, current: Open): JsonObject {
        val health = DeviceHealthRedaction.redact(DeviceHealthCollector.read(context))
        val policy = health.policy()
        val counts = policy.packages()
        val state = current.engine.state
        return mapOf(
            "mode" to ManagementModeStore.read(context).name,
            "health" to mapOf("verification" to policy.verification().name, "ownership" to policy.ownership().name,
                "packages" to mapOf("allowed" to counts.allowed(), "blocked" to counts.blocked())),
            "passErrors" to policy.verificationErrors(),
            "syncErrors" to current.syncErrors,
            "commands" to state.commands.values.filter { it.state.finished }.sortedBy { it.sequence }.map {
                mapOf("sequence" to it.sequence, "kind" to it.kind, "state" to it.state.name, "code" to it.code,
                    "secureLock" to it.secureLock, "reapplyVerified" to it.reapplyVerified,
                    "verifiedGeneration" to it.verified?.fields("verifiedSha256"))
            },
            "recoveryUses" to state.recoveryUses,
            "auditCodes" to health.audit().map { it.eventCode() },
        )
    }

    fun receive(context: Context, exchange: RemoteSync.Exchange, nonce: String, documents: List<RemoteDocument>):
        RemoteSync.Response = onRemoteThread(context, RemoteSync.Response(DISABLED), RemoteSync.Response(WRITE_FAILED)) {
        engine.failure?.let { return@onRemoteThread RemoteSync.Response(it) }
        val pendingSync = sync ?: return@onRemoteThread RemoteSync.Response(RemoteFailure("sync-response-stale"))
        engine.receive(pendingSync, exchange, nonce, now(context), documents).also { response ->
            val policies = response.decisions.filter { documents[it.index].type == DocumentType.POLICY }
            val reason = policies.firstNotNullOfOrNull { it.failure?.code?.takeIf(::isInlinePolicyRefusal) }
            if (reason != null || policies.any { it.failure == null }) policyRefusal.value = reason
        }
    }

    private fun isInlinePolicyRefusal(code: String) =
        code == RemotePolicyProjection.LOCALE_UNSUPPORTED || code == RemotePolicyProjection.FILTER_CLEANUP_LIMIT

    fun recover(context: Context, choices: Set<RemoteOverride>, code: String): RemoteEngine.RecoveryResult =
        onRemoteThread(context, RemoteEngine.RecoveryResult(RemoteEngine.RecoveryOutcome.REFUSED, DISABLED),
            RemoteEngine.RecoveryResult(RemoteEngine.RecoveryOutcome.REFUSED, RemoteFailure("recovery-commit-failed"))) {
            val result = engine.recover(choices, code, now(context))
            if (result.outcome == RemoteEngine.RecoveryOutcome.COMMITTED) {
                RemoteTestScheduler.schedule(context)
                result.copy(projection = engine.ensureProjected())
            } else result
        }

    fun dispatch(context: Context, sequence: Long): RemoteFailure? = onRemoteThread(context, DISABLED, WRITE_FAILED) {
        engine.dispatch(sequence, { now(context) }, object : RemoteEngine.CommandPlatform {
            override fun isDeviceSecure(): Boolean =
                requireNotNull(context.getSystemService(KeyguardManager::class.java)).isDeviceSecure

            override fun lockNow() {
                val dpm = requireNotNull(context.getSystemService(DevicePolicyManager::class.java))
                check(dpm.isDeviceOwnerApp(context.packageName))
                dpm.lockNow()
            }
        })
    }

    private fun <T> onRemoteThread(
        context: Context, blocked: T, failed: T = blocked, resumeMode: Boolean = true,
        revoke: Boolean = true, work: Open.() -> T
    ): T =
        PolicyReconciliationCoordinator.callOnPolicyThread {
            try {
                val app = context.applicationContext
                if (!remoteEnabled(app)) return@callOnPolicyThread blocked
                val current = open(app)
                current.engine.checkStores()
                // Whatever the caller came for, an exposed package is hidden again first.
                if (revoke) current.engine.revokeReleases()
                if (resumeMode && !commitRemoteMode(app, current.engine)) return@callOnPolicyThread failed
                current.work()
            } catch (_: Exception) {
                failed
            }
        }

    private fun remoteEnabled(context: Context): Boolean =
        RemoteEnrolmentGate.permits() && ManagementModeStore.hasCommittedRemoteIntent(context) &&
            !ManagementModeStore.read(context).usesLocalPolicy()

    /** A restart between the journal commit and the mode commit can finish the transition. */
    private fun commitRemoteMode(context: Context, engine: RemoteEngine): Boolean =
        engine.lost || engine.state.binding == null || engine.state.trust == null ||
            engine.state.reanchored || engine.state.trust?.version == 0L ||
            ManagementModeStore.commitRemote(context)

    private fun now(context: Context) = RemoteTime(
        Settings.Global.getInt(context.contentResolver, Settings.Global.BOOT_COUNT, -1).toLong(),
        SystemClock.elapsedRealtime()
    )

    private val DISABLED = RemoteFailure(RemotePolicyApplier.UNAVAILABLE)
    private val WRITE_FAILED = RemoteFailure("journal-write-failed")

    private fun open(context: Context): Open = open ?: run {
        val schema = context.assets.open("v1.schema.json").use { RemoteSchema(it.readBytes()) }
        val projection = RemotePolicyProjection(context)
        val journal = openJournal(context).also { it.preserveLegacyPin() }
        val engine = RemoteEngine(journal, schema, projection, ::recoveryMac, recoveredModeReady = {
            ManagementModeStore.read(context) == ManagementMode.REMOTE
        })
        // Store writes are authorized only for the generation this journal holds.
        AdminAuthority.CommittedPolicy.bindJournal { if (engine.lost) null else engine.state.generation()?.sha256 }
        Open(projection, engine, RemoteVerifier(schema)).also { open = it }
    }

    private fun openJournal(context: Context): RemoteJournal {
        return RemoteJournal(
            context.getSharedPreferences(JOURNAL_PREFS, Context.MODE_PRIVATE),
            context.getSharedPreferences(JOURNAL_MARKER_PREFS, Context.MODE_PRIVATE),
            RemoteJournalGuardFile(File(context.noBackupFilesDir, JOURNAL_GUARD_FILE), guardMac),
            journalFileAbsent = { preferencesFilesAbsent(context, JOURNAL_PREFS) },
            markerFileAbsent = { preferencesFilesAbsent(context, JOURNAL_MARKER_PREFS) },
            remoteCommitted = { ManagementModeStore.hasPreviouslyBound(context) },
            recoveryPinFile = RecoveryPinFile(File(context.noBackupFilesDir, RECOVERY_PIN_FILE), pinMac)
        )
    }

    private fun preferencesFilesAbsent(context: Context, name: String): Boolean {
        val base = File(context.dataDir, "shared_prefs/$name.xml")
        return Files.notExists(base.toPath(), NOFOLLOW_LINKS) &&
            Files.notExists(File(base.path + ".bak").toPath(), NOFOLLOW_LINKS)
    }

    /** JVM tests build a new application for every test. The opened journal belongs to the previous one. */
    internal fun closeForTests() {
        open = null
        policyRefusal.value = null
    }

    internal fun setGuardMacForTests(mac: ((ByteArray, Boolean) -> ByteArray)?) {
        guardMac = mac ?: ::keystoreGuardMac
    }

    internal fun setPinMacForTests(mac: ((ByteArray, Boolean) -> ByteArray)?) {
        pinMac = mac ?: ::keystorePinMac
    }

    const val RECOVERY_PIN_FILE = "remote-recovery-pin"
    const val JOURNAL_PREFS = "remote_policy_journal"
    const val JOURNAL_MARKER_PREFS = "remote_policy_journal_marker"
    const val JOURNAL_GUARD_FILE = "remote-policy-guard"

    private fun failed(failure: RemoteFailure) =
        LockdownPolicyController.PolicyResult(false, false, 0, 0, listOf(failure.code))

    private fun recoveryMac(data: ByteArray, create: Boolean): ByteArray =
        keystoreMac("remote_recovery_hmac", data, create)

    private fun keystoreGuardMac(data: ByteArray, create: Boolean): ByteArray =
        keystoreMac("remote_journal_guard_hmac", data, create, replaceInvalidated = true)

    private fun keystorePinMac(data: ByteArray, create: Boolean): ByteArray =
        keystoreMac("remote_reanchor_pin_hmac", data, create, replaceInvalidated = true)

    private fun keystoreMac(
        alias: String, data: ByteArray, create: Boolean, replaceInvalidated: Boolean = false
    ): ByteArray {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        fun generate(): SecretKey {
            check(create)
            return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore").run {
                init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256).build())
                generateKey()
            }
        }
        fun sign(key: SecretKey): ByteArray = Mac.getInstance("HmacSHA256").run {
            init(key)
            doFinal(data)
        }
        try {
            return sign((store.getKey(alias, null) as SecretKey?) ?: generate())
        } catch (failure: Exception) {
            if (!create || !replaceInvalidated ||
                (failure !is KeyPermanentlyInvalidatedException && failure !is UnrecoverableKeyException)) throw failure
            store.deleteEntry(alias)
            return sign(generate())
        }
    }
}
