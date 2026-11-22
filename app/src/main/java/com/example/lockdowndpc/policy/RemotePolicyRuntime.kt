package com.example.lockdowndpc.policy

import android.app.KeyguardManager
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.Build
import android.os.SystemClock
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.example.lockdowndpc.remote.RemoteBinding
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
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/** Policy-thread owner of the journal. Provisioning and sync entry points are gated separately. */
internal object RemotePolicyRuntime {
    private data class Open(
        val projection: RemotePolicyProjection, val engine: RemoteEngine, val verifier: RemoteVerifier,
        var sync: RemoteSync? = null
    )

    private var open: Open? = null
    private var guardMac: (ByteArray, Boolean) -> ByteArray = ::keystoreGuardMac

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
                return LockdownPolicyController.applyRemoteContainment(context)
            }
            val pass = current.engine.reconcile()
            if (pass.failure != null) return failed(pass.failure)
            val result = current.projection.lastResult
            if (pass.verified && result != null) result
            else if (result != null && !result.applied()) result
            else failed(RemoteFailure("remote-policy-unverified"))
        } catch (_: Exception) {
            failed(RemoteFailure("journal-write-failed"))
        }
    }

    fun bindFleet(context: Context, binding: RemoteBinding, pinnedId: String, rootSpki: String): RemoteFailure? =
        onRemoteThread(context, DISABLED, WRITE_FAILED, resumeMode = false) {
            val app = context.applicationContext
            val sdk = Build.VERSION.SDK_INT
            val trust = engine.state.trust
            val interrupted = !engine.lost && sdk >= RemoteEngine.MIN_SDK && engine.state.binding == binding &&
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

    fun beginExchange(context: Context): RemoteSync.Exchange? = onRemoteThread(context, null) {
        val binding = engine.state.binding ?: return@onRemoteThread null
        if (engine.settleInterruptedCommands() != null) return@onRemoteThread null
        val sync = this.sync ?: RemoteSync(verifier, binding).also { this.sync = it }
        val nonce = ByteArray(32).also { SecureRandom().nextBytes(it) }
        sync.begin(RemoteCrypto.encode(nonce), now(context))
    }

    fun receive(context: Context, exchange: RemoteSync.Exchange, nonce: String, documents: List<RemoteDocument>):
        RemoteSync.Response = onRemoteThread(context, RemoteSync.Response(DISABLED), RemoteSync.Response(WRITE_FAILED)) {
        engine.failure?.let { return@onRemoteThread RemoteSync.Response(it) }
        val pendingSync = sync ?: return@onRemoteThread RemoteSync.Response(RemoteFailure("sync-response-stale"))
        engine.receive(pendingSync, exchange, nonce, now(context), documents)
    }

    fun recover(context: Context, choices: Set<RemoteOverride>, code: String): RemoteEngine.RecoveryResult =
        onRemoteThread(context, RemoteEngine.RecoveryResult(RemoteEngine.RecoveryOutcome.REFUSED, DISABLED),
            RemoteEngine.RecoveryResult(RemoteEngine.RecoveryOutcome.REFUSED, RemoteFailure("recovery-commit-failed"))) {
            val result = engine.recover(choices, code, now(context))
            if (result.outcome == RemoteEngine.RecoveryOutcome.COMMITTED) {
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
        context: Context, blocked: T, failed: T = blocked, resumeMode: Boolean = true, work: Open.() -> T
    ): T =
        PolicyReconciliationCoordinator.callOnPolicyThread {
            try {
                val app = context.applicationContext
                if (!remoteEnabled(app)) return@callOnPolicyThread blocked
                val current = open(app)
                current.engine.checkStores()
                // Whatever the caller came for, an exposed package is hidden again first.
                current.engine.revokeReleases()
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
        val engine = RemoteEngine(openJournal(context), schema, projection, ::recoveryMac)
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
            remoteCommitted = { ManagementModeStore.read(context) == ManagementMode.REMOTE }
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
    }

    internal fun setGuardMacForTests(mac: ((ByteArray, Boolean) -> ByteArray)?) {
        guardMac = mac ?: ::keystoreGuardMac
    }

    const val JOURNAL_PREFS = "remote_policy_journal"
    const val JOURNAL_MARKER_PREFS = "remote_policy_journal_marker"
    const val JOURNAL_GUARD_FILE = "remote-policy-guard"

    private fun failed(failure: RemoteFailure) =
        LockdownPolicyController.PolicyResult(false, false, 0, 0, listOf(failure.code))

    private fun recoveryMac(data: ByteArray, create: Boolean): ByteArray =
        keystoreMac("remote_recovery_hmac", data, create)

    private fun keystoreGuardMac(data: ByteArray, create: Boolean): ByteArray =
        keystoreMac("remote_journal_guard_hmac", data, create)

    private fun keystoreMac(alias: String, data: ByteArray, create: Boolean): ByteArray {
        val store = KeyStore.getInstance("AndroidKeyStore")
        store.load(null)
        val key = if (store.containsAlias(alias)) {
            store.getKey(alias, null) as SecretKey
        } else {
            check(create)
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore").run {
                init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setDigests(KeyProperties.DIGEST_SHA256).build())
                generateKey()
            }
        }
        return Mac.getInstance("HmacSHA256").run {
            init(key)
            doFinal(data)
        }
    }
}
