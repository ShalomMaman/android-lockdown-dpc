package com.example.lockdowndpc.policy

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.util.Log
import com.example.lockdowndpc.BuildConfig
import com.example.lockdowndpc.remote.RemoteClientWire
import com.example.lockdowndpc.remote.RemoteClockSample
import com.example.lockdowndpc.remote.RemoteHttpRefusal
import com.example.lockdowndpc.remote.RemoteHttps
import com.example.lockdowndpc.remote.WireJson
import java.net.URLEncoder
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class RemoteTestJobService : JobService() {
    private val cancellations = ConcurrentHashMap<Int, AtomicBoolean>()

    override fun onStartJob(params: JobParameters): Boolean {
        if (!RemoteTestScheduler.eligible(this)) return false
        val cancelled = AtomicBoolean(false)
        cancellations.put(params.jobId, cancelled)?.set(true)
        executor.execute {
            val retry = RemoteClientCycle.run(
                ready = { !cancelled.get() && RemoteTestScheduler.eligible(applicationContext) },
                attempt = {
                    val active = client ?: RemoteTestClient(applicationContext).also { client = it }
                    active.run(cancelled::get)
                },
            )
            if (cancellations.remove(params.jobId, cancelled) && !cancelled.get()) {
                jobFinished(params, retry)
            }
            RemoteTestScheduler.refreshPeriodic(applicationContext)
        }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean {
        cancellations.remove(params.jobId)?.set(true)
        return true
    }

    private companion object {
        // Only the single job executor accesses the client and its clock offset.
        var client: RemoteTestClient? = null
        val executor = Executors.newSingleThreadExecutor { task ->
            Thread(task, "device-guard-remote-test").apply { isDaemon = true }
        }
    }
}

class RemoteTestLifecycleReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED || intent.action == Intent.ACTION_MY_PACKAGE_REPLACED) {
            val pending = goAsync()
            PolicyReconciliationCoordinator.runOnPolicyThread {
                try {
                    RemoteTestScheduler.schedule(context.applicationContext)
                } finally {
                    pending?.finish()
                }
            }
        }
    }
}

internal object RemoteTestScheduler {
    private const val PERIODIC = 0x44475201
    private const val IMMEDIATE = 0x44475202
    private const val DEFAULT_PULL_MINUTES = 15L

    fun eligible(context: Context): Boolean =
        BuildConfig.REMOTE_ENROLMENT_ENABLED && RemoteProvisioning.supportsArtifact(context) &&
            RemoteProvisioning.unlocked(context) && RemoteProvisioning.deviceOwner(context) &&
            ManagementModeStore.hasCommittedRemoteIntent(context)

    @JvmStatic
    fun schedule(context: Context) = schedule(context, includeImmediate = true)

    fun refreshPeriodic(context: Context) = schedule(context, includeImmediate = false)

    private fun schedule(context: Context, includeImmediate: Boolean) {
        if (!eligible(context)) return
        PolicyReconciliationCoordinator.callOnPolicyThread {
            if (!eligible(context)) return@callOnPolicyThread
            val scheduler = context.getSystemService(JobScheduler::class.java) ?: return@callOnPolicyThread
            updatePeriodic(context, scheduler, RemotePolicyRuntime.committedPullMinutes(context))
            if (includeImmediate && scheduler.getPendingJob(IMMEDIATE) == null) {
                submit(scheduler, job(context, periodic = false))
            }
        }
    }

    internal fun updatePeriodic(context: Context, scheduler: JobScheduler, pullMinutes: Long?) {
        val interval = intervalMillis(pullMinutes)
        if (scheduler.getPendingJob(PERIODIC)?.intervalMillis != interval) {
            submit(scheduler, job(context, periodic = true, pullMinutes = pullMinutes))
        }
    }

    private fun submit(scheduler: JobScheduler, job: JobInfo) {
        if (scheduler.schedule(job) != JobScheduler.RESULT_SUCCESS) {
            Log.w("RemoteTestScheduler", "remote-job-schedule-failed")
        }
    }

    private fun intervalMillis(pullMinutes: Long?) = (pullMinutes ?: DEFAULT_PULL_MINUTES) * 60_000L

    internal fun job(context: Context, periodic: Boolean, pullMinutes: Long? = null): JobInfo =
        JobInfo.Builder(if (periodic) PERIODIC else IMMEDIATE, ComponentName(context, RemoteTestJobService::class.java))
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
            .setPersisted(true)
            .setBackoffCriteria(30_000, JobInfo.BACKOFF_POLICY_EXPONENTIAL)
            .apply { if (periodic) setPeriodic(intervalMillis(pullMinutes)) }
            .build()
}

/** JobService delegates delays and process-death retry to JobScheduler. */
internal object RemoteClientCycle {
    private const val STALE = "sync-response-stale"

    fun run(ready: () -> Boolean, attempt: () -> Boolean): Boolean {
        if (!ready()) return false
        return try {
            attempt()
        } catch (error: RemoteHttpRefusal) {
            // The caller explicitly restarts an expired challenge. Other permanent
            // refusals can be inspected on the server and retried on a later period.
            error.status == 408 || error.status == 429 || error.status >= 500
        } catch (_: Exception) {
            true
        }
    }

    fun sync(
        clock: RemoteSyncClock,
        cancelled: () -> Boolean,
        prepare: () -> RemotePolicyRuntime.SyncRequest?,
        send: (RemotePolicyRuntime.SyncRequest, Long) -> ByteArray?,
        apply: (RemotePolicyRuntime.SyncRequest, ByteArray) -> RemotePolicyRuntime.SyncResult,
        discard: (RemotePolicyRuntime.SyncRequest) -> Unit,
        reportError: (String) -> Unit,
    ): Boolean {
        var clockRetryAvailable = true
        var replies = 0
        // Report applied changes promptly, with at most four replies per job.
        while (replies < 4 && !cancelled()) {
            val request = prepare() ?: return true
            try {
                if (cancelled()) return true
                val bytes = send(request, clock.timestamp()) ?: return true
                // A received reply still belongs to this exchange after onStopJob.
                val result = apply(request, bytes)
                if (result.retry) return true
                if (!result.followUp) return false
                replies++
            } catch (error: RemoteHttpRefusal) {
                if (error.status != 409 || error.code != STALE) throw error
                reportError(STALE)
                if (!clockRetryAvailable || !clock.correct(error.clockSample)) throw error
                clockRetryAvailable = false
            } finally {
                discard(request)
            }
        }
        return true
    }
}

internal class RemoteSyncClock(private val wallMillis: () -> Long = System::currentTimeMillis) {
    private var offsetMillis = 0L

    fun timestamp(): Long = (wallMillis() + offsetMillis) / 1000

    fun correct(sample: RemoteClockSample?): Boolean {
        if (sample == null || sample.serverMillis <= 0 || sample.receivedMillis <= 0) return false
        val estimate = sample.serverMillis - sample.receivedMillis
        if (estimate !in -MAX_OFFSET_MS..MAX_OFFSET_MS) return false
        offsetMillis = estimate
        return true
    }

    private companion object {
        const val MAX_OFFSET_MS = 24 * 60 * 60_000L
    }
}

private class RemoteTestClient(private val context: Context) {
    private val store = RemoteClientStore(context)
    private val identity = AndroidRemoteIdentity(context)
    private val clock = RemoteSyncClock()

    fun run(cancelled: () -> Boolean): Boolean {
        val config = store.config() ?: return false
        val api = RemoteHttps(config.server, config.pins)
        if (config.ticket != null && !enrol(api, config, config.ticket, cancelled)) return true
        val key = store.identity() ?: return true

        return RemoteClientCycle.sync(
            clock, cancelled,
            prepare = { RemotePolicyRuntime.prepareSync(context) },
            send = { request, timestamp ->
                val signature = identity.sign(key, RemoteClientWire.syncTranscript(timestamp, request.body))
                if (cancelled()) null else api.request(RemoteClientWire.SYNC, request.body, mapOf(
                    RemoteClientWire.TIMESTAMP_HEADER to timestamp.toString(),
                    RemoteClientWire.SIGNATURE_HEADER to signature,
                ))
            },
            apply = { request, bytes ->
                RemotePolicyRuntime.receiveAndApply(context, request.exchange, RemoteClientWire.syncReply(bytes))
            },
            discard = { RemotePolicyRuntime.discardExchange(context, it.exchange) },
            reportError = { RemotePolicyRuntime.recordSyncError(context, it) },
        )
    }

    private fun enrol(api: RemoteHttps, config: RemoteClientConfig, ticket: String, cancelled: () -> Boolean): Boolean {
        var pending = store.pending()
        val bound = RemotePolicyRuntime.boundDevice(context)
        if (bound != null) return pending != null && pending.deviceId == bound && store.complete(config, pending)
        if (cancelled() || !RemotePolicyRuntime.baselineVerified(context) || cancelled()) return false
        if (pending == null) {
            val body = WireJson.canonical(mapOf("ticket" to ticket))
            if (cancelled()) return false
            val challenge = RemoteClientWire.challenge(api.request(RemoteClientWire.START, body))
            pending = RemoteClientStore.Pending(challenge)
            if (!store.savePending(pending)) return false
        }
        if (cancelled()) return false
        val proof = if (pending.finish != null) pending else {
            identity.prepare(pending.challenge, ticket, config.root).also {
                if (!store.savePending(it)) return false
            }
        }
        if (cancelled()) return false
        val device = try {
            RemoteClientWire.enrolled(api.request(RemoteClientWire.FINISH, requireNotNull(proof.finish).toByteArray()))
        } catch (failure: RemoteHttpRefusal) {
            if (failure.status != 410 || failure.code != "challenge-expired") throw failure
            if (store.savePending(null)) identity.forgetExpired(proof.challenge)
            return false
        }
        require(device.deviceId == proof.deviceId)
        val fleet = URLEncoder.encode(device.fleetId, Charsets.UTF_8.name())
        if (cancelled()) return false
        val root = RemoteClientWire.root(api.request(RemoteClientWire.KEY_SET + "?fleetId=" + fleet), device.fleetId)
        if (cancelled() || RemotePolicyRuntime.finishEnrolment(context, device, config.root, root) != null) return false
        return store.complete(config, proof)
    }
}
