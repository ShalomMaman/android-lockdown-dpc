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
                attempt = { RemoteTestClient(applicationContext).run(cancelled::get) },
            )
            if (cancellations.remove(params.jobId, cancelled) && !cancelled.get()) {
                jobFinished(params, retry)
            }
        }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean {
        cancellations.remove(params.jobId)?.set(true)
        return true
    }

    private companion object {
        val executor = Executors.newSingleThreadExecutor { task ->
            Thread(task, "device-guard-remote-test").apply { isDaemon = true }
        }
    }
}

class RemoteTestLifecycleReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED || intent.action == Intent.ACTION_MY_PACKAGE_REPLACED) {
            RemoteTestScheduler.schedule(context)
        }
    }
}

internal object RemoteTestScheduler {
    private const val PERIODIC = 0x44475201
    private const val IMMEDIATE = 0x44475202

    fun eligible(context: Context): Boolean =
        BuildConfig.REMOTE_ENROLMENT_ENABLED && RemoteProvisioning.supportsArtifact(context) &&
            RemoteProvisioning.unlocked(context) && RemoteProvisioning.deviceOwner(context) &&
            ManagementModeStore.hasCommittedRemoteIntent(context)

    @JvmStatic
    fun schedule(context: Context) {
        if (!eligible(context)) return
        val scheduler = context.getSystemService(JobScheduler::class.java) ?: return
        for (id in listOf(PERIODIC, IMMEDIATE)) {
            if (scheduler.getPendingJob(id) == null && scheduler.schedule(job(context, id)) != JobScheduler.RESULT_SUCCESS) {
                Log.w("RemoteTestScheduler", "remote-job-schedule-failed")
            }
        }
    }

    internal fun job(context: Context, periodic: Boolean): JobInfo = job(context, if (periodic) PERIODIC else IMMEDIATE)

    private fun job(context: Context, id: Int): JobInfo =
        JobInfo.Builder(id, ComponentName(context, RemoteTestJobService::class.java))
            .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
            .setPersisted(true)
            .setBackoffCriteria(30_000, JobInfo.BACKOFF_POLICY_EXPONENTIAL)
            .apply { if (id == PERIODIC) setPeriodic(15 * 60_000L) }
            .build()
}

/** JobService delegates delays and process-death retry to JobScheduler. */
internal object RemoteClientCycle {
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
}

private class RemoteTestClient(private val context: Context) {
    private val store = RemoteClientStore(context)
    private val identity = AndroidRemoteIdentity(context)

    fun run(cancelled: () -> Boolean): Boolean {
        val config = store.config() ?: return false
        val api = RemoteHttps(config.server, config.pins)
        if (config.ticket != null && !enrol(api, config, config.ticket, cancelled)) return true
        val key = store.identity() ?: return true

        // Report the result of a changed policy, key rotation or command promptly.
        // Bound the number of immediate exchanges even if the server keeps changing.
        repeat(4) {
            if (cancelled()) return true
            val request = RemotePolicyRuntime.prepareSync(context) ?: return true
            try {
                val timestamp = System.currentTimeMillis() / 1000
                val signature = identity.sign(key, RemoteClientWire.syncTranscript(timestamp, request.body))
                if (cancelled()) return true
                val bytes = api.request(RemoteClientWire.SYNC, request.body, mapOf(
                    RemoteClientWire.TIMESTAMP_HEADER to timestamp.toString(),
                    RemoteClientWire.SIGNATURE_HEADER to signature,
                ))
                val result = RemotePolicyRuntime.receiveAndApply(
                    context, request.exchange, RemoteClientWire.syncReply(bytes), cancelled,
                )
                if (result.retry) return true
                if (!result.followUp) return false
            } finally {
                RemotePolicyRuntime.discardExchange(context, request.exchange)
            }
        }
        return true
    }

    private fun enrol(api: RemoteHttps, config: RemoteClientConfig, ticket: String, cancelled: () -> Boolean): Boolean {
        var pending = store.pending()
        val bound = RemotePolicyRuntime.boundDevice(context)
        if (bound != null) return pending != null && pending.deviceId == bound && store.complete(config, pending)
        if (cancelled() || !RemotePolicyRuntime.baselineVerified(context) || cancelled()) return false
        if (pending == null) {
            val body = WireJson.canonical(mapOf("ticket" to ticket))
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
        if (cancelled()) return false
        val fleet = URLEncoder.encode(device.fleetId, Charsets.UTF_8.name())
        val root = RemoteClientWire.root(api.request(RemoteClientWire.KEY_SET + "?fleetId=" + fleet), device.fleetId)
        if (cancelled() || RemotePolicyRuntime.finishEnrolment(context, device, config.root, root) != null) return false
        return store.complete(config, proof)
    }
}
