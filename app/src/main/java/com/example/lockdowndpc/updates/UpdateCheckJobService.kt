package com.example.lockdowndpc.updates

import android.app.job.JobParameters
import android.app.job.JobService
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class UpdateCheckJobService : JobService() {
    override fun onStartJob(params: JobParameters): Boolean {
        val cancelled = AtomicBoolean(false)
        CANCELLATIONS[params.jobId] = cancelled
        EXECUTOR.execute {
            val result = SecureUpdateManager.checkNow(applicationContext, cancelled::get)
            if (CANCELLATIONS.remove(params.jobId, cancelled) && !cancelled.get()) {
                jobFinished(params, result == UpdateCheckResult.FAILED)
            }
        }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean {
        CANCELLATIONS.remove(params.jobId)?.set(true)
        return true
    }

    companion object {
        private val EXECUTOR = Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "secure-update-check").apply { isDaemon = true }
        }
        private val CANCELLATIONS = ConcurrentHashMap<Int, AtomicBoolean>()
    }
}
