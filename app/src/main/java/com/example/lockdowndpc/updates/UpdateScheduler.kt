package com.example.lockdowndpc.updates

import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.content.ComponentName
import android.content.Context

object UpdateScheduler {
    private const val PERIODIC_JOB_ID = 0x44555044
    private const val INITIAL_JOB_ID = 0x44555045
    private const val PERIOD_MS = 24L * 60L * 60L * 1_000L
    private const val FLEX_MS = 6L * 60L * 60L * 1_000L

    @JvmStatic
    fun schedule(context: Context) {
        val scheduler = context.getSystemService(JobScheduler::class.java) ?: return
        if (!UpdateConfig.isConfigured) {
            scheduler.cancel(PERIODIC_JOB_ID)
            scheduler.cancel(INITIAL_JOB_ID)
            return
        }
        val component = ComponentName(context, UpdateCheckJobService::class.java)
        if (scheduler.getPendingJob(PERIODIC_JOB_ID) == null) {
            val periodicJob = JobInfo.Builder(
                PERIODIC_JOB_ID,
                component,
            )
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .setPersisted(true)
                .setPeriodic(PERIOD_MS, FLEX_MS)
                .setBackoffCriteria(30L * 60L * 1_000L, JobInfo.BACKOFF_POLICY_EXPONENTIAL)
                .build()
            scheduler.schedule(periodicJob)
        }

        // A newly bootstrapped build should verify its channel as soon as a
        // network is available instead of waiting for the first daily window.
        if (UpdateStateStore.read(context).lastCheckedAt == 0L &&
            scheduler.getPendingJob(INITIAL_JOB_ID) == null
        ) {
            val initialJob = JobInfo.Builder(INITIAL_JOB_ID, component)
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .setBackoffCriteria(30L * 60L * 1_000L, JobInfo.BACKOFF_POLICY_EXPONENTIAL)
                .build()
            scheduler.schedule(initialJob)
        }
    }
}
