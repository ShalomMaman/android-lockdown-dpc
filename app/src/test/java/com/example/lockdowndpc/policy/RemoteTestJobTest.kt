package com.example.lockdowndpc.policy

import android.app.job.JobInfo
import android.app.job.JobScheduler
import android.net.NetworkCapabilities
import android.os.UserManager
import com.example.lockdowndpc.remote.RemoteClockSample
import com.example.lockdowndpc.remote.RemoteHttpRefusal
import com.example.lockdowndpc.remote.RemoteSync
import com.example.lockdowndpc.remote.RemoteTime
import java.net.ConnectException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [32], manifest = Config.NONE)
class RemoteTestJobTest {
    @Test fun serverDownRequestsExponentialRetryAndRecoveryFinishesTheJob() {
        val context = RuntimeEnvironment.getApplication()
        for (periodic in listOf(false, true)) {
            val info = RemoteTestScheduler.job(context, periodic)
            assertEquals(periodic, info.isPeriodic)
            assertTrue(info.isPersisted)
            assertTrue(info.requiredNetwork?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true)
            assertEquals(JobInfo.BACKOFF_POLICY_EXPONENTIAL, info.backoffPolicy)
            assertEquals(30_000L, info.initialBackoffMillis)
        }
        assertTrue(RemoteClientCycle.run({ true }) { throw ConnectException() })
        assertTrue(RemoteClientCycle.run({ true }) { throw RemoteHttpRefusal(503, null) })
        assertFalse(RemoteClientCycle.run({ true }) { false })
    }

    @Test fun credentialLockedDeviceNeverStartsClientWork() {
        val context = RuntimeEnvironment.getApplication()
        shadowOf(context.getSystemService(UserManager::class.java)).setUserUnlocked(false)
        assertFalse(RemoteClientCycle.run({ RemoteProvisioning.unlocked(context) }) {
            throw AssertionError("Network work before first unlock")
        })
    }

    @Test fun periodicJobTracksCommittedCadenceAndLeavesImmediateJobAlone() {
        val context = RuntimeEnvironment.getApplication()
        val scheduler = requireNotNull(context.getSystemService(JobScheduler::class.java))
        val immediate = RemoteTestScheduler.job(context, periodic = false)
        assertEquals(JobScheduler.RESULT_SUCCESS, scheduler.schedule(immediate))
        val periodicId = RemoteTestScheduler.job(context, periodic = true).id

        for ((committed, expected) in listOf(null to 15L, 60L to 60L, 240L to 240L, 15L to 15L)) {
            RemoteTestScheduler.updatePeriodic(context, scheduler, committed)
            val periodic = requireNotNull(scheduler.getPendingJob(periodicId))
            assertEquals(expected * 60_000L, periodic.intervalMillis)
            RemoteTestScheduler.updatePeriodic(context, scheduler, committed)
            assertSame(periodic, scheduler.getPendingJob(periodicId))
            assertSame(immediate, scheduler.getPendingJob(immediate.id))
        }
    }

    @Test fun staleClockIsCorrectedOnceWithAFreshExchangeAndReasonInTheNextReport() {
        val server = 1_800_000_000_000L
        var wall = server + 30_000L
        val clock = RemoteSyncClock { wall }
        val errors = mutableListOf<String>()
        val discarded = mutableListOf<String>()
        val timestamps = mutableListOf<Long>()
        var nonce = 0

        assertFalse(RemoteClientCycle.sync(
            clock, cancelled = { false },
            prepare = { request("nonce-${++nonce}", errors.joinToString()) },
            send = { request, timestamp ->
                timestamps.add(timestamp)
                if (timestamps.size == 1) {
                    throw RemoteHttpRefusal(409, STALE, RemoteClockSample(server, wall))
                }
                assertEquals(STALE, request.body.decodeToString())
                assertEquals(listOf("nonce-1"), discarded)
                byteArrayOf(1)
            },
            apply = { request, _ ->
                assertEquals("nonce-2", request.exchange.nonce)
                RemotePolicyRuntime.SyncResult(retry = false)
            },
            discard = { discarded.add(it.exchange.nonce) },
            reportError = { errors.add(it) },
        ))
        assertEquals(listOf(server / 1000 + 30, server / 1000), timestamps)
        assertEquals(listOf("nonce-1", "nonce-2"), discarded)
        wall += 5_000
        assertEquals(server / 1000 + 5, clock.timestamp())
    }

    @Test fun staleClockRetryIsBoundedAndRequiresAUsableAuthenticatedDate() {
        val wall = 1_800_000_000_000L
        val usable = RemoteClockSample(wall - 10_000L, wall)
        val outsideBound = RemoteClockSample(wall + 11 * 60_000L, wall)
        for ((sample, attempts) in listOf(null to 1, outsideBound to 1, usable to 2)) {
            val clock = RemoteSyncClock { wall }
            val reports = mutableListOf<String>()
            var sent = 0
            assertFalse(RemoteClientCycle.run(ready = { true }) {
                RemoteClientCycle.sync(
                    clock, cancelled = { false },
                    prepare = { request("nonce-$sent") },
                    send = { _, _ ->
                        sent++
                        throw RemoteHttpRefusal(409, STALE, sample)
                    },
                    apply = { _, _ -> throw AssertionError("Refusal must not be applied") },
                    discard = {},
                    reportError = { reports.add(it) },
                )
            })
            assertEquals(attempts, sent)
            assertEquals(List(attempts) { STALE }, reports)
            assertEquals(wall / 1000 - if (sample == usable) 10 else 0, clock.timestamp())
        }
    }

    @Test fun cancellationAfterReplyStillAppliesItButStopsFollowUpRequests() {
        var cancelled = false
        val events = mutableListOf<String>()

        assertTrue(RemoteClientCycle.sync(
            RemoteSyncClock(), { cancelled },
            prepare = {
                events.add("prepare")
                request("nonce")
            },
            send = { _, _ ->
                events.add("send")
                cancelled = true
                byteArrayOf(42)
            },
            apply = { request, bytes ->
                assertTrue(cancelled)
                assertEquals("nonce", request.exchange.nonce)
                assertEquals(42, bytes.single().toInt())
                events.add("apply")
                RemotePolicyRuntime.SyncResult(retry = false, followUp = true)
            },
            discard = { events.add("discard") },
            reportError = { throw AssertionError(it) },
        ))
        assertEquals(listOf("prepare", "send", "apply", "discard"), events)
    }

    @Test fun cancellationDuringPreparationDiscardsTheExchangeWithoutSending() {
        var cancelled = false
        var discarded = false
        assertTrue(RemoteClientCycle.sync(
            RemoteSyncClock(), { cancelled },
            prepare = {
                cancelled = true
                request("nonce")
            },
            send = { _, _ -> throw AssertionError("Network request after cancellation") },
            apply = { _, _ -> throw AssertionError("No reply to apply") },
            discard = { discarded = true },
            reportError = { throw AssertionError(it) },
        ))
        assertTrue(discarded)
    }

    private fun request(nonce: String, report: String = "") = RemotePolicyRuntime.SyncRequest(
        RemoteSync.Exchange(nonce, RemoteTime(1, 100)), report.encodeToByteArray(),
    )

    private companion object {
        const val STALE = "sync-response-stale"
    }
}
