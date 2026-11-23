package com.example.lockdowndpc.policy

import android.app.job.JobInfo
import android.net.NetworkCapabilities
import android.os.UserManager
import com.example.lockdowndpc.remote.RemoteHttpRefusal
import java.net.ConnectException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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
}
