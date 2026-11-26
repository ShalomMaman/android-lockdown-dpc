package com.example.lockdowndpc.ui

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.Looper
import android.os.SystemClock
import android.view.InputDevice
import android.view.MotionEvent
import androidx.annotation.StringRes
import com.example.lockdowndpc.R
import com.example.lockdowndpc.admin.LockdownAdminReceiver
import com.example.lockdowndpc.maintenance.MaintenanceStore
import com.example.lockdowndpc.policy.AuditLog
import com.example.lockdowndpc.policy.ManagementModeStore
import com.example.lockdowndpc.policy.PolicyReconciliationCoordinator
import com.example.lockdowndpc.security.AdminSession
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [32], qualifiers = "w400dp-h800dp-mdpi")
class MaintenanceRefreshTest {
    @After
    fun tearDown() {
        AdminSession.lock()
        shadowOf(Looper.getMainLooper()).idle()
    }

    @Test
    fun swipeReReadsRestoreDebtWhileThePolicyQueueIsBusy() {
        val context = RuntimeEnvironment.getApplication()
        val dpm = requireNotNull(context.getSystemService(DevicePolicyManager::class.java))
        val admin = LockdownAdminReceiver.componentName(context)
        assertTrue(shadowOf(dpm).setDeviceOwner(admin))
        assertTrue(ManagementModeStore.selectLocal(context))
        assertTrue(context.getSharedPreferences("lockdown_policy", Context.MODE_PRIVATE).edit()
            .putBoolean("protection_enabled", true).commit())
        AdminSession.unlock()

        Robolectric.buildActivity(MaintenanceActivity::class.java).setup().use { controller ->
            val activity = controller.get()
            activity.awaitLabel(R.string.maint_section_capabilities)
            assertNull(activity.findLabel(R.string.maint_restore_failed_headline))

            assertTrue(context.getSharedPreferences("maintenance", Context.MODE_PRIVATE).edit()
                .putBoolean("restore_pending", true).commit())
            val auditBefore = AuditLog.formatted(context)
            val restrictionsBefore = dpm.getUserRestrictions(admin).keySet().toSet()

            val policyThreadOccupied = CountDownLatch(1)
            val releasePolicyThread = CountDownLatch(1)
            PolicyReconciliationCoordinator.runOnPolicyThread {
                policyThreadOccupied.countDown()
                releasePolicyThread.await(10L, TimeUnit.SECONDS)
            }
            try {
                assertTrue(policyThreadOccupied.await(5L, TimeUnit.SECONDS))
                activity.swipeDown()
                activity.awaitLabel(R.string.maint_restore_failed_headline)
            } finally {
                releasePolicyThread.countDown()
            }

            // Flush anything the gesture might have queued before checking for writes.
            val policyQueueDrained = CountDownLatch(1)
            PolicyReconciliationCoordinator.runOnPolicyThread { policyQueueDrained.countDown() }
            assertTrue(policyQueueDrained.await(5L, TimeUnit.SECONDS))
            assertTrue(MaintenanceStore.restorePending(context))
            assertEquals(auditBefore, AuditLog.formatted(context))
            assertEquals(restrictionsBefore, dpm.getUserRestrictions(admin).keySet().toSet())
        }
    }

    private fun MaintenanceActivity.awaitLabel(@StringRes id: Int) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5L)
        while (findLabel(id) == null) {
            assertTrue("Expected ${getString(id)}", System.nanoTime() < deadline)
            Thread.sleep(10L)
        }
    }

    private fun MaintenanceActivity.swipeDown() {
        val decor = window.decorView
        val downTime = SystemClock.uptimeMillis()
        val x = decor.width / 2f
        val startY = decor.height / 3f
        val distance = decor.height / 2f
        for (step in 0..10) {
            val action = when (step) {
                0 -> MotionEvent.ACTION_DOWN
                10 -> MotionEvent.ACTION_UP
                else -> MotionEvent.ACTION_MOVE
            }
            val event = MotionEvent.obtain(
                downTime, SystemClock.uptimeMillis(), action, x, startY + distance * step / 10f, 0,
            ).apply { source = InputDevice.SOURCE_TOUCHSCREEN }
            try {
                dispatchTouchEvent(event)
            } finally {
                event.recycle()
            }
            shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(16))
        }
    }
}
