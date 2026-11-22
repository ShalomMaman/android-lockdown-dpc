package com.example.lockdowndpc.ui

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.Looper
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import com.example.lockdowndpc.admin.LockdownAdminReceiver
import com.example.lockdowndpc.security.AdminSession
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [32])
class RecoveryConsoleTest {
    @Test
    fun freshConsoleRestoresTheRecoveryPinSetupGateAndDropsAnyAdminSession() {
        val context = RuntimeEnvironment.getApplication()
        val dpm = requireNotNull(context.getSystemService(DevicePolicyManager::class.java))
        assertTrue(shadowOf(dpm).setDeviceOwner(LockdownAdminReceiver.componentName(context)))
        assertTrue(
            context.getSharedPreferences("admin_security", Context.MODE_PRIVATE).edit()
                .putString("pin_salt", "previous-salt")
                .putString("pin_verifier", "previous-verifier")
                .putBoolean("recovery_pin_reset_pending", true)
                .commit(),
        )

        AdminSession.unlock()
        assertEquals(ConsoleScreen.PIN_SETUP, initialScreen(context))
        val setup = PinSetupMode.restored(context)
        assertEquals(PinSetupMode.RECOVERY, setup)
        assertTrue(setup.replacing)
        assertFalse(setup.canCancel)
        assertFalse(AdminSession.isUnlocked())
    }

    @Test
    fun backIsConsumedOnRecoveryCodeAndRecoveryPinSetupScreens() {
        assertBackStaysOn(ConsoleScreen.RECOVERY, PinSetupMode.INITIAL)
        assertBackStaysOn(ConsoleScreen.PIN_SETUP, PinSetupMode.RECOVERY)
    }

    private fun assertBackStaysOn(initial: ConsoleScreen, setup: PinSetupMode) {
        Robolectric.buildActivity(ComponentActivity::class.java).setup().use { controller ->
            val activity = controller.get()
            var screen = initial
            activity.setContent {
                ConsoleBackHandler(screen, setup, navigationBlocked = false) { screen = it }
            }
            shadowOf(Looper.getMainLooper()).idle()

            assertTrue(activity.onBackPressedDispatcher.hasEnabledCallbacks())
            activity.onBackPressedDispatcher.onBackPressed()
            assertFalse(activity.isFinishing)
            assertEquals(initial, screen)
        }
    }
}
