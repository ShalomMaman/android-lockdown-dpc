package com.example.lockdowndpc.ui

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.ui.InternalComposeUiApi
import androidx.compose.ui.platform.ViewRootForTest
import androidx.compose.ui.semantics.SemanticsNode
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import com.example.lockdowndpc.R
import com.example.lockdowndpc.admin.LockdownAdminReceiver
import com.example.lockdowndpc.security.AdminPinStore
import com.example.lockdowndpc.security.AdminSession
import com.example.lockdowndpc.security.LegacyAdminPinTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowSystemClock
import java.time.Duration

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [32])
class RecoveryConsoleTest {
    @Test
    fun freshConsoleIgnoresTheObsoleteMarkerOnProcessRestart() {
        val context = seedDeviceOwner()
        assertTrue(
            context.getSharedPreferences("admin_security", Context.MODE_PRIVATE).edit()
                .putBoolean("recovery_pin_reset_pending", true)
                .commit(),
        )
        AdminSession.unlock()
        assertEquals(ConsoleScreen.LOCKED, initialScreen(context))
        assertFalse(AdminSession.isUnlocked())
    }

    @Test
    fun liveGrantShowsRecoveryPinSetupAndExpiryReturnsToTheLockedScreen() {
        val context = seedDeviceOwner()
        AdminSession.unlock()
        LegacyAdminPinTest.startConsoleRecovery(context)

        Robolectric.buildActivity(MainActivity::class.java).setup().use { controller ->
            val activity = controller.get()
            assertTrue(consoleText(activity).contains(context.getString(R.string.pin_setup_title_replace)))
            assertFalse(consoleText(activity).contains(context.getString(R.string.action_cancel)))
            assertFalse(AdminSession.isUnlocked())
            activity.onBackPressedDispatcher.onBackPressed()
            assertFalse(activity.isFinishing)
            assertTrue(consoleText(activity).contains(context.getString(R.string.pin_setup_title_replace)))

            assertEquals(ConsoleScreen.PIN_SETUP, initialScreen(context))
        }

        ShadowSystemClock.advanceBy(Duration.ofMinutes(3))
        assertNull(AdminPinStore.getRecoveryGrant(context))
        assertEquals(ConsoleScreen.LOCKED, initialScreen(context))
        assertEquals(ConsoleScreen.LOCKED,
            ConsoleScreen.PIN_SETUP.afterRecoveryGrantEnds(PinSetupMode.RECOVERY, AdminSession.isUnlocked()))
    }

    @Test
    fun staleRecoverySetupReturnsToAdminWhenAnotherConsoleHasCompletedTheReset() {
        assertEquals(ConsoleScreen.ADMIN,
            ConsoleScreen.PIN_SETUP.afterRecoveryGrantEnds(PinSetupMode.RECOVERY, adminUnlocked = true))
    }

    @OptIn(InternalComposeUiApi::class)
    private fun consoleText(activity: ComponentActivity): Set<String> {
        fun findRoot(view: View): ViewRootForTest? = when (view) {
            is ViewRootForTest -> view
            is ViewGroup -> (0 until view.childCount).firstNotNullOfOrNull { findRoot(view.getChildAt(it)) }
            else -> null
        }

        fun text(node: SemanticsNode): List<String> =
            node.config.getOrNull(SemanticsProperties.Text).orEmpty().map { it.text } +
                node.children.flatMap(::text)

        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(50))
        val root = requireNotNull(findRoot(activity.window.decorView))
        return text(root.semanticsOwner.unmergedRootSemanticsNode).toSet()
    }

    private fun seedDeviceOwner(): Context {
        val context = RuntimeEnvironment.getApplication()
        val dpm = requireNotNull(context.getSystemService(DevicePolicyManager::class.java))
        assertTrue(shadowOf(dpm).setDeviceOwner(LockdownAdminReceiver.componentName(context)))
        assertTrue(
            context.getSharedPreferences("admin_security", Context.MODE_PRIVATE).edit()
                .putString("pin_salt", "AAAAAAAAAAAAAAAAAAAAAA==")
                .putString("pin_verifier", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
                .commit(),
        )

        return context
    }

    @Test
    fun backIsConsumedOnRecoveryCodeScreen() {
        assertBackStaysOn(ConsoleScreen.RECOVERY, PinSetupMode.INITIAL)
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
