package com.example.lockdowndpc.ui

import android.os.Looper
import android.os.SystemClock
import android.view.View
import android.view.ViewGroup
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.annotation.StringRes
import androidx.compose.ui.InternalComposeUiApi
import androidx.compose.ui.platform.ViewRootForTest
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsNode
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import com.example.lockdowndpc.R
import com.example.lockdowndpc.policy.ManagementModeStore
import com.example.lockdowndpc.policy.PlayStoreCompatibilityStore
import com.example.lockdowndpc.policy.SystemPolicyControl
import com.example.lockdowndpc.policy.SystemPolicyStore
import com.example.lockdowndpc.security.AdminSession
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowSystemClock
import java.time.Duration

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [32])
class PolicyConfirmationScreenTest {
    @After
    fun tearDown() {
        AdminSession.lock()
        // Let Compose finish dispatching the closed activity's work before Robolectric resets the looper.
        shadowOf(Looper.getMainLooper()).idle()
    }

    @Test
    fun usbPolicyIsWrittenOnlyAfterExplicitConfirmation() = withConsole { activity ->
        val usbPolicy = SystemPolicyControl.USB_FILE_TRANSFER
        val original = SystemPolicyStore.isRequested(activity, usbPolicy)
        assertFalse(SystemPolicyStore.hasExplicitChoice(activity, usbPolicy))

        activity.tap(R.string.system_policy_control_usb_file_transfer_title)
        assertNotNull(activity.findLabel(R.string.system_policy_confirm_apply))
        assertNull(activity.findLabel(R.string.system_policy_section_schedule))
        assertFalse(SystemPolicyStore.hasExplicitChoice(activity, usbPolicy))

        activity.onBackPressedDispatcher.onBackPressed()
        assertNotNull(activity.findLabel(R.string.system_policy_section_schedule))
        assertNull(activity.findLabel(R.string.system_policy_confirm_apply))
        assertFalse(activity.isFinishing)
        assertFalse(SystemPolicyStore.hasExplicitChoice(activity, usbPolicy))
        assertEquals(original, SystemPolicyStore.isRequested(activity, usbPolicy))

        activity.tap(R.string.system_policy_control_usb_file_transfer_title)
        assertNotNull(activity.findLabel(R.string.system_policy_confirm_apply))
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(550))
        activity.tap(R.string.system_policy_confirm_apply)
        assertTrue(SystemPolicyStore.hasExplicitChoice(activity, usbPolicy))
        assertEquals(!original, SystemPolicyStore.isRequested(activity, usbPolicy))
    }

    @Test
    fun confirmTapWithinTheEntryGuardDoesNotWritePolicy() = withConsole { activity ->
        val policy = SystemPolicyControl.USB_FILE_TRANSFER
        val original = SystemPolicyStore.isRequested(activity, policy)
        val openedAt = SystemClock.uptimeMillis()
        activity.tap(R.string.system_policy_control_usb_file_transfer_title)
        val label = requireNotNull(activity.findLabel(R.string.system_policy_confirm_apply))
        val confirm = generateSequence(label) { it.parent }
            .first { it.config.getOrNull(SemanticsActions.OnClick) != null || SemanticsProperties.Disabled in it.config }
        assertTrue(SystemClock.uptimeMillis() - openedAt < 500L)
        confirm.config.getOrNull(SemanticsActions.OnClick)?.action?.invoke()

        assertFalse(SystemPolicyStore.hasExplicitChoice(activity, policy))
        assertEquals(original, SystemPolicyStore.isRequested(activity, policy))
        assertNotNull(activity.findLabel(R.string.system_policy_confirm_apply))
    }

    @Test
    fun repeatedConfirmCallbacksAreDebouncedUntilTheNextTapWindow() = withConsole { activity ->
        val usbPolicy = SystemPolicyControl.USB_FILE_TRANSFER
        val original = SystemPolicyStore.isRequested(activity, usbPolicy)

        activity.tap(R.string.system_policy_control_usb_file_transfer_title)
        assertNotNull(activity.findLabel(R.string.system_policy_confirm_apply))
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(550))
        val confirm = requireNotNull(activity.clickAction(R.string.system_policy_confirm_apply))
        confirm()
        confirm()
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(50))

        // A second delivery of the same confirm must not flip the choice back.
        assertTrue(SystemPolicyStore.hasExplicitChoice(activity, usbPolicy))
        assertEquals(!original, SystemPolicyStore.isRequested(activity, usbPolicy))
    }

    @Test
    fun playCompatibilityBackAndExpiredSessionBothLeaveTheSettingUntouched() = withConsole { activity ->
        val original = PlayStoreCompatibilityStore.isEnabled(activity)
        activity.tap(R.string.system_policy_play_compat_row)
        assertNotNull(activity.findLabel(R.string.system_policy_confirm_apply))
        assertNull(activity.findLabel(R.string.system_policy_play_compat_row))
        assertEquals(original, PlayStoreCompatibilityStore.isEnabled(activity))

        activity.onBackPressedDispatcher.onBackPressed()
        assertNotNull(activity.findLabel(R.string.system_policy_play_compat_row))
        assertNull(activity.findLabel(R.string.system_policy_confirm_apply))
        assertEquals(original, PlayStoreCompatibilityStore.isEnabled(activity))

        activity.tap(R.string.system_policy_play_compat_row)
        assertNotNull(activity.findLabel(R.string.system_policy_confirm_apply))
        ShadowSystemClock.advanceBy(Duration.ofMinutes(3))
        assertFalse(AdminSession.isUnlocked())
        activity.tap(R.string.system_policy_confirm_apply)
        assertEquals(original, PlayStoreCompatibilityStore.isEnabled(activity))
        assertNotNull(activity.findLabel(R.string.system_policy_error_auth))
    }

    private fun withConsole(test: (SystemPolicyActivity) -> Unit) {
        AdminSession.unlock()
        Robolectric.buildActivity(SystemPolicyActivity::class.java).setup().use { controller ->
            val activity = controller.get()
            assertTrue(ManagementModeStore.selectLocal(activity))
            test(activity)
        }
    }

    private fun ComponentActivity.tap(@StringRes id: Int) {
        assertTrue(requireNotNull(clickAction(id))())
    }

    private fun ComponentActivity.clickAction(@StringRes id: Int): (() -> Boolean)? {
        val label = requireNotNull(findLabel(id)) { getString(id) }
        return generateSequence(label) { it.parent }
            .firstNotNullOfOrNull { it.config.getOrNull(SemanticsActions.OnClick)?.action }
    }
}

@OptIn(InternalComposeUiApi::class)
internal fun ComponentActivity.findLabel(@StringRes id: Int): SemanticsNode? {
    shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(50))
    val root = requireNotNull(findComposeRoot(window.decorView))
    val label = getString(id)

    fun find(node: SemanticsNode): SemanticsNode? {
        if (node.config.getOrNull(SemanticsProperties.Text).orEmpty().any { it.text == label }) {
            return node
        }
        return node.children.firstNotNullOfOrNull(::find)
    }

    return find(root.semanticsOwner.unmergedRootSemanticsNode)
}

@OptIn(InternalComposeUiApi::class)
private fun findComposeRoot(view: View): ViewRootForTest? = when (view) {
    is ViewRootForTest -> view
    is ViewGroup -> (0 until view.childCount).firstNotNullOfOrNull { findComposeRoot(view.getChildAt(it)) }
    else -> null
}
