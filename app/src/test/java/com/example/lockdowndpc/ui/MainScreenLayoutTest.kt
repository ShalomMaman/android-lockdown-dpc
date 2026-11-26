package com.example.lockdowndpc.ui

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.graphics.Bitmap
import android.graphics.Canvas
import android.os.Looper
import android.view.View
import androidx.activity.ComponentActivity
import androidx.annotation.StringRes
import androidx.compose.ui.InternalComposeUiApi
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.layout.LayoutInfo
import androidx.compose.ui.platform.AndroidUiDispatcher
import androidx.compose.ui.platform.ViewRootForTest
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsNode
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getAllSemanticsNodes
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.text.AnnotatedString
import androidx.lifecycle.lifecycleScope
import com.example.lockdowndpc.R
import com.example.lockdowndpc.admin.LockdownAdminReceiver
import com.example.lockdowndpc.policy.ManagementMode
import com.example.lockdowndpc.security.AdminPinStore
import com.example.lockdowndpc.security.AdminSession
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.async
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import java.io.File
import java.time.Duration
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import kotlin.math.roundToInt

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [32], shadows = [LayoutTestPinKey::class])
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@OptIn(InternalComposeUiApi::class)
class MainScreenLayoutTest {
    @Test
    fun mainScreensFitShortViewports() {
        val context = RuntimeEnvironment.getApplication()
        val dpm = requireNotNull(context.getSystemService(DevicePolicyManager::class.java))
        assertTrue(shadowOf(dpm).setDeviceOwner(LockdownAdminReceiver.componentName(context)))
        assertTrue(AdminPinStore.setInitialPin(context, TestPin))
        installInventoryFixture(context)

        val results = mutableListOf<Measurement>()
        val overflow = linkedSetOf<String>()
        val mode = context.getSharedPreferences("management_mode", Context.MODE_PRIVATE)
        try {
            for (width in listOf(360, 390, 768, 1024)) {
                RuntimeEnvironment.setQualifiers("en-rUS-w${width}dp-h${ViewportHeight}dp-mdpi")
                assertTrue(mode.edit().putString("mode", ManagementMode.LOCAL_PIN.name).commit())

                withActivity(MainActivity::class.java) { activity ->
                    activity.signIn()
                    results += measure(activity, "Main", width, R.string.admin_apply, overflow)
                    activity.click(R.string.admin_kiosk_row)
                    activity.click(R.string.kiosk_profile_single_app)
                    results += measure(activity, "KioskConsole", width, R.string.kiosk_action_choose_app, overflow)
                }

                for (screen in localScreens) {
                    AdminSession.unlock()
                    withActivity(screen.activity) { activity ->
                        results += measure(activity, screen.name, width, screen.mainAction, overflow) {
                            when (screen.activity) {
                                AllowedAppsActivity::class.java -> activity.nodes().any { node ->
                                    node.config.getOrNull(SemanticsProperties.ContentDescription)
                                        .orEmpty().any { "example.layout.app1" in it }
                                }
                                DeviceHealthActivity::class.java -> activity.action(screen.mainAction)?.let {
                                    SemanticsProperties.Disabled !in it.config
                                } == true
                                else -> true
                            }
                        }
                    }
                }

                // The unbound local fixture enters the shipping remote status UI without a network binding.
                assertTrue(mode.edit().putString("mode", ManagementMode.ENROLLING.name).commit())
                withActivity(MainActivity::class.java) { activity ->
                    activity.awaitLayout("RemoteConsole status") {
                        activity.nodes().any { it.hasText(activity.getString(R.string.remote_policy_unavailable)) }
                    }
                    results += measure(activity, "RemoteConsole", width, null, overflow)
                }
            }
        } finally {
            AdminSession.lock()
        }

        printReport(results)
        assertTrue(overflow.joinToString("\n", "Horizontal overflow:\n"), overflow.isEmpty())
    }

    private fun measure(
        activity: ComponentActivity,
        screen: String,
        width: Int,
        @StringRes mainAction: Int?,
        overflow: MutableSet<String>,
        contentReady: () -> Boolean = { true },
    ): Measurement {
        // Wait for the real content to replace any loading frame.
        activity.awaitLayout("$screen content") {
            (mainAction == null || activity.action(mainAction) != null) && contentReady()
        }
        val decor = activity.window.decorView
        assertEquals("$screen window width", width, decor.width)
        assertTrue("$screen has a viewport", decor.height > 0)
        val root = activity.composeRoot()
        val action = mainAction?.let {
            requireNotNull(activity.action(it)) { "$screen is missing ${activity.getString(it)}" }
        }
        val belowFirstViewport = action?.let {
            val top = it.positionInWindow.y
            val bottom = top + it.size.height
            top >= decor.height || bottom > decor.height || bottom > it.boundsInWindow.bottom + 1f
        } ?: false
        savePng(decor, "$screen-${width}dp.png")

        val nodes = activity.nodes()
        val scroll = nodes.firstOrNull { SemanticsProperties.VerticalScrollAxisRange in it.config }
        val range = scroll?.config?.getOrNull(SemanticsProperties.VerticalScrollAxisRange)
        val location = "$screen ${width}dp"
        checkHorizontalBounds(root, decor.width, location, overflow)
        val scrollDistance = if (scroll != null && SemanticsActions.ScrollToIndex in scroll.config) {
            // A LazyColumn range is expressed in item positions. Measure the actual pixels
            // consumed and check each new set of rows as they are placed.
            measureLazyScroll(activity, scroll, root, decor.width, location, overflow)
        } else {
            range?.maxValue?.invoke() ?: 0f
        }
        return Measurement(screen, width, decor.height, decor.height + scrollDistance.roundToInt(), belowFirstViewport)
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    private fun measureLazyScroll(
        activity: ComponentActivity,
        scroll: SemanticsNode,
        root: ViewRootForTest,
        windowWidth: Int,
        location: String,
        overflow: MutableSet<String>,
    ): Float {
        val scrollBy = requireNotNull(scroll.config.getOrNull(SemanticsActions.ScrollByOffset))
        val step = scroll.boundsInWindow.height / 2f
        check(step > 0f) { "$location has no visible list viewport" }
        var distance = 0f
        repeat(200) {
            // The semantics action animates the scroll and needs Compose's frame clock.
            val result = activity.lifecycleScope.async(AndroidUiDispatcher.Main) { scrollBy(Offset(0f, step)).y }
            activity.awaitLayout("$location list scroll") { result.isCompleted }
            val consumed = result.getCompleted()
            if (consumed <= 0f) return distance
            distance += consumed
            checkHorizontalBounds(root, windowWidth, location, overflow)
        }
        error("$location did not reach the end of the list")
    }

    private fun checkHorizontalBounds(
        root: ViewRootForTest,
        windowWidth: Int,
        location: String,
        overflow: MutableSet<String>,
    ) {
        val info = root.semanticsOwner.unmergedRootSemanticsNode.layoutInfo
        val origin = info.coordinates
        val windowX = origin.localToWindow(Offset.Zero).x
        val horizontalScrollers = root.semanticsOwner.getAllSemanticsNodes(mergingEnabled = false)
            .filter { SemanticsProperties.HorizontalScrollAxisRange in it.config }
            .associateBy { it.id }

        fun checkBounds(node: LayoutInfo, left: Float, right: Float, width: Int) {
            if (width > windowWidth || left < 0f || left >= windowWidth || right > windowWidth) {
                overflow += "$location node ${node.semanticsId}: x=$left..$right, width=$width " +
                    "(window 0..$windowWidth)"
            }
        }

        for (node in placedLayoutNodes(info, horizontalScrollers.keys)) {
            val scroller = horizontalScrollers[node.semanticsId]
            if (scroller != null) {
                // Horizontal scroll content can extend past its viewport by design.
                val left = scroller.positionInWindow.x
                val width = scroller.size.width
                if (width > 0) checkBounds(node, left, left + width, width)
                continue
            }
            val coordinates = listOf(node.coordinates) + node.getModifierInfo().map { it.coordinates }
            for (coordinate in coordinates) {
                if (!coordinate.isAttached || coordinate.size.width == 0) continue
                // Semantic bounds clip at ancestors. Raw layout bounds reveal overflows even
                // in clipped children and in content below the first viewport.
                val bounds = origin.localBoundingBoxOf(coordinate, clipBounds = false)
                checkBounds(node, windowX + bounds.left, windowX + bounds.right, coordinate.size.width)
            }
        }
    }

    private fun placedLayoutNodes(info: LayoutInfo, horizontalScrollerIds: Set<Int>): Sequence<LayoutInfo> = sequence {
        if (!info.isPlaced || !info.isAttached || info.isDeactivated) return@sequence
        yield(info)
        if (info.semanticsId in horizontalScrollerIds) return@sequence
        for (child in ComposeLayoutTree.children(info)) yieldAll(placedLayoutNodes(child, horizontalScrollerIds))
    }

    private fun ComponentActivity.signIn() {
        awaitLayout("Main PIN field") { nodes().any { SemanticsActions.SetText in it.config } }
        val field = nodes().first { SemanticsActions.SetText in it.config }
        val setText = requireNotNull(field.config.getOrNull(SemanticsActions.SetText)?.action)
        assertTrue(setText(AnnotatedString(TestPin)))
        click(R.string.locked_unlock)
    }

    private fun ComponentActivity.click(@StringRes id: Int) {
        awaitLayout(getString(id)) { action(id) != null }
        val click = requireNotNull(action(id)?.config?.getOrNull(SemanticsActions.OnClick)?.action)
        assertTrue(click())
        // Deliver the recomposition before taking the next measurement.
        shadowOf(Looper.getMainLooper()).idleFor(Duration.ofMillis(50))
    }

    private fun ComponentActivity.action(@StringRes id: Int): SemanticsNode? = nodes()
        .filter { it.hasText(getString(id)) }
        .mapNotNull { label ->
            generateSequence(label) { it.parent }.firstOrNull {
                SemanticsActions.OnClick in it.config || it.config.getOrNull(SemanticsProperties.Role) == Role.Button
            }
        }
        .minByOrNull { it.positionInWindow.y }

    private fun ComponentActivity.awaitLayout(description: String, ready: () -> Boolean) {
        val looper = shadowOf(Looper.getMainLooper())
        val deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos()
        do {
            looper.idleFor(Duration.ofMillis(16))
            findComposeRoot(window.decorView)?.measureAndLayoutForTest()
            if (ready()) return
            Thread.sleep(5L)
        } while (System.nanoTime() < deadline)
        error("Timed out waiting for $description")
    }

    private fun ComponentActivity.composeRoot() = requireNotNull(findComposeRoot(window.decorView))

    private fun ComponentActivity.nodes(): Sequence<SemanticsNode> {
        val root = findComposeRoot(window.decorView) ?: return emptySequence()
        fun descendants(node: SemanticsNode): Sequence<SemanticsNode> = sequence {
            yield(node)
            for (child in node.children) yieldAll(descendants(child))
        }
        return descendants(root.semanticsOwner.unmergedRootSemanticsNode)
    }

    private fun SemanticsNode.hasText(text: String) =
        config.getOrNull(SemanticsProperties.Text).orEmpty().any { it.text == text }

    private fun <T : ComponentActivity> withActivity(type: Class<T>, test: (T) -> Unit) {
        Robolectric.buildActivity(type).setup().use { test(it.get()) }
        shadowOf(Looper.getMainLooper()).idle()
    }

    private fun savePng(view: View, name: String) {
        // Gradle's Android unit-test worker runs from the app module directory.
        val directory = File("build/layout-shots")
        check(directory.isDirectory || directory.mkdirs()) { "Could not create $directory" }
        val bitmap = Bitmap.createBitmap(view.width, view.height, Bitmap.Config.ARGB_8888)
        try {
            view.draw(Canvas(bitmap))
            File(directory, name).outputStream().use {
                check(bitmap.compress(Bitmap.CompressFormat.PNG, 100, it)) { "Could not encode $name" }
            }
        } finally {
            bitmap.recycle()
        }
    }

    private fun installInventoryFixture(context: Context) {
        val pm = shadowOf(context.packageManager)
        for (index in 1..20) {
            val name = "example.layout.app$index"
            pm.installPackage(PackageInfo().apply {
                packageName = name
                applicationInfo = ApplicationInfo().apply {
                    packageName = name
                    flags = ApplicationInfo.FLAG_INSTALLED
                    enabled = true
                    nonLocalizedLabel = "Layout example app $index"
                }
            })
        }
    }

    private fun printReport(results: List<Measurement>) {
        for (result in results) {
            if (result.contentHeight > 3 * result.viewportHeight) {
                println("Layout advisory: ${result.screen} at ${result.width}dp exceeds 3 viewports")
            }
            if (result.actionBelowFirstViewport) {
                println("Layout advisory: ${result.screen} at ${result.width}dp has a main action below the first viewport")
            }
        }
        println("Longest screens (largest measured height per screen)")
        println("Screen               Width (dp)  Content (dp)")
        results.sortedByDescending { it.contentHeight }.distinctBy { it.screen }.take(3).forEach {
            println("%-20s %10d %13d".format(it.screen, it.width, it.contentHeight))
        }
    }

    private data class Measurement(
        val screen: String,
        val width: Int,
        val viewportHeight: Int,
        val contentHeight: Int,
        val actionBelowFirstViewport: Boolean,
    )

    private data class Screen(
        val name: String,
        val activity: Class<out ComponentActivity>,
        @StringRes val mainAction: Int,
    )

    private companion object {
        const val TestPin = "123456"
        const val ViewportHeight = 640
        val localScreens = listOf(
            Screen("AllowedApps", AllowedAppsActivity::class.java, R.string.sysinv_save),
            Screen("SystemPolicy", SystemPolicyActivity::class.java, R.string.system_policy_apply),
            Screen("HomeFilter", HomeFilterActivity::class.java, R.string.home_filter_enable),
            Screen("Maintenance", MaintenanceActivity::class.java, R.string.maint_action_review),
            Screen("ManagementIdentity", ManagementIdentityActivity::class.java, R.string.mgmtid_action_add_manual),
            Screen("DeviceHealth", DeviceHealthActivity::class.java, R.string.health_export_action),
        )
    }
}

// Keep the real PIN flow and session gates. Only stand in for the device's hardware-backed key.
@Implements(AdminPinStore::class)
class LayoutTestPinKey {
    companion object {
        @JvmStatic
        @Implementation
        fun getOrCreateHmacKey(): SecretKey = SecretKeySpec(ByteArray(32), "HmacSHA256")
    }
}
