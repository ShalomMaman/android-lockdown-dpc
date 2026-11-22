package com.example.lockdowndpc.policy

import android.content.Context
import android.content.ContextWrapper
import android.content.SharedPreferences
import com.example.lockdowndpc.remote.Generation
import com.example.lockdowndpc.remote.JournalState
import com.example.lockdowndpc.remote.JsonObject
import com.example.lockdowndpc.remote.RemoteFixtures
import com.example.lockdowndpc.remote.RemoteProjection
import com.example.lockdowndpc.testing.MemoryPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [32], manifest = Config.NONE)
class RemoteProjectionStoreTest {
    private val f = RemoteFixtures

    @Test fun everyActualProjectionCommitFailsClosedInTheLiveProcess() {
        val sites = listOf(
            "lockdown_policy" to "protection_mode",
            "lockdown_policy" to "admin_selected_system_packages",
            "lockdown_policy" to "system_risk_signer:com.oem.gallery",
            "play_store_compatibility" to "compatibility_enabled",
            "system_policy" to "schema_version",
            "home_filter" to "vpn_package",
            "lockdown_policy" to "management_cert:com.tailscale.ipn",
            "kiosk_policy" to "kiosk_mode",
            "remote_policy_locale" to "choice"
        )
        val app: Context = RuntimeEnvironment.getApplication()
        val device = app.createDeviceProtectedStorageContext()
        assertTrue(device.getSharedPreferences(ManagementModeStore.MARKER_PREFS, Context.MODE_PRIVATE)
            .edit().putBoolean(ManagementModeStore.MARKER_KEY, true).commit())
        assertFalse(RemoteEnrolmentGate.permits())
        RemoteTestGate.open(true)
        try {
            everySite(app, sites)
        } finally {
            RemoteTestGate.open(false)
            AdminAuthority.CommittedPolicy.bindJournal(null)
        }
    }

    private fun everySite(app: Context, sites: List<Pair<String, String>>) {
        fun <T> onPolicyThread(work: () -> T): T =
            PolicyReconciliationCoordinator.callOnPolicyThread(java.util.function.Supplier { work() })
        for ((file, key) in sites) {
            val stores = sites.map { it.first }.distinct().associateWith {
                MemoryPreferences(emptyMap<String, Any>()).apply { failCommit = false }
            }
            val wrapper = object : ContextWrapper(app) {
                override fun getSharedPreferences(name: String, mode: Int): SharedPreferences =
                    stores[name]?.preferences() ?: super.getSharedPreferences(name, mode)
            }
            // The fixture policy carries a language, which only Android 13 and later can read back.
            val writer = RemotePolicyProjection(wrapper, sdk = 33)
            var passes = 0
            val projection = object : RemoteProjection {
                override fun project(policy: JsonObject, target: Generation) = writer.project(policy, target)
                override fun apply(target: Generation, stillCurrent: () -> Boolean): Boolean {
                    passes++
                    return stillCurrent()
                }
            }
            val old = f.generation("policy-1")
            val target = f.generation("policy-5")
            val harness = f.harness(JournalState(policy = f.policy("policy-5"), verified = old), projection)
            AdminAuthority.CommittedPolicy.bindJournal { harness.engine.state.generation()?.sha256 }
            assertTrue(harness.journal.stamp(target))
            var refused = false
            stores.getValue(file).apply {
                beforeCommit = java.util.function.Consumer { keys ->
                    failCommit = key in keys
                    refused = refused || failCommit
                }
            }
            assertEquals("$file/$key", "journal-write-failed", onPolicyThread { harness.engine.ensureProjected() }.failure?.code)
            assertTrue("$file/$key", refused)
            assertEquals(0, passes)
            assertEquals(old, harness.engine.state.verified)
            assertEquals(target, harness.engine.state.generation())

            stores.getValue(file).beforeCommit = java.util.function.Consumer { stores.getValue(file).failCommit = false }
            assertTrue("$file/$key", onPolicyThread { harness.engine.ensureProjected() }.verified)
            assertEquals(1, passes)
            assertEquals(target, harness.engine.state.verified)
        }
    }
}
