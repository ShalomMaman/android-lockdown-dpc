package com.example.lockdowndpc.policy

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.Signature
import android.content.pm.SigningInfo
import com.example.lockdowndpc.admin.LockdownAdminReceiver
import com.example.lockdowndpc.remote.CommittedPolicy
import com.example.lockdowndpc.remote.Generation
import com.example.lockdowndpc.remote.JournalState
import com.example.lockdowndpc.remote.JsonObject
import com.example.lockdowndpc.remote.RemoteFailure
import com.example.lockdowndpc.remote.RemoteFixtures
import com.example.lockdowndpc.remote.RemoteOverride
import com.example.lockdowndpc.remote.RemoteSync
import com.example.lockdowndpc.remote.RemoteTime
import com.example.lockdowndpc.remote.WireJson
import com.example.lockdowndpc.remote.obj
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.shadow.api.Shadow
import org.robolectric.shadows.ShadowPackageManager
import org.robolectric.shadows.ShadowSigningInfo

/**
 * Acceptance criterion A1 through the real journal, projection, stores and policy pass:
 * a package the previous generation hid is released only by a pass that verified.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [32], shadows = [LockdownPolicyApplyTest.FilterDevicePolicy::class])
class RemotePolicyGatewayFaultTest {
    private val f = RemoteFixtures
    private lateinit var context: Context
    private lateinit var admin: ComponentName
    private lateinit var dpm: DevicePolicyManager
    private lateinit var device: LockdownPolicyApplyTest.FilterDevicePolicy
    private lateinit var projection: RemotePolicyProjection
    private lateinit var harness: RemoteFixtures.Harness
    private lateinit var target: Generation
    private val previous = f.generation("policy-1")

    @Before fun setUp() {
        context = RuntimeEnvironment.getApplication()
        admin = LockdownAdminReceiver.componentName(context)
        dpm = context.getSystemService(DevicePolicyManager::class.java)
        device = Shadow.extract(dpm)
        assertTrue(device.setDeviceOwner(admin))
        assertTrue(context.createDeviceProtectedStorageContext()
            .getSharedPreferences(ManagementModeStore.MARKER_PREFS, Context.MODE_PRIVATE)
            .edit().putBoolean(ManagementModeStore.MARKER_KEY, true).commit())
        install(VPN)
        install(READER)
        // The previous verified generation hid the reader. The committed one allows it.
        assertTrue(dpm.setApplicationHidden(admin, READER, true))
        val committed = CommittedPolicy.fromBytes(WireJson.canonical(policy()), 0)
        target = Generation(committed.version, committed.hash, emptySet())
        projection = RemotePolicyProjection(context)
        harness = f.harness(JournalState(policy = committed, verified = previous), projection)
    }

    @Test fun vpnLockdownRefusalKeepsThePackageHiddenAndTheVerifiedHashUnchanged() {
        device.refuseVpn = true
        device.beforeVpnWrite = Runnable { assertTrue(dpm.isApplicationHidden(admin, READER)) }

        val pass = harness.engine.ensureProjected()

        assertFalse(pass.verified)
        val errors = requireNotNull(projection.lastResult).errors()
        assertTrue(errors.toString(), errors.any { it.startsWith("home-filter:vpn=REFUSED,") })
        // The projection did store the new selection; only the release waited.
        assertTrue(READER in AllowedAppsStore.getAllowedPackages(context))
        assertTrue(dpm.isApplicationHidden(admin, READER))
        assertEquals(previous, harness.engine.state.verified)
        assertEquals(target, harness.engine.state.generation())
        assertNextPassVerifiesAndReleases()
    }

    @Test fun processDeathBetweenAndroidCallsKeepsThePackageHiddenAndTheVerifiedHashUnchanged() {
        device.beforeVpnWrite = Runnable {
            assertTrue(dpm.isApplicationHidden(admin, READER))
            throw ProcessDeath()
        }
        try {
            harness.engine.ensureProjected()
            fail("The pass must reach the VPN lockdown")
        } catch (_: ProcessDeath) {
            // The process is gone between two Android calls.
        }
        harness.restart()

        assertTrue(dpm.isApplicationHidden(admin, READER))
        assertEquals(previous, harness.engine.state.verified)
        assertEquals(target, harness.engine.state.generation())
        assertNextPassVerifiesAndReleases()
    }

    @Test fun policyTheStoresCannotHoldIsRefusedBeforeTheJournalChanges() {
        val fresh = f.harness(JournalState(), projection)
        val protectedSystemApp = policy() + ("apps" to mapOf("mode" to "ALLOW_SELECTED", "allowed" to emptyList<String>(),
            "systemSelection" to listOf(mapOf("package" to "com.android.vending",
                "signerSha256" to "00".repeat(32), "versionCode" to 1L))))
        assertEquals(RemoteFailure("doc-field-invalid", "/policy/apps/systemSelection"),
            fresh.engine.commitBaseline(protectedSystemApp))
        val blockedVpn = policy() + ("homeFilter" to (policy().obj("homeFilter") + ("vpnPackage" to "com.android.chrome")))
        assertEquals(RemoteFailure("doc-field-invalid", "/policy/homeFilter/vpnPackage"),
            fresh.engine.commitBaseline(blockedVpn))
        assertNull(fresh.engine.state.policy)
        fresh.restart()
        assertNull(fresh.engine.state.policy)
        assertNull(fresh.engine.commitBaseline(policy()))
    }

    /** The build gate is off: with a marker present, no runtime entry point reaches the journal. */
    @Test fun gateOffRefusesEveryRuntimeEntryPointAndWritesNothing() {
        assertFalse(RemoteEnrolmentGate.permits())
        val unavailable = RemotePolicyApplier.UNAVAILABLE
        assertEquals(unavailable, RemotePolicyRuntime.bindFleet(context, f.binding, f.binding.deviceId, "")?.code)
        assertNull(RemotePolicyRuntime.beginExchange(context))
        assertEquals(unavailable, RemotePolicyRuntime.receive(context,
            RemoteSync.Exchange(f.nonce, RemoteTime(1, 1)), f.nonce, emptyList()).failure?.code)
        val recovery = RemotePolicyRuntime.recover(context, setOf(RemoteOverride.NETWORK_OFF), "2222 2222 2222 2222 2222")
        assertEquals(unavailable, recovery.failure?.code)
        assertEquals(unavailable, RemotePolicyRuntime.dispatch(context, 1)?.code)
        assertEquals(listOf(unavailable), RemotePolicyRuntime.reconcile(context).errors())
        assertTrue(context.getSharedPreferences("remote_policy_journal", Context.MODE_PRIVATE).all.isEmpty())
    }

    /** Once the fault is gone, the next pass verifies and only then releases the package. */
    private fun assertNextPassVerifiesAndReleases() {
        device.refuseVpn = false
        device.beforeVpnWrite = Runnable { assertTrue(dpm.isApplicationHidden(admin, READER)) }
        val pass = harness.engine.ensureProjected()
        assertTrue(projection.lastResult?.errors().toString(), pass.verified)
        assertFalse(dpm.isApplicationHidden(admin, READER))
        assertEquals(target, harness.engine.state.verified)
    }

    private fun policy(): JsonObject = mapOf(
        "managementMode" to "REMOTE",
        "protection" to mapOf("state" to "ON"),
        "apps" to mapOf("mode" to "ALLOW_SELECTED", "allowed" to listOf(READER)),
        "homeFilter" to mapOf(
            "enabled" to true,
            "vpnPackage" to VPN,
            "vpnSignerSha256" to MessageDigest.getInstance("SHA-256").digest(SIGNER)
                .joinToString("") { "%02x".format(it.toInt() and 255) },
            "pacUrl" to "https://filter.example.org/proxy.pac",
            "routing" to mapOf("tailnetId" to "Ttest1", "loginUrl" to "https://routing.example.org",
                "exitNodeId" to "test-exit", "organizationName" to "TEST ONLY")
        )
    )

    private fun install(name: String) {
        val application = ApplicationInfo()
        application.packageName = name
        application.enabled = true
        val signing = Shadow.newInstanceOf(SigningInfo::class.java)
        Shadow.extract<ShadowSigningInfo>(signing).setSignatures(arrayOf(Signature(SIGNER)))
        val info = PackageInfo()
        info.packageName = name
        info.applicationInfo = application
        info.signingInfo = signing
        Shadow.extract<ShadowPackageManager>(context.packageManager).installPackage(info)
    }

    private class ProcessDeath : Error()

    private companion object {
        const val VPN = "com.example.filter"
        const val READER = "com.example.reader"
        val SIGNER = byteArrayOf(1, 2, 3)
    }
}
