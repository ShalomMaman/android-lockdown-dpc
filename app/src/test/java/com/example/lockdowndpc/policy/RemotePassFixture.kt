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
import com.example.lockdowndpc.remote.RemoteEngine
import com.example.lockdowndpc.remote.RemoteFixtures
import com.example.lockdowndpc.remote.WireJson
import java.security.MessageDigest
import java.util.function.Supplier
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.shadow.api.Shadow
import org.robolectric.shadows.ShadowPackageManager
import org.robolectric.shadows.ShadowSigningInfo

/**
 * A remote-managed device for end-to-end tests: the real journal engine, the
 * real projection into the stores and the real policy pass, on the policy
 * thread, against a scriptable Device Owner.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [32], shadows = [LockdownPolicyApplyTest.FilterDevicePolicy::class])
abstract class RemotePassFixture {
    internal val f = RemoteFixtures
    internal lateinit var context: Context
    internal lateinit var admin: ComponentName
    internal lateinit var dpm: DevicePolicyManager
    internal lateinit var device: LockdownPolicyApplyTest.FilterDevicePolicy
    internal lateinit var projection: RemotePolicyProjection
    internal lateinit var harness: RemoteFixtures.Harness
    internal val previous = f.generation("policy-1")

    @Before fun enterRemoteMode() {
        context = RuntimeEnvironment.getApplication()
        admin = LockdownAdminReceiver.componentName(context)
        dpm = context.getSystemService(DevicePolicyManager::class.java)
        device = Shadow.extract(dpm)
        assertTrue(device.setDeviceOwner(admin))
        assertTrue(context.createDeviceProtectedStorageContext()
            .getSharedPreferences(ManagementModeStore.MARKER_PREFS, Context.MODE_PRIVATE)
            .edit().putBoolean(ManagementModeStore.MARKER_KEY, true).commit())
        RemoteEnrolmentGate.openForTests(true)
        AdminAuthority.CommittedPolicy.bindJournal {
            if (::harness.isInitialized) harness.engine.state.generation()?.sha256 else null
        }
        projection = RemotePolicyProjection(context)
        install(VPN)
    }

    @After fun leaveRemoteMode() {
        RemoteEnrolmentGate.openForTests(false)
        AdminAuthority.CommittedPolicy.bindJournal(null)
        RemotePolicyRuntime.closeForTests()
    }

    /** A device whose journal holds [policy], with [verified] as the last generation a pass read back. */
    internal fun commit(policy: JsonObject, verified: Generation? = previous) {
        harness = f.harness(JournalState(policy = committed(policy), verified = verified), projection)
    }

    /** A newer policy becomes the journal's target. */
    internal fun replace(policy: JsonObject) {
        assertTrue(harness.journal.save(harness.engine.state.copy(policy = committed(policy))))
    }

    internal fun committed(policy: JsonObject) = CommittedPolicy.fromBytes(WireJson.canonical(policy), 0)
    internal fun target(): Generation = requireNotNull(harness.engine.state.generation())
    internal fun verified(): Generation? = harness.engine.state.verified
    internal fun pass(): RemoteEngine.Pass = onPolicyThread { harness.engine.ensureProjected() }
    internal fun errors(): List<String> = projection.lastResult?.errors().orEmpty()
    internal fun hidden(name: String): Boolean = dpm.isApplicationHidden(admin, name)

    internal fun <T> onPolicyThread(work: () -> T): T =
        PolicyReconciliationCoordinator.callOnPolicyThread(Supplier { work() })

    internal fun assertVerified() {
        val pass = pass()
        assertTrue("${pass.failure} ${errors()}", pass.verified)
    }

    internal fun policy(
        allowed: List<String> = emptyList(), filter: JsonObject? = filter(VPN), extra: JsonObject = emptyMap()
    ): JsonObject = mapOf(
        "managementMode" to "REMOTE",
        "protection" to mapOf("state" to "ON"),
        "apps" to mapOf("mode" to "ALLOW_SELECTED", "allowed" to allowed)
    ) + (if (filter == null) emptyMap() else mapOf("homeFilter" to filter)) + extra

    internal fun filter(vpn: String, pac: String = PAC): JsonObject = mapOf(
        "enabled" to true,
        "vpnPackage" to vpn,
        "vpnSignerSha256" to SIGNER_DIGEST,
        "pacUrl" to pac,
        "routing" to mapOf("tailnetId" to "Ttest1", "loginUrl" to "https://routing.example.org",
            "exitNodeId" to "test-exit", "organizationName" to "TEST ONLY")
    )

    internal fun install(name: String, system: Boolean = false, versionCode: Long = 1) {
        val application = ApplicationInfo()
        application.packageName = name
        application.enabled = true
        if (system) application.flags = ApplicationInfo.FLAG_SYSTEM
        val signing = Shadow.newInstanceOf(SigningInfo::class.java)
        Shadow.extract<ShadowSigningInfo>(signing).setSignatures(arrayOf(Signature(SIGNER)))
        val info = PackageInfo()
        info.packageName = name
        info.applicationInfo = application
        info.signingInfo = signing
        info.longVersionCode = versionCode
        Shadow.extract<ShadowPackageManager>(context.packageManager).installPackage(info)
    }

    internal class ProcessDeath : Error()

    internal companion object {
        const val VPN = "com.example.filter"
        const val OTHER_VPN = "com.example.otherfilter"
        const val READER = "com.example.reader"
        const val SECOND_READER = "com.example.secondreader"
        const val PAC = "https://filter.example.org/proxy.pac"
        val SIGNER = byteArrayOf(1, 2, 3)
        val SIGNER_DIGEST: String = MessageDigest.getInstance("SHA-256").digest(SIGNER)
            .joinToString("") { "%02x".format(it.toInt() and 255) }
    }
}
