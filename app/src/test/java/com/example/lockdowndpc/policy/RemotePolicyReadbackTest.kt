package com.example.lockdowndpc.policy

import com.example.lockdowndpc.remote.Generation
import com.example.lockdowndpc.remote.JournalState
import com.example.lockdowndpc.remote.ReleaseLedger
import com.example.lockdowndpc.remote.RemoteFixtures
import com.example.lockdowndpc.remote.RemoteProjection
import com.example.lockdowndpc.remote.asObject
import com.example.lockdowndpc.remote.items
import java.util.function.BooleanSupplier
import java.util.function.Predicate
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RemotePolicyReadbackTest {
    private val f = RemoteFixtures
    private val filter = HomeFilterPolicy.Settings(
        HomeFilterPolicy.Config("org.example.vpn", "https://filter.example/proxy.pac", "",
            HomeFilterPolicy.Routing("Tfixture", "https://example.org", "exit", "Fixture"), null),
        true, null, false
    )

    @Test fun everyReadBackVectorUsesActualProtectionAndVisibilityChecks() {
        for (raw in f.vectors("journal").items("readBackCases")) {
            val case = raw.asObject()
            val target = case["target"] as? String ?: "policy-5"
            val faults = case["protections"].asObject()
            val sdk = (case["deviceSdk"] as? Long)?.toInt() ?: 35
            val desiredVisible = case["wouldUnhide"] == true
            var hidden = case["previouslyHidden"] == true
            var filterDebt = case["previousFilter"] != null
            var caDebt = case["previousCa"] != null
            val ca = "fixture-ca"
            val vpn = HomeFilterPolicyTest.FakeGateway()
            vpn.refuseVpn = faults["vpnLockdown"] == "refused"
            val settings = if (filterDebt) {
                vpn.vpnPackage = filter.config().vpnPackage()
                vpn.lockdown = true
                vpn.pacUrl = filter.config().pacUrl()
                vpn.refuseProxy = faults["filterRemoval"] == "refused"
                filter.requestDisable()
            } else filter
            vpn.hasCa = caDebt
            vpn.refuseCa = faults["caRemoval"] == "refused"
            val projection = object : RemoteProjection by f.noProjection {
                override fun apply(target: Generation, stillCurrent: () -> Boolean, releases: ReleaseLedger): Boolean {
                    val errors = mutableListOf<String>()
                    if (faults["vpnLockdown"] == "interrupted") throw TestProcessDeath()
                    val device = SystemPolicyEnforcerTest.FakeGateway()
                    val choices = when {
                        faults.containsKey("wifi_configuration") -> {
                            device.refuseAdd.add("no_config_wifi")
                            mapOf(SystemPolicyControl.WIFI_CONFIGURATION to true)
                        }
                        faults.containsKey("date_and_time") -> mapOf(SystemPolicyControl.DATE_AND_TIME to true)
                        else -> emptyMap()
                    }
                    val report = SystemPolicyEnforcer.enforce(sdk, SystemPolicyProfile.PILOT, choices, device)
                    LockdownPolicyController.verifyRemoteControls(report, choices.keys, sdk, errors)
                    val network = HomeFilterController.reconcileRemote(settings, sdk, vpn,
                        if (caDebt) setOf(ca) else emptySet(), emptySet(), BooleanSupplier {
                            caDebt = false
                            filterDebt = false
                            true
                        }, errors)
                    LockdownPolicyController.reconcilePackageVisibility("org.example.reader", !desiredVisible,
                        network && errors.isEmpty() && stillCurrent(),
                        BooleanSupplier { hidden }, Predicate { hidden = it; true }, errors)
                    return network && errors.isEmpty()
                }
            }
            val old = f.generation("policy-1")
            val harness = f.harness(JournalState(policy = f.policy(target), verified = old), projection)
            val verified = try {
                harness.engine.ensureProjected().verified
            } catch (_: TestProcessDeath) {
                harness.restart()
                false
            }
            val evidence = mutableMapOf<String, Any?>("packageHidden" to hidden,
                "verified" to if (harness.engine.state.verified == old) "policy-1" else target)
            if ("previousCa" in case) evidence["retainPreviousCa"] = caDebt
            if ("previousFilter" in case) evidence["retainPreviousFilter"] = filterDebt
            f.check(case, f.result(if (verified) "verified" else "unverified") + evidence)
        }
    }

    @Test fun replacingFilterKeepsTheNewVpnAndProxyWhileCleaningTheOldRouting() {
        val previous = HomeFilterPolicy.Config("org.example.oldvpn", "https://old.example/proxy.pac",
            "", HomeFilterPolicy.Routing("Told", "https://example.org", "old", "Fixture"), null)
        val device = HomeFilterPolicyTest.FakeGateway()
        device.vpnPackage = filter.config().vpnPackage()
        device.pacUrl = filter.config().pacUrl()
        assertTrue(HomeFilterPolicy.reconcileRetiredConfig(previous, filter.config(), device))
        assertEquals(filter.config().vpnPackage(), device.vpnPackage)
        assertEquals(filter.config().pacUrl(), device.pacUrl)
    }

    @Test fun cleanupThatCannotBeRecordedLeavesThePassUnverified() {
        val errors = mutableListOf<String>()
        assertFalse(HomeFilterController.reconcileRemote(HomeFilterPolicy.Settings.OFF, 35,
            HomeFilterPolicyTest.FakeGateway(), emptySet(), emptySet(), BooleanSupplier { false }, errors))
        assertEquals(listOf("journal-write-failed"), errors)
    }

    @Test fun onlyAControlThatIsOnMustBeInForce() {
        val device = SystemPolicyEnforcerTest.FakeGateway()
        fun errors(sdk: Int, choices: Map<SystemPolicyControl, Boolean>): List<String> {
            val found = mutableListOf<String>()
            val report = SystemPolicyEnforcer.enforce(sdk, SystemPolicyProfile.PILOT, choices, device)
            LockdownPolicyController.verifyRemoteControls(report, choices.keys, sdk, found)
            return found
        }
        val off = SystemPolicyControl.values().associateWith { false }
        // Nothing is asked of an old release, so nothing is missing.
        assertEquals(emptyList<String>(), errors(27, off))
        // A default that this release cannot enforce is still a requested control.
        assertTrue(errors(27, emptyMap()).any { it.startsWith("remote-system-policy:") })
        // A named control must be enforced in full.
        assertTrue(errors(28, off + (SystemPolicyControl.UNKNOWN_SOURCE_INSTALLS to true)).isNotEmpty())
        assertEquals(emptyList<String>(), errors(35, off + (SystemPolicyControl.UNKNOWN_SOURCE_INSTALLS to true)))
    }

    private class TestProcessDeath : Error()
}
