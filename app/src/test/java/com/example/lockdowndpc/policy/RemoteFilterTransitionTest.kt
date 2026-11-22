package com.example.lockdowndpc.policy

import com.example.lockdowndpc.remote.Generation
import com.example.lockdowndpc.remote.RemoteOverride
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The filter that is in force stays in force, whole: its VPN lockdown, its
 * proxy, its certificate and its application, until a pass has verified what
 * replaces it or has finished cleaning up after it.
 */
class RemoteFilterTransitionTest : RemotePassFixture() {
    private lateinit var first: Generation

    @Before fun runTheFirstFilter() {
        commit(policy(filter = filter(VPN, PAC, CA_A)))
        assertVerified()
        first = target()
        assertFirstFilterProtects()
    }

    @Test fun switchThatCannotStartKeepsTheOldFilter() {
        replace(policy(filter = filter(OTHER_VPN, OTHER_PAC, CA_B)))

        // The new filter application is not installed.
        assertFalse(pass().verified)
        assertTrue(errors().toString(), errors().any { it.startsWith("home-filter:vpn=MISSING_VPN,") })
        assertFirstFilterProtects()

        // It is installed and Android refuses to make it the always-on VPN.
        install(OTHER_VPN)
        device.refuseVpn = true
        assertFalse(pass().verified)
        assertTrue(errors().toString(), errors().any { it.startsWith("home-filter:vpn=REFUSED,") })
        assertFirstFilterProtects()

        device.refuseVpn = false
        assertSecondFilterTakesOver()
    }

    /** The failure comes after the VPN lockdown already moved: the old lockdown, proxy and certificate come back. */
    @Test fun lateFailureAfterTheVpnSwapPutsThePreviousVpnProxyAndCertificateBack() {
        install(OTHER_VPN)
        replace(policy(filter = filter(OTHER_VPN, OTHER_PAC, CA_B)))
        var vpnWrites = 0
        device.beforeVpnWrite = Runnable { vpnWrites++ }

        // The lockdown moves to the new VPN, then Android refuses the new PAC proxy.
        device.refuseProxyChange = true
        assertFalse(pass().verified)
        assertTrue(errors().toString(), errors().any { it.startsWith("home-filter:vpn=CONFIRMED,proxy=REFUSED,") })
        assertEquals("the swap and the way back", 2, vpnWrites)
        assertFirstFilterProtects()

        // The lockdown and the proxy both move, then Android refuses the new certificate.
        device.refuseProxyChange = false
        device.refuseCaInstall = true
        assertFalse(pass().verified)
        assertTrue(errors().toString(), errors().any {
            it.startsWith("home-filter:vpn=CONFIRMED,proxy=CONFIRMED,ca=REFUSED,")
        })
        assertEquals(4, vpnWrites)
        assertFirstFilterProtects()

        device.refuseCaInstall = false
        assertSecondFilterTakesOver()
    }

    /** A replacement the old policy hid is shown through the release record, and hidden again when the switch fails. */
    @Test fun hiddenReplacementIsReleasedThroughTheLedgerAndHiddenAgainWhenTheSwitchFails() {
        install(OTHER_VPN)
        assertTrue(dpm.setApplicationHidden(admin, OTHER_VPN, true))
        replace(policy(filter = filter(OTHER_VPN, OTHER_PAC, CA_B)))
        var recordedBeforeTheVpnMoved = false
        device.beforeVpnWrite = Runnable {
            recordedBeforeTheVpnMoved = recordedBeforeTheVpnMoved || OTHER_VPN in harness.engine.state.releases
        }

        device.refuseProxyChange = true
        assertFalse(pass().verified)
        assertTrue(recordedBeforeTheVpnMoved)
        assertTrue(hidden(OTHER_VPN))
        assertTrue(harness.engine.state.releases.isEmpty())
        assertFirstFilterProtects()

        device.refuseProxyChange = false
        assertSecondFilterTakesOver()
    }

    /** A teardown that stops anywhere before its last step leaves the VPN lockdown in force. */
    @Test fun teardownReleasesTheVpnLockdownOnlyAfterEverythingElseIsProvenGone() {
        replace(policy(filter = null))
        val refusals = listOf<(Boolean) -> Unit>(
            { device.refuseProxyChange = it },        // the PAC proxy
            { device.refuseUninstallUnblock = it },   // the uninstall block
            { device.refuseManagedConfigChange = it } // the routing settings
        )
        for ((step, refuse) in refusals.withIndex()) {
            refuse(true)
            assertFalse("step $step", pass().verified)
            assertTrue("step $step ${errors()}", "home-filter:previous-config-removal-unverified" in errors())
            assertEquals("step $step", VPN, dpm.getAlwaysOnVpnPackage(admin))
            assertTrue("step $step", dpm.isAlwaysOnVpnLockdownEnabled(admin))
            assertFalse("step $step", hidden(VPN))
            assertEquals("step $step", first, verified())
            refuse(false)
        }

        assertVerified()
        assertNull(dpm.getAlwaysOnVpnPackage(admin))
        assertEquals("", pacUrl())
        assertFalse(hasCa(CA_A))
        assertFalse(dpm.isUninstallBlocked(admin, VPN))
        assertTrue(hidden(VPN))
        assertEquals(target(), verified())
        assertTrue(HomeFilterStore.retiredFilters(context).isEmpty())
    }

    /** Every superseded filter is a cleanup the device still owes. The list is bounded, never dropped, and never in the way of turning the filter off. */
    @Test fun cleanupDebtIsCappedAndNeverBlocksTurningTheFilterOff() {
        fun settings(index: Int) = HomeFilterPolicy.Settings(
            HomeFilterPolicy.Config("com.example.filter$index", PAC, "", null, null), true, null, false)
        // The stored filter and sixteen replacements fill the list exactly.
        for (index in 1..HomeFilterStore.MAX_RETIRED) {
            assertTrue("$index", HomeFilterStore.projectRemote(context, settings(index)))
        }
        assertEquals(HomeFilterStore.MAX_RETIRED, HomeFilterStore.retiredFilters(context).size)
        // One more replacement is refused and nothing is lost.
        assertFalse(HomeFilterStore.projectRemote(context, settings(HomeFilterStore.MAX_RETIRED + 1)))
        assertEquals(HomeFilterStore.MAX_RETIRED, HomeFilterStore.retiredFilters(context).size)
        assertEquals("com.example.filter${HomeFilterStore.MAX_RETIRED}",
            HomeFilterStore.read(context).config().vpnPackage())

        // The recovery override turns the filter off from the full list, and the teardown clears all of it.
        assertTrue(harness.journal.save(harness.engine.state.copy(overrides = setOf(RemoteOverride.NETWORK_OFF))))
        assertVerified()
        assertNull(dpm.getAlwaysOnVpnPackage(admin))
        assertEquals("", pacUrl())
        assertFalse(hasCa(CA_A))
        assertTrue(HomeFilterStore.retiredFilters(context).isEmpty())
        assertTrue(HomeFilterStore.retiredCas(context).isEmpty())
        assertFalse(HomeFilterStore.read(context).configured())
        assertEquals(target(), verified())
    }

    private fun assertFirstFilterProtects() {
        assertEquals(VPN, dpm.getAlwaysOnVpnPackage(admin))
        assertTrue(dpm.isAlwaysOnVpnLockdownEnabled(admin))
        assertFalse(hidden(VPN))
        assertEquals(PAC, pacUrl())
        assertTrue(hasCa(CA_A))
        assertFalse(hasCa(CA_B))
        assertFalse(errors().toString(), "home-filter:previous-protection-restore-unverified" in errors())
        assertEquals(first, verified())
    }

    private fun assertSecondFilterTakesOver() {
        device.beforeVpnWrite = Runnable { }
        assertVerified()
        assertEquals(OTHER_VPN, dpm.getAlwaysOnVpnPackage(admin))
        assertTrue(dpm.isAlwaysOnVpnLockdownEnabled(admin))
        assertFalse(hidden(OTHER_VPN))
        assertEquals(OTHER_PAC, pacUrl())
        assertTrue(hasCa(CA_B))
        assertFalse(hasCa(CA_A))
        assertTrue(hidden(VPN))
        assertEquals(target(), verified())
        assertTrue(harness.engine.state.releases.isEmpty())
    }
}
