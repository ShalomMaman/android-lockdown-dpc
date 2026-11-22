package com.example.lockdowndpc.policy

import android.net.ConnectivityManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * The filter VPN that is in force stays in force, with its application, until
 * a pass has verified what replaces it or has finished cleaning up after it.
 */
class RemoteFilterTransitionTest : RemotePassFixture() {

    @Before fun runTheFirstFilter() {
        commit(policy())
        assertVerified()
        assertFilterInForce(VPN)
    }

    @Test fun failedSwitchKeepsTheOldVpnLockedDownAndItsApplicationVisible() {
        val first = target()
        // The new policy names another filter and no longer allows the old application.
        replace(policy(filter = filter(OTHER_VPN)))

        // The new filter application is not installed.
        assertFalse(pass().verified)
        assertTrue(errors().toString(), errors().any { it.startsWith("home-filter:vpn=MISSING_VPN,") })
        assertOldFilterStillProtects(first)

        // It is installed and Android refuses to make it the always-on VPN.
        install(OTHER_VPN)
        device.refuseVpn = true
        assertFalse(pass().verified)
        assertTrue(errors().toString(), errors().any { it.startsWith("home-filter:vpn=REFUSED,") })
        assertOldFilterStillProtects(first)

        // The replacement verifies. Only now does the old application go.
        device.refuseVpn = false
        assertVerified()
        assertFilterInForce(OTHER_VPN)
        assertTrue(hidden(VPN))
        assertEquals(target(), verified())
    }

    @Test fun failedTeardownKeepsTheVpnUntilTheProxyIsProvenGone() {
        val first = target()
        // The new policy has no filter. Android refuses to clear the PAC proxy.
        replace(policy(filter = null))
        device.refuseProxyChange = true

        assertFalse(pass().verified)

        assertTrue(errors().toString(), "home-filter:previous-config-removal-unverified" in errors())
        assertOldFilterStillProtects(first)
        assertEquals(PAC, pacUrl())

        // The cleanup succeeds. The VPN lockdown is released last, then the application is hidden.
        device.refuseProxyChange = false
        assertVerified()
        assertNull(dpm.getAlwaysOnVpnPackage(admin))
        assertEquals("", pacUrl())
        assertTrue(hidden(VPN))
        assertEquals(target(), verified())
        assertTrue(HomeFilterStore.retiredFilters(context).isEmpty())
    }

    /** Every superseded filter is a cleanup the device still owes. The list is bounded and never dropped. */
    @Test fun cleanupDebtIsCappedWithoutLosingAnEntry() {
        fun settings(index: Int) = HomeFilterPolicy.Settings(
            HomeFilterPolicy.Config("com.example.filter$index", PAC, "", null, null), true, null, false)
        // The stored filter and sixteen replacements fill the list exactly.
        for (index in 1..HomeFilterStore.MAX_RETIRED) {
            assertTrue("$index", HomeFilterStore.projectRemote(context, settings(index)))
        }
        assertEquals(HomeFilterStore.MAX_RETIRED, HomeFilterStore.retiredFilters(context).size)
        assertFalse(HomeFilterStore.projectRemote(context, settings(HomeFilterStore.MAX_RETIRED + 1)))
        assertEquals(HomeFilterStore.MAX_RETIRED, HomeFilterStore.retiredFilters(context).size)
        assertEquals("com.example.filter${HomeFilterStore.MAX_RETIRED}",
            HomeFilterStore.read(context).config().vpnPackage())
    }

    private fun assertFilterInForce(vpn: String) {
        assertEquals(vpn, dpm.getAlwaysOnVpnPackage(admin))
        assertTrue(dpm.isAlwaysOnVpnLockdownEnabled(admin))
        assertFalse(hidden(vpn))
    }

    private fun assertOldFilterStillProtects(first: com.example.lockdowndpc.remote.Generation) {
        assertFilterInForce(VPN)
        assertEquals(first, verified())
    }

    private fun pacUrl(): String =
        context.getSystemService(ConnectivityManager::class.java).defaultProxy?.pacFileUrl?.toString().orEmpty()
}
