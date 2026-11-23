package com.example.lockdowndpc.policy

import android.content.Context
import com.example.lockdowndpc.BuildConfig
import com.example.lockdowndpc.remote.CommandEntry
import com.example.lockdowndpc.remote.CommandState
import com.example.lockdowndpc.remote.JournalState
import com.example.lockdowndpc.remote.RemoteFailure
import com.example.lockdowndpc.remote.RemoteOverride
import com.example.lockdowndpc.remote.RemoteSync
import com.example.lockdowndpc.remote.RemoteTime
import com.example.lockdowndpc.remote.obj
import java.util.function.Consumer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test

/**
 * Acceptance criterion A1 through the real journal, projection, stores and policy pass:
 * a package the previous generation hid is visible only while a pass that verified stands behind it.
 */
class RemotePolicyGatewayFaultTest : RemotePassFixture() {

    @Before fun hideWhatThePreviousGenerationHid() {
        install(READER)
        install(SECOND_READER)
        assertTrue(dpm.setApplicationHidden(admin, READER, true))
        assertTrue(dpm.setApplicationHidden(admin, SECOND_READER, true))
        commit(policy(allowed = listOf(READER, SECOND_READER)))
    }

    @Test fun vpnLockdownRefusalKeepsThePackageHiddenAndTheVerifiedHashUnchanged() {
        val target = target()
        device.refuseVpn = true
        device.beforeVpnWrite = Runnable { assertTrue(hidden(READER)) }

        assertFalse(pass().verified)

        assertTrue(errors().toString(), errors().any { it.startsWith("home-filter:vpn=REFUSED,") })
        // The projection did store the new selection; only the release waited.
        assertTrue(READER in AllowedAppsStore.getAllowedPackages(context))
        assertTrue(hidden(READER))
        assertEquals(previous, verified())
        assertEquals(target, target())
        assertNextPassVerifiesAndReleases()
    }

    @Test fun processDeathBetweenAndroidCallsKeepsThePackageHiddenAndTheVerifiedHashUnchanged() {
        device.beforeVpnWrite = Runnable {
            assertTrue(hidden(READER))
            throw ProcessDeath()
        }
        try {
            pass()
            fail("The pass must reach the VPN lockdown")
        } catch (_: ProcessDeath) {
            // The process is gone between two Android calls.
        }
        harness.restart()

        assertTrue(hidden(READER))
        assertEquals(previous, verified())
        assertNextPassVerifiesAndReleases()
    }

    /** One release succeeds and Android refuses the next: the first is hidden again. */
    @Test fun refusedSecondReleaseHidesTheFirstAgain() {
        val released = mutableListOf<String>()
        device.afterUnhide = Consumer { name ->
            released.add(name)
            device.refuseUnhide.addAll(listOf(READER, SECOND_READER) - name)
        }

        assertFalse(pass().verified)

        assertEquals(1, released.size)
        assertTrue(errors().toString(), errors().any { it.startsWith("package-policy-update-rejected:") })
        assertTrue(hidden(READER))
        assertTrue(hidden(SECOND_READER))
        assertEquals(previous, verified())
        assertTrue(harness.engine.state.releases.isEmpty())

        device.afterUnhide = Consumer { }
        device.refuseUnhide.clear()
        assertNextPassVerifiesAndReleases()
    }

    /** The process dies after the first release: the journal already holds the intent, and the next pass undoes it. */
    @Test fun processDeathAfterTheFirstReleaseIsUndoneByTheNextPass() {
        device.afterUnhide = Consumer { throw ProcessDeath() }
        try {
            pass()
            fail("The pass must reach the first release")
        } catch (_: ProcessDeath) {
            // One package is visible and nothing in this process can hide it any more.
        }
        assertEquals(1, listOf(READER, SECOND_READER).count { !hidden(it) })
        harness.restart()
        assertEquals(setOf(READER, SECOND_READER), harness.engine.state.releases)
        assertEquals(previous, verified())

        // The next pass cannot verify either. It still starts by hiding what was exposed.
        device.afterUnhide = Consumer { }
        device.refuseProxyChange = true
        assertFalse(pass().verified)
        assertTrue(hidden(READER))
        assertTrue(hidden(SECOND_READER))
        assertEquals(previous, verified())
        assertTrue(harness.engine.state.releases.isEmpty())

        device.refuseProxyChange = false
        assertNextPassVerifiesAndReleases()
    }

    /**
     * The next start has more to deal with than the exposed package: a command the
     * dead process left mid-dispatch, and a journal that refuses every write. The
     * package is hidden again first, before any of that can stop the pass.
     */
    @Test fun exposedPackageIsHiddenAgainBeforeCommandHandlingEvenWhenTheJournalRefusesWrites() {
        device.afterUnhide = Consumer { throw ProcessDeath() }
        try {
            pass()
            fail("The pass must reach the first release")
        } catch (_: ProcessDeath) {
            // One package is visible.
        }
        assertEquals(1, listOf(READER, SECOND_READER).count { !hidden(it) })
        harness.restart()
        assertTrue(harness.journal.save(harness.engine.state.copy(commands = mapOf(
            7L to CommandEntry(7, "lock_now", RemoteTime(1, 1), CommandState.DISPATCHING)))))
        harness.restart()
        device.afterUnhide = Consumer { }
        harness.memory.failCommit = true

        val refused = onPolicyThread { harness.engine.reconcile() }

        assertEquals("journal-write-failed", refused.failure?.code)
        assertTrue(hidden(READER))
        assertTrue(hidden(SECOND_READER))
        // Nothing could be written: the command is still unsettled and the record still names the packages.
        assertEquals(CommandState.DISPATCHING, harness.engine.state.commands[7]?.state)
        assertEquals(setOf(READER, SECOND_READER), harness.engine.state.releases)
        assertEquals(previous, verified())

        harness.memory.failCommit = false
        assertTrue(onPolicyThread { harness.engine.reconcile() }.verified)
        assertFalse(hidden(READER))
        assertFalse(hidden(SECOND_READER))
        assertEquals(CommandState.OUTCOME_UNKNOWN, harness.engine.state.commands[7]?.state)
        assertTrue(harness.engine.state.releases.isEmpty())
    }

    /** Every release succeeded and the verified hash could not be stored: nothing stays visible on the old hash. */
    @Test fun failedVerifiedWriteHidesWhatThePassReleased() {
        var journalCommits = 0
        harness.memory.beforeCommit = Consumer { keys ->
            // The release record is the first journal commit of the pass, the verified hash the second.
            harness.memory.failCommit = "state" in keys && ++journalCommits == 2
        }

        val pass = pass()

        assertEquals("journal-write-failed", pass.failure?.code)
        assertTrue(errors().isEmpty())
        assertTrue(hidden(READER))
        assertTrue(hidden(SECOND_READER))
        assertEquals(previous, verified())

        harness.memory.beforeCommit = Consumer { harness.memory.failCommit = false }
        assertNextPassVerifiesAndReleases()
    }

    @Test fun policyTheStoresCannotHoldIsRefusedBeforeTheJournalChanges() {
        val fresh = f.harness(JournalState(), projection)
        val refused = mapOf(
            "/policy/apps/systemSelection" to policy(extra = mapOf("apps" to mapOf(
                "mode" to "ALLOW_SELECTED", "allowed" to emptyList<String>(),
                "systemSelection" to listOf(mapOf("package" to "com.android.vending",
                    "signerSha256" to "00".repeat(32), "versionCode" to 1L))))),
            "/policy/homeFilter/vpnPackage" to policy(filter = filter("com.android.chrome")),
            // An enabled filter without routing settings could be stored and never verified.
            "/policy/homeFilter/routing" to policy(filter = filter(VPN) - "routing"),
            // A kiosk needs a local way out, which the remote console does not have yet.
            "/policy/kiosk/mode" to policy(extra = mapOf("kiosk" to mapOf(
                "mode" to "SINGLE_APP", "targetPackage" to READER))),
        )
        for ((path, policy) in refused) {
            assertEquals(RemoteFailure("doc-field-invalid", path), fresh.engine.commitBaseline(policy))
        }
        assertEquals(RemoteFailure("doc-field-invalid", "/policy/kiosk/mode"), fresh.engine.commitBaseline(
            policy(extra = mapOf("kiosk" to mapOf("mode" to "SINGLE_SITE", "siteUrl" to "https://kiosk.example.org/")))))
        assertNull(fresh.engine.state.policy)
        fresh.restart()
        assertNull(fresh.engine.state.policy)
        assertNull(fresh.engine.commitBaseline(policy()))
    }

    /** The build gate is off: with a marker present, no runtime entry point reaches the journal. */
    @Test fun gateOffRefusesEveryRuntimeEntryPointAndWritesNothing() {
        RemoteTestGate.open(false)
        org.junit.Assume.assumeFalse(RemoteEnrolmentGate.permits())
        val unavailable = RemotePolicyApplier.UNAVAILABLE
        assertEquals(unavailable, RemotePolicyRuntime.bindFleet(context, f.binding, f.binding.deviceId, "")?.code)
        assertNull(RemotePolicyRuntime.beginExchange(context))
        assertEquals(unavailable, RemotePolicyRuntime.receive(context,
            RemoteSync.Exchange(f.nonce, RemoteTime(1, 1)), f.nonce, emptyList()).failure?.code)
        val recovery = RemotePolicyRuntime.recover(context, setOf(RemoteOverride.NETWORK_OFF), "2222 2222 2222 2222 2222")
        assertEquals(unavailable, recovery.failure?.code)
        assertEquals(unavailable, RemotePolicyRuntime.dispatch(context, 1)?.code)
        assertEquals(listOf(unavailable), RemotePolicyRuntime.reconcile(context).errors())
        assertNull(RemotePolicyRuntime.journalFailure(context))
        assertTrue(context.getSharedPreferences(RemotePolicyRuntime.JOURNAL_PREFS, Context.MODE_PRIVATE).all.isEmpty())
        assertTrue(context.getSharedPreferences(RemotePolicyRuntime.JOURNAL_MARKER_PREFS, Context.MODE_PRIVATE)
            .all.isEmpty())
    }

    /** Store writes are authorized only on the policy thread, with the gate on, for the journal's own generation. */
    @Test fun projectionAuthorityNeedsTheGateThePolicyThreadAndTheJournalGeneration() {
        fun <T> withAuthority(block: (AdminAuthority.CommittedPolicy) -> T): T =
            AdminAuthority.CommittedPolicy.forProjection(context).use { block(it) }
        fun permitted(): Boolean = withAuthority { AdminAuthority.CommittedPolicy.permits(context, it) }

        assertTrue(onPolicyThread { permitted() })
        assertEquals(target().sha256, onPolicyThread { withAuthority { it.generation() } })
        // Any other thread, even with everything else in place.
        assertFalse(permitted())
        // The journal moved on while the authority was held.
        assertFalse(onPolicyThread {
            withAuthority { held ->
                assertTrue(harness.journal.save(harness.engine.state.copy(overrides = setOf(RemoteOverride.NETWORK_OFF))))
                AdminAuthority.CommittedPolicy.permits(context, held)
            }
        })
        // A closed authority.
        assertFalse(onPolicyThread { withAuthority { it }.let { AdminAuthority.CommittedPolicy.permits(context, it) } })
        // Drop the test override. The remoteTest artifact still has its build gate on.
        RemoteTestGate.open(false)
        if (BuildConfig.REMOTE_ENROLMENT_ENABLED) {
            assertTrue(onPolicyThread { permitted() })
            assertVerified()
            assertEquals(target(), verified())
            assertFalse(hidden(READER))
            assertFalse(hidden(SECOND_READER))
            return
        }

        // The release gate is off: no authority, no projection and no pass.
        assertFalse(onPolicyThread { permitted() })
        val refused = onPolicyThread {
            withAuthority {
                LockdownPolicyController.applyRemoteProjection(context, it, { true }, true, { true })
            }
        }
        assertEquals(listOf(RemotePolicyApplier.UNAVAILABLE), refused.errors())
        assertEquals("journal-write-failed", pass().failure?.code)
        assertTrue(hidden(READER))
        assertNull(dpm.getAlwaysOnVpnPackage(admin))
    }

    /** Once the fault is gone, the next pass verifies and only then releases the packages. */
    private fun assertNextPassVerifiesAndReleases() {
        val target = target()
        device.refuseVpn = false
        device.beforeVpnWrite = Runnable {
            assertTrue(hidden(READER))
            assertTrue(hidden(SECOND_READER))
        }
        assertVerified()
        assertFalse(hidden(READER))
        assertFalse(hidden(SECOND_READER))
        assertEquals(target, verified())
        assertTrue(harness.engine.state.releases.isEmpty())
    }
}
