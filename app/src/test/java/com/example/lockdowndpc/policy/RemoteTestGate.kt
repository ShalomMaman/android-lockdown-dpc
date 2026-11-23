package com.example.lockdowndpc.policy

import com.example.lockdowndpc.BuildConfig
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements

/** Test-only replacement for the build constant at the enrolment boundary. */
@Implements(RemoteEnrolmentGate::class)
class RemoteTestGate {
    companion object {
        @Volatile private var opened = false

        internal fun open(open: Boolean) {
            opened = open
        }

        @JvmStatic
        @Implementation
        fun permits(): Boolean = BuildConfig.REMOTE_ENROLMENT_ENABLED || opened

        @JvmStatic
        fun closeRuntime() {
            AdminAuthority.CommittedPolicy.bindJournal(null)
            RemotePolicyRuntime.closeForTests()
        }
    }
}
