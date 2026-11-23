package com.example.lockdowndpc.policy

/**
 * Opens the enrolment gate for JVM tests. The application has no way to do
 * this: the switch is a private field that only this test-tree helper writes.
 */
internal object RemoteTestGate {
    fun open(open: Boolean) {
        val field = RemoteEnrolmentGate::class.java.getDeclaredField("openedByTest")
        field.isAccessible = true
        field.setBoolean(null, open)
    }

    @JvmStatic
    fun closeRuntime() {
        AdminAuthority.CommittedPolicy.bindJournal(null)
        RemotePolicyRuntime.closeForTests()
    }
}
