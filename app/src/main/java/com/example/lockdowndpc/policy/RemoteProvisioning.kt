package com.example.lockdowndpc.policy

import com.example.lockdowndpc.remote.JsonObject

internal object RemoteProvisioning {
    // Match the shared pilot baseline. ADB remains available for the recovery drill.
    fun baseline(): JsonObject = mapOf(
        "managementMode" to "REMOTE",
        "protection" to mapOf("state" to "ON"),
        "apps" to mapOf("mode" to "ALLOW_SELECTED", "allowed" to emptyList<String>(),
            "systemSelection" to emptyList<String>(), "playCompatibility" to false),
        "systemControls" to SystemPolicyControl.defaultsFor(SystemPolicyProfile.PILOT)
            .mapKeys { it.key.storageKey() },
        "homeFilter" to mapOf("enabled" to false),
        "managementPins" to emptyMap<String, Any>(),
        "kiosk" to mapOf("mode" to "OFF"),
        "sync" to mapOf("pullMinutes" to 15L),
    )
}
