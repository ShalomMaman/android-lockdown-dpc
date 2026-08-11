package com.example.lockdowndpc.updates

import com.example.lockdowndpc.BuildConfig

/** Build-time configuration. Empty values disable remote updates fail-closed. */
object UpdateConfig {
    val manifestUrl: String
        get() = BuildConfig.UPDATE_MANIFEST_URL.trim()

    val metadataPublicKey: String
        get() = BuildConfig.UPDATE_PUBLIC_KEY.trim()

    val isConfigured: Boolean
        get() = metadataPublicKey.isNotEmpty() && try {
            UpdateEnvelopeVerifier.requireCleanHttpsUrl(manifestUrl)
            true
        } catch (_: UpdateVerificationException) {
            false
        }
}
