package com.example.lockdowndpc.updates

import com.example.lockdowndpc.BuildConfig

/** Build-time configuration. Empty values disable remote updates fail-closed. */
object UpdateConfig {
    val manifestUrl: String
        get() = BuildConfig.UPDATE_MANIFEST_URL.trim()

    val metadataPublicKey: String
        get() = BuildConfig.UPDATE_PUBLIC_KEY.trim()

    val isConfigured: Boolean
        get() = isConfigurationValid(manifestUrl, metadataPublicKey)

    internal fun isConfigurationValid(manifestUrl: String, metadataPublicKey: String): Boolean =
        manifestUrl.isNotBlank() && metadataPublicKey.isNotBlank() && try {
            UpdateEnvelopeVerifier.requireCleanHttpsUrl(manifestUrl)
            UpdateEnvelopeVerifier.requireP256PublicKey(metadataPublicKey)
            true
        } catch (_: UpdateVerificationException) {
            false
        }
}
