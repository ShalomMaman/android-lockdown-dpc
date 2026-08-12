package com.example.lockdowndpc.updates

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.util.Base64

class UpdateConfigTest {
    @Test
    fun `accepts only clean HTTPS with a P-256 metadata key`() {
        assertTrue(UpdateConfig.isConfigurationValid(HTTPS_URL, encodedEcKey(256)))
    }

    @Test
    fun `rejects an empty or malformed channel`() {
        assertFalse(UpdateConfig.isConfigurationValid("", encodedEcKey(256)))
        assertFalse(UpdateConfig.isConfigurationValid(HTTPS_URL, ""))
        assertFalse(UpdateConfig.isConfigurationValid("http://updates.example.test/latest.json", encodedEcKey(256)))
        assertFalse(UpdateConfig.isConfigurationValid(HTTPS_URL, "not-base64"))
    }

    @Test
    fun `rejects a valid EC key on the wrong curve`() {
        assertFalse(UpdateConfig.isConfigurationValid(HTTPS_URL, encodedEcKey(384)))
    }

    private fun encodedEcKey(size: Int): String {
        val keyPair = KeyPairGenerator.getInstance("EC").apply { initialize(size) }.generateKeyPair()
        return Base64.getEncoder().encodeToString(keyPair.public.encoded)
    }

    private companion object {
        const val HTTPS_URL = "https://updates.example.test/latest.json"
    }
}
