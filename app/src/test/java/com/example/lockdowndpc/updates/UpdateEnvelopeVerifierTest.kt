package com.example.lockdowndpc.updates

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64

class UpdateEnvelopeVerifierTest {
    private val keyPair: KeyPair = KeyPairGenerator.getInstance("EC").apply {
        initialize(256)
    }.generateKeyPair()

    private val publicKeyBase64: String = Base64.getEncoder()
        .encodeToString(keyPair.public.encoded)

    @Test
    fun `accepts a valid signed update`() {
        val result = UpdateEnvelopeVerifier.verify(
            envelopeBytes = signedEnvelope(validPayload()),
            publicKeyBase64 = publicKeyBase64,
            expectedPackage = EXPECTED_PACKAGE,
            nowEpochSeconds = NOW,
        )

        assertEquals(EXPECTED_PACKAGE, result.packageName)
        assertEquals(9L, result.versionCode)
        assertEquals("0.5.0", result.versionName)
        assertEquals("https://updates.example.test/device-guard-0.5.0.apk", result.apkUrl)
        assertEquals(APK_SHA256, result.apkSha256)
        assertEquals(1_234_567L, result.apkSize)
        assertEquals(NOW - 60L, result.issuedAtEpochSeconds)
        assertEquals(NOW + 3_600L, result.expiresAtEpochSeconds)
    }

    @Test
    fun `rejects payload altered after signing`() {
        val originalPayload = validPayload()
        val signature = sign(originalPayload)
        val alteredPayload = originalPayload.replace("\"versionCode\":9", "\"versionCode\":10")
        val envelope = envelope(alteredPayload.toByteArray(), signature)

        assertRejected(envelope)
    }

    @Test
    fun `rejects an altered signature`() {
        val payload = validPayload().toByteArray()
        val signature = sign(validPayload()).also { bytes ->
            bytes[bytes.lastIndex] = (bytes.last().toInt() xor 0x01).toByte()
        }

        assertRejected(envelope(payload, signature))
    }

    @Test
    fun `rejects an expired envelope`() {
        assertRejected(signedEnvelope(validPayload(expiresAt = NOW)))
    }

    @Test
    fun `rejects metadata with an excessive validity window`() {
        assertRejected(
            signedEnvelope(
                validPayload(expiresAt = NOW + MAX_METADATA_VALIDITY_SECONDS + 3_600L),
            ),
        )
    }

    @Test
    fun `rejects an update for another package`() {
        assertRejected(signedEnvelope(validPayload(packageName = "com.attacker.replacement")))
    }

    @Test
    fun `rejects a non HTTPS apk URL`() {
        assertRejected(signedEnvelope(validPayload(apkUrl = "http://updates.example.test/app.apk")))
    }

    @Test
    fun `rejects invalid URL-safe Base64 in the envelope`() {
        val malformed = """{"payload":"%%%","signature":"%%%"}""".toByteArray()

        assertRejected(malformed)
    }

    @Test
    fun `rejects an invalid public key encoding`() {
        assertThrows(UpdateVerificationException::class.java) {
            UpdateEnvelopeVerifier.verify(
                envelopeBytes = signedEnvelope(validPayload()),
                publicKeyBase64 = "not-base64%%%",
                expectedPackage = EXPECTED_PACKAGE,
                nowEpochSeconds = NOW,
            )
        }
    }

    @Test
    fun `rejects an EC key that is not P-256`() {
        val p384 = KeyPairGenerator.getInstance("EC").apply { initialize(384) }.generateKeyPair()
        val payload = validPayload().toByteArray()
        val signature = Signature.getInstance("SHA256withECDSA").run {
            initSign(p384.private)
            update(payload)
            sign()
        }
        assertThrows(UpdateVerificationException::class.java) {
            UpdateEnvelopeVerifier.verify(
                envelopeBytes = envelope(payload, signature),
                publicKeyBase64 = Base64.getEncoder().encodeToString(p384.public.encoded),
                expectedPackage = EXPECTED_PACKAGE,
                nowEpochSeconds = NOW,
            )
        }
    }

    private fun assertRejected(envelopeBytes: ByteArray) {
        assertThrows(UpdateVerificationException::class.java) {
            UpdateEnvelopeVerifier.verify(
                envelopeBytes = envelopeBytes,
                publicKeyBase64 = publicKeyBase64,
                expectedPackage = EXPECTED_PACKAGE,
                nowEpochSeconds = NOW,
            )
        }
    }

    private fun signedEnvelope(payload: String): ByteArray =
        envelope(payload.toByteArray(), sign(payload))

    private fun sign(payload: String): ByteArray = Signature.getInstance("SHA256withECDSA").run {
        initSign(keyPair.private)
        update(payload.toByteArray())
        sign()
    }

    private fun envelope(payload: ByteArray, signature: ByteArray): ByteArray {
        val encoder = Base64.getUrlEncoder().withoutPadding()
        return """{"payload":"${encoder.encodeToString(payload)}","signature":"${encoder.encodeToString(signature)}"}"""
            .toByteArray()
    }

    private fun validPayload(
        packageName: String = EXPECTED_PACKAGE,
        apkUrl: String = "https://updates.example.test/device-guard-0.5.0.apk",
        expiresAt: Long = NOW + 3_600L,
    ): String = """{"schemaVersion":1,"packageName":"$packageName","versionCode":9,"versionName":"0.5.0","apkUrl":"$apkUrl","apkSha256":"$APK_SHA256","apkSize":1234567,"issuedAt":${NOW - 60L},"expiresAt":$expiresAt}"""

    private companion object {
        const val EXPECTED_PACKAGE = "com.example.lockdowndpc"
        const val NOW = 1_800_000_000L
        const val APK_SHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
}
