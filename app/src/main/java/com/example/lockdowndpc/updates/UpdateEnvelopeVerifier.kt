package com.example.lockdowndpc.updates

import org.json.JSONObject
import java.net.URI
import java.security.KeyFactory
import java.security.Signature
import java.security.AlgorithmParameters
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

internal const val UPDATE_SCHEMA_VERSION = 1
internal const val MAX_MANIFEST_BYTES = 64 * 1024
internal const val MAX_APK_BYTES = 100L * 1024L * 1024L
internal const val MAX_METADATA_VALIDITY_SECONDS = 91L * 24L * 60L * 60L
internal const val MAX_CLOCK_SKEW_SECONDS = 5L * 60L

data class AuthorizedUpdate(
    val packageName: String,
    val versionCode: Long,
    val versionName: String,
    val apkUrl: String,
    val apkSha256: String,
    val apkSize: Long,
    val issuedAtEpochSeconds: Long,
    val expiresAtEpochSeconds: Long,
)

class UpdateVerificationException(message: String) : Exception(message)

object UpdateEnvelopeVerifier {
    fun verify(
        envelopeBytes: ByteArray,
        publicKeyBase64: String,
        expectedPackage: String,
        nowEpochSeconds: Long,
    ): AuthorizedUpdate {
        if (envelopeBytes.isEmpty() || envelopeBytes.size > MAX_MANIFEST_BYTES) {
            throw UpdateVerificationException("גודל manifest אינו תקין")
        }
        val envelope = try {
            JSONObject(envelopeBytes.toString(Charsets.UTF_8))
        } catch (_: RuntimeException) {
            throw UpdateVerificationException("מבנה manifest אינו תקין")
        }
        val payloadBytes = decodeUrlBase64(envelope.optString("payload"))
        val signatureBytes = decodeUrlBase64(envelope.optString("signature"))
        verifySignature(payloadBytes, signatureBytes, publicKeyBase64)

        val payload = try {
            JSONObject(payloadBytes.toString(Charsets.UTF_8))
        } catch (_: RuntimeException) {
            throw UpdateVerificationException("תוכן manifest אינו תקין")
        }
        if (payload.optInt("schemaVersion", -1) != UPDATE_SCHEMA_VERSION) {
            throw UpdateVerificationException("גרסת manifest אינה נתמכת")
        }
        val packageName = payload.optString("packageName")
        if (packageName != expectedPackage) {
            throw UpdateVerificationException("חבילת העדכון אינה תואמת")
        }
        val versionCode = payload.optLong("versionCode", -1L)
        if (versionCode <= 0L) {
            throw UpdateVerificationException("קוד גרסה אינו תקין")
        }
        val versionName = payload.optString("versionName")
        if (versionName.isBlank() || versionName.length > 64) {
            throw UpdateVerificationException("שם גרסה אינו תקין")
        }
        val apkSize = payload.optLong("apkSize", -1L)
        if (apkSize <= 0L || apkSize > MAX_APK_BYTES) {
            throw UpdateVerificationException("גודל APK אינו מורשה")
        }
        val sha256 = payload.optString("apkSha256").lowercase()
        if (!sha256.matches(Regex("[0-9a-f]{64}"))) {
            throw UpdateVerificationException("SHA-256 אינו תקין")
        }
        val apkUrl = requireCleanHttpsUrl(payload.optString("apkUrl"))
        val issuedAt = payload.optLong("issuedAt", -1L)
        val expiresAt = payload.optLong("expiresAt", -1L)
        if (issuedAt <= 0L || issuedAt > nowEpochSeconds + MAX_CLOCK_SKEW_SECONDS) {
            throw UpdateVerificationException("זמן הנפקת manifest אינו תקין")
        }
        if (expiresAt <= nowEpochSeconds ||
            expiresAt <= issuedAt ||
            expiresAt - issuedAt > MAX_METADATA_VALIDITY_SECONDS
        ) {
            throw UpdateVerificationException("manifest העדכון פג תוקף")
        }
        return AuthorizedUpdate(
            packageName = packageName,
            versionCode = versionCode,
            versionName = versionName,
            apkUrl = apkUrl,
            apkSha256 = sha256,
            apkSize = apkSize,
            issuedAtEpochSeconds = issuedAt,
            expiresAtEpochSeconds = expiresAt,
        )
    }

    private fun verifySignature(payload: ByteArray, signatureBytes: ByteArray, keyBase64: String) {
        try {
            val keyBytes = Base64.getDecoder().decode(keyBase64)
            val publicKey = KeyFactory.getInstance("EC")
                .generatePublic(X509EncodedKeySpec(keyBytes))
            if (publicKey !is ECPublicKey || !isSecp256r1(publicKey.params)) {
                throw UpdateVerificationException("מפתח manifest חייב להיות EC P-256")
            }
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(publicKey)
            verifier.update(payload)
            if (!verifier.verify(signatureBytes)) {
                throw UpdateVerificationException("חתימת manifest אינה תקינה")
            }
        } catch (exception: UpdateVerificationException) {
            throw exception
        } catch (_: RuntimeException) {
            throw UpdateVerificationException("מפתח או חתימת manifest אינם תקינים")
        } catch (_: java.security.GeneralSecurityException) {
            throw UpdateVerificationException("אימות חתימת manifest נכשל")
        }
    }

    private fun isSecp256r1(actual: ECParameterSpec): Boolean {
        val parameters = AlgorithmParameters.getInstance("EC")
        parameters.init(ECGenParameterSpec("secp256r1"))
        val expected = parameters.getParameterSpec(ECParameterSpec::class.java)
        return actual.curve == expected.curve &&
            actual.generator == expected.generator &&
            actual.order == expected.order &&
            actual.cofactor == expected.cofactor
    }

    private fun decodeUrlBase64(value: String): ByteArray = try {
        if (value.isBlank() || value.length > MAX_MANIFEST_BYTES * 2) {
            throw IllegalArgumentException()
        }
        Base64.getUrlDecoder().decode(value)
    } catch (_: IllegalArgumentException) {
        throw UpdateVerificationException("קידוד manifest אינו תקין")
    }

    internal fun requireCleanHttpsUrl(value: String): String {
        val uri = try {
            URI(value)
        } catch (_: Exception) {
            throw UpdateVerificationException("כתובת APK אינה תקינה")
        }
        if (!uri.scheme.equals("https", ignoreCase = true) ||
            uri.host.isNullOrBlank() ||
            uri.userInfo != null ||
            uri.fragment != null ||
            uri.rawQuery?.length.orZero() > 2_048
        ) {
            throw UpdateVerificationException("כתובת APK חייבת להיות HTTPS נקייה")
        }
        return uri.toASCIIString()
    }

    private fun Int?.orZero(): Int = this ?: 0
}
