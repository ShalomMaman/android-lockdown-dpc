package com.example.lockdowndpc.policy

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import com.example.lockdowndpc.remote.RemoteClientWire
import com.example.lockdowndpc.remote.RemoteCrypto
import com.example.lockdowndpc.remote.WireJson
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.cert.Certificate
import java.security.spec.ECGenParameterSpec

/** Called on the network worker after first unlock. Private keys stay in Android. */
internal class AndroidRemoteIdentity(private val context: Context) {
    private val dpm = requireNotNull(context.getSystemService(DevicePolicyManager::class.java))

    fun prepare(challenge: String, ticket: String, root: String): RemoteClientStore.Pending {
        val alias = alias(challenge)
        val keystore = store()
        val chain = keystore.getCertificateChain(alias)?.toList() ?: generate(alias, challenge)
        require(chain.size in 1..16)
        val deviceId = RemoteCrypto.encode(RemoteCrypto.sha256(chain.first().publicKey.encoded))
        val encodedChain = chain.map { RemoteCrypto.encode(it.encoded) }
        val facts = buildMap {
            put("sdk", Build.VERSION.SDK_INT.toLong())
            put("firmwareFamily", Build.DEVICE)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                // The root digest is the fleet-scoped, non-personal organisation identifier.
                if (dpm.enrollmentSpecificId.isEmpty()) dpm.setOrganizationId(root)
                dpm.enrollmentSpecificId.takeIf { it.isNotEmpty() }?.let { put("enrollmentSpecificId", it) }
            }
        }
        val transcript = RemoteClientWire.enrolTranscript(challenge, ticket, encodedChain, facts)
        val signature = sign(challenge, transcript)
        val finish = WireJson.canonical(mapOf("ticket" to ticket, "attestationChain" to encodedChain,
            "facts" to facts, "transcriptSignature" to signature)).toString(Charsets.UTF_8)
        return RemoteClientStore.Pending(challenge, deviceId, finish)
    }

    fun sign(challenge: String, bytes: ByteArray): String {
        val alias = alias(challenge)
        val key = store().getKey(alias, null) as? PrivateKey
        return RemoteCrypto.encode(Signature.getInstance("SHA256withECDSA").run {
            initSign(requireNotNull(key))
            update(bytes)
            sign()
        })
    }

    fun forgetExpired(challenge: String) {
        store().deleteEntry(alias(challenge))
    }

    private fun generate(alias: String, challenge: String): List<Certificate> {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
            try {
                return generate(alias, challenge, strongBox = true)
            } catch (_: StrongBoxUnavailableException) {
                // Some devices offer StrongBox without supporting this key and attestation combination.
            }
        }
        return generate(alias, challenge, strongBox = false)
    }

    private fun generate(alias: String, challenge: String, strongBox: Boolean): List<Certificate> {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(RemoteCrypto.decode(challenge).also { require(it.size == 32) })
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) spec.setIsStrongBoxBacked(true)
        // Generate in this app's Keystore namespace so attestation binds the
        // remote-test APK identity that the reference server verifies.
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER).apply {
            initialize(spec.build())
            generateKeyPair()
        }
        return requireNotNull(store().getCertificateChain(alias)).toList()
    }

    private fun alias(challenge: String): String {
        require(RemoteCrypto.decode(challenge).size == 32)
        return "dg-remote-$challenge"
    }

    private fun store(): KeyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }

    private companion object {
        const val PROVIDER = "AndroidKeyStore"
    }
}
