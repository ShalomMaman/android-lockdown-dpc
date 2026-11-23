package com.example.lockdowndpc.remote

import java.security.cert.CertPathBuilder
import java.security.cert.CertStore
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.PKIXBuilderParameters
import java.security.cert.PKIXCertPathBuilderResult
import java.security.cert.TrustAnchor
import java.security.cert.X509CertSelector
import java.security.cert.X509Certificate
import java.util.Date
import javax.net.ssl.X509TrustManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [32], manifest = Config.NONE)
class RemotePinnedTrustManagerTest {
    // Public test certificates only. All three signing keys were discarded.
    private val certificates = requireNotNull(javaClass.getResourceAsStream("/remote/tls-chain.crt")).use { input ->
        CertificateFactory.getInstance("X.509").generateCertificates(input).map { it as X509Certificate }
    }
    private val leaf = certificates[0]
    private val root = certificates[1]
    private val unrelated = certificates[2]
    private val platform = PkixTrustManager(arrayOf(root, unrelated))

    @Test fun appendedCertificateOutsideVerifiedPathCannotSatisfyPin() {
        val presented = arrayOf(leaf, root, unrelated)
        assertEquals(listOf(leaf, root), platform.checkServerTrusted(presented, "EC", HOST))

        val pinned = RemotePinnedTrustManager(platform, HOST, listOf(pin(unrelated)))
        val failure = assertThrows(CertificateException::class.java) {
            pinned.checkServerTrusted(presented, "EC")
        }
        assertEquals("remote-tls-pin-mismatch", failure.message)
    }

    @Test fun pinMatchesTheVerifiedPathIncludingAnOmittedTrustAnchor() {
        val pinned = RemotePinnedTrustManager(platform, HOST, listOf(pin(root)))
        pinned.checkServerTrusted(arrayOf(leaf), "EC")
    }

    private fun pin(cert: X509Certificate) = RemoteCrypto.encode(RemoteCrypto.sha256(cert.publicKey.encoded))

    // Android's host-aware adapter accepts a trust manager with this public
    // three-argument method. Build a real PKIX path from the public test certs.
    class PkixTrustManager(private val roots: Array<X509Certificate>) : X509TrustManager {
        override fun getAcceptedIssuers() = roots

        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
            throw CertificateException("client authentication is outside this fixture")
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            checkServerTrusted(chain, authType, HOST)
        }

        fun checkServerTrusted(chain: Array<X509Certificate>, authType: String, host: String): List<X509Certificate> {
            assertEquals(HOST, host)
            assertEquals("EC", authType)
            val selector = X509CertSelector().apply { certificate = chain.first() }
            val parameters = PKIXBuilderParameters(roots.map { TrustAnchor(it, null) }.toSet(), selector).apply {
                isRevocationEnabled = false
                date = Date(chain.first().notBefore.time + 60_000)
                addCertStore(CertStore.getInstance("Collection", CollectionCertStoreParameters(chain.toList())))
            }
            val result = CertPathBuilder.getInstance("PKIX").build(parameters) as PKIXCertPathBuilderResult
            return result.certPath.certificates.map { it as X509Certificate } + result.trustAnchor.trustedCert
        }
    }

    private companion object {
        const val HOST = "remote.example.test"
    }
}
