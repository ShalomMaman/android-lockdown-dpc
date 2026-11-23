package com.example.lockdowndpc.remote

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.URI
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

internal class RemoteHttpRefusal(val status: Int, val code: String?) : IOException()

/** The command key is authenticated in RemoteVerifier. TLS pins, when supplied, are separate. */
internal class RemoteHttps(server: String, pins: List<String>) {
    private val base = RemoteClientWire.serverUrl(server)
    private val sockets = if (pins.isEmpty()) null else {
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        factory.init(null as java.security.KeyStore?)
        val platform = factory.trustManagers.filterIsInstance<X509TrustManager>().single()
        val pinned = object : X509TrustManager by platform {
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                platform.checkServerTrusted(chain, authType)
                if (chain.none { RemoteCrypto.encode(RemoteCrypto.sha256(it.publicKey.encoded)) in pins }) {
                    throw CertificateException("remote-tls-pin-mismatch")
                }
            }
        }
        SSLContext.getInstance("TLS").apply { init(null, arrayOf(pinned), null) }.socketFactory
    }

    fun request(path: String, body: ByteArray? = null, headers: Map<String, String> = emptyMap()): ByteArray {
        val connection = URI.create(base + path).toURL().openConnection() as HttpsURLConnection
        try {
            connection.instanceFollowRedirects = false
            connection.useCaches = false
            connection.connectTimeout = TIMEOUT_MS
            connection.readTimeout = TIMEOUT_MS
            sockets?.let { connection.sslSocketFactory = it }
            for ((key, value) in headers) connection.setRequestProperty(key, value)
            if (body != null) {
                connection.requestMethod = "POST"
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                connection.setFixedLengthStreamingMode(body.size)
                connection.outputStream.use { it.write(body) }
            }
            val status = connection.responseCode
            if (status != 200) {
                val code = if (status == 410) connection.errorStream?.use {
                    runCatching { WireJson.parse(it.bounded(1024)).asObject().text("code") }.getOrNull()
                } else null
                throw RemoteHttpRefusal(status, code)
            }
            return connection.inputStream.use { it.bounded(MAX_REPLY) }
        } finally {
            connection.disconnect()
        }
    }

    private fun java.io.InputStream.bounded(limit: Int): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            val count = read(buffer)
            if (count < 0) return output.toByteArray()
            if (output.size() + count > limit) throw IOException("remote-response-too-large")
            output.write(buffer, 0, count)
        }
    }

    private companion object {
        const val TIMEOUT_MS = 10_000
        const val MAX_REPLY = 2 * 1024 * 1024
    }
}
