package com.example.lockdowndpc.remote

import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

internal object RemoteCrypto {
    fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    fun decode(text: String): ByteArray = Base64.getUrlDecoder().decode(text).also {
        require(encode(it) == text)
    }

    fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
    fun hex(bytes: ByteArray): String = bytes.joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }
    fun unhex(value: String): ByteArray {
        require(value.length == 64 && value.all { it in '0'..'9' || it in 'a'..'f' })
        return ByteArray(32) { value.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    fun generation(committed: String, overrides: Set<RemoteOverride>): String {
        val codes = overrides.map { it.code }.sorted()
        val bytes = "dg-gen/1\u0000".toByteArray(Charsets.US_ASCII) + unhex(committed) +
            byteArrayOf(codes.size.toByte()) + codes.flatMap { code ->
                listOf(code.length.toByte()) + code.toByteArray(Charsets.US_ASCII).toList()
            }.toByteArray()
        return hex(sha256(bytes))
    }

    private val spkiPrefix = decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE")
    private val prime = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
    private val b = BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)

    fun publicKey(encoded: String): PublicKey {
        val bytes = decode(encoded)
        val start = spkiPrefix.size
        require(bytes.size == start + 64 && bytes.copyOfRange(0, start).contentEquals(spkiPrefix))
        val x = BigInteger(1, bytes.copyOfRange(start, start + 32))
        val y = BigInteger(1, bytes.copyOfRange(start + 32, bytes.size))
        require(x < prime && y < prime && y.multiply(y).mod(prime) ==
            x.pow(3).subtract(x.multiply(BigInteger.valueOf(3))).add(b).mod(prime))
        return KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(bytes))
    }

    fun keyId(encoded: String): String = encode(sha256(decode(encoded)))

    fun verifies(key: PublicKey, bytes: ByteArray, der: ByteArray): Boolean {
        if (!strictDer(der)) return false
        return Signature.getInstance("SHA256withECDSA").run {
            initVerify(key)
            update(bytes)
            verify(der)
        }
    }

    // P-256 ECDSA is a short DER sequence of exactly two positive, minimally encoded integers.
    private fun strictDer(der: ByteArray): Boolean {
        if (der.size !in 8..72 || der[0] != 0x30.toByte() || der[1].toInt() != der.size - 2) return false
        var at = 2
        repeat(2) {
            if (at + 2 >= der.size || der[at++] != 2.toByte()) return false
            val size = der[at++].toInt()
            if (size !in 1..33 || at + size > der.size || der[at] < 0) return false
            if (der[at] == 0.toByte() && (size == 1 || der[at + 1] >= 0)) return false
            at += size
        }
        return at == der.size
    }

    fun isCanonicalCa(encoded: String): Boolean = runCatching {
        val der = Base64.getDecoder().decode(encoded)
        if (Base64.getEncoder().encodeToString(der) != encoded) return@runCatching false
        val input = ByteArrayInputStream(der)
        val ca = CertificateFactory.getInstance("X.509").generateCertificate(input) as X509Certificate
        input.available() == 0 && ca.basicConstraints >= 0 && ca.encoded.contentEquals(der)
    }.getOrDefault(false)
}

internal enum class RemoteOverride(val code: String) {
    COMMANDS_OFF("commands-off"),
    NETWORK_OFF("network-off");

    companion object {
        fun fromCode(code: String): RemoteOverride = entries.single { it.code == code }
    }
}
