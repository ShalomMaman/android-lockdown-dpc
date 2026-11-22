package com.example.lockdowndpc.remote

internal enum class DocumentType(val wire: String, val versionField: String) {
    KEY_SET("keyset", "keySetVersion"),
    POLICY("fleet-policy", "fleetPolicyVersion"),
    RECOVERY("recovery", "recoveryVersion"),
    COMMAND("command", "sequence")
}

internal data class RemoteTrust(
    val root: String,
    val successor: String? = null,
    val version: Long = 0,
    val policyKeys: List<String> = emptyList(),
    val server: String? = null,
    val serverUrl: String? = null
) {
    fun roots() = listOfNotNull(root, successor)

    fun signers(type: DocumentType): List<String> = when (type) {
        DocumentType.KEY_SET -> roots()
        DocumentType.POLICY, DocumentType.RECOVERY -> policyKeys
        DocumentType.COMMAND -> listOfNotNull(server)
    }
}

internal data class RemoteBinding(val fleetId: String, val deviceId: String)

/** A response slot supplies the expected role without interpreting unauthenticated payload JSON. */
internal data class RemoteDocument(val type: DocumentType, val envelope: ByteArray)

internal class RemoteVerifier(private val schema: RemoteSchema, private val allowFixtureKeys: Boolean = false) {
    internal class Authenticated private constructor(
        val type: DocumentType,
        val signer: String,
        val body: JsonObject,
        private val exactPayload: ByteArray
    ) {
        val version: Long get() = body.number(type.versionField)
        val keySetVersion: Long get() = body.number("keySetVersion")
        val payload: ByteArray get() = exactPayload.copyOf()
        val committedSha256: String get() = RemoteCrypto.hex(RemoteCrypto.sha256(exactPayload))

        fun rotatedTrust() = RemoteTrust(
            root = signer, successor = body["successorRoot"] as String?,
            version = keySetVersion, policyKeys = body.items("fleetPolicyKeys").map { it as String },
            server = body.text("serverKey"), serverUrl = body.text("serverUrl")
        )

        companion object {
            fun verify(
                verifier: RemoteVerifier, input: RemoteDocument, trust: RemoteTrust, binding: RemoteBinding
            ): Authenticated {
                val envelope = verifier.schema.envelope(input.envelope)
                val id = envelope.text("keyId")
                if (!verifier.permitsKeyId(id)) refuse("doc-key-unknown")
                val signer = trust.signers(input.type).firstOrNull { RemoteCrypto.keyId(it) == id }
                    ?: refuse("doc-key-unknown")
                val payload = RemoteCrypto.decode(envelope.text("payload"))
                val signature = RemoteCrypto.decode(envelope.text("signature"))
                val valid = runCatching {
                    RemoteCrypto.verifies(RemoteCrypto.publicKey(signer), payload, signature)
                }.getOrDefault(false)
                if (!valid) refuse("doc-signature-invalid")

                val body = verifier.schema.decode(payload)
                val type = verifier.schema.payload(body)
                if (type != input.type) refuse("doc-type-unexpected", "/type")
                val document = body.asObject()
                if (document.text("fleetId") != binding.fleetId) refuse("doc-field-invalid", "/fleetId")
                if (type == DocumentType.KEY_SET) verifier.verifyRoles(document, trust)
                return Authenticated(type, signer, document, payload)
            }
        }
    }

    fun authenticate(input: RemoteDocument, trust: RemoteTrust, binding: RemoteBinding): Authenticated = try {
        Authenticated.verify(this, input, trust, binding)
    } catch (refused: Refused) {
        throw refused
    } catch (_: RuntimeException) {
        // One malformed document is refused by itself. Later documents still run.
        refuse("doc-field-invalid")
    }

    fun checkFloorsAndBinding(
        doc: Authenticated, activeVersion: Long, floor: Long, deviceId: String, nonce: String?, canRetry: Boolean
    ) {
        if (doc.keySetVersion < activeVersion || doc.version < floor || (doc.version == floor && !canRetry)) {
            refuse("doc-version-rollback")
        }
        when (doc.type) {
            DocumentType.KEY_SET -> return
            DocumentType.POLICY -> if (deviceId !in doc.body.items("deviceIds")) refuse("doc-device-not-listed")
            DocumentType.RECOVERY, DocumentType.COMMAND ->
                if (doc.body.text("deviceId") != deviceId) refuse("doc-device-not-listed")
        }
        if (doc.type == DocumentType.COMMAND && doc.body.text("nonce") != nonce) refuse("command-nonce-mismatch")
    }

    fun bootstrap(pinnedId: String, rootSpki: String, binding: RemoteBinding): RemoteTrust {
        require(binding.fleetId.isNotEmpty() && RemoteCrypto.decode(binding.deviceId).size == 32)
        RemoteCrypto.publicKey(rootSpki)
        if (RemoteCrypto.keyId(rootSpki) != pinnedId || !permitsKeyId(pinnedId) ||
            !permitsKeyId(binding.deviceId)) refuse("doc-key-unknown")
        return RemoteTrust(rootSpki)
    }

    internal class AuthenticatedReanchor private constructor(
        val binding: RemoteBinding,
        val trust: RemoteTrust,
        val floors: Map<DocumentType, Long>,
        val floorPayloadSha256: Map<DocumentType, String>
    ) {
        companion object {
            fun verify(
                verifier: RemoteVerifier, input: ByteArray, pin: RecoveryPin, nonce: String
            ): AuthenticatedReanchor = try {
                if (input.size > RemoteReanchor.MAX_ENVELOPE_BYTES) refuse("doc-field-invalid")
                val envelope = verifier.schema.envelope(input)
                if (envelope.text("keyId") != pin.rootFingerprint || !verifier.permitsKeyId(pin.rootFingerprint)) {
                    refuse("re-anchor-root-mismatch")
                }
                val payload = RemoteCrypto.decode(envelope.text("payload"))
                // Read only the candidate verification key before checking the signature.
                // The full SPKI must hash to the independently authenticated fingerprint.
                val body = verifier.schema.decode(payload).asObject()
                val spki = body["rootSpki"] as? String ?: refuse("doc-field-invalid", "/rootSpki")
                if (RemoteCrypto.keyId(spki) != pin.rootFingerprint) refuse("re-anchor-root-mismatch")
                if (!RemoteCrypto.verifies(RemoteCrypto.publicKey(spki), payload,
                        RemoteCrypto.decode(envelope.text("signature")))) refuse("doc-signature-invalid")
                verifier.schema.requireValid(RemoteReanchor.TYPE, body)
                if (body.text("rootFingerprint") != pin.rootFingerprint) refuse("re-anchor-root-mismatch")
                val binding = RemoteBinding(body.text("fleetId"), body.text("deviceId"))
                if (binding.fingerprint() != pin.bindingFingerprint) refuse("re-anchor-binding-mismatch")
                if (body.text("nonce") != nonce) refuse("re-anchor-nonce-invalid")
                val floors = body.obj("floors")
                AuthenticatedReanchor(binding, verifier.bootstrap(pin.rootFingerprint, spki, binding),
                    DocumentType.entries.associateWith { floors.number(it.wire) },
                    RemoteReanchor.resendableTypes.mapNotNull { type ->
                        body["floorPayloadSha256"]?.asObject()?.get(type.wire)?.let { type to (it as String) }
                    }.toMap())
            } catch (error: Refused) {
                throw error
            } catch (_: Exception) {
                refuse("doc-field-invalid")
            }
        }
    }

    fun authenticateReanchor(input: ByteArray, pin: RecoveryPin, nonce: String): AuthenticatedReanchor =
        AuthenticatedReanchor.verify(this, input, pin, nonce)

    fun permitsKeyId(id: String): Boolean = allowFixtureKeys || id !in TEST_KEY_IDS

    private fun verifyRoles(doc: JsonObject, trust: RemoteTrust) {
        val roots = trust.roots() + listOfNotNull(doc["successorRoot"] as String?)
        val servers = doc.text("serverKey")
        val policies = doc.items("fleetPolicyKeys").map { it as String }
        val keys = listOf("serverKey" to servers) + policies.mapIndexed { i, key -> "fleetPolicyKeys/$i" to key } +
            listOfNotNull((doc["successorRoot"] as String?)?.let { "successorRoot" to it })
        for ((path, key) in keys) {
            if (!permitsKeyId(RemoteCrypto.keyId(key))) refuse("doc-field-invalid", "/$path")
        }
        if (servers in roots || servers in policies) refuse("doc-field-invalid", "/serverKey")
        if (policies.any { it in roots }) refuse("doc-field-invalid", "/fleetPolicyKeys")
    }

    companion object {
        internal val TEST_KEY_IDS = setOf(
            "wqxIfMAeuyha6pKbj8Ob-aoDUU9-ZGwnbb-EgRBEaZU", "UJp-JBAqRc7SuBFldywo2TmT8pYAXWLrlBjKp_XGf5A",
            "yuBMSRn_FyWj104OArTzeExdiHdbYIs7RguY37aICpI", "AC_1Ky9Jg9KideBpZ_zXxvTKlcp-USbj1h9Rl4z51QM",
            "htxuEHubuWZIGu6bTg0LBRTPuH64WYhbyaVB6pyldnk", "8iXZ83US03Z5z5ZaTwn9ifumVvnNpaOHHyghOAyGJTw",
            "0N7UdpZGSywqoLCZa9dcI5BE7QtTB04SaEykPmwe74I", "yry0uOnre8zDLuLKEy0BbEzndWUotWqG1JSNz18Rh5o",
            "Ihuz3CXaARD5vI17XSYr3rE4zuHGSUphX-gk-9Nav70", "bBiF1hHDuE3iZhUHVRdArxFAUamsy29m94F8d7jc000",
            "Wt5dqGUiOGEOmQnsjREkEhaDTi-Gwutlowxos8oCfYw", "GcH_iCSKuBg3eIxngwpuYtYDy-GlCwjyfzHejbgNCZg",
            "zFpgccW8b2hDsgIYtmCFrf3OcBrhtx8ahFN8skRU-Pg"
        )
    }
}
