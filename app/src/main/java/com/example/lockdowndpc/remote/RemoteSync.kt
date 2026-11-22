package com.example.lockdowndpc.remote

internal data class RemoteTime(val boot: Long, val elapsed: Long) {
    val known: Boolean get() = boot >= 0L && elapsed >= 0L
}

internal class RemoteSync(private val verifier: RemoteVerifier, private val binding: RemoteBinding) {
    class Exchange internal constructor(val nonce: String, val sent: RemoteTime) {
        val cutoff = Math.addExact(sent.elapsed, WINDOW_MS)
        fun fresh(now: RemoteTime) = now.boot == sent.boot && now.elapsed in sent.elapsed until cutoff
    }

    data class Decision(val index: Int, val failure: RemoteFailure?)
    data class Response(val failure: RemoteFailure?, val decisions: List<Decision> = emptyList())

    private var outstanding: Exchange? = null

    fun begin(nonce: String, now: RemoteTime): Exchange? {
        if (outstanding?.fresh(now) == true || !now.known || now.elapsed > Long.MAX_VALUE - WINDOW_MS) return null
        require(RemoteCrypto.decode(nonce).size == 32)
        return Exchange(nonce, now).also { outstanding = it }
    }

    fun expire(now: RemoteTime) {
        if (outstanding?.fresh(now) == false) outstanding = null
    }

    fun respond(
        exchange: Exchange, responseNonce: String, now: RemoteTime, documents: List<RemoteDocument>,
        trust: () -> RemoteTrust, floor: (DocumentType) -> Long,
        canRetry: (RemoteVerifier.Authenticated) -> Boolean,
        accept: (RemoteVerifier.Authenticated, Exchange) -> RemoteFailure?
    ): Response {
        if (outstanding !== exchange) return stale()
        outstanding = null
        if (!exchange.fresh(now) || responseNonce != exchange.nonce) return stale()

        val decisions = mutableListOf<Decision>()
        for (type in DocumentType.entries) {
            val active = trust()
            val candidates = documents.withIndex().filter { it.value.type == type }.mapNotNull { (index, document) ->
                try {
                    index to verifier.authenticate(document, active, binding)
                } catch (error: Refused) {
                    decisions.add(Decision(index, error.failure))
                    null
                }
            }
            val ordered = if (type == DocumentType.KEY_SET || type == DocumentType.POLICY) {
                candidates.sortedByDescending { it.second.version }
            } else candidates
            var storeFailure: RemoteFailure? = null
            for ((index, doc) in ordered) {
                if (storeFailure != null) {
                    decisions.add(Decision(index, storeFailure))
                    continue
                }
                val failure = try {
                    val trustVersion = trust().version
                    val keySetFloor = maxOf(trustVersion, floor(DocumentType.KEY_SET))
                    // Once a keyset is reserved, delegated keys cannot act
                    // under its version until that keyset is committed.
                    if (type != DocumentType.KEY_SET && trustVersion < keySetFloor) refuse("doc-version-rollback")
                    verifier.checkFloorsAndBinding(
                        doc, keySetFloor, floor(type), binding.deviceId, exchange.nonce, canRetry(doc)
                    )
                    accept(doc, exchange)
                } catch (error: Refused) {
                    error.failure
                }
                decisions.add(Decision(index, failure))
                // A higher admissible version that hit a disk failure does not
                // make an older candidate in the same step the selected policy.
                if (failure?.code == "journal-write-failed") storeFailure = failure
            }
        }
        return Response(null, decisions)
    }

    private fun stale() = Response(RemoteFailure("sync-response-stale"))

    companion object {
        const val WINDOW_MS = 120_000L
    }
}
