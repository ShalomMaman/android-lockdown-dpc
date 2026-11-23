package com.example.lockdowndpc.policy

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.PersistableBundle
import com.example.lockdowndpc.remote.JsonObject
import com.example.lockdowndpc.remote.RemoteClientWire
import com.example.lockdowndpc.remote.RemoteCrypto
import com.example.lockdowndpc.remote.RemoteEngine
import com.example.lockdowndpc.remote.WireJson
import com.example.lockdowndpc.remote.asObject
import com.example.lockdowndpc.remote.items
import com.example.lockdowndpc.remote.text
import com.example.lockdowndpc.security.DurablePreferences

internal object RemoteTransport {
    @JvmStatic
    fun supportsArtifact(context: Context): Boolean {
        val flags = context.applicationInfo.flags
        return RemoteEnrolmentGate.permits() && Build.VERSION.SDK_INT >= RemoteEngine.MIN_SDK &&
            flags and (ApplicationInfo.FLAG_TEST_ONLY or ApplicationInfo.FLAG_DEBUGGABLE) == 0
    }

    @JvmStatic
    fun schedule(context: Context) = RemoteTestScheduler.schedule(context)

    @JvmStatic
    fun mark(context: Context, request: Intent): Boolean = runCatching {
        supportsArtifact(context) && RemoteEnrolmentGate.remoteExtras(request) != null &&
            ManagementModeStore.markProvisioningRemoteIntent(context)
    }.getOrDefault(false)

    @JvmStatic
    fun store(context: Context, request: Intent): Boolean = runCatching {
        if (!RemoteTestScheduler.unlocked(context) || !RemoteTestScheduler.deviceOwner(context) || !mark(context, request)) return false
        val config = RemoteClientConfig.from(requireNotNull(RemoteEnrolmentGate.remoteExtras(request)))
        RemoteClientStore(context).initialise(config)
    }.getOrDefault(false)
}

internal class RemoteClientConfig(
    val server: String, val root: String, val pins: List<String>, val ticket: String?
) {
    init {
        require(RemoteClientWire.serverUrl(server) == server)
        require(RemoteCrypto.decode(root).size == 32)
        require(pins.size <= 2 && pins.all { RemoteCrypto.decode(it).size == 32 })
        ticket?.let(RemoteClientWire::ticketDigest)
    }

    companion object {
        private val supported = setOf("dg.remote.v", "dg.remote.server", "dg.remote.root", "dg.remote.tls",
            "dg.remote.ticket", "dg.remote.fleet")

        fun from(extras: PersistableBundle): RemoteClientConfig {
            require(extras.keySet().filter { it.startsWith("dg.remote.") }.all { it in supported })
            require(extras.getString("dg.remote.v") == "1")
            val pins = if (extras.containsKey("dg.remote.tls")) {
                requireNotNull(extras.getString("dg.remote.tls")).split(',')
            } else emptyList()
            return RemoteClientConfig(
                RemoteClientWire.serverUrl(requireNotNull(extras.getString("dg.remote.server"))),
                requireNotNull(extras.getString("dg.remote.root")), pins,
                requireNotNull(extras.getString("dg.remote.ticket")),
            )
        }
    }
}

/** Credential-protected and excluded from backups. Never logs tickets, chains or facts. */
internal class RemoteClientStore(context: Context) {
    data class Pending(val challenge: String, val deviceId: String? = null, val finish: String? = null)

    private val prefs = context.getSharedPreferences("remote_test_client", Context.MODE_PRIVATE)

    fun initialise(config: RemoteClientConfig): Boolean = synchronized(WRITE_LOCK) {
        val current = config()
        if (current != null) {
            return current.server == config.server && current.root == config.root && current.pins == config.pins &&
                (current.ticket == null || current.ticket == config.ticket)
        }
        writeConfig(config)
    }

    fun config(): RemoteClientConfig? = read(CONFIG)?.let {
        RemoteClientConfig(it.text("server"), it.text("root"), it.items("pins").map { pin -> pin as String },
            it["ticket"] as String?)
    }

    fun pending(): Pending? = read(PENDING)?.let {
        Pending(it.text("challenge"), it["deviceId"] as String?, it["finish"] as String?)
    }

    fun savePending(value: Pending?): Boolean = synchronized(WRITE_LOCK) {
        write(PENDING, value?.let {
            mapOf("challenge" to it.challenge, "deviceId" to it.deviceId, "finish" to it.finish)
        })
    }

    fun complete(config: RemoteClientConfig, pending: Pending): Boolean = synchronized(WRITE_LOCK) {
        val update = prefs.edit().putString(IDENTITY, pending.challenge).remove(PENDING)
        update.putString(CONFIG, encode(configFields(RemoteClientConfig(config.server, config.root, config.pins, null))))
        DurablePreferences.commit(prefs, update, CONFIG, PENDING, IDENTITY)
    }

    fun identity(): String? = prefs.getString(IDENTITY, null)

    private fun writeConfig(config: RemoteClientConfig) = write(CONFIG, configFields(config))
    private fun configFields(config: RemoteClientConfig): JsonObject =
        mapOf("server" to config.server, "root" to config.root, "pins" to config.pins, "ticket" to config.ticket)

    private fun read(key: String) = prefs.getString(key, null)?.let { WireJson.parse(it.toByteArray()).asObject() }
    private fun encode(value: JsonObject) = WireJson.canonical(value).toString(Charsets.UTF_8)
    private fun write(key: String, value: JsonObject?): Boolean {
        val edit = prefs.edit()
        if (value == null) edit.remove(key) else edit.putString(key, encode(value))
        return DurablePreferences.commit(prefs, edit, key)
    }

    private companion object {
        const val CONFIG = "config"
        const val PENDING = "pending"
        const val IDENTITY = "identity"
        val WRITE_LOCK = Any()
    }
}
