package com.example.lockdowndpc.remote

import java.net.URI
import java.util.Base64
import java.util.regex.Pattern

internal data class RemoteFailure(val code: String, val path: String? = null)
internal class Refused(val failure: RemoteFailure) : RuntimeException(failure.code)
internal fun refuse(code: String, path: String? = null): Nothing = throw Refused(RemoteFailure(code, path))

/** Validates the closed subset of JSON Schema used by the bundled v1 contract. */
internal class RemoteSchema(bytes: ByteArray) {
    private val defs = WireJson.parse(bytes).asObject().obj("\$defs")
    private val patterns = mutableMapOf<String, Pattern>()

    fun decode(bytes: ByteArray): Any? = try {
        WireJson.parse(bytes)
    } catch (_: Exception) {
        refuse("doc-field-invalid", "")
    }

    fun envelope(bytes: ByteArray): JsonObject {
        if (bytes.size > WireJson.MAX_ENVELOPE) refuse("doc-field-invalid", "")
        val result = decode(bytes)
        requireValid("envelope", result)
        return result.asObject()
    }

    fun payload(value: Any?): DocumentType {
        val typeName = (value as? Map<*, *>)?.get("type")
        if (typeName !is String) refuse("doc-field-invalid", "/type")
        val type = DocumentType.entries.firstOrNull { it.wire == typeName }
            ?: refuse("doc-type-unexpected", "/type")
        requireValid(type.wire, value)
        return type
    }

    fun requireValid(name: String, value: Any?) = validate(defs.obj(name), value, "")

    private fun validate(schema: JsonObject, value: Any?, path: String) {
        fun invalid(): Nothing = refuse("doc-field-invalid", path)
        require(schema.keys.all { it in SUPPORTED })
        (schema["\$ref"] as String?)?.let {
            require(it.startsWith("#/\$defs/"))
            val name = it.substringAfterLast('/')
            // Decode directly to avoid recursive regex evaluation on long payload strings.
            when (name) {
                "base64url", "base64url16", "base64url32" -> {
                    val size = (value as? String)?.let { encoded ->
                        runCatching { RemoteCrypto.decode(encoded).size }.getOrNull()
                    } ?: invalid()
                    if (size == 0 || (name == "base64url16" && size != 16) ||
                        (name == "base64url32" && size != 32)) invalid()
                }
                else -> validate(defs.obj(name), value, path)
            }
            when (name) {
                "p256Spki" -> if (runCatching { RemoteCrypto.publicKey(value as String) }.isFailure) invalid()
                "httpsUrl", "pacUrl", "kioskUrl", "serverUrl" -> if (!urlValid(name, value as String)) invalid()
            }
        }
        if (schema.containsKey("type") && !matchesType(schema.text("type"), value)) invalid()
        if (schema.containsKey("const") && value != schema["const"]) invalid()
        if (schema.containsKey("enum") && value !in schema.items("enum")) {
            if (path == "/kind" && value is String) refuse("command-unknown", path)
            invalid()
        }
        when (value) {
            is Map<*, *> -> {
                val properties = schema["properties"]?.asObject().orEmpty()
                val fields = value.asObject()
                if (schema["additionalProperties"] == false) {
                    (fields.keys - properties.keys).minWithOrNull(WireJson::compareScalars)?.let {
                        refuse("doc-field-unknown", pointer(path, it))
                    }
                }
                (schema["required"] as? List<*>)?.forEach {
                    if (!fields.containsKey(it)) refuse("doc-field-invalid", pointer(path, it.toString()))
                }
                if (fields.size > (schema["maxProperties"] as? Long ?: Long.MAX_VALUE)) invalid()
                properties.forEach { (key, child) ->
                    if (fields.containsKey(key)) validate(child.asObject(), fields[key], pointer(path, key))
                }
            }
            is List<*> -> {
                if (value.size.toLong() !in bounds(schema, "minItems", "maxItems")) invalid()
                if (schema["uniqueItems"] == true && value.toSet().size != value.size) invalid()
                schema["items"]?.let { child ->
                    value.forEachIndexed { index, item -> validate(child.asObject(), item, pointer(path, index.toString())) }
                }
                if (path.endsWith("/apps/systemSelection") &&
                    value.map { it.asObject().text("package") }.toSet().size != value.size) invalid()
            }
            is String -> {
                if (value.codePointCount(0, value.length).toLong() !in bounds(schema, "minLength", "maxLength")) invalid()
                (schema["pattern"] as? String)?.let { pattern ->
                    val matches = when {
                        path.endsWith("/caCertificate") -> runCatching {
                            Base64.getEncoder().encodeToString(Base64.getDecoder().decode(value)) == value
                        }.getOrDefault(false)
                        else -> testPattern(pattern, value)
                    }
                    if (!matches) invalid()
                }
                if (path.endsWith("/canary/expectedBody") && value.toByteArray().size > 1024) invalid()
            }
            is Long -> if (value !in bounds(schema, "minimum", "maximum")) invalid()
        }
        (schema["oneOf"] as? List<*>)?.let { branches ->
            if (branches.count {
                    try {
                        validate(it.asObject(), value, path)
                        true
                    } catch (_: Refused) {
                        false
                    }
                } != 1) invalid()
        }
        if (path.endsWith("/caCertificate") && value is String && schema.containsKey("oneOf") &&
            !RemoteCrypto.isCanonicalCa(value)) invalid()
    }

    private fun testPattern(pattern: String, value: String): Boolean {
        if (pattern == "\\S") {
            return value.any { !Character.isWhitespace(it) && !Character.isSpaceChar(it) && it != '\u0085' }
        }
        // The separators disambiguate repetitions. Make them possessive so a long
        // sequence of package or DNS labels cannot exhaust the regex stack.
        val compiled = synchronized(patterns) {
            patterns.getOrPut(pattern) {
                val bounded = pattern.replace("*)*", "*)*+").replace("*)+", "*)++")
                    .replace("])?)*", "])?)*+")
                Pattern.compile(bounded, Pattern.UNICODE_CHARACTER_CLASS)
            }
        }
        return try {
            compiled.matcher(value).find()
        } catch (_: StackOverflowError) {
            false
        }
    }

    private fun urlValid(kind: String, value: String): Boolean {
        val authority = value.substringAfter("://").takeWhile { it != '/' && it != '?' && it != '#' }
        val host = if (authority.startsWith('[')) authority.substringBefore(']') + "]" else authority.substringBefore(':')
        val port = authority.removePrefix(host).removePrefix(":")
        if (port.isNotEmpty() && (port.toIntOrNull() ?: 0) !in 1..65535) return false
        if (host.startsWith('[') && runCatching { URI("https://$host").host }.getOrNull() == null) return false
        if (kind != "kioskUrl") return true
        if ('.' !in host && ':' !in host) return false
        val path = value.substringAfter("://").removePrefix(authority).substringBefore('?').substringBefore('#')
        return path.split('/').none { it.replace("%2e", ".", ignoreCase = true) in setOf(".", "..") }
    }

    private fun matchesType(type: String, value: Any?): Boolean = when (type) {
        "object" -> value is Map<*, *>
        "array" -> value is List<*>
        "string" -> value is String
        "integer" -> value is Long
        "boolean" -> value is Boolean
        "null" -> value == null
        else -> error("Unknown schema type")
    }

    private fun bounds(schema: JsonObject, min: String, max: String) =
        (schema[min] as? Long ?: Long.MIN_VALUE)..(schema[max] as? Long ?: Long.MAX_VALUE)

    private fun pointer(path: String, key: String) = path + "/" + key.replace("~", "~0").replace("/", "~1")

    companion object {
        private val SUPPORTED = setOf("\$ref", "type", "oneOf", "const", "enum", "minimum", "maximum",
            "properties", "required", "additionalProperties", "maxProperties", "items",
            "minItems", "maxItems", "uniqueItems", "pattern", "minLength", "maxLength", "default")
    }
}
