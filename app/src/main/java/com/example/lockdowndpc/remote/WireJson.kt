package com.example.lockdowndpc.remote

import java.nio.ByteBuffer
import java.util.Collections

/** JSON with the deliberately narrower number and Unicode grammar of dg-signed/1. */
internal object WireJson {
    const val MAX_INTEGER = 9_007_199_254_740_991L
    const val MAX_ENVELOPE = 65_536

    fun parse(bytes: ByteArray): Any? = Parser(
        Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString()
    ).parse()

    fun canonical(value: Any?): ByteArray = buildString { appendJson(value) }.toByteArray(Charsets.UTF_8)

    private fun StringBuilder.appendJson(value: Any?) {
        when (value) {
            null -> append("null")
            is Boolean -> append(value)
            is Long -> {
                require(value in -MAX_INTEGER..MAX_INTEGER)
                append(value)
            }
            is String -> {
                checkUnicode(value)
                append('"')
                value.forEach {
                    when (it) {
                        '"' -> append("\\\"")
                        '\\' -> append("\\\\")
                        '\b' -> append("\\b")
                        '\t' -> append("\\t")
                        '\n' -> append("\\n")
                        '\u000c' -> append("\\f")
                        '\r' -> append("\\r")
                        in '\u0000'..'\u001f' -> append("\\u00").append(it.code.toString(16).padStart(2, '0'))
                        else -> append(it)
                    }
                }
                append('"')
            }
            is List<*> -> {
                append('[')
                value.forEachIndexed { index, item ->
                    if (index > 0) append(',')
                    appendJson(item)
                }
                append(']')
            }
            is Map<*, *> -> {
                append('{')
                // Compare Unicode scalar values. All v1 schema property names are ASCII.
                val keys = value.keys.map { it as String }.sortedWith(::compareScalars)
                keys.forEachIndexed { index, key ->
                    if (index > 0) append(',')
                    appendJson(key)
                    append(':')
                    appendJson(value[key])
                }
                append('}')
            }
            else -> throw IllegalArgumentException("Unsupported JSON value")
        }
    }

    fun compareScalars(left: String, right: String): Int {
        var a = 0
        var b = 0
        while (a < left.length && b < right.length) {
            val x = left.codePointAt(a)
            val y = right.codePointAt(b)
            if (x != y) return x.compareTo(y)
            a += Character.charCount(x)
            b += Character.charCount(y)
        }
        return (left.length - a).compareTo(right.length - b)
    }

    private fun checkUnicode(value: String) {
        var index = 0
        while (index < value.length) {
            val char = value[index++]
            if (char.isHighSurrogate()) {
                require(index < value.length && value[index++].isLowSurrogate())
            } else {
                require(!char.isLowSurrogate())
            }
        }
    }

    private class Parser(private val input: String) {
        private var at = 0
        private fun peek() = input.getOrNull(at)
        private fun whitespace() {
            while (true) {
                when (peek()) {
                    ' ', '\t', '\n', '\r' -> at++
                    else -> return
                }
            }
        }
        private fun take(char: Char): Boolean {
            if (peek() != char) return false
            at++
            return true
        }
        fun parse(): Any? {
            val result = value(0)
            whitespace()
            require(at == input.length)
            return result
        }
        private fun value(depth: Int): Any? {
            require(depth < 64)
            whitespace()
            return when (peek()) {
                '{' -> objectValue(depth)
                '[' -> arrayValue(depth)
                '"' -> string()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                '-', in '0'..'9' -> integer()
                else -> throw IllegalArgumentException("Invalid JSON token")
            }
        }
        private fun literal(token: String, value: Any?): Any? {
            require(input.startsWith(token, at))
            at += token.length
            return value
        }
        private fun integer(): Long {
            val start = at
            val negative = take('-')
            if (take('0')) {
                require(!negative)
            } else {
                require((peek() ?: '\u0000') in '1'..'9')
                do { at++ } while ((peek() ?: '\u0000') in '0'..'9')
            }
            require(at - start <= 17)
            return input.substring(start, at).toLong().also { require(it in -MAX_INTEGER..MAX_INTEGER) }
        }
        private fun objectValue(depth: Int): Map<String, Any?> {
            at++
            val result = linkedMapOf<String, Any?>()
            whitespace()
            if (!take('}')) {
                do {
                    whitespace()
                    val key = string()
                    require(!result.containsKey(key))
                    whitespace()
                    require(take(':'))
                    result[key] = value(depth + 1)
                    whitespace()
                } while (take(','))
                require(take('}'))
            }
            return Collections.unmodifiableMap(result)
        }
        private fun arrayValue(depth: Int): List<Any?> {
            at++
            val result = mutableListOf<Any?>()
            whitespace()
            if (!take(']')) {
                do {
                    result.add(value(depth + 1))
                    whitespace()
                } while (take(','))
                require(take(']'))
            }
            return Collections.unmodifiableList(result)
        }
        private fun string(): String {
            require(take('"'))
            val result = StringBuilder()
            while (!take('"')) {
                val char = input.getOrNull(at++) ?: throw IllegalArgumentException("Unterminated JSON string")
                require(char >= ' ')
                result.append(if (char == '\\') escape() else char)
            }
            return result.toString().also(::checkUnicode)
        }
        private fun escape(): Char = when (val char = input.getOrNull(at++)) {
            '"', '\\', '/' -> char
            'b' -> '\b'
            'f' -> '\u000c'
            'n' -> '\n'
            'r' -> '\r'
            't' -> '\t'
            'u' -> {
                require(at + 4 <= input.length)
                val hex = input.substring(at, at + 4)
                require(hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' })
                at += 4
                hex.toInt(16).toChar()
            }
            else -> throw IllegalArgumentException("Invalid JSON escape")
        }
    }
}

internal typealias JsonObject = Map<String, Any?>

@Suppress("UNCHECKED_CAST")
internal fun Any?.asObject(): JsonObject = this as Map<String, Any?>
internal fun JsonObject.obj(key: String): JsonObject = getValue(key).asObject()
internal fun JsonObject.text(key: String): String = getValue(key) as String
internal fun JsonObject.number(key: String): Long = getValue(key) as Long
internal fun JsonObject.items(key: String): List<*> = getValue(key) as List<*>
