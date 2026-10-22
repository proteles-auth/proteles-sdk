package com.proteles.auth

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

// A minimal, strict JSON (RFC 8259) parser and writer.
//
// Why not a library: `org.json` is built into Android but absent from the JVM,
// so the one `core` that both run would need a dependency for ~250 lines. A
// JSON library inside the ID-token path is also a dependency inside an
// authentication path, and the strictness below is a property this SDK wants
// rather than one a general-purpose parser offers:
//
// - **Duplicate member names are refused.** RFC 7515 §4 and RFC 7519 §4 let a
//   JOSE parser either refuse them or take the last; refusing means a header or
//   payload can only ever mean one thing, whichever parser reads it. The refusal
//   is its own exception, raised only for a document that is otherwise
//   well-formed — the order reference-verify.mjs checks in (`JSON.parse`, then
//   the duplicate scan), so a vector is refused for the same reason here.
// - Input bytes must be well-formed UTF-8 (no replacement characters), with no
//   byte-order mark, no trailing content, no comments, no trailing commas, no
//   leading zeros, no lone surrogates, and at most MAX_DEPTH levels of nesting.

internal sealed class JsonValue

internal class JsonObject(val members: Map<String, JsonValue>) : JsonValue() {
    operator fun get(name: String): JsonValue? = members[name]
    fun has(name: String): Boolean = members.containsKey(name)
    fun string(name: String): String? = (members[name] as? JsonString)?.value
    fun number(name: String): JsonNumber? = members[name] as? JsonNumber
    fun boolean(name: String): Boolean? = (members[name] as? JsonBoolean)?.value
}

internal class JsonArray(val items: List<JsonValue>) : JsonValue()

internal class JsonString(val value: String) : JsonValue()

/** A number, kept as the literal that arrived so nothing is rounded until asked. */
internal class JsonNumber(val literal: String) : JsonValue() {
    val double: Double get() = literal.toDouble()

    /** The value as a Long when it is integral and in range; otherwise null. */
    fun longOrNull(): Long? {
        literal.toLongOrNull()?.let { return it }
        val d = double
        return if (d.isFinite() && d == Math.floor(d) && d >= Long.MIN_VALUE.toDouble() && d <= Long.MAX_VALUE.toDouble()) {
            d.toLong()
        } else {
            null
        }
    }
}

internal class JsonBoolean(val value: Boolean) : JsonValue()

internal object JsonNull : JsonValue()

internal open class JsonSyntaxException(message: String) : Exception(message)

/** A well-formed document that names one member twice in an object. */
internal class JsonDuplicateMemberException(message: String) : JsonSyntaxException(message)

internal object Json {
    const val MAX_DEPTH: Int = 64
    private const val HEX = "0123456789abcdef"

    fun parse(text: String): JsonValue = Parser(text).document()

    /** Parses well-formed UTF-8. Malformed bytes are a syntax error, never U+FFFD. */
    fun parseUtf8(bytes: ByteArray): JsonValue = parse(decodeUtf8Strict(bytes))

    fun parseObject(text: String): JsonObject =
        parse(text) as? JsonObject ?: throw JsonSyntaxException("expected a JSON object")

    fun parseObjectUtf8(bytes: ByteArray): JsonObject =
        parseUtf8(bytes) as? JsonObject ?: throw JsonSyntaxException("expected a JSON object")

    fun decodeUtf8Strict(bytes: ByteArray): String = try {
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    } catch (e: CharacterCodingException) {
        throw JsonSyntaxException("not well-formed UTF-8")
    }

    fun write(value: JsonValue): String = StringBuilder().also { write(value, it) }.toString()

    private fun write(value: JsonValue, out: StringBuilder) {
        when (value) {
            is JsonObject -> {
                out.append('{')
                var first = true
                for ((k, v) in value.members) {
                    if (!first) out.append(',')
                    first = false
                    writeString(k, out)
                    out.append(':')
                    write(v, out)
                }
                out.append('}')
            }
            is JsonArray -> {
                out.append('[')
                value.items.forEachIndexed { i, v ->
                    if (i > 0) out.append(',')
                    write(v, out)
                }
                out.append(']')
            }
            is JsonString -> writeString(value.value, out)
            is JsonNumber -> out.append(value.literal)
            is JsonBoolean -> out.append(if (value.value) "true" else "false")
            JsonNull -> out.append("null")
        }
    }

    private fun writeString(s: String, out: StringBuilder) {
        out.append('"')
        for (c in s) {
            when {
                c == '"' -> out.append("\\\"")
                c == '\\' -> out.append("\\\\")
                c == '\n' -> out.append("\\n")
                c == '\r' -> out.append("\\r")
                c == '\t' -> out.append("\\t")
                c < ' ' -> out.append("\\u00").append(HEX[c.code shr 4]).append(HEX[c.code and 0xF])
                else -> out.append(c)
            }
        }
        out.append('"')
    }

    private class Parser(private val s: String) {
        private var i = 0

        /** The first repeated member name, reported once the whole document has parsed. */
        private var duplicate: String? = null

        fun document(): JsonValue {
            skipWhitespace()
            val v = value(0)
            skipWhitespace()
            if (i != s.length) fail("unexpected content after the document")
            duplicate?.let { throw JsonDuplicateMemberException("duplicate member name \"$it\"") }
            return v
        }

        private fun fail(message: String): Nothing = throw JsonSyntaxException("$message at offset $i")

        private fun skipWhitespace() {
            while (i < s.length) {
                val c = s[i]
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') i++ else return
            }
        }

        private fun value(depth: Int): JsonValue {
            if (depth > MAX_DEPTH) fail("nested too deeply")
            if (i >= s.length) fail("unexpected end of input")
            return when (s[i]) {
                '{' -> obj(depth)
                '[' -> array(depth)
                '"' -> JsonString(string())
                't' -> literal("true", JsonBoolean(true))
                'f' -> literal("false", JsonBoolean(false))
                'n' -> literal("null", JsonNull)
                '-', in '0'..'9' -> number()
                else -> fail("unexpected character")
            }
        }

        private fun literal(word: String, v: JsonValue): JsonValue {
            if (!s.startsWith(word, i)) fail("invalid literal")
            i += word.length
            return v
        }

        private fun obj(depth: Int): JsonObject {
            i++ // {
            val members = LinkedHashMap<String, JsonValue>()
            skipWhitespace()
            if (i < s.length && s[i] == '}') {
                i++
                return JsonObject(members)
            }
            while (true) {
                skipWhitespace()
                if (i >= s.length || s[i] != '"') fail("expected a member name")
                val name = string()
                skipWhitespace()
                if (i >= s.length || s[i] != ':') fail("expected ':'")
                i++
                skipWhitespace()
                val v = value(depth + 1)
                if (members.put(name, v) != null && duplicate == null) duplicate = name
                skipWhitespace()
                if (i >= s.length) fail("unterminated object")
                when (s[i]) {
                    ',' -> i++
                    '}' -> {
                        i++
                        return JsonObject(members)
                    }
                    else -> fail("expected ',' or '}'")
                }
            }
        }

        private fun array(depth: Int): JsonArray {
            i++ // [
            val items = ArrayList<JsonValue>()
            skipWhitespace()
            if (i < s.length && s[i] == ']') {
                i++
                return JsonArray(items)
            }
            while (true) {
                skipWhitespace()
                items.add(value(depth + 1))
                skipWhitespace()
                if (i >= s.length) fail("unterminated array")
                when (s[i]) {
                    ',' -> i++
                    ']' -> {
                        i++
                        return JsonArray(items)
                    }
                    else -> fail("expected ',' or ']'")
                }
            }
        }

        private fun string(): String {
            i++ // opening quote
            val out = StringBuilder()
            while (true) {
                if (i >= s.length) fail("unterminated string")
                val c = s[i++]
                when {
                    c == '"' -> return out.toString()
                    c == '\\' -> escape(out)
                    c < ' ' -> fail("unescaped control character in a string")
                    Character.isHighSurrogate(c) -> {
                        if (i >= s.length || !Character.isLowSurrogate(s[i])) fail("lone surrogate")
                        out.append(c).append(s[i++])
                    }
                    Character.isLowSurrogate(c) -> fail("lone surrogate")
                    else -> out.append(c)
                }
            }
        }

        private fun escape(out: StringBuilder) {
            if (i >= s.length) fail("unterminated escape")
            when (val e = s[i++]) {
                '"' -> out.append('"')
                '\\' -> out.append('\\')
                '/' -> out.append('/')
                'b' -> out.append('\b')
                'f' -> out.append('\u000C')
                'n' -> out.append('\n')
                'r' -> out.append('\r')
                't' -> out.append('\t')
                'u' -> {
                    val unit = hex4()
                    when {
                        Character.isHighSurrogate(unit) -> {
                            if (!s.startsWith("\\u", i)) fail("lone surrogate")
                            i += 2
                            val low = hex4()
                            if (!Character.isLowSurrogate(low)) fail("lone surrogate")
                            out.append(unit).append(low)
                        }
                        Character.isLowSurrogate(unit) -> fail("lone surrogate")
                        else -> out.append(unit)
                    }
                }
                else -> fail("invalid escape '\\$e'")
            }
        }

        private fun hex4(): Char {
            if (i + 4 > s.length) fail("truncated \\u escape")
            var v = 0
            repeat(4) {
                val d = Character.digit(s[i++], 16)
                if (d < 0) fail("invalid \\u escape")
                v = v * 16 + d
            }
            return v.toChar()
        }

        private fun number(): JsonNumber {
            val start = i
            if (s[i] == '-') i++
            if (i >= s.length) fail("truncated number")
            when {
                s[i] == '0' -> i++
                s[i] in '1'..'9' -> while (i < s.length && s[i] in '0'..'9') i++
                else -> fail("invalid number")
            }
            if (i < s.length && s[i] == '.') {
                i++
                if (i >= s.length || s[i] !in '0'..'9') fail("invalid fraction")
                while (i < s.length && s[i] in '0'..'9') i++
            }
            if (i < s.length && (s[i] == 'e' || s[i] == 'E')) {
                i++
                if (i < s.length && (s[i] == '+' || s[i] == '-')) i++
                if (i >= s.length || s[i] !in '0'..'9') fail("invalid exponent")
                while (i < s.length && s[i] in '0'..'9') i++
            }
            return JsonNumber(s.substring(start, i))
        }
    }
}

/** A JSON value as plain Kotlin: String, Long or Double, Boolean, List, Map, or null. */
internal fun JsonValue.toNative(): Any? = when (this) {
    is JsonObject -> members.mapValues { it.value.toNative() }
    is JsonArray -> items.map { it.toNative() }
    is JsonString -> value
    is JsonNumber -> longOrNull() ?: double
    is JsonBoolean -> value
    JsonNull -> null
}
