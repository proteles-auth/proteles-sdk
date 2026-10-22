package com.proteles.auth

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Base64

/**
 * base64url without padding (RFC 7515 §2), decoded strictly.
 *
 * §5.2 divergence 6: a padded segment is a second spelling of one token and is
 * refused. For the same reason a segment whose last character carries non-zero
 * unused bits is refused too: it decodes to the same bytes as the canonical
 * spelling, so accepting it would be a second spelling by another route.
 */
internal object Base64Url {
    private val encoder = Base64.getUrlEncoder().withoutPadding()

    fun encode(bytes: ByteArray): String = encoder.encodeToString(bytes)

    /** The decoded bytes, or null when [segment] is not canonical unpadded base64url. */
    fun decodeStrict(segment: String): ByteArray? {
        for (c in segment) {
            val ok = c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c == '-' || c == '_'
            if (!ok) return null
        }
        if (segment.length % 4 == 1) return null
        val bytes = try {
            Base64.getUrlDecoder().decode(segment)
        } catch (e: IllegalArgumentException) {
            return null
        }
        return if (encode(bytes) == segment) bytes else null
    }
}

internal fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

/**
 * RFC 3986 percent-encoding of everything outside the unreserved set, over
 * UTF-8. Used for query parameters and form bodies alike: a form parser decodes
 * `%20` as a space, and a query parser never mistakes it for a literal `+`.
 */
internal object PercentEncoding {
    private const val HEX = "0123456789ABCDEF"

    fun encode(value: String): String {
        val out = StringBuilder(value.length + 16)
        for (b in value.toByteArray(Charsets.UTF_8)) {
            val c = b.toInt() and 0xFF
            val unreserved = c in 'A'.code..'Z'.code || c in 'a'.code..'z'.code || c in '0'.code..'9'.code ||
                c == '-'.code || c == '.'.code || c == '_'.code || c == '~'.code
            if (unreserved) {
                out.append(c.toChar())
            } else {
                out.append('%').append(HEX[c shr 4]).append(HEX[c and 0xF])
            }
        }
        return out.toString()
    }

    /** `name=value&…`, in the order given. */
    fun form(params: List<Pair<String, String>>): String =
        params.joinToString("&") { (k, v) -> "${encode(k)}=${encode(v)}" }

    /**
     * Decodes an `application/x-www-form-urlencoded` query (`+` is a space), keeping
     * repeated names so a caller can refuse them. Throws [IllegalArgumentException]
     * on a malformed escape or bytes that are not UTF-8.
     */
    fun decodeQuery(query: String): List<Pair<String, String>> {
        if (query.isEmpty()) return emptyList()
        return query.split('&').filter { it.isNotEmpty() }.map { pair ->
            val eq = pair.indexOf('=')
            if (eq < 0) decodeComponent(pair) to "" else decodeComponent(pair.substring(0, eq)) to decodeComponent(pair.substring(eq + 1))
        }
    }

    private fun decodeComponent(s: String): String {
        val out = ByteArrayOutputStream(s.length)
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c == '+' -> {
                    out.write(' '.code)
                    i++
                }
                c == '%' -> {
                    require(i + 3 <= s.length) { "truncated percent escape" }
                    val hi = Character.digit(s[i + 1], 16)
                    val lo = Character.digit(s[i + 2], 16)
                    require(hi >= 0 && lo >= 0) { "invalid percent escape" }
                    out.write(hi * 16 + lo)
                    i += 3
                }
                else -> {
                    // A run of literal characters, encoded together so a surrogate
                    // pair stays one code point.
                    var end = i
                    while (end < s.length && s[end] != '%' && s[end] != '+') end++
                    out.write(s.substring(i, end).toByteArray(Charsets.UTF_8))
                    i = end
                }
            }
        }
        return try {
            Json.decodeUtf8Strict(out.toByteArray())
        } catch (e: JsonSyntaxException) {
            throw IllegalArgumentException("percent-decoded bytes are not UTF-8")
        }
    }
}
