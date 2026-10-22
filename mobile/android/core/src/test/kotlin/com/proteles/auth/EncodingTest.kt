package com.proteles.auth

import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class Base64UrlTest {
    @Test
    fun `canonical unpadded base64url round-trips`() {
        for (n in 0..40) {
            val bytes = ByteArray(n) { (it * 37 + 11).toByte() }
            val s = Base64Url.encode(bytes)
            assertEquals(-1, s.indexOf('='))
            assertContentEquals(bytes, Base64Url.decodeStrict(s))
        }
    }

    @Test
    fun `padding, the standard alphabet, whitespace and impossible lengths are refused`() {
        assertNotNull(Base64Url.decodeStrict("QQ"))
        assertNull(Base64Url.decodeStrict("QQ=="), "padded")
        assertNull(Base64Url.decodeStrict("QQ="), "padded")
        assertNull(Base64Url.decodeStrict("a+b/"), "standard alphabet")
        assertNull(Base64Url.decodeStrict("QU JD"), "space")
        assertNull(Base64Url.decodeStrict("QUJDR"), "length 4n+1")
    }

    @Test
    fun `a non-canonical final character is refused`() {
        // "QQ" is 'A'; "QR" decodes to the same byte with a non-zero unused bit.
        assertContentEquals(byteArrayOf(0x41), Base64Url.decodeStrict("QQ"))
        assertNull(Base64Url.decodeStrict("QR"))
    }
}

class PercentEncodingTest {
    @Test
    fun `unreserved characters pass, everything else is percent-encoded as UTF-8`() {
        assertEquals("AZaz09-._~", PercentEncoding.encode("AZaz09-._~"))
        assertEquals("a%20b%2Bc%26d%3De%2F%3A%3F%23", PercentEncoding.encode("a b+c&d=e/:?#"))
        assertEquals("%C3%A9%F0%9F%94%91", PercentEncoding.encode("é🔑"))
    }

    @Test
    fun `query decoding keeps repeats, reads + as a space and refuses bad escapes`() {
        assertEquals(
            listOf("a" to "1 2", "a" to "3", "b" to "", "c" to "é"),
            PercentEncoding.decodeQuery("a=1+2&a=3&b&c=%C3%A9"),
        )
        assertFailsWith<IllegalArgumentException> { PercentEncoding.decodeQuery("a=%4") }
        assertFailsWith<IllegalArgumentException> { PercentEncoding.decodeQuery("a=%zz") }
        assertFailsWith<IllegalArgumentException> { PercentEncoding.decodeQuery("a=%C3") }
    }
}

class JsonTest {
    @Test
    fun `parses the shapes a token carries`() {
        val o = Json.parseObject("""{"s":"x\"yé🔑","n":-1.5e3,"i":1800000000,"t":true,"f":false,"z":null,"a":[1,"b",{}]}""")
        assertEquals("x\"yé🔑", o.string("s"))
        assertEquals(-1500.0, o.number("n")!!.double)
        assertEquals(1800000000L, o.number("i")!!.longOrNull())
        assertEquals(true, o.boolean("t"))
        assertIs<JsonNull>(o["z"])
        assertEquals(listOf(1L, "b", emptyMap<String, Any?>()), o["a"]!!.toNative())
    }

    @Test
    fun `a duplicate name is its own refusal, and only in an otherwise well-formed document`() {
        assertFailsWith<JsonDuplicateMemberException> { Json.parse("""{"a":1,"a":2}""") }
        assertFailsWith<JsonDuplicateMemberException> { Json.parse("""[{"b":{"a":1,"a":2}}]""") }
        val malformedToo = assertFailsWith<JsonSyntaxException> { Json.parse("""{"a":1,"a":2,}""") }
        assertFalse(malformedToo is JsonDuplicateMemberException, "a syntax error anywhere is reported as one")
    }

    @Test
    fun `refuses what RFC 8259 does not allow, and duplicate names`() {
        val bad = listOf(
            """{"a":1,"a":2}""",
            """{"a":1,}""",
            """[1,2,]""",
            """{"a":01}""",
            """{"a":1.}""",
            """{"a":.5}""",
            """{"a":+1}""",
            """{a:1}""",
            """{'a':1}""",
            """{"a":1} x""",
            """{"a":"\x"}""",
            """{"a":"\ud800"}""",
            """{"a":"\udc00"}""",
            "{\"a\":\"tab\there\"}",
            """{"a":tru}""",
            """// c
{}""",
            "",
            "﻿{}",
        )
        for (text in bad) assertFailsWith<JsonSyntaxException>(text) { Json.parse(text) }
    }

    @Test
    fun `refuses deep nesting rather than overflowing the stack`() {
        val deep = "[".repeat(Json.MAX_DEPTH + 2) + "]".repeat(Json.MAX_DEPTH + 2)
        assertFailsWith<JsonSyntaxException> { Json.parse(deep) }
        val ok = "[".repeat(Json.MAX_DEPTH) + "]".repeat(Json.MAX_DEPTH)
        Json.parse(ok)
    }

    @Test
    fun `refuses bytes that are not UTF-8`() {
        assertFailsWith<JsonSyntaxException> { Json.parseUtf8(byteArrayOf('"'.code.toByte(), 0xC3.toByte(), '"'.code.toByte())) }
        assertFailsWith<JsonSyntaxException> { Json.parseUtf8(byteArrayOf('"'.code.toByte(), 0xFF.toByte(), '"'.code.toByte())) }
    }

    @Test
    fun `writes what it reads`() {
        val text = """{"s":"a\"b\\c\n\u0001é","n":12,"x":[true,false,null],"o":{"k":-0.5}}"""
        val parsed = Json.parse(text)
        assertEquals(text, Json.write(parsed))
        assertEquals(parsed.toNative(), Json.parse(Json.write(parsed)).toNative())
    }
}
