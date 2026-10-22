package com.proteles.auth

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestFactory
import java.io.File
import java.security.MessageDigest
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The shared vectors (mobile/vectors/vectors.json), read from the repository
 * at test time — never a copy — with each vector's `expect.now` as the clock and
 * its `jwks` as the only key set.
 *
 * A refusal must also be for the reason the vector's name claims: the expected
 * reasons are read from reference-verify.mjs's EXPECTED_REASON table rather than
 * retyped here, so the two cannot drift apart.
 *
 * No count is pinned anywhere: the file grows (29 vectors, then 35 on
 * 2026-09-25). Instead the file is held to be **the canonical copy** — the
 * bytes SHA256SUMS records for the server repository's generated file
 * (mobile/vectors/SOURCE.md), each vector well-formed — and every refusing
 * vector to have a reason in the reference.
 */
class IdTokenVectorsTest {

    private val vectorsDir: File = (System.getProperty("proteles.vectors.dir")?.let(::File) ?: File("../../vectors")).canonicalFile

    private val document: JsonObject by lazy {
        val file = File(vectorsDir, "vectors.json")
        check(file.isFile) { "shared vectors not found at $file" }
        Json.parseObject(file.readText())
    }

    private val vectors: List<JsonObject> by lazy { (document["vectors"] as JsonArray).items.map { it as JsonObject } }

    /** The SHA-256 that SHA256SUMS records for vectors.json, lower-case hex. */
    private val recordedSum: String by lazy {
        val sums = File(vectorsDir, "SHA256SUMS")
        check(sums.isFile) { "no SHA256SUMS beside the vectors at $sums" }
        Regex("^([0-9a-f]{64}) [ *]vectors\\.json$", RegexOption.MULTILINE).find(sums.readText())?.groupValues?.get(1)
            ?: error("SHA256SUMS has no line for vectors.json")
    }

    /** reference-verify.mjs's EXPECTED_REASON, parsed from its source. */
    private val expectedReasons: Map<String, String> by lazy {
        val source = File(vectorsDir, "reference-verify.mjs").readText()
        val start = source.indexOf("const EXPECTED_REASON = {")
        check(start >= 0) { "EXPECTED_REASON not found in reference-verify.mjs" }
        val block = source.substring(start, source.indexOf("};", start))
        Regex("\"([^\"]+)\":\\s*\"([^\"]+)\"").findAll(block).associate { it.groupValues[1] to it.groupValues[2] }
    }

    @TestFactory
    fun `every shared vector reaches its verdict, each refusal for its own reason`(): List<DynamicTest> =
        vectors.map { v ->
            val name = v.string("name")!!
            DynamicTest.dynamicTest(name) { check(v, name) }
        }

    private fun check(v: JsonObject, name: String) {
        val expect = v["expect"] as JsonObject
        val now = expect.number("now")!!.longOrNull()!!
        val expectation = IdTokenExpectation(
            issuer = expect.string("issuer")!!,
            audience = expect.string("audience")!!,
            nonce = if (expect["nonce"] == JsonNull) null else expect.string("nonce")!!,
            accessToken = if (expect["accessToken"] == JsonNull) null else expect.string("accessToken")!!,
        )
        val verdict = v.string("verdict")!!
        val keys = StaticKeySource(v["jwks"] as JsonObject)
        val outcome = runBlocking {
            try {
                IdTokenVerifier(Clock { now }).verify(v.string("token")!!, keys, expectation)
                null
            } catch (e: ProtelesException.IdTokenRejected) {
                e
            }
        }
        when (verdict) {
            "accept" -> if (outcome != null) fail("$name: expected accept, refused with ${outcome.reason.code}: ${outcome.message}")
            "reject" -> {
                if (outcome == null) fail("$name: expected reject, accepted")
                assertEquals(expectedReasons[name], outcome.reason.code, "$name refused for the wrong reason")
            }
            else -> fail("$name: unknown verdict $verdict")
        }
    }

    @Test
    fun `the vector file is the canonical copy, each vector well-formed`() {
        // A truncated, stale or hand-edited file fails here, whatever its length;
        // a refresh from the server repository, with its sum, does not.
        val actual = MessageDigest.getInstance("SHA-256").digest(File(vectorsDir, "vectors.json").readBytes())
            .joinToString("") { "%02x".format(it) }
        assertEquals(recordedSum, actual, "vectors.json does not match SHA256SUMS (mobile/vectors/SOURCE.md)")
        val names = vectors.map { it.string("name") }
        assertEquals(names.size, names.toSet().size, "each vector is named once")
        for (v in vectors) {
            val name = v.string("name")
            assertTrue(v.string("verdict") in setOf("accept", "reject"), "$name: verdict ${v.string("verdict")}")
            assertTrue(!v.string("token").isNullOrEmpty(), "$name: token")
            assertTrue(v["jwks"] is JsonObject, "$name: jwks")
            val expect = v["expect"] as? JsonObject
            assertTrue(expect != null && expect.string("issuer") != null && expect.string("audience") != null && expect.number("now") != null, "$name: expect")
        }
        assertTrue(vectors.any { it.string("verdict") == "accept" } && vectors.any { it.string("verdict") == "reject" }, "both verdicts are represented")
        assertEquals(60L, (document["constants"] as JsonObject).number("clockSkewSeconds")!!.longOrNull())
        assertEquals(IdTokenVerifier.CLOCK_SKEW_SECONDS, 60L)
    }

    @Test
    fun `every refusing vector has an expected reason, and every reason names a vector`() {
        val refusing = vectors.filter { it.string("verdict") == "reject" }.map { it.string("name")!! }.toSet()
        assertTrue(expectedReasons.isNotEmpty(), "parsed no reasons from reference-verify.mjs")
        assertEquals(refusing, expectedReasons.keys, "refusing vectors vs reference-verify.mjs EXPECTED_REASON")
        val known = IdTokenRejection.entries.map { it.code }.toSet()
        for ((name, reason) in expectedReasons) assertTrue(reason in known, "$name: reason $reason has no IdTokenRejection")
    }
}
