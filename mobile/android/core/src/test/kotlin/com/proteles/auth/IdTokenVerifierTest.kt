package com.proteles.auth

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * The verifier beyond the shared vectors: the refusals this SDK adds, and the
 * order of the checks where a vector cannot show it.
 */
class IdTokenVerifierTest {
    private val now = 1_800_000_000L
    private val key = SHARED_KEY
    private val keys = StaticKeySource(toJson(jwksOf(key)) as JsonObject)
    private val expected = IdTokenExpectation(ISSUER, CLIENT_ID, nonce = "n1", accessToken = "at-1")

    private fun reason(token: String, expectation: IdTokenExpectation = expected): String = runBlocking {
        assertFailsWith<ProtelesException.IdTokenRejected> { IdTokenVerifier(Clock { now }).verify(token, keys, expectation) }.reason.code
    }

    private fun good(extra: Map<String, Any?> = emptyMap()) = idTokenClaims(now, nonce = "n1", accessToken = "at-1", extra = extra)

    @Test
    fun `the control verifies and exposes its claims`(): Unit = runBlocking {
        val claims = IdTokenVerifier(Clock { now }).verify(
            key.sign(good(mapOf("email" to "a@example.com", "email_verified" to true, "amr" to listOf("pwd", "otp"), "acr" to "urn:x"))),
            keys,
            expected,
        )
        assertEquals("user-1", claims.subject)
        assertEquals(ISSUER, claims.issuer)
        assertEquals(listOf(CLIENT_ID), claims.audience)
        assertEquals(now - 5, claims.authTime)
        assertEquals("a@example.com", claims.email)
        assertEquals(true, claims.emailVerified)
        assertEquals(listOf("pwd", "otp"), claims.amr)
        assertEquals("urn:x", claims.acr)
        assertEquals(now + 900, claims["exp"])
    }

    @Test
    fun `the algorithm is refused before the key is looked up`() {
        // No key carries this kid; the refusal must still be about the algorithm.
        val t = key.sign(good(), mapOf("alg" to "HS256", "kid" to "nobody"))
        assertEquals("algorithm", reason(t))
        assertEquals("algorithm", reason(key.sign(good(), mapOf("kid" to key.kid))), "alg absent")
        assertEquals("algorithm", reason(key.sign(good(), mapOf("alg" to "rs256", "kid" to key.kid))), "case matters")
    }

    @Test
    fun `a crit header is refused`() {
        assertEquals("crit", reason(key.sign(good(), mapOf("alg" to "RS256", "kid" to key.kid, "crit" to listOf("exp")))))
    }

    @Test
    fun `a kid that is not a non-empty string is missing`() {
        assertEquals("kid-missing", reason(key.sign(good(), mapOf("alg" to "RS256", "kid" to ""))))
        assertEquals("kid-missing", reason(key.sign(good(), mapOf("alg" to "RS256", "kid" to 7))))
    }

    @Test
    fun `a token signed by another key does not verify`() {
        val other = SigningKey(key.kid)
        assertEquals("signature", reason(other.sign(good())))
    }

    @Test
    fun `a non-canonical signature spelling is refused before verification`() {
        val t = key.sign(good())
        val sig = t.substringAfterLast('.')
        // Flip the last character to another with the same significant bits.
        val last = sig.last()
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        val twin = alphabet[alphabet.indexOf(last) xor 1]
        assertEquals("signature-not-base64url", reason(t.dropLast(1) + twin))
    }

    @Test
    fun `duplicate claims and non-JSON segments are refused`() {
        val header = Base64Url.encode("""{"alg":"RS256","kid":"${key.kid}"}""".toByteArray())
        val dupPayload = Base64Url.encode("""{"iss":"$ISSUER","sub":"a","sub":"b"}""".toByteArray())
        val sig = java.security.Signature.getInstance("SHA256withRSA").apply {
            initSign(key.pair.private)
            update("$header.$dupPayload".toByteArray())
        }.sign()
        assertEquals("duplicate-member", reason("$header.$dupPayload.${Base64Url.encode(sig)}"))
        assertEquals("header-not-json", reason("${Base64Url.encode("nope".toByteArray())}.e30.e30"))
        // Before the algorithm: a header that names alg twice means two things.
        assertEquals("duplicate-member", reason("${Base64Url.encode("""{"alg":"RS256","alg":"none"}""".toByteArray())}.e30.e30"))
        // Malformed anywhere beats a duplicate, as in reference-verify.mjs (JSON.parse, then the scan).
        assertEquals("header-not-json", reason("${Base64Url.encode("""{"alg":"RS256","alg":"none",}""".toByteArray())}.e30.e30"))
        assertEquals("duplicate-member", reason("${Base64Url.encode("""{"alg":"RS256","kid":"k","x":{"a":1,"a":2}}""".toByteArray())}.e30.e30"), "nested objects too")
    }

    @Test
    fun `the claims are read only after the signature`() {
        // A payload that would fail every claim check, with a bad signature: the
        // refusal is the signature, because nothing in the payload was read.
        val t = key.sign(mapOf("iss" to "https://evil.example"))
        val forged = t.substringBeforeLast('.') + "." + key.sign(good()).substringAfterLast('.')
        assertEquals("signature", reason(forged))
    }

    @Test
    fun `aud that is not a string or a one-string array is refused`() {
        assertEquals("audience", reason(key.sign(good(mapOf("aud" to 5)))))
        assertEquals("audience", reason(key.sign(good(mapOf("aud" to listOf<String>())))))
        assertEquals("audience", reason(key.sign(good(mapOf("aud" to listOf(5))))))
        assertEquals("audience", reason(key.sign(good() - "aud")))
    }

    @Test
    fun `exp that is not a number is missing, iat is optional`() {
        assertEquals("exp-missing", reason(key.sign(good(mapOf("exp" to "1800000900")))))
        runBlocking { IdTokenVerifier(Clock { now }).verify(key.sign(good() - "iat"), keys, expected) }
    }

    @Test
    fun `the skew edges are 60 seconds exactly`(): Unit = runBlocking {
        val at = { t: Long -> IdTokenVerifier(Clock { t }) }
        val token = key.sign(good(mapOf("exp" to now, "iat" to now)))
        at(now + 60).verify(token, keys, expected) // exp + 60: not yet refused
        assertEquals("expired", assertFailsWith<ProtelesException.IdTokenRejected> { at(now + 61).verify(token, keys, expected) }.reason.code)
        at(now - 60).verify(token, keys, expected) // iat 60 s ahead: accepted
        assertEquals(
            "issued-in-the-future",
            assertFailsWith<ProtelesException.IdTokenRejected> { at(now - 61).verify(token, keys, expected) }.reason.code,
        )
    }

    @Test
    fun `with the clock left out (the refresh path), every other rule still holds, and the times are judged apart`(): Unit = runBlocking {
        val skewed = IdTokenVerifier(Clock { now - 3600 }) // this device's clock is an hour behind the server's
        val untimed = IdTokenExpectation(ISSUER, CLIENT_ID, nonce = null, accessToken = "at-1", checkTime = false)
        val claims = skewed.verify(key.sign(good()), keys, untimed)
        assertEquals(IdTokenRejection.ISSUED_IN_THE_FUTURE, skewed.timeRejection(claims))
        assertEquals(IdTokenRejection.EXPIRED, IdTokenVerifier(Clock { now + 3600 }).timeRejection(claims))
        assertEquals(null, IdTokenVerifier(Clock { now }).timeRejection(claims))

        suspend fun refusal(token: String) =
            assertFailsWith<ProtelesException.IdTokenRejected> { skewed.verify(token, keys, untimed) }.reason.code
        assertEquals("at-hash", refusal(key.sign(good(mapOf("at_hash" to IdTokenVerifier.atHash("another"))))))
        assertEquals("issuer", refusal(key.sign(good(mapOf("iss" to "https://evil.example")))))
        assertEquals("audience", refusal(key.sign(good(mapOf("aud" to "another-client")))))
        assertEquals("exp-missing", refusal(key.sign(good() - "exp")))
        assertEquals("signature", refusal(SigningKey(key.kid).sign(good())))
        assertEquals("no-usable-key", refusal(SigningKey("unknown-kid").sign(good())))
        assertEquals("sub", refusal(key.sign(good() - "sub")))
        // A day fast: its exp looks long past, which is no refusal either (§10.9 item 2).
        val fast = IdTokenVerifier(Clock { now + 86_400 })
        assertEquals(IdTokenRejection.EXPIRED, fast.timeRejection(fast.verify(key.sign(good()), keys, untimed)))
        // The default (sign-in, and every vector) still holds the times to the clock.
        val timed = IdTokenExpectation(ISSUER, CLIENT_ID, nonce = null, accessToken = "at-1")
        assertEquals(
            "issued-in-the-future",
            assertFailsWith<ProtelesException.IdTokenRejected> { skewed.verify(key.sign(good()), keys, timed) }.reason.code,
        )
    }

    @Test
    fun `at_hash is the left half of SHA-256, base64url`() {
        // OIDC Core §3.1.3.6; value computed independently with node:crypto.
        assertEquals("DBL3NfZ5ZYRCNmpv7TLa3A", IdTokenVerifier.atHash("access-token-for-the-vectors"))
    }
}
