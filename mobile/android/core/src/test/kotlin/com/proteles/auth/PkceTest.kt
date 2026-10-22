package com.proteles.auth

import org.junit.jupiter.api.Test
import java.security.SecureRandom
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class PkceTest {
    /** A SecureRandom that hands out fixed bytes, for known-answer tests. */
    private class FixedRandom(private val bytes: ByteArray) : SecureRandom() {
        override fun nextBytes(out: ByteArray) {
            require(out.size == bytes.size) { "asked for ${out.size} bytes, have ${bytes.size}" }
            bytes.copyInto(out)
        }
    }

    // RFC 7636 Appendix B.
    private val rfcOctets = intArrayOf(
        116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173,
        187, 186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83,
        132, 141, 121,
    ).map { it.toByte() }.toByteArray()

    @Test
    fun `RFC 7636 Appendix B known answer`() {
        val verifier = Pkce.generateVerifier(FixedRandom(rfcOctets))
        assertEquals("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", verifier)
        assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", Pkce.challenge(verifier))
    }

    @Test
    fun `verifier and challenge are exactly 43 unpadded base64url characters`() {
        val alphabet = Regex("^[A-Za-z0-9_-]{43}$")
        val random = SecureRandom()
        repeat(200) {
            val verifier = Pkce.generateVerifier(random)
            val challenge = Pkce.challenge(verifier)
            assertTrue(alphabet.matches(verifier), "verifier $verifier")
            // trap 5: the server refuses any challenge that is not exactly 43 characters
            assertTrue(alphabet.matches(challenge), "challenge $challenge")
        }
    }

    @Test
    fun `verifiers, states and nonces are fresh each time`() {
        val random = SecureRandom()
        val seen = (1..100).map { Pkce.generateVerifier(random) } + (1..100).map { Pkce.randomToken(random) }
        assertEquals(seen.size, seen.toSet().size)
        assertNotEquals(Pkce.randomToken(random), Pkce.randomToken(random))
        assertEquals(43, Pkce.randomToken(random).length)
    }

    @Test
    fun `the method is S256`() {
        assertEquals("S256", Pkce.METHOD)
    }
}
