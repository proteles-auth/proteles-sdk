package com.proteles.auth

import org.junit.jupiter.api.Test
import java.security.SecureRandom
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AuthorizationRequestTest {
    private val config = ProtelesConfiguration(ISSUER, CLIENT_ID, REDIRECT, listOf("openid", "profile", "email"))
    private val metadata = ProviderMetadata.parse(toJson(discoveryDocument()) as JsonObject, ISSUER)

    @Test
    fun `the URL carries exactly the §10_2 parameters, each once`() {
        val request = AuthorizationRequest.create(metadata, config, SecureRandom())
        assertTrue(request.url.startsWith("$AUTHORIZE?"), request.url)
        val q = queryOf(request.url)
        assertEquals(
            setOf("response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method"),
            q.keys,
        )
        q.values.forEach { assertEquals(1, it.size) }
        assertEquals("code", q["response_type"]!![0])
        assertEquals(CLIENT_ID, q["client_id"]!![0])
        assertEquals(REDIRECT, q["redirect_uri"]!![0])
        assertEquals("openid profile email", q["scope"]!![0])
        assertEquals("S256", q["code_challenge_method"]!![0])
        assertEquals(request.state, q["state"]!![0])
        assertEquals(request.nonce, q["nonce"]!![0])
        assertEquals(Pkce.challenge(request.codeVerifier), q["code_challenge"]!![0])
        assertEquals(43, q["code_challenge"]!![0].length)
        // P2.12: the server ignores login_hint, so it is never sent.
        assertFalse(request.url.contains("login_hint"))
        // The verifier never leaves the app on this hop.
        assertFalse(request.url.contains(request.codeVerifier))
    }

    @Test
    fun `values are percent-encoded, a space as percent-20`() {
        val request = AuthorizationRequest.create(metadata, config, SecureRandom())
        assertTrue(request.url.contains("redirect_uri=https%3A%2F%2Fmobile.example.com%2Foauth%2Fcallback"), request.url)
        assertTrue(request.url.contains("scope=openid%20profile%20email"), request.url)
    }

    @Test
    fun `state, nonce and verifier are 43-character random values, fresh per request`() {
        val a = AuthorizationRequest.create(metadata, config, SecureRandom())
        val b = AuthorizationRequest.create(metadata, config, SecureRandom())
        for (v in listOf(a.state, a.nonce, a.codeVerifier)) assertEquals(43, v.length)
        assertEquals(3, setOf(a.state, a.nonce, a.codeVerifier).size)
        assertTrue(a.state != b.state && a.nonce != b.nonce && a.codeVerifier != b.codeVerifier)
    }

    @Test
    fun `an endpoint that already has a query keeps it`() {
        assertEquals("https://a/authz?tenant=x&k=v", AuthorizationRequest.appendQuery("https://a/authz?tenant=x", listOf("k" to "v")))
        assertEquals("https://a/authz?k=v", AuthorizationRequest.appendQuery("https://a/authz?", listOf("k" to "v")))
        assertEquals("https://a/authz?k=v", AuthorizationRequest.appendQuery("https://a/authz", listOf("k" to "v")))
    }
}

class AuthorizationCallbackTest {
    private val state = "s-123"

    private fun parse(callback: String) = AuthorizationCallback.parse(callback, REDIRECT, state, ISSUER)

    private fun enc(v: String) = PercentEncoding.encode(v)

    @Test
    fun `a matching callback yields the code`() {
        assertEquals("the-code", parse("$REDIRECT?code=the-code&state=$state&iss=${enc(ISSUER)}"))
        // parameter order is irrelevant
        assertEquals("c2", parse("$REDIRECT?iss=${enc(ISSUER)}&state=$state&code=c2"))
    }

    @Test
    fun `state mismatch, missing state and repeated state are refused`() {
        assertFailsWith<ProtelesException.StateMismatch> { parse("$REDIRECT?code=c&state=other&iss=${enc(ISSUER)}") }
        assertFailsWith<ProtelesException.StateMismatch> { parse("$REDIRECT?code=c&iss=${enc(ISSUER)}") }
        assertFailsWith<ProtelesException.StateMismatch> { parse("$REDIRECT?code=c&state=$state&state=$state&iss=${enc(ISSUER)}") }
        assertFailsWith<ProtelesException.StateMismatch> { parse("$REDIRECT?code=c&state=&iss=${enc(ISSUER)}") }
    }

    @Test
    fun `a missing iss is refused, not skipped (RFC 9207)`() {
        val e = assertFailsWith<ProtelesException.IssuerMismatch> { parse("$REDIRECT?code=c&state=$state") }
        assertEquals(ISSUER, e.expected)
        assertNull(e.actual)
    }

    @Test
    fun `a wrong iss is refused, byte for byte`() {
        val e = assertFailsWith<ProtelesException.IssuerMismatch> { parse("$REDIRECT?code=c&state=$state&iss=${enc("https://evil.example")}") }
        assertEquals("https://evil.example", e.actual)
        assertFailsWith<ProtelesException.IssuerMismatch> { parse("$REDIRECT?code=c&state=$state&iss=${enc("$ISSUER/")}") }
        assertFailsWith<ProtelesException.IssuerMismatch> {
            parse("$REDIRECT?code=c&state=$state&iss=${enc(ISSUER)}&iss=${enc(ISSUER)}")
        }
    }

    @Test
    fun `an error response becomes a typed authorization error`() {
        val e = assertFailsWith<ProtelesException.AuthorizationError> {
            parse("$REDIRECT?error=access_denied&error_description=The+user+said+no&state=$state&iss=${enc(ISSUER)}")
        }
        assertEquals("access_denied", e.error)
        assertEquals("The user said no", e.errorDescription)
    }

    @Test
    fun `an error response is checked for state and iss before it is believed`() {
        assertFailsWith<ProtelesException.StateMismatch> {
            parse("$REDIRECT?error=access_denied&state=forged&iss=${enc(ISSUER)}")
        }
        assertFailsWith<ProtelesException.IssuerMismatch> { parse("$REDIRECT?error=access_denied&state=$state") }
    }

    @Test
    fun `a callback to another path or scheme is not a response to this request`() {
        assertFailsWith<ProtelesException.StateMismatch> {
            parse("https://mobile.example.com/other?code=c&state=$state&iss=${enc(ISSUER)}")
        }
        assertFailsWith<ProtelesException.StateMismatch> {
            parse("https://attacker.example.com/oauth/callback?code=c&state=$state&iss=${enc(ISSUER)}")
        }
    }

    @Test
    fun `no code, an empty code or two codes is an invalid response`() {
        val e = assertFailsWith<ProtelesException.AuthorizationError> { parse("$REDIRECT?state=$state&iss=${enc(ISSUER)}") }
        assertEquals("invalid_response", e.error)
        assertFailsWith<ProtelesException.AuthorizationError> { parse("$REDIRECT?code=&state=$state&iss=${enc(ISSUER)}") }
        assertFailsWith<ProtelesException.AuthorizationError> { parse("$REDIRECT?code=a&code=b&state=$state&iss=${enc(ISSUER)}") }
    }

    @Test
    fun `a malformed query is refused`() {
        assertFailsWith<ProtelesException.StateMismatch> { parse("$REDIRECT?code=%zz&state=$state&iss=${enc(ISSUER)}") }
    }

    @Test
    fun `the end-session return is checked for its target and state`() {
        AuthorizationCallback.checkEndSessionReturn("$POST_LOGOUT?state=abc", POST_LOGOUT, "abc")
        assertFailsWith<ProtelesException.StateMismatch> {
            AuthorizationCallback.checkEndSessionReturn("$POST_LOGOUT?state=zzz", POST_LOGOUT, "abc")
        }
        assertFailsWith<ProtelesException.StateMismatch> {
            AuthorizationCallback.checkEndSessionReturn("$REDIRECT?state=abc", POST_LOGOUT, "abc")
        }
    }
}
