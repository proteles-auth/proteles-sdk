package com.proteles.auth

import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import java.io.IOException
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/** docs/mobile-SDKs.md §10.2 step 1. */
class DiscoveryTest {
    @Test
    fun `discovery is fetched from the issuer once and cached`(): Unit = runBlocking {
        val h = ClientHarness()
        val md = (1..10).map { async { h.client.providerMetadata() } }.awaitAll().first()
        assertEquals(TOKEN, md.tokenEndpoint)
        assertEquals(AUTHORIZE, md.authorizationEndpoint)
        assertEquals(JWKS, md.jwksUri)
        assertEquals(REVOKE, md.revocationEndpoint)
        assertEquals(END_SESSION, md.endSessionEndpoint)
        h.client.signIn(h.browser())
        h.client.signOut()
        assertEquals(1, h.transport.requestsTo(DISCOVERY).size)
        assertEquals("GET", h.transport.requestsTo(DISCOVERY).single().method)
    }

    @Test
    fun `the discovery URL drops one trailing slash from the issuer`() {
        assertEquals("https://a.example/.well-known/openid-configuration", ProviderMetadata.discoveryUrl("https://a.example"))
        assertEquals("https://a.example/t/x/.well-known/openid-configuration", ProviderMetadata.discoveryUrl("https://a.example/t/x/"))
    }

    @Test
    fun `a document naming another issuer is refused, byte for byte`(): Unit = runBlocking {
        for (issuer in listOf("https://evil.example", "$ISSUER/", ISSUER.uppercase())) {
            val h = ClientHarness(discovery = discoveryDocument(issuer = issuer))
            val e = assertFailsWith<ProtelesException.IssuerMismatch> { h.client.providerMetadata() }
            assertEquals(ISSUER, e.expected)
            assertEquals(issuer, e.actual)
        }
    }

    @Test
    fun `a failure is not cached`(): Unit = runBlocking {
        val h = ClientHarness()
        h.transport.on("GET", DISCOVERY) { throw IOException("offline") }
        assertFailsWith<ProtelesException.Network> { h.client.providerMetadata() }
        h.transport.on("GET", DISCOVERY) { ok(discoveryDocument()) }
        assertEquals(TOKEN, h.client.providerMetadata().tokenEndpoint)
    }

    @Test
    fun `HTTP failures map to what a caller does about them`(): Unit = runBlocking {
        val h = ClientHarness()
        h.transport.on("GET", DISCOVERY) { status(404) }
        assertFailsWith<ProtelesException.Configuration> { h.client.providerMetadata() }
        h.transport.on("GET", DISCOVERY) { status(503) }
        assertFailsWith<ProtelesException.Network> { h.client.providerMetadata() }
        h.transport.on("GET", DISCOVERY) { status(429, headers = mapOf("retry-after" to listOf("7"))) }
        assertEquals(7L, assertFailsWith<ProtelesException.RateLimited> { h.client.providerMetadata() }.retryAfterSeconds)
        h.transport.on("GET", DISCOVERY) { HttpResponse(200, emptyMap(), "not json".toByteArray()) }
        assertFailsWith<ProtelesException.Configuration> { h.client.providerMetadata() }
    }

    @Test
    fun `endpoints must be https, and the required ones present`() {
        fun parse(doc: Map<String, Any?>, issuer: String = ISSUER) = ProviderMetadata.parse(toJson(doc) as JsonObject, issuer)
        assertFailsWith<ProtelesException.Configuration> { parse(discoveryDocument() + ("token_endpoint" to "http://auth.example.test/token")) }
        assertFailsWith<ProtelesException.Configuration> { parse(discoveryDocument() - "token_endpoint") }
        assertFailsWith<ProtelesException.Configuration> { parse(discoveryDocument() - "jwks_uri") }
        assertFailsWith<ProtelesException.Configuration> { parse(discoveryDocument() + ("authorization_endpoint" to 5)) }
        assertNull(parse(discoveryDocument(revocation = false, endSession = false)).revocationEndpoint)
        // Loopback http is accepted only when the issuer itself is loopback http (development).
        val local = "http://127.0.0.1:8080"
        val md = parse(
            mapOf(
                "issuer" to local,
                "authorization_endpoint" to "$local/oauth/authorize",
                "token_endpoint" to "$local/oauth/token",
                "jwks_uri" to "$local/.well-known/jwks.json",
            ),
            local,
        )
        assertEquals("$local/oauth/token", md.tokenEndpoint)
    }

    @Test
    fun `an http issuer on any loopback host can be discovered, localhost included (10_1)`(): Unit = runBlocking {
        for (issuer in listOf("http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080")) {
            // Configuration and discovery in one pass: an issuer accepted at
            // construction must not have its own endpoints refused.
            val configuration = ProtelesConfiguration(issuer, CLIENT_ID, REDIRECT)
            val document = mapOf(
                "issuer" to issuer,
                "authorization_endpoint" to "$issuer/oauth/authorize",
                "token_endpoint" to "$issuer/oauth/token",
                "jwks_uri" to "$issuer/.well-known/jwks.json",
                "revocation_endpoint" to "$issuer/oauth/revoke",
                "end_session_endpoint" to "$issuer/oauth/logout",
            )
            val transport = StubTransport().on("GET", "$issuer/.well-known/openid-configuration") { ok(document) }
            val client = ProtelesClient(configuration, InMemoryTokenStore(), CrossProcessLock.inProcessOnly("discovery-$issuer"), transport)
            assertEquals("$issuer/oauth/token", client.providerMetadata().tokenEndpoint, issuer)
        }
    }

    @Test
    fun `http endpoints are refused off the loopback hosts, and whenever the issuer is https`() {
        fun parse(issuer: String, endpoint: String) = ProviderMetadata.parse(
            toJson(
                mapOf(
                    "issuer" to issuer,
                    "authorization_endpoint" to "$issuer/oauth/authorize",
                    "token_endpoint" to endpoint,
                    "jwks_uri" to "$issuer/.well-known/jwks.json",
                ),
            ) as JsonObject,
            issuer,
        )
        val local = "http://localhost:8080"
        // Positive control: the same shape with a loopback endpoint parses.
        assertEquals("$local/oauth/token", parse(local, "$local/oauth/token").tokenEndpoint)
        // A loopback issuer never sends the code, verifier or refresh token in cleartext off the device.
        for (remote in listOf("http://auth.example.test/token", "http://localhost.example.com/token", "http://10.0.2.2:8080/token", "http://127.0.0.2/token")) {
            assertFailsWith<ProtelesException.Configuration>(remote) { parse(local, remote) }
        }
        assertFailsWith<ProtelesException.Configuration> { parse(ISSUER, "http://localhost:8080/oauth/token") }
    }
}

class StoredSessionTest {
    @Test
    fun `a session round-trips through its encoding, claims byte for byte`(): Unit = runBlocking {
        val h = ClientHarness()
        h.client.signIn(h.browser())
        val s = h.store.session!!
        val back = StoredSession.decode(s.encode())
        assertEquals(s.accessToken, back.accessToken)
        assertEquals(s.refreshToken, back.refreshToken)
        assertEquals(s.idToken, back.idToken)
        assertEquals(s.obtainedAt, back.obtainedAt)
        assertEquals(s.expiresAt, back.expiresAt)
        assertEquals(s.claims!!.payloadJson, back.claims!!.payloadJson)
        assertEquals(s.issuer, back.issuer)
        assertEquals(s.clientId, back.clientId)
        assertEquals(s.scope, back.scope)
    }

    @Test
    fun `anything encode would not write is refused`() {
        assertFailsWith<IllegalArgumentException> { StoredSession.decode("{}".toByteArray()) }
        assertFailsWith<IllegalArgumentException> { StoredSession.decode("nope".toByteArray()) }
        assertFailsWith<IllegalArgumentException> { StoredSession.decode("""{"v":2}""".toByteArray()) }
    }
}
