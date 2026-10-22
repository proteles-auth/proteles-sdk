package com.proteles.auth

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.jupiter.api.Test
import java.io.IOException
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class JwksCacheTest {
    private val now = 1_800_000_000L
    private val clock = MutableClock(now)
    private val keyA = SigningKey("key-a")
    private val keyB = SigningKey("key-b")

    private fun verifier() = IdTokenVerifier(clock)
    private fun expectation() = IdTokenExpectation(ISSUER, CLIENT_ID, nonce = null, accessToken = null)

    @Test
    fun `an unknown kid refetches the key set - a rotation`(): Unit = runBlocking {
        var published = jwksOf(keyA)
        val transport = StubTransport().on("GET", JWKS) { ok(published) }
        val cache = JwksCache(JWKS, transport, clock)

        verifier().verify(keyA.sign(idTokenClaims(now)), cache, expectation())
        assertEquals(1, transport.requestsTo(JWKS).size)

        // The issuer rotates to key B. The cache is fresh, but B is unknown: refetch.
        published = jwksOf(keyA, keyB)
        verifier().verify(keyB.sign(idTokenClaims(now)), cache, expectation())
        assertEquals(2, transport.requestsTo(JWKS).size)

        // Known and fresh: no fetch.
        verifier().verify(keyB.sign(idTokenClaims(now)), cache, expectation())
        assertEquals(2, transport.requestsTo(JWKS).size)
    }

    @Test
    fun `concurrent refreshes collapse into one fetch (single-threaded, deterministic)`(): Unit = runBlocking {
        val gate = CompletableDeferred<Unit>()
        val transport = StubTransport().on("GET", JWKS) {
            gate.await()
            ok(jwksOf(keyA))
        }
        val cache = JwksCache(JWKS, transport, clock)
        val token = keyA.sign(idTokenClaims(now))
        val callers = (1..25).map { async { verifier().verify(token, cache, expectation()) } }
        repeat(10) { yield() } // every caller runs up to its suspension point
        assertEquals(1, transport.requestsTo(JWKS).size, "fetches while in flight")
        gate.complete(Unit)
        callers.awaitAll()
        assertEquals(1, transport.requestsTo(JWKS).size, "fetches in total")
    }

    @Test
    fun `concurrent refreshes collapse into one fetch (many threads)`(): Unit = runBlocking(Dispatchers.Default) {
        val transport = StubTransport().on("GET", JWKS) {
            delay(300) // long enough that every caller arrives while it is in flight
            ok(jwksOf(keyA))
        }
        val cache = JwksCache(JWKS, transport, clock)
        val token = keyA.sign(idTokenClaims(now))
        (1..64).map { async { verifier().verify(token, cache, expectation()) } }.awaitAll()
        assertEquals(1, transport.requestsTo(JWKS).size)
    }

    @Test
    fun `a failed fetch is shared by every waiter, and the next call tries again`(): Unit = runBlocking {
        val gate = CompletableDeferred<Unit>()
        var fail = true
        val transport = StubTransport().on("GET", JWKS) {
            gate.await()
            if (fail) throw IOException("offline") else ok(jwksOf(keyA))
        }
        val cache = JwksCache(JWKS, transport, clock)
        val token = keyA.sign(idTokenClaims(now))
        val callers = (1..5).map { async { runCatching { verifier().verify(token, cache, expectation()) } } }
        repeat(10) { yield() }
        gate.complete(Unit)
        val results = callers.awaitAll()
        assertTrue(results.all { it.exceptionOrNull() is ProtelesException.Network }, results.toString())
        assertEquals(1, transport.requestsTo(JWKS).size)
        fail = false
        verifier().verify(token, cache, expectation())
        assertEquals(2, transport.requestsTo(JWKS).size)
    }

    @Test
    fun `a stale-but-present key is used when the refetch fails`(): Unit = runBlocking {
        var up = true
        val transport = StubTransport().on("GET", JWKS) { if (up) ok(jwksOf(keyA)) else status(503) }
        val cache = JwksCache(JWKS, transport, clock, ttlSeconds = 600)
        val token = keyA.sign(idTokenClaims(now))
        verifier().verify(token, cache, expectation())

        clock.advance(601) // stale
        up = false
        val fresh = keyA.sign(idTokenClaims(clock.epochSeconds()))
        verifier().verify(fresh, cache, expectation()) // falls back, does not fail closed
        assertEquals(2, transport.requestsTo(JWKS).size)

        // An unknown kid has nothing to fall back to.
        val e = assertFailsWith<ProtelesException.Network> {
            verifier().verify(keyB.sign(idTokenClaims(clock.epochSeconds())), cache, expectation())
        }
        assertTrue(e.message!!.contains("503"), e.message)
        assertEquals(503, e.httpStatus, "a 5xx from the key set is Network, with its status (§10.9 item 4)")
    }

    @Test
    fun `a key set with no usable key is an error, and the keys already held are kept`(): Unit = runBlocking {
        var doc: Map<String, Any?> = jwksOf(keyA)
        val transport = StubTransport().on("GET", JWKS) { ok(doc) }
        val cache = JwksCache(JWKS, transport, clock)
        assertNotNull(cache.key("key-a"))

        doc = mapOf("keys" to listOf(keyB.jwk + ("use" to "enc")))
        assertFailsWith<ProtelesException.Network> { cache.key("key-b") }
        assertNotNull(cache.key("key-a"), "the old key survives a bad document")
    }

    @Test
    fun `the JWK filter - kty, use, alg, kid, size`() {
        fun usable(vararg jwks: Map<String, Any?>) = JsonWebKeySet.usableKeys(toJson(mapOf("keys" to jwks.toList())) as JsonObject).keys
        val base = keyA.jwk
        assertEquals(setOf("key-a"), usable(base))
        assertEquals(setOf("key-a"), usable(base - "use" - "alg"), "use and alg are optional")
        assertEquals(emptySet(), usable(base + ("use" to "enc")))
        assertEquals(emptySet(), usable(base + ("alg" to "RS512")))
        assertEquals(emptySet(), usable(base + ("use" to null)), "present and not sig")
        assertEquals(emptySet(), usable(base + ("kty" to "EC")))
        assertEquals(emptySet(), usable(base - "kid"))
        assertEquals(emptySet(), usable(base + ("n" to "${base["n"]}=")), "padded modulus")
        assertEquals(emptySet(), usable(SigningKey("small", bits = 1024).jwk), "below 2048 bits")
        assertEquals(emptySet(), usable(base + ("e" to "AQ")), "exponent 1")
        assertEquals(emptySet(), usable(base + ("e" to "Ag")), "even exponent")
        assertEquals(setOf("key-a"), usable(base + ("e" to "Aw")), "exponent 3 is odd and allowed")
        // first usable key wins on a shared kid; an unusable one before it is skipped
        val second = SigningKey("key-a").jwk
        val keys = JsonWebKeySet.usableKeys(toJson(mapOf("keys" to listOf(base + ("use" to "enc"), second, base))) as JsonObject)
        assertEquals(1, keys.size)
        assertEquals((second["n"] as String), Base64Url.encode(keys.getValue("key-a").modulus.toByteArray().let { if (it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it }))
    }

    @Test
    fun `a missing or non-array keys member is no keys`(): Unit = runBlocking {
        assertNull(StaticKeySource(Json.parseObject("{}")).key("x"))
        assertNull(StaticKeySource(Json.parseObject("""{"keys":{}}""")).key("x"))
    }
}
