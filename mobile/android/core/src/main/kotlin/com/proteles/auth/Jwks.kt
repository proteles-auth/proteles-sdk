package com.proteles.auth

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.math.BigInteger
import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPublicKeySpec
import kotlin.coroutines.cancellation.CancellationException

/** Where the verifier finds the key a token's `kid` names. */
internal interface KeySource {
    /**
     * The RS256 verification key for [kid], or null when no usable key carries it.
     * Throws [ProtelesException] when the keys could not be obtained at all.
     */
    suspend fun key(kid: String): RSAPublicKey?
}

internal object JsonWebKeySet {
    /** Below this an RSA key is refused as a verification key. */
    const val MIN_MODULUS_BITS: Int = 2048

    /**
     * The keys in [document] fit to verify an RS256 signature, by `kid`
     * (docs/mobile-SDKs.md §5 step 2, §5.2 divergence 5): `kty` is `RSA`; `use`,
     * if present, is `sig`; `alg`, if present, is `RS256`. A key that fails any of
     * these is not a verification key — not an error, simply never selected. When
     * two usable keys share a `kid`, the first wins, as in reference-verify.mjs.
     */
    fun usableKeys(document: JsonObject): Map<String, RSAPublicKey> {
        val keys = document["keys"] as? JsonArray ?: return emptyMap()
        val out = LinkedHashMap<String, RSAPublicKey>()
        for (entry in keys.items) {
            val jwk = entry as? JsonObject ?: continue
            if (jwk.string("kty") != "RSA") continue
            if (jwk.has("use") && jwk.string("use") != "sig") continue
            if (jwk.has("alg") && jwk.string("alg") != "RS256") continue
            val kid = jwk.string("kid")
            if (kid.isNullOrEmpty() || out.containsKey(kid)) continue
            val n = jwk.string("n")?.let { Base64Url.decodeStrict(it) } ?: continue
            val e = jwk.string("e")?.let { Base64Url.decodeStrict(it) } ?: continue
            val modulus = BigInteger(1, n)
            val exponent = BigInteger(1, e)
            if (modulus.bitLength() < MIN_MODULUS_BITS || exponent < BigInteger.valueOf(3) || !exponent.testBit(0)) continue
            val key = try {
                KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(modulus, exponent)) as RSAPublicKey
            } catch (ex: Exception) {
                continue
            }
            out[kid] = key
        }
        return out
    }
}

/** A fixed key set — the vectors' `jwks`, used as the only key set. */
internal class StaticKeySource(document: JsonObject) : KeySource {
    private val keys = JsonWebKeySet.usableKeys(document)
    override suspend fun key(kid: String): RSAPublicKey? = keys[kid]
}

/**
 * The issuer's published keys, cached (docs/mobile-SDKs.md §5 step 2):
 *
 * - **An unknown `kid` triggers a refetch** — that is what a key rotation looks
 *   like from here.
 * - **Concurrent refetches collapse into one fetch** (§5.2 divergence 7): the
 *   first caller fetches, everyone who arrives while it is in flight awaits the
 *   same result.
 * - **A failed refetch falls back to a stale-but-present key** rather than failing
 *   closed, so a JWKS outage does not sign everybody out. An unknown `kid` has
 *   nothing to fall back to, and the failure is raised.
 * - **A document with no usable key is an error**, not an empty cache; the keys
 *   already held are kept.
 */
internal class JwksCache(
    private val jwksUri: String,
    private val transport: Transport,
    private val clock: Clock,
    private val ttlSeconds: Long = 600,
    /** The client's: a 429 here holds its token requests too (§10.9 item 3). */
    private val rateLimits: RateLimitGate = RateLimitGate(clock),
) : KeySource {
    private val mutex = Mutex()
    private var inFlight: CompletableDeferred<Map<String, RSAPublicKey>>? = null // guarded by mutex

    @Volatile private var keys: Map<String, RSAPublicKey> = emptyMap()

    @Volatile private var fetchedAt: Long? = null

    override suspend fun key(kid: String): RSAPublicKey? {
        val cached = keys[kid]
        val at = fetchedAt
        if (cached != null && at != null && clock.epochSeconds() - at < ttlSeconds) return cached
        val fresh = try {
            refresh()
        } catch (e: ProtelesException) {
            if (cached != null) return cached
            throw e
        }
        return fresh[kid]
    }

    private suspend fun refresh(): Map<String, RSAPublicKey> {
        var leader = false
        val flight = mutex.withLock {
            inFlight ?: CompletableDeferred<Map<String, RSAPublicKey>>().also {
                inFlight = it
                leader = true
            }
        }
        if (leader) {
            try {
                val fetched = fetch()
                keys = fetched
                fetchedAt = clock.epochSeconds()
                flight.complete(fetched)
            } catch (e: CancellationException) {
                // The leader was cancelled; the others were not, and must not
                // receive a cancellation that is not theirs.
                flight.completeExceptionally(ProtelesException.Network("the key-set fetch was cancelled", e))
                throw e
            } catch (e: ProtelesException) {
                flight.completeExceptionally(e)
            } catch (e: Exception) {
                flight.completeExceptionally(ProtelesException.Network("the key-set fetch failed", e))
            } finally {
                withContext(NonCancellable) { mutex.withLock { if (inFlight === flight) inFlight = null } }
            }
        }
        return flight.await()
    }

    private suspend fun fetch(): Map<String, RSAPublicKey> {
        val response = sendOrNetworkError(
            transport,
            HttpRequest("GET", jwksUri, mapOf("Accept" to "application/json")),
        )
        if (response.status == 429) throw rateLimits.close(response)
        // §10.9 item 4: a 5xx (or anything but 200) is "try later", with its status.
        if (response.status != 200) {
            throw ProtelesException.Network("the key set answered HTTP ${response.status}", httpStatus = response.status)
        }
        val document = try {
            Json.parseObjectUtf8(response.body)
        } catch (e: JsonSyntaxException) {
            throw ProtelesException.Network("the key set is not a JSON object")
        }
        val usable = JsonWebKeySet.usableKeys(document)
        if (usable.isEmpty()) {
            throw ProtelesException.Network("the key set publishes no usable RS256 signing key")
        }
        return usable
    }
}
