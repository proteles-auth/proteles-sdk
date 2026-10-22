package com.proteles.auth

import java.security.GeneralSecurityException
import java.security.Signature

/** What a verified ID token must say (docs/mobile-SDKs.md §5.2). */
internal class IdTokenExpectation(
    val issuer: String,
    val audience: String,
    /**
     * The nonce this login sent, or null for a token that cannot carry one (the
     * refresh grant). Null is the only skip; "" is an expectation nothing meets.
     */
    val nonce: String?,
    /** The access token from the same response (M3: then `at_hash` is mandatory), or null. */
    val accessToken: String?,
    /**
     * Whether `exp` and `iat` are held to this device's clock. False only for a
     * refresh-minted token (docs/mobile-SDKs.md §10.9 item 2): it arrived over
     * TLS in the response that minted it, and `at_hash` binds it to the access
     * token minted with it, so a clock disagreement is not a reason to refuse
     * it. `exp` must still be present, and every other rule applies — see
     * [IdTokenVerifier.timeRejection] and ProtelesClient's refresh.
     */
    val checkTime: Boolean = true,
)

/**
 * ID-token verification, in the order docs/mobile-SDKs.md §5 gives — **the order
 * is the security property** — and with the answers §5.2 settles. It is held to
 * `mobile/vectors/vectors.json` by the tests, vector by vector, including the
 * reason each refusal is for.
 *
 * Among its refusals, none reachable by a token this server issues: a
 * non-canonical base64url segment (see [Base64Url]), a `crit` header, and JSON
 * naming a member twice (see [Json]) — all three settled into §5.2 on
 * 2026-09-25, with the reason names `reference-verify.mjs` gives them.
 */
internal class IdTokenVerifier(private val clock: Clock) {

    suspend fun verify(token: String, keys: KeySource, expected: IdTokenExpectation): IdTokenClaims {
        val parts = token.split('.')
        if (parts.size != 3) reject(IdTokenRejection.NOT_THREE_SEGMENTS, "a compact JWS has three segments")
        val (h, p, s) = parts

        val headerBytes = Base64Url.decodeStrict(h)
            ?: reject(IdTokenRejection.HEADER_NOT_BASE64URL, "the header is not unpadded base64url")
        val header = try {
            Json.parseObjectUtf8(headerBytes)
        } catch (e: JsonDuplicateMemberException) {
            reject(IdTokenRejection.DUPLICATE_MEMBER, "the header names a member twice")
        } catch (e: JsonSyntaxException) {
            reject(IdTokenRejection.HEADER_NOT_JSON, "the header is not a JSON object")
        }

        // 1. The algorithm, first: before any key is looked up or any claim read.
        if (header.string("alg") != "RS256") reject(IdTokenRejection.ALGORITHM, "only RS256 is accepted")
        if (header.has("crit")) reject(IdTokenRejection.CRITICAL_HEADER, "no JWS extension is understood here")

        // 2. The key, by kid, from keys fit for signature verification.
        val kid = header.string("kid")
        if (kid.isNullOrEmpty()) reject(IdTokenRejection.KID_MISSING, "the header names no kid")
        val key = keys.key(kid) ?: reject(IdTokenRejection.NO_USABLE_KEY, "no usable RS256 key carries this kid")

        // 3. The signature, over the bytes exactly as they arrived.
        val signature = Base64Url.decodeStrict(s)
            ?: reject(IdTokenRejection.SIGNATURE_NOT_BASE64URL, "the signature is not unpadded base64url")
        val payloadBytes = Base64Url.decodeStrict(p)
            ?: reject(IdTokenRejection.PAYLOAD_NOT_BASE64URL, "the payload is not unpadded base64url")
        val verified = try {
            Signature.getInstance("SHA256withRSA").run {
                initVerify(key)
                update("$h.$p".toByteArray(Charsets.US_ASCII))
                verify(signature)
            }
        } catch (e: GeneralSecurityException) {
            false
        }
        if (!verified) reject(IdTokenRejection.SIGNATURE, "the signature does not verify")

        // 4. Only now, the claims.
        val claims = try {
            Json.parseObjectUtf8(payloadBytes)
        } catch (e: JsonDuplicateMemberException) {
            reject(IdTokenRejection.DUPLICATE_MEMBER, "the payload names a claim twice")
        } catch (e: JsonSyntaxException) {
            reject(IdTokenRejection.PAYLOAD_NOT_JSON, "the payload is not a JSON object")
        }
        if (claims.string("iss") != expected.issuer) reject(IdTokenRejection.ISSUER, "iss is not the configured issuer")
        val audience: List<Any?> = when (val aud = claims["aud"]) {
            is JsonArray -> aud.items.map { (it as? JsonString)?.value }
            is JsonString -> listOf(aud.value)
            else -> listOf(null)
        }
        // One audience, naming this client: several would need azp, which this issuer never sends.
        if (audience.size != 1 || audience[0] != expected.audience) {
            reject(IdTokenRejection.AUDIENCE, "aud does not name this client, alone")
        }
        if (claims.string("sub").isNullOrEmpty()) reject(IdTokenRejection.SUBJECT, "sub is missing")
        if (claims.number("exp") == null) reject(IdTokenRejection.EXP_MISSING, "exp is missing")
        if (expected.checkTime) timeRejection(claims)?.let { reject(it, TIME_DETAIL.getValue(it)) }

        // 5. The nonce: null is the explicit skip; anything else must be present and equal.
        val nonce = expected.nonce
        if (nonce != null && (nonce.isEmpty() || claims.string("nonce") != nonce)) {
            reject(IdTokenRejection.NONCE, "the nonce is not the one this login sent")
        }

        // 6. at_hash, whenever the caller holds the access token (M3).
        val accessToken = expected.accessToken
        if (accessToken != null && claims.string("at_hash") != atHash(accessToken)) {
            reject(IdTokenRejection.AT_HASH, "at_hash does not describe the access token from this response")
        }

        return IdTokenClaims(claims, Json.decodeUtf8Strict(payloadBytes))
    }

    /**
     * The refusal this device's clock gives a token's `exp` and `iat` (§5.2
     * divergence 1: 60 s skew on `exp`, and on `iat` in the future), or null when
     * both are within it. A refresh verifies without judging the clock and asks
     * this afterwards, only to decide whether to adopt the claims.
     */
    fun timeRejection(claims: IdTokenClaims): IdTokenRejection? = timeRejection(claims.json)

    private fun timeRejection(claims: JsonObject): IdTokenRejection? {
        val exp = claims.number("exp")?.double ?: return IdTokenRejection.EXP_MISSING
        val now = clock.epochSeconds().toDouble()
        if (now > exp + CLOCK_SKEW_SECONDS) return IdTokenRejection.EXPIRED
        val iat = claims.number("iat")?.double
        if (iat != null && iat > now + CLOCK_SKEW_SECONDS) return IdTokenRejection.ISSUED_IN_THE_FUTURE
        return null
    }

    companion object {
        /** §5.2 divergence 1: on `exp`, and on `iat` in the future. */
        const val CLOCK_SKEW_SECONDS: Long = 60

        private val TIME_DETAIL = mapOf(
            IdTokenRejection.EXP_MISSING to "exp is missing",
            IdTokenRejection.EXPIRED to "expired more than ${CLOCK_SKEW_SECONDS}s ago",
            IdTokenRejection.ISSUED_IN_THE_FUTURE to "iat is more than ${CLOCK_SKEW_SECONDS}s ahead",
        )

        /** OIDC Core §3.1.3.6: the left half of SHA-256 over the ASCII access token, base64url. */
        fun atHash(accessToken: String): String {
            val digest = sha256(accessToken.toByteArray(Charsets.US_ASCII))
            return Base64Url.encode(digest.copyOfRange(0, digest.size / 2))
        }

        private fun reject(reason: IdTokenRejection, detail: String): Nothing =
            throw ProtelesException.IdTokenRejected(reason, detail)
    }
}
