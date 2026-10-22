package com.proteles.auth

import java.security.SecureRandom

/**
 * PKCE (RFC 7636) with S256, and the random `state` and `nonce`
 * (docs/mobile-SDKs.md §10.2 step 2).
 *
 * The server refuses any challenge that is not exactly 43 characters (trap 5)
 * and any method but S256 (trap 6). 32 random bytes as unpadded base64url are
 * 43 characters, and so is the base64url of a SHA-256 digest — so both halves
 * are 43 by construction, and the tests hold them to it.
 */
public object Pkce {
    /** The only method this server accepts; `plain` and an absent method are refused. */
    public const val METHOD: String = "S256"

    /** A fresh code verifier: 32 bytes from [random], base64url without padding (43 characters). */
    public fun generateVerifier(random: SecureRandom): String = randomToken(random)

    /** base64url(SHA-256(ASCII(verifier))), without padding. */
    public fun challenge(verifier: String): String = Base64Url.encode(sha256(verifier.toByteArray(Charsets.US_ASCII)))

    /** 32 random bytes, base64url without padding: used for `state` and `nonce`. */
    internal fun randomToken(random: SecureRandom): String {
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        return Base64Url.encode(bytes)
    }
}
