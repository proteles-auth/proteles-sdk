package com.proteles.auth

import java.net.URI
import java.net.URISyntaxException
import java.security.SecureRandom

/**
 * One authorization request: the URL the browser opens, and the secrets that
 * bind the callback and the token exchange to it (docs/mobile-SDKs.md §10.2
 * steps 2–3). The secrets never leave this object except in the requests they
 * belong to.
 */
internal class AuthorizationRequest(
    val url: String,
    val state: String,
    val nonce: String,
    val codeVerifier: String,
    val redirectUri: String,
) {
    companion object {
        fun create(metadata: ProviderMetadata, configuration: ProtelesConfiguration, random: SecureRandom): AuthorizationRequest {
            val state = Pkce.randomToken(random)
            val nonce = Pkce.randomToken(random)
            val verifier = Pkce.generateVerifier(random)
            val params = listOf(
                "response_type" to "code",
                "client_id" to configuration.clientId,
                "redirect_uri" to configuration.redirectUri,
                "scope" to configuration.scope,
                "state" to state,
                "nonce" to nonce,
                "code_challenge" to Pkce.challenge(verifier),
                "code_challenge_method" to Pkce.METHOD,
                // No login_hint: the server does not honour it (§6 P2.12).
            )
            val url = appendQuery(metadata.authorizationEndpoint, params)
            return AuthorizationRequest(url, state, nonce, verifier, configuration.redirectUri)
        }

        /** Appends [params] to [endpoint], keeping any query the endpoint already has. */
        fun appendQuery(endpoint: String, params: List<Pair<String, String>>): String {
            val query = PercentEncoding.form(params)
            return when {
                !endpoint.contains('?') -> "$endpoint?$query"
                endpoint.endsWith('?') || endpoint.endsWith('&') -> "$endpoint$query"
                else -> "$endpoint&$query"
            }
        }
    }
}

/**
 * Reads a browser callback (docs/mobile-SDKs.md §10.2 step 4), in the order that
 * makes each check mean something:
 *
 * 1. It must be addressed to [expectedRedirectUri] (scheme, authority, path) —
 *    otherwise it is not a response to this request: [ProtelesException.StateMismatch].
 * 2. `state` must be present once and equal the one sent: otherwise
 *    [ProtelesException.StateMismatch]. Checked before `error`, so a forged error
 *    response is refused as forged rather than reported as the server's.
 * 3. `iss` (RFC 9207) must be present once and equal the issuer byte for byte:
 *    otherwise [ProtelesException.IssuerMismatch]. Discovery advertises
 *    `authorization_response_iss_parameter_supported`, so an absent `iss` is a
 *    refusal, not a pass — and it is checked on error responses too.
 * 4. `error` becomes [ProtelesException.AuthorizationError].
 * 5. Otherwise exactly one non-empty `code`.
 */
internal object AuthorizationCallback {
    fun parse(callbackUri: String, expectedRedirectUri: String, expectedState: String, expectedIssuer: String): String {
        val params = parseParams(callbackUri, expectedRedirectUri)
        checkState(params, expectedState)

        val iss = params["iss"]
        if (iss == null || iss.size != 1 || iss[0] != expectedIssuer) {
            throw ProtelesException.IssuerMismatch(
                expected = expectedIssuer,
                actual = iss?.joinToString(","),
                message = if (iss == null) {
                    "the authorization response carried no iss (RFC 9207); it may not come from the configured issuer"
                } else {
                    "the authorization response names another issuer (RFC 9207)"
                },
            )
        }

        params["error"]?.let { error ->
            throw ProtelesException.AuthorizationError(
                error = error.first(),
                errorDescription = params["error_description"]?.first(),
                errorUri = params["error_uri"]?.first(),
            )
        }

        val code = params["code"]
        if (code == null || code.size != 1 || code[0].isEmpty()) {
            throw ProtelesException.AuthorizationError(
                error = "invalid_response",
                errorDescription = "the authorization response carried no single authorization code",
                errorUri = null,
            )
        }
        return code[0]
    }

    /** For the end-session return: addressed to [expectedRedirectUri], with the `state` that was sent. */
    fun checkEndSessionReturn(callbackUri: String, expectedRedirectUri: String, expectedState: String) {
        checkState(parseParams(callbackUri, expectedRedirectUri), expectedState)
    }

    private fun checkState(params: Map<String, List<String>>, expectedState: String) {
        val state = params["state"]
        if (state == null || state.size != 1 || state[0] != expectedState) {
            throw ProtelesException.StateMismatch(
                if (state == null) "the callback carried no state" else "the callback's state is not the one this request sent",
            )
        }
    }

    private fun parseParams(callbackUri: String, expectedRedirectUri: String): Map<String, List<String>> {
        val callback = try {
            URI(callbackUri)
        } catch (e: URISyntaxException) {
            throw ProtelesException.StateMismatch("the callback is not a valid URI")
        }
        val expected = URI(expectedRedirectUri)
        val sameTarget = callback.scheme.equals(expected.scheme, ignoreCase = true) &&
            callback.rawAuthority == expected.rawAuthority &&
            (callback.rawPath ?: "") == (expected.rawPath ?: "")
        if (!sameTarget || callback.isOpaque) {
            throw ProtelesException.StateMismatch("the callback is not addressed to this request's redirect URI")
        }
        val pairs = try {
            PercentEncoding.decodeQuery(callback.rawQuery ?: "")
        } catch (e: IllegalArgumentException) {
            throw ProtelesException.StateMismatch("the callback's query is malformed")
        }
        return pairs.groupBy({ it.first }, { it.second })
    }
}
