package com.proteles.auth

import java.net.URI

/**
 * The parts of the issuer's discovery document this SDK uses
 * (docs/mobile-SDKs.md §10.2 step 1). Endpoints are read from discovery rather
 * than derived by convention (§6 P1.6).
 */
public class ProviderMetadata internal constructor(
    public val issuer: String,
    public val authorizationEndpoint: String,
    public val tokenEndpoint: String,
    public val jwksUri: String,
    /** Absent means sign-out can only clear locally, and says so. */
    public val revocationEndpoint: String?,
    /** Absent means the browser session cannot be ended from the app. */
    public val endSessionEndpoint: String?,
) {
    internal companion object {
        /** `{issuer}/.well-known/openid-configuration` — one trailing slash dropped first, per OIDC Discovery §4. */
        fun discoveryUrl(issuer: String): String = issuer.removeSuffix("/") + "/.well-known/openid-configuration"

        /**
         * Validates a discovery document against the configured [expectedIssuer].
         * The document's `issuer` must equal it byte for byte; every endpoint must be
         * https — or, when the issuer itself is http, http on one of the loopback
         * hosts §10.1 allows the issuer (`localhost`, `127.0.0.1`, `[::1]`): local
         * development and integration tests against a server on this machine. Never
         * http to any other host, which would carry the code, the verifier and the
         * refresh token in cleartext off the device.
         */
        fun parse(document: JsonObject, expectedIssuer: String): ProviderMetadata {
            val issuer = document.string("issuer")
            if (issuer != expectedIssuer) {
                throw ProtelesException.IssuerMismatch(
                    expected = expectedIssuer,
                    actual = issuer,
                    message = "the discovery document names issuer ${issuer ?: "(none)"}, not the configured $expectedIssuer",
                )
            }
            val loopbackIssuer = expectedIssuer.startsWith("http:")
            fun endpoint(name: String, required: Boolean): String? {
                val value = document[name]
                if (value == null || value == JsonNull) {
                    if (required) throw ProtelesException.Configuration("the discovery document has no $name")
                    return null
                }
                val url = (value as? JsonString)?.value
                    ?: throw ProtelesException.Configuration("the discovery document's $name is not a string")
                val uri = try {
                    URI(url)
                } catch (e: Exception) {
                    throw ProtelesException.Configuration("the discovery document's $name is not a URL")
                }
                val ok = when (uri.scheme) {
                    "https" -> !uri.host.isNullOrEmpty()
                    "http" -> loopbackIssuer && uri.host in ProtelesConfiguration.LOOPBACK_HOSTS
                    else -> false
                }
                if (!ok || uri.rawFragment != null) {
                    throw ProtelesException.Configuration("the discovery document's $name is not an https URL")
                }
                return url
            }
            return ProviderMetadata(
                issuer = issuer,
                authorizationEndpoint = endpoint("authorization_endpoint", required = true)!!,
                tokenEndpoint = endpoint("token_endpoint", required = true)!!,
                jwksUri = endpoint("jwks_uri", required = true)!!,
                revocationEndpoint = endpoint("revocation_endpoint", required = false),
                endSessionEndpoint = endpoint("end_session_endpoint", required = false),
            )
        }
    }
}
