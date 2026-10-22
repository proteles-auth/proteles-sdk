package com.proteles.auth

/**
 * The claims of a verified ID token.
 *
 * These are what [ProtelesClient.currentClaims] returns for as long as the user
 * is signed in — **not** tied to the ID token's own `exp`, which shares the
 * access token's fifteen minutes (docs/mobile-SDKs.md §3 trap 7). Cache the
 * claims, not the token's validity.
 */
public class IdTokenClaims internal constructor(
    internal val json: JsonObject,
    /** The payload exactly as it was signed, for storage. */
    internal val payloadJson: String,
) {
    public val issuer: String get() = json.string("iss").orEmpty()
    public val subject: String get() = json.string("sub").orEmpty()
    public val audience: List<String>
        get() = when (val aud = json["aud"]) {
            is JsonArray -> aud.items.mapNotNull { (it as? JsonString)?.value }
            is JsonString -> listOf(aud.value)
            else -> emptyList()
        }
    public val expiresAt: Long? get() = json.number("exp")?.longOrNull()
    public val issuedAt: Long? get() = json.number("iat")?.longOrNull()

    /** The session's authentication instant; inherited across refresh, never restamped (trap 8). */
    public val authTime: Long? get() = json.number("auth_time")?.longOrNull()
    public val nonce: String? get() = json.string("nonce")
    public val email: String? get() = json.string("email")
    public val emailVerified: Boolean? get() = json.boolean("email_verified")
    public val preferredUsername: String? get() = json.string("preferred_username")
    public val amr: List<String>
        get() = (json["amr"] as? JsonArray)?.items?.mapNotNull { (it as? JsonString)?.value }.orEmpty()
    public val acr: String? get() = json.string("acr")

    /** Any claim, as String, Long or Double, Boolean, List, Map, or null. */
    public operator fun get(name: String): Any? = json[name]?.toNative()

    /** Every claim, as [get] returns them. */
    public fun toMap(): Map<String, Any?> = json.members.mapValues { it.value.toNative() }

    override fun toString(): String = "IdTokenClaims(iss=$issuer, sub=$subject)"

    internal companion object {
        fun fromPayloadJson(payloadJson: String): IdTokenClaims = IdTokenClaims(Json.parseObject(payloadJson), payloadJson)
    }
}
