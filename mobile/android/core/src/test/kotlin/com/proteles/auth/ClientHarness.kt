package com.proteles.auth

import java.util.concurrent.atomic.AtomicInteger

/**
 * A ProtelesClient wired to a scripted server: discovery, JWKS, and a token
 * endpoint that mints real RS256 ID tokens with the nonce and at_hash of each
 * exchange, so the whole sign-in and refresh paths run against the real verifier.
 *
 * [clock] is the device's. The server stamps `iat`/`exp` with its own time,
 * [serverNow] — the device clock plus [serverClockOffset], so a test can move
 * one without the other ([moveDeviceClock]).
 */
class ClientHarness(
    val clock: MutableClock = MutableClock(1_800_000_000L),
    val key: SigningKey = SHARED_KEY,
    val store: RecordingStore = RecordingStore(),
    // One key per record: two harnesses over one store share the lock, as two clients in one process must.
    val lock: CrossProcessLock = CrossProcessLock.inProcessOnly("harness-store-${System.identityHashCode(store)}"),
    val configuration: ProtelesConfiguration = ProtelesConfiguration(
        ISSUER,
        CLIENT_ID,
        REDIRECT,
        postLogoutRedirectUri = POST_LOGOUT,
    ),
    discovery: Map<String, Any?> = discoveryDocument(),
) {
    val transport = StubTransport()
    val client = ProtelesClient(configuration, store, lock, transport, clock)

    private val counter = AtomicInteger()

    /** The nonce of the last authorization request the browser saw. */
    @Volatile var lastNonce: String? = null

    /** Overrides for the next ID token's claims. */
    @Volatile var idTokenExtra: Map<String, Any?> = emptyMap()
    @Volatile var idTokenSub: String = "user-1"
    @Volatile var issueIdToken: Boolean = true
    @Volatile var issueRefreshToken: Boolean = true
    /** `expires_in` as the server sends it: a Number, so a test can send a fraction. */
    @Volatile var expiresIn: Number = 900

    /** How far the server's clock is ahead of the device's. */
    @Volatile var serverClockOffset: Long = 0

    fun serverNow(): Long = clock.epochSeconds() + serverClockOffset

    /** The device clock moves (set by hand, an RTC reset); the server's does not. */
    fun moveDeviceClock(seconds: Long) {
        clock.advance(seconds)
        serverClockOffset -= seconds
    }

    /** Replace to script the token endpoint; the default mints a token set. */
    @Volatile var tokenEndpoint: suspend (HttpRequest) -> HttpResponse = { request -> mint(request) }

    init {
        transport.on("GET", DISCOVERY) { ok(discovery) }
        transport.on("GET", JWKS) { ok(jwksOf(key)) }
        transport.on("POST", TOKEN) { tokenEndpoint(it) }
        transport.on("POST", REVOKE) { status(200) }
    }

    fun mint(request: HttpRequest): HttpResponse {
        val n = counter.incrementAndGet()
        val accessToken = "at-$n"
        val nonce = if (request.formValue("grant_type") == "authorization_code") lastNonce else null
        val body = buildMap<String, Any?> {
            put("access_token", accessToken)
            put("token_type", "Bearer")
            put("expires_in", expiresIn)
            if (issueRefreshToken) put("refresh_token", "rt-$n")
            if (issueIdToken) {
                put(
                    "id_token",
                    key.sign(idTokenClaims(serverNow(), nonce = nonce, accessToken = accessToken, sub = idTokenSub, extra = idTokenExtra)),
                )
            }
            put("scope", "openid profile email")
        }
        return ok(body)
    }

    /** A browser that completes the authorization with [code], echoing the request's state and the issuer. */
    fun browser(
        code: String = "the-code",
        callback: ((state: String) -> String)? = null,
    ): FakeBrowser = FakeBrowser { url, returnUri ->
        val q = queryOf(url)
        lastNonce = q["nonce"]?.single()
        val state = q["state"]!!.single()
        callback?.invoke(state)
            ?: "$returnUri?code=$code&state=$state&iss=${PercentEncoding.encode(ISSUER)}"
    }

    val tokenRequests: List<HttpRequest> get() = transport.requestsTo(TOKEN)
}
