import Foundation

/// A native app's client for one Proteles tenant (docs/mobile-SDKs.md §10).
///
/// ```swift
/// let client = try ProtelesClient(configuration: .init(
///     issuer: "https://acme.proteles.example",
///     clientId: "com.example.app",
///     redirectURI: "https://app.example.com/oauth/callback"))
///
/// let user = try await client.signIn(presentationAnchor: window)
/// let token = try await client.validAccessToken()   // before every API call
/// try await client.signOut()
/// ```
///
/// An actor: every token operation is serialised, a refresh is single-flight
/// within the process and — with an App Group — across processes (§10.6).
public actor ProtelesClient {
    public nonisolated let configuration: ProtelesConfiguration
    /// Which lock serialises this client's refreshes.
    public nonisolated let lockScope: RefreshLockScope

    private let transport: any HTTPTransport
    private let store: any TokenStore
    private let lock: any RefreshLock
    private let now: @Sendable () -> Date
    private let tokenClient: TokenClient
    private let backgroundActivity: any BackgroundActivity
    /// After a 429 from any endpoint: no token request, no refresh and no
    /// sign-in opening the browser before `Retry-After` (§10.9 items 3 and 8).
    /// Shared with the token client, discovery and the key set.
    private let gate: RateLimitGate

    private struct Discovered: Sendable {
        let document: DiscoveryDocument
        let keys: JWKSCache
    }

    private var discovered: Discovered?
    private var discoveryTask: Task<Discovered, any Error>?
    private var refreshTask: Task<String, any Error>?
    /// After a refresh failed while the stored token was still good: no new
    /// attempt before `until` (§10.9 item 3). In memory, per client.
    private var refreshBackoff: Backoff?
    /// A sign-in, or a sign-out that ends the browser session, is running.
    private var browserFlowRunning = false
    /// Refresh tokens this client knows are dead: refused with `invalid_grant`,
    /// revoked at sign-out, or abandoned with a session that failed a trust
    /// rule. A stored session holding one is no session (§10.9 item 1): it is
    /// never presented again, even when the store could not be cleared.
    private var retired: Set<String> = []

    /// The longest a failed refresh is held off while the stored token is
    /// still good — never more than half the time it has left (§10.9 item 3).
    static let maximumRefreshBackoff: TimeInterval = 30

    /// A client with the defaults: `URLSession`, the Keychain, and a
    /// cross-process lock when `appGroupIdentifier` is set.
    ///
    /// - Throws: `.configuration` when an App Group is configured and has no
    ///   container (on iOS, the entitlement is missing), or when a
    ///   `keychainAccessGroup` is configured without an App Group (see
    ///   `init(configuration:transport:store:lock:)`).
    public init(configuration: ProtelesConfiguration) throws {
        try self.init(
            configuration: configuration,
            transport: URLSessionTransport(),
            store: KeychainTokenStore(configuration: configuration)
        )
    }

    /// A client with a supplied transport, store and lock.
    ///
    /// With `lock` left `nil` the client chooses: `flock` in the App Group
    /// container when `appGroupIdentifier` is set, otherwise an in-process
    /// lock.
    ///
    /// A configuration that shares the session with other processes — a
    /// `keychainAccessGroup` or an `appGroupIdentifier` — needs a lock that
    /// excludes them, because two processes refreshing one single-use token at
    /// once leave one of them holding a dead token (§4, §10.6). So it is
    /// refused with only an in-process lock (§10.9 item 9): a
    /// `keychainAccessGroup` without an `appGroupIdentifier` and no `lock`, or
    /// either with `InProcessRefreshLock`. Pass a `FileRefreshLock`, or a lock
    /// of your own that excludes every process sharing the record.
    public init(
        configuration: ProtelesConfiguration,
        transport: any HTTPTransport,
        store: any TokenStore,
        lock: (any RefreshLock)? = nil
    ) throws {
        try self.init(configuration: configuration, transport: transport, store: store, lock: lock, now: { Date() })
    }

    init(
        configuration: ProtelesConfiguration,
        transport: any HTTPTransport,
        store: any TokenStore,
        lock: (any RefreshLock)?,
        now: @escaping @Sendable () -> Date,
        backgroundActivity: any BackgroundActivity = ProcessBackgroundActivity()
    ) throws {
        let sharedAcrossProcesses = configuration.keychainAccessGroup != nil || configuration.appGroupIdentifier != nil
        let sharedButInProcess = ProtelesAuthError.configuration(
            "keychainAccessGroup and appGroupIdentifier share the session with other processes, and their refreshes must be serialised with this one's: an in-process lock cannot (§10.9 item 9). Set appGroupIdentifier for the App Group's file lock, or pass a lock that excludes every process")
        if let lock {
            if lock is InProcessRefreshLock, sharedAcrossProcesses { throw sharedButInProcess }
            self.lock = lock
            if let fileLock = lock as? FileRefreshLock {
                self.lockScope = .crossProcess(lockFile: fileLock.url)
            } else if lock is InProcessRefreshLock {
                self.lockScope = .inProcess
            } else {
                self.lockScope = .custom
            }
        } else if let group = configuration.appGroupIdentifier {
            guard let fileLock = FileRefreshLock.appGroup(group, clientId: configuration.clientId) else {
                throw ProtelesAuthError.configuration(
                    "the App Group \"\(group)\" has no container; add it to the app's App Groups entitlement")
            }
            self.lock = fileLock
            self.lockScope = .crossProcess(lockFile: fileLock.url)
        } else {
            guard !sharedAcrossProcesses else { throw sharedButInProcess }
            self.lock = InProcessRefreshLock(key: configuration.keychainService)
            self.lockScope = .inProcess
        }
        self.configuration = configuration
        self.transport = transport
        self.store = store
        self.now = now
        self.backgroundActivity = backgroundActivity
        let gate = RateLimitGate(now: now)
        self.gate = gate
        self.tokenClient = TokenClient(transport: transport, clientId: configuration.clientId, now: now, gate: gate)
    }

    // MARK: - Sign in (§10.2)

    /// Runs the authorization code flow with PKCE through `browser`, verifies
    /// the ID token, and persists the session before returning the user.
    ///
    /// Cancelling the calling task dismisses the browser; once the browser has
    /// returned a code, nothing that follows is the caller's to cancel
    /// (§10.9 item 7). Tokens the server issued that this client will not
    /// hold — the ID token was refused, the store could not be written, the
    /// lock could not be taken — are revoked, best effort, rather than left
    /// alive for thirty days.
    ///
    /// - Throws: `.cancelled` when the user closes the browser;
    ///   `.alreadyInProgress` when a sign-in or end-session is already running
    ///   on this client; `.rateLimited` before the browser opens, while a 429
    ///   is being waited out; see `ProtelesAuthError` for the rest.
    public func signIn(using browser: any AuthorizationBrowser) async throws -> UserClaims {
        guard !browserFlowRunning else { throw ProtelesAuthError.alreadyInProgress }
        // The user would type a password for a code that cannot be redeemed.
        if let wait = gate.remaining() { throw ProtelesAuthError.rateLimited(retryAfter: wait) }
        browserFlowRunning = true
        defer { browserFlowRunning = false }

        let discovered = try await discover()
        let request = try AuthorizationRequest.make(endpoint: discovered.document.authorizationEndpoint, configuration: configuration)

        let callback = try await browser.open(request.url, redirectURI: configuration.redirectURL)
        let code = try AuthorizationCallback.code(
            from: callback,
            redirectURI: configuration.redirectURL,
            expectedState: request.state,
            expectedIssuer: configuration.issuer
        )

        // The code is single-use and the user has authenticated: from the
        // exchange on this runs to the end, whatever happens to the caller.
        let redemption = Task { try await self.redeem(code: code, request: request, discovered: discovered) }
        return try await redemption.value
    }

    /// The code exchange and everything after it. Runs in a task of its own,
    /// so the caller's cancellation never reaches it.
    private func redeem(code: String, request: AuthorizationRequest, discovered: Discovered) async throws -> UserClaims {
        // The access token's lifetime starts before the request is sent, so
        // time in flight counts against it rather than past its real expiry.
        let requestedAt = now()
        let answer = try await tokenClient.exchangeCode(
            endpoint: discovered.document.tokenEndpoint,
            code: code,
            redirectURI: configuration.redirectURI,
            codeVerifier: request.pkce.verifier
        )
        do {
            return try await keep(answer.checked(), requestedAt: requestedAt, request: request, discovered: discovered)
        } catch {
            // A family nobody holds (§10.9 item 7) — including one from a
            // response refused as malformed, as the Android SDK does.
            if let refreshToken = answer.refreshToken { await revokeQuietly(refreshToken, discovered: discovered) }
            throw error
        }
    }

    private func keep(_ tokens: TokenResponse, requestedAt: Date, request: AuthorizationRequest, discovered: Discovered) async throws -> UserClaims {
        guard let idToken = tokens.idToken else { throw ProtelesAuthError.idTokenRejected(.missing) }
        let verified = try await IDTokenVerifier.verify(
            idToken,
            expecting: IDTokenExpectations(
                issuer: configuration.issuer,
                audience: configuration.clientId,
                nonce: .required(request.nonce),
                accessToken: tokens.accessToken,
                now: now()
            ),
            keys: discovered.keys
        )

        let session = StoredSession(
            issuer: configuration.issuer,
            clientId: configuration.clientId,
            refreshToken: tokens.refreshToken,
            accessToken: tokens.accessToken,
            accessTokenReceivedAt: requestedAt,
            accessTokenExpiresAt: requestedAt.addingTimeInterval(tokens.expiresIn),
            idToken: idToken,
            claims: verified.claims,
            scope: tokens.scope
        )
        // Persist, then return (§10.2 step 7) — under the refresh lock, after
        // any refresh already running, so an old family's rotation cannot land
        // on top of this sign-in.
        if let running = refreshTask { _ = try? await running.value }
        switch await underLock({ try await self.writeSession(session) }) {
        case .ran(let result):
            try result.get()
        case .unavailable(let failure):
            // Another process's refresh could write over an unlocked write;
            // the caller revokes what this sign-in got (§10.9 item 7).
            throw failure
        }
        refreshBackoff = nil
        return UserClaims(verified.claims)
    }

    // MARK: - A valid access token (§10.3)

    /// The stored access token, refreshed first when it is past half its
    /// life. Call it before every API request; do not cache what it returns.
    ///
    /// While the stored token has not expired, a refresh that fails hands it
    /// out and raises nothing — except for the failures that end the session
    /// (§10.9 item 1): `invalid_grant`, a refresh-minted ID token that fails a
    /// trust rule, and a refresh token already known to be dead. A store that
    /// cannot be written is raised, and does not end the session.
    ///
    /// - Throws: `.signInRequired` when there is no session or it has ended
    ///   (the session is cleared); `.idTokenRejected` when a refresh-minted ID
    ///   token was not to be trusted (the session is cleared, its refresh
    ///   token revoked); `.rateLimited`, `.network` or `.tokenEndpoint` when a
    ///   needed refresh failed and the stored token has expired (the session
    ///   is kept); `.storage` when the store is unavailable.
    public func validAccessToken() async throws -> String {
        if let running = refreshTask { return try await running.value }
        guard let session = try readStored() else { throw ProtelesAuthError.signInRequired }
        // A session whose refresh token is known dead goes to `refresh`, which
        // ends it under the lock.
        if !isDead(session), !session.needsRefresh(at: now()), let token = session.accessToken { return token }

        let task = Task { try await self.refresh() }
        refreshTask = task
        // A refresh may hold a cross-process lock — the App Group's `flock`,
        // or an app's own, which may be one — across its requests. If the
        // system is about to suspend the process, cancel it so the lock is
        // released first (0xdead10cc). With only the in-process lock there is
        // nothing to release, and a refresh abandoned after the server rotated
        // would lose the new refresh token (§4 "persist before you use"): it
        // is left to finish when the process resumes, as the Android SDK
        // never abandons a rotation once sent.
        let releasesACrossProcessLock = lockScope != .inProcess
        let endActivity = backgroundActivity.begin(reason: "Refreshing the sign-in session") {
            if releasesACrossProcessLock { task.cancel() }
        }
        defer {
            refreshTask = nil
            endActivity()
        }
        return try await task.value
    }

    /// The signed-in user's claims, or `nil` when signed out. Reads the store,
    /// so it reflects a refresh or sign-out made by another process. Only
    /// reads it: a session this client knows has ended reads as signed out,
    /// and is deleted by the next `validAccessToken`, under the lock.
    public func currentUser() throws -> UserClaims? {
        try readSession().map { UserClaims($0.claims) }
    }

    private func refresh() async throws -> String {
        // A session whose refresh token is known dead ends (§10.9 item 1).
        if let stored = try readStored(), isDead(stored) { try await endDeadSession() }

        // A backoff holds everything, discovery included (§10.9 item 3).
        let at = now()
        if let wait = gate.remaining() {
            guard let session = try readSession() else { throw ProtelesAuthError.signInRequired }
            if let token = session.unexpiredAccessToken(at: at) { return token }
            throw ProtelesAuthError.rateLimited(retryAfter: wait)
        }
        if let backoff = refreshBackoff, at < backoff.until {
            guard let session = try readSession() else { throw ProtelesAuthError.signInRequired }
            if let token = session.unexpiredAccessToken(at: at) { return token }
            throw backoff.failure
        }

        // Outside the lock: it is held for as few requests as possible.
        let discovered: Discovered
        do {
            discovered = try await discover()
        } catch {
            return try fallBack(asProtelesError(error))
        }

        switch await underLock({ try await self.refreshHoldingLock(discovered) }) {
        case .ran(let result):
            return try result.get()
        case .unavailable(let failure):
            // The wait for another process's refresh failed — it outlasted the
            // timeout, or this refresh was cancelled. That process has likely
            // finished by now: re-read, and hand out a usable token if one is
            // there (§10.9 item 9).
            guard let session = try readSession() else { throw ProtelesAuthError.signInRequired }
            let at = now()
            if !session.needsRefresh(at: at), let token = session.accessToken { return token }
            if let token = session.unexpiredAccessToken(at: at) { return token }
            throw failure
        }
    }

    /// Ends a stored session whose refresh token this client knows is dead
    /// (§10.9 item 1): it reads as signed out, and is deleted under the
    /// refresh lock after a re-read — never on a read outside it, where a
    /// sign-in another process has just written would be deleted with it.
    private func endDeadSession() async throws -> Never {
        // A lock that cannot be taken leaves the record for the next call;
        // it reads as signed out meanwhile.
        _ = await underLock { await self.deleteIfDead() }
        throw ProtelesAuthError.signInRequired
    }

    /// Under the lock: deletes the record if it still holds a dead session.
    private func deleteIfDead() {
        guard let stored = try? readStored(), isDead(stored) else { return }
        try? clearSession()
    }

    private func refreshHoldingLock(_ discovered: Discovered) async throws -> String {
        // Re-read: another process, or another client in this one, may have
        // refreshed while this one waited for the lock (§10.6).
        guard let session = try readStored() else { throw ProtelesAuthError.signInRequired }
        if isDead(session) {
            try? clearSession() // under the lock, just re-read
            throw ProtelesAuthError.signInRequired
        }
        if !session.needsRefresh(at: now()), let token = session.accessToken { return token }

        guard let refreshToken = session.refreshToken else {
            // A client without the refresh_token grant: the session ends with
            // its access token.
            if let token = session.unexpiredAccessToken(at: now()) { return token }
            try clearSession()
            throw ProtelesAuthError.signInRequired
        }

        // The lifetime starts before the request is sent (as the Android
        // SDK's refresh takes it), so time in flight counts against it.
        let requestedAt = now()
        let answer: UncheckedTokenResponse
        do {
            answer = try await tokenClient.refresh(endpoint: discovered.document.tokenEndpoint, refreshToken: refreshToken)
        } catch {
            let failure = asProtelesError(error)
            if case .tokenEndpoint(error: "invalid_grant", _, _) = failure {
                // A writer outside this lock may have replaced the token we
                // presented; its session is live, and deleting it would sign
                // both processes out. This refresh holds no live token.
                if case .replaced(let token) = try await recordCheck(expected: refreshToken, live: nil, discovered: discovered) {
                    return token
                }
                // Terminal (§4): the family is gone. Retrying costs rate-limit
                // budget and files warnings against the tenant — and if the
                // record cannot be deleted, it still reads as signed out.
                retired.insert(refreshToken)
                try? clearSession()
                throw ProtelesAuthError.signInRequired
            }
            return try fallBack(failure)
        }

        // The server spent `refreshToken` before it answered (§2.3): the new
        // one is the family's only live credential, so it is persisted as soon
        // as the body parses, before anything else in it is checked (§10.9
        // item 5). The previous access token stays with it — still good at
        // the server, and past half its life, so the next reader refreshes
        // again if this one goes no further. Only onto the record this refresh
        // started from, though: a sign-out or sign-in made meanwhile by a
        // writer outside this lock stands.
        var rotated = refreshToken
        if let next = answer.refreshToken {
            if case .replaced(let token) = try await recordCheck(expected: refreshToken, live: next, discovered: discovered) {
                return token
            }
            var pending = session
            pending.refreshToken = next
            try writeSession(pending) // `.storage` is raised, and the session not ended
            rotated = next
        }

        let response: TokenResponse
        do {
            response = try answer.checked()
        } catch {
            return try fallBack(asProtelesError(error))
        }

        var claims = session.claims
        var idToken = session.idToken
        if let raw = response.idToken {
            do {
                // The refresh grant mints no nonce, so the skip is explicit;
                // the at_hash binds the new access token. The device's clock
                // is not judged (§10.9 item 2).
                let verified = try await IDTokenVerifier.verify(
                    raw,
                    expecting: IDTokenExpectations(
                        issuer: configuration.issuer,
                        audience: configuration.clientId,
                        nonce: .skippedForRefreshGrant,
                        accessToken: response.accessToken,
                        now: now(),
                        judgesClock: false
                    ),
                    keys: discovered.keys
                )
                guard bytesEqual(verified.subject, session.subject) else {
                    throw ProtelesAuthError.idTokenRejected(.subjectChanged)
                }
                // Adopted only when this clock agrees with its times, as the
                // Android SDK does; either way the session goes on.
                if IDTokenVerifier.clockRejection(verified.claims, now: now()) == nil {
                    claims = verified.claims
                    idToken = raw
                }
            } catch ProtelesAuthError.idTokenRejected(let reason) {
                // Not to be trusted: the session ends at once (§10.9 item 1).
                // Every rejection is a verdict on the token; a key set that
                // cannot be used is `.network`, below.
                await abandon(rotated, discovered: discovered)
                throw ProtelesAuthError.idTokenRejected(reason)
            } catch {
                // The key set cannot be reached or used now (a 429 from it has
                // closed the gate). That says nothing against tokens the token
                // endpoint just handed this client over TLS: they are kept
                // with the previous claims, as the Android SDK does, and the
                // next refresh verifies again.
            }
        }

        var refreshed = session
        refreshed.refreshToken = rotated
        refreshed.accessToken = response.accessToken
        refreshed.accessTokenReceivedAt = requestedAt
        refreshed.accessTokenExpiresAt = requestedAt.addingTimeInterval(response.expiresIn)
        refreshed.idToken = idToken
        refreshed.claims = claims
        refreshed.scope = response.scope ?? session.scope
        // Persisted before it is returned (§4 "persist before you use").
        if case .replaced(let token) = try await recordCheck(expected: rotated, live: rotated, discovered: discovered) {
            return token
        }
        try writeSession(refreshed)
        refreshBackoff = nil
        return response.accessToken
    }

    /// A refresh that failed in a way that does not end the session (§10.3,
    /// §10.9 items 1 and 3): the stored token while it has not expired, and a
    /// backoff before the next attempt. A store that cannot be used is never
    /// softened.
    private func fallBack(_ failure: ProtelesAuthError) throws -> String {
        let at = now()
        if case .storage = failure { throw failure }
        let session = try? readSession()
        if let token = session?.unexpiredAccessToken(at: at) {
            if case .rateLimited = failure {
                // Waited out by the gate, which the 429 closed.
            } else if let session {
                let wait = min(Self.maximumRefreshBackoff, session.accessTokenExpiresAt.timeIntervalSince(at) / 2)
                if wait > 0 { refreshBackoff = Backoff(until: at.addingTimeInterval(wait), failure: failure) }
            }
            return token
        }
        throw failure
    }

    /// Ends a session that failed a trust rule: its refresh token is never
    /// presented again, the record is deleted if it is still this session's,
    /// and the family is revoked, best effort — as the Android SDK does.
    private func abandon(_ refreshToken: String, discovered: Discovered) async {
        retired.insert(refreshToken)
        if case .session(let current)? = try? readRecord(), let stored = current.refreshToken, bytesEqual(stored, refreshToken) {
            try? clearSession()
        }
        await revokeQuietly(refreshToken, discovered: discovered)
    }

    private enum RecordCheck {
        case unchanged
        /// Another writer replaced the record; hand out its token.
        case replaced(String)
    }

    /// Whether the stored record still holds `expected`, the token this
    /// refresh started from, before a refresh writes over it or deletes it.
    /// Inside the lock only a writer that could not take it can have changed
    /// it, so this is a check against the rare case; the Keychain has no
    /// compare-and-swap, which narrows the window to a read and a write rather
    /// than closing it.
    ///
    /// When it no longer does — a sign-out or sign-in made without the lock
    /// stands — `live`, the refresh token this refresh now holds, is held by
    /// nobody: it is retired and revoked, best effort, rather than left a
    /// thirty-day family, as the Android SDK does.
    ///
    /// - Throws: `.signInRequired` when the record is gone (signed out
    ///   elsewhere); `.network` when it was replaced and its token is not
    ///   usable either.
    private func recordCheck(expected: String, live: String?, discovered: Discovered) async throws -> RecordCheck {
        // A store that cannot be read now could be read a moment ago; carry on
        // and let the write report it, rather than lose the rotation.
        guard let record = try? readRecord() else { return .unchanged }
        let outcome: Result<RecordCheck, ProtelesAuthError>
        switch record {
        case .empty:
            outcome = .failure(.signInRequired)
        case .session(let current):
            if let stored = current.refreshToken, bytesEqual(stored, expected) { return .unchanged }
            if let token = current.unexpiredAccessToken(at: now()) {
                outcome = .success(.replaced(token))
            } else {
                outcome = .failure(.network("another process replaced the session during this refresh; retry"))
            }
        case .undecodable, .foreign:
            outcome = .failure(.network("another process replaced the session during this refresh; retry"))
        }
        if let live {
            retired.insert(live)
            await revokeQuietly(live, discovered: discovered)
        }
        return try outcome.get()
    }

    // MARK: - Sign out (§10.4)

    /// Clears the stored session, then revokes its refresh token (§10.9 item
    /// 6) — clearing it **whether or not revocation succeeds**, so a device
    /// that cannot reach the server can still sign out. The revocation's
    /// outcome is in the result, not hidden. Neither step is the caller's to
    /// cancel.
    ///
    /// The session is cleared under the refresh lock, so a refresh running in
    /// another process cannot write its rotation back over the deletion; if
    /// the lock cannot be taken (another process has held it past the
    /// timeout) it is cleared anyway.
    ///
    /// Pass `endSession` (from a user gesture) to also end the browser
    /// session at `end_session_endpoint`; without it the browser stays signed
    /// in and the next sign-in may not ask for credentials.
    ///
    /// - Throws: `.storage` when the session could not be cleared — its
    ///   refresh token was revoked all the same (the message says whether
    ///   that revocation succeeded), and this client will not present it
    ///   again; `.alreadyInProgress`, having done nothing, when `endSession`
    ///   is passed while a sign-in or end-session is running.
    @discardableResult
    public func signOut(endSession browser: (any AuthorizationBrowser)? = nil) async throws -> SignOutResult {
        let showsBrowser = browser != nil
        if showsBrowser {
            guard !browserFlowRunning else { throw ProtelesAuthError.alreadyInProgress }
            browserFlowRunning = true
        }
        defer { if showsBrowser { browserFlowRunning = false } }

        let signedOut = Task { await self.clearThenRevoke() }
        let (taken, revocation) = await signedOut.value
        if let failure = taken.clearFailure { throw Self.storageFailure(failure, revocation: revocation) }

        guard let browser else {
            return SignOutResult(revocation: revocation, endSession: .notRequested)
        }
        let endSession = await endBrowserSession(browser, idTokenHint: taken.idToken)
        return SignOutResult(revocation: revocation, endSession: endSession)
    }

    /// Clear, then revoke. Runs in a task of its own, so the caller's
    /// cancellation never reaches it.
    private func clearThenRevoke() async -> (TakenSession, SignOutResult.Revocation) {
        if let running = refreshTask { _ = try? await running.value }
        let taken: TakenSession
        switch await underLock({ await self.takeSession() }) {
        case .ran(let result):
            taken = (try? result.get()) ?? takeSession()
        case .unavailable:
            // A device must always be able to sign out (§10.4, §10.9 item 9).
            // A refresh in another process re-reads before each write and
            // finds nothing.
            taken = takeSession()
        }
        refreshBackoff = nil
        if let refreshToken = taken.refreshToken { retired.insert(refreshToken) }

        // The network only now, outside the lock, with the session already
        // gone from this device — or, if it could not be deleted, retired
        // here and about to be dead at the server (§10.9 item 6).
        return (taken, await revoke(taken))
    }

    /// What sign-out took from the store before deleting it.
    private struct TakenSession: Sendable {
        var refreshToken: String?
        var idToken: String?
        /// Why the refresh token could not be revoked, when a record was there
        /// but could not be read.
        var unrevocable: ProtelesAuthError?
        /// Why the record could not be deleted.
        var clearFailure: ProtelesAuthError?
    }

    /// The storage error sign-out raises when the record could not be
    /// deleted, carrying what became of the revocation that went ahead anyway
    /// (§10.9 item 6) — the Android SDK suppresses a failed revocation into
    /// the same error.
    private static func storageFailure(_ failure: ProtelesAuthError, revocation: SignOutResult.Revocation) -> ProtelesAuthError {
        guard case .storage(let message) = failure else { return failure }
        switch revocation {
        case .revoked:
            return .storage("\(message); the refresh token was revoked")
        case .notAttempted:
            return .storage("\(message); there was no refresh token to revoke")
        case .failed(let error):
            return .storage("\(message); revoking the refresh token failed too: \(error.localizedDescription)")
        }
    }

    /// Reads what sign-out needs, then deletes the record whatever the read
    /// found: a record that cannot be read still has to go.
    private func takeSession() -> TakenSession {
        let found: Result<Record, ProtelesAuthError>
        do {
            found = .success(try readRecord())
        } catch {
            found = .failure(Self.storageError(error))
        }
        var taken: TakenSession
        switch found {
        case .success(.empty), .success(.foreign):
            // Another configuration's session is not this client's to revoke:
            // its refresh token belongs to another issuer's endpoint. It is
            // deleted all the same — the person asked to sign out here.
            taken = TakenSession()
        case .success(.session(let session)):
            // Revoked even when this client knows it is dead (§10.9 item 6):
            // the server burns the whole family for any member presented,
            // spent ones included, and that also ends a family an earlier
            // revocation left alive by failing offline. Refreshing never
            // presents a dead token; signing out is the one place it should.
            taken = TakenSession(refreshToken: session.refreshToken, idToken: session.idToken)
        case .success(.undecodable(let data)):
            // Not this SDK's shape — perhaps a newer one's. Take the refresh
            // token by name if it is there, and only from a record that names
            // this configuration's issuer and client, so it goes to the
            // endpoint that issued it; otherwise say it was abandoned.
            let object = JSONValue.parseObject(data)
            let named = { (name: String, value: String) in
                object?[name]?.stringValue.map { bytesEqual($0, value) } ?? false
            }
            if named("issuer", configuration.issuer), named("clientId", configuration.clientId),
               let refreshToken = object?["refreshToken"]?.stringValue, !refreshToken.isEmpty {
                taken = TakenSession(refreshToken: refreshToken, idToken: object?["idToken"]?.stringValue)
            } else {
                taken = TakenSession(unrevocable: .storage(
                    "the stored session could not be decoded, so its refresh token could not be revoked"))
            }
        case .failure(let error):
            taken = TakenSession(unrevocable: .storage(
                "the stored session could not be read, so its refresh token could not be revoked: \(error.localizedDescription)"))
        }
        do {
            try clearSession()
        } catch {
            taken.clearFailure = Self.storageError(error)
        }
        return taken
    }

    private func revoke(_ taken: TakenSession) async -> SignOutResult.Revocation {
        if let unrevocable = taken.unrevocable { return .failed(unrevocable) }
        guard let refreshToken = taken.refreshToken else { return .notAttempted }
        do {
            let discovered = try await discover()
            try await revoke(refreshToken, discovered: discovered)
            return .revoked
        } catch {
            return .failed(asProtelesError(error))
        }
    }

    private func revoke(_ refreshToken: String, discovered: Discovered) async throws {
        guard let endpoint = discovered.document.revocationEndpoint else {
            throw ProtelesAuthError.configuration("discovery advertises no revocation_endpoint")
        }
        try await tokenClient.revoke(endpoint: endpoint, refreshToken: refreshToken)
    }

    /// Revocation whose failure there is no one to tell about.
    private func revokeQuietly(_ refreshToken: String, discovered: Discovered) async {
        try? await revoke(refreshToken, discovered: discovered)
    }

    private func endBrowserSession(_ browser: any AuthorizationBrowser, idTokenHint: String?) async -> SignOutResult.EndSession {
        do {
            let discovered = try await discover()
            guard let endpoint = discovered.document.endSessionEndpoint else {
                return .failed(.configuration("discovery advertises no end_session_endpoint"))
            }
            let state = try SecureRandom.token()
            guard let url = EndSessionRequest.url(
                endpoint: endpoint,
                idTokenHint: idTokenHint,
                clientId: configuration.clientId,
                postLogoutRedirectURI: configuration.postLogoutRedirectURI,
                state: state
            ) else {
                return .failed(.configuration("cannot build the end-session URL"))
            }
            let returnTo = configuration.postLogoutRedirectURL ?? configuration.redirectURL
            let callback = try await browser.open(url, redirectURI: returnTo)
            guard let expected = configuration.postLogoutRedirectURL else { return .completed }
            try AuthorizationCallback.checkEndSessionReturn(callback, redirectURI: expected, expectedState: state)
            return .completed
        } catch ProtelesAuthError.cancelled {
            return .dismissed
        } catch {
            return .failed(asProtelesError(error))
        }
    }

    // MARK: - The refresh lock

    private enum Locked<T: Sendable>: Sendable {
        /// The lock was taken and `body` ran, to this result.
        case ran(Result<T, ProtelesAuthError>)
        /// The lock could not be taken; `body` did not run.
        case unavailable(ProtelesAuthError)
    }

    /// `body` under the refresh lock, telling a lock that could not be taken
    /// apart from a `body` that failed — each caller has its own way to go on
    /// without the lock.
    private func underLock<T: Sendable>(_ body: @Sendable () async throws -> T) async -> Locked<T> {
        do {
            let result = try await lock.withLock { () async -> Result<T, ProtelesAuthError> in
                do {
                    return .success(try await body())
                } catch {
                    return .failure(asProtelesError(error))
                }
            }
            return .ran(result)
        } catch {
            return .unavailable(asProtelesError(error))
        }
    }

    // MARK: - Discovery (§10.2 step 1), cached for the life of the client

    private func discover() async throws -> Discovered {
        if let discovered { return discovered }
        if let running = discoveryTask { return try await running.value }
        let configuration = self.configuration
        let transport = self.transport
        let now = self.now
        let gate = self.gate
        let task = Task {
            let document = try await DiscoveryDocument.fetch(configuration, transport: transport, gate: gate)
            return Discovered(document: document, keys: JWKSCache(uri: document.jwksURI, transport: transport, now: now, gate: gate))
        }
        discoveryTask = task
        defer { discoveryTask = nil }
        let fetched = try await task.value
        if let discovered { return discovered }
        discovered = fetched
        return fetched
    }

    /// For tests: how many times the key set has been fetched.
    func keySetFetchCount() async -> Int {
        await discovered?.keys.fetchCount ?? 0
    }

    // MARK: - The stored record

    private enum Record {
        case empty
        /// A session written for this configuration's issuer and client.
        case session(StoredSession)
        /// A session written for another issuer or client that shares the
        /// Keychain service (§10.5 keys it by `clientId` alone).
        case foreign
        /// Bytes this SDK cannot decode — perhaps a newer SDK's record, or an
        /// older one's written before a session named its configuration.
        case undecodable(Data)
    }

    private func readRecord() throws -> Record {
        let data: Data?
        do {
            data = try store.read()
        } catch {
            throw Self.storageError(error)
        }
        guard let data else { return .empty }
        guard let session = try? StoredSession.decode(data) else { return .undecodable(data) }
        guard session.belongs(to: configuration) else { return .foreign }
        return .session(session)
    }

    /// This configuration's stored session, dead or alive, or `nil` when there
    /// is none.
    ///
    /// A record this SDK cannot read cannot be refreshed either: it is no
    /// session. Nor is a record for another issuer or client: it is never
    /// handed out, refreshed or revoked here. Either is left in place rather
    /// than deleted — it may be a newer SDK's, or another configuration's,
    /// written by another process of the same app — and the next sign-in or
    /// sign-out replaces it.
    private func readStored() throws -> StoredSession? {
        guard case .session(let session) = try readRecord() else { return nil }
        return session
    }

    /// The stored session this client can use: `readStored`, less a session
    /// whose refresh token this client knows is dead (§10.9 item 1). Only
    /// reads — the dead one is deleted under the lock (`endDeadSession`).
    private func readSession() throws -> StoredSession? {
        guard let session = try readStored(), !isDead(session) else { return nil }
        return session
    }

    /// Whether `session`'s refresh token is one this client knows is dead.
    private func isDead(_ session: StoredSession) -> Bool {
        session.refreshToken.map { retired.contains($0) } ?? false
    }

    private func writeSession(_ session: StoredSession) throws {
        do {
            try store.write(session.encoded())
        } catch {
            throw Self.storageError(error)
        }
    }

    private func clearSession() throws {
        do {
            try store.delete()
        } catch {
            throw Self.storageError(error)
        }
    }

    private static func storageError(_ error: any Error) -> ProtelesAuthError {
        if let error = error as? ProtelesAuthError, case .storage = error { return error }
        return .storage(String(describing: error))
    }
}

/// A refresh failure the client is waiting out.
private struct Backoff: Sendable {
    let until: Date
    let failure: ProtelesAuthError
}
