import CryptoKit
import Foundation
import Security
@testable import ProtelesAuth

// Everything the tests stand in for: the server (a stub transport), the user
// (a stub browser), the clock, the Keychain, and the server's signing key.

enum Fixture {
    static let issuer = "https://auth.example.test"
    static let clientId = "com.example.mobile"
    static let redirectURI = "https://mobile.example.com/oauth/callback"
    static let postLogoutRedirectURI = "https://mobile.example.com/oauth/signed-out"
    static let subject = "user-1"
    static let t0 = Date(timeIntervalSince1970: 1_800_000_000)

    static func configuration(
        issuer: String = issuer,
        postLogoutRedirectURI: String? = nil,
        appGroupIdentifier: String? = nil
    ) throws -> ProtelesConfiguration {
        try ProtelesConfiguration(
            issuer: issuer,
            clientId: clientId,
            redirectURI: redirectURI,
            postLogoutRedirectURI: postLogoutRedirectURI,
            appGroupIdentifier: appGroupIdentifier
        )
    }
}

// MARK: - Clock

final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var current: Date

    init(_ start: Date = Fixture.t0) { current = start }

    var now: Date {
        lock.lock()
        defer { lock.unlock() }
        return current
    }

    func advance(_ seconds: TimeInterval) {
        lock.lock()
        defer { lock.unlock() }
        current = current.addingTimeInterval(seconds)
    }

    var function: @Sendable () -> Date { { [self] in self.now } }
}

// MARK: - The server's signing key

/// An RSA key generated for this test run, and ID tokens signed with it.
final class TestSigner: @unchecked Sendable {
    static let shared = TestSigner(kid: "test-key-1")
    static let rotated = TestSigner(kid: "test-key-2")

    let kid: String
    let privateKey: SecKey
    let publicKeyDER: Data
    let n: String
    let e: String

    init(kid: String) {
        self.kid = kid
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: 2048,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
              let publicKey = SecKeyCopyPublicKey(key),
              let der = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            fatalError("cannot generate a test RSA key: \(String(describing: error?.takeRetainedValue()))")
        }
        privateKey = key
        publicKeyDER = der
        let (modulus, exponent) = TestDER.rsaPublicKeyComponents(der)
        n = Base64URL.encode(modulus)
        e = Base64URL.encode(exponent)
    }

    var jwk: JSONValue {
        .object(["kty": .string("RSA"), "kid": .string(kid), "use": .string("sig"), "alg": .string("RS256"), "n": .string(n), "e": .string(e)])
    }

    static func jwks(_ signers: TestSigner...) -> Data {
        encode(.object(["keys": .array(signers.map(\.jwk))]))
    }

    func sign(_ claims: [String: JSONValue], header: [String: JSONValue]? = nil) -> String {
        let header = header ?? ["alg": .string("RS256"), "typ": .string("JWT"), "kid": .string(kid)]
        let input = Base64URL.encode(Self.encode(.object(header))) + "." + Base64URL.encode(Self.encode(.object(claims)))
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, .rsaSignatureMessagePKCS1v15SHA256, Data(input.utf8) as CFData, &error) as Data? else {
            fatalError("cannot sign: \(String(describing: error?.takeRetainedValue()))")
        }
        return input + "." + Base64URL.encode(signature)
    }

    /// An ID token as this server mints one.
    func idToken(
        nonce: String?,
        accessToken: String?,
        subject: String = Fixture.subject,
        issuedAt: Date = Fixture.t0,
        lifetime: TimeInterval = 900
    ) -> String {
        var claims: [String: JSONValue] = [
            "iss": .string(Fixture.issuer),
            "sub": .string(subject),
            "aud": .string(Fixture.clientId),
            "exp": .number(issuedAt.timeIntervalSince1970 + lifetime),
            "iat": .number(issuedAt.timeIntervalSince1970),
            "auth_time": .number(issuedAt.timeIntervalSince1970),
            "email": .string("user-1@example.test"),
            "email_verified": .bool(true),
            "amr": .array([.string("pwd")]),
        ]
        if let nonce { claims["nonce"] = .string(nonce) }
        if let accessToken { claims["at_hash"] = .string(IDTokenVerifier.atHash(accessToken)) }
        return sign(claims)
    }

    static func encode(_ value: JSONValue) -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try! encoder.encode(value)
    }
}

/// Just enough DER reading to take `n` and `e` out of a PKCS#1 RSAPublicKey.
enum TestDER {
    static func rsaPublicKeyComponents(_ der: Data) -> (Data, Data) {
        let bytes = [UInt8](der)
        var index = 0
        func expect(_ tag: UInt8) {
            precondition(bytes[index] == tag, "unexpected DER tag")
            index += 1
        }
        func length() -> Int {
            let first = bytes[index]
            index += 1
            if first < 0x80 { return Int(first) }
            var value = 0
            for _ in 0..<Int(first & 0x7F) {
                value = value << 8 | Int(bytes[index])
                index += 1
            }
            return value
        }
        func integer() -> Data {
            expect(0x02)
            let count = length()
            let value = Data(bytes[index..<index + count].drop(while: { $0 == 0 }))
            index += count
            return value
        }
        expect(0x30)
        _ = length()
        return (integer(), integer())
    }
}

// MARK: - The server

/// A stub transport routing by path, recording every request.
final class StubServer: HTTPTransport, @unchecked Sendable {
    typealias Handler = @Sendable (HTTPRequest) async throws -> HTTPResponse

    private let lock = NSLock()
    private var handlers: [String: Handler] = [:]
    private var recorded: [HTTPRequest] = []

    init(issuer: String = Fixture.issuer, discoveryIssuer: String? = nil, signers: [TestSigner] = [TestSigner.shared]) {
        let document: JSONValue = .object([
            "issuer": .string(discoveryIssuer ?? issuer),
            "authorization_endpoint": .string("\(issuer)/oauth/authorize"),
            "token_endpoint": .string("\(issuer)/oauth/token"),
            "jwks_uri": .string("\(issuer)/.well-known/jwks.json"),
            "revocation_endpoint": .string("\(issuer)/oauth/revoke"),
            "end_session_endpoint": .string("\(issuer)/oauth/logout"),
            "authorization_response_iss_parameter_supported": .bool(true),
            "code_challenge_methods_supported": .array([.string("S256")]),
        ])
        let jwks = TestSigner.encode(.object(["keys": .array(signers.map(\.jwk))]))
        on("/.well-known/openid-configuration") { _ in .json(document) }
        on("/.well-known/jwks.json") { _ in HTTPResponse(status: 200, headers: ["Content-Type": "application/json"], body: jwks) }
        on("/oauth/revoke") { _ in HTTPResponse(status: 200) }
    }

    func on(_ path: String, _ handler: @escaping Handler) {
        lock.lock()
        defer { lock.unlock() }
        handlers[path] = handler
    }

    var requests: [HTTPRequest] {
        lock.lock()
        defer { lock.unlock() }
        return recorded
    }

    func requests(to path: String) -> [HTTPRequest] { requests.filter { $0.url.path == path } }

    func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        let handler: Handler? = {
            lock.lock()
            defer { lock.unlock() }
            recorded.append(request)
            return handlers[request.url.path]
        }()
        guard let handler else { return HTTPResponse(status: 404) }
        return try await handler(request)
    }
}

extension HTTPResponse {
    static func json(_ value: JSONValue, status: Int = 200, headers: [String: String] = [:]) -> HTTPResponse {
        HTTPResponse(status: status, headers: headers.merging(["Content-Type": "application/json"]) { a, _ in a }, body: TestSigner.encode(value))
    }

    static func tokens(access: String, refresh: String?, idToken: String?, expiresIn: Double = 900) -> HTTPResponse {
        var body: [String: JSONValue] = [
            "access_token": .string(access),
            "token_type": .string("Bearer"),
            "expires_in": .number(expiresIn),
            "scope": .string("openid profile email"),
        ]
        if let refresh { body["refresh_token"] = .string(refresh) }
        if let idToken { body["id_token"] = .string(idToken) }
        return .json(.object(body))
    }

    static func oauthError(_ error: String, description: String? = nil, status: Int = 400, headers: [String: String] = [:]) -> HTTPResponse {
        var body: [String: JSONValue] = ["error": .string(error)]
        if let description { body["error_description"] = .string(description) }
        return .json(.object(body), status: status, headers: headers)
    }
}

extension HTTPRequest {
    /// The form fields as a dictionary; fails the lookup on a repeated name.
    var form: [String: String] {
        Dictionary(formFields.map { ($0.name, $0.value) }, uniquingKeysWith: { _, _ in "<repeated>" })
    }

    var query: [String: String] {
        let query = URLComponents(url: url, resolvingAgainstBaseURL: false)?.percentEncodedQuery ?? ""
        return Dictionary(FormEncoding.decode(query).map { ($0.name, $0.value) }, uniquingKeysWith: { _, _ in "<repeated>" })
    }
}

func queryItems(of url: URL) -> [(name: String, value: String)] {
    FormEncoding.decode(URLComponents(url: url, resolvingAgainstBaseURL: false)?.percentEncodedQuery ?? "")
}

// MARK: - The user

/// Stands in for `ASWebAuthenticationSession`: hands the URL to a closure that
/// plays the server and the user, and returns what it returns.
final class StubBrowser: AuthorizationBrowser, @unchecked Sendable {
    typealias Behaviour = @Sendable (URL) throws -> URL
    private let lock = NSLock()
    private var opened: [URL] = []
    private let behaviour: Behaviour

    init(_ behaviour: @escaping Behaviour) {
        self.behaviour = behaviour
    }

    var openedURLs: [URL] {
        lock.lock()
        defer { lock.unlock() }
        return opened
    }

    @MainActor
    func open(_ url: URL, redirectURI: URL) async throws -> URL {
        record(url)
        return try behaviour(url)
    }

    private func record(_ url: URL) {
        lock.lock()
        defer { lock.unlock() }
        opened.append(url)
    }

    /// A user who signs in: the server redirects back with a code, the state
    /// it was sent, and its issuer.
    static func signsIn(code: String = "code-1", issuer: String? = Fixture.issuer, state override: String? = nil) -> StubBrowser {
        StubBrowser { url in
            let query = Dictionary(queryItems(of: url).map { ($0.name, $0.value) }, uniquingKeysWith: { a, _ in a })
            var fields = [("code", code), ("state", override ?? query["state"] ?? "")]
            if let issuer { fields.append(("iss", issuer)) }
            return URL(string: "\(Fixture.redirectURI)?\(FormEncoding.encode(fields))")!
        }
    }

    static func cancels() -> StubBrowser {
        StubBrowser { _ in throw ProtelesAuthError.cancelled }
    }
}

/// Plays the token endpoint for a sign-in: checks PKCE against the challenge
/// the browser carried, and mints an ID token bound to the nonce the browser
/// carried and the access token it returns.
final class SignInServer: @unchecked Sendable {
    let server: StubServer
    private let lock = NSLock()
    private var challenge: String?
    private var nonce: String?
    var idTokenNonceOverride: String?
    /// Runs inside the token request before it answers — to hold it open, or
    /// to see whether the task running it was cancelled.
    let exchangeHook = Recorded<(@Sendable () async throws -> Void)?>(nil)

    init(server: StubServer = StubServer()) {
        self.server = server
        server.on("/oauth/token") { [unowned self] request in
            let form = request.form
            guard form["grant_type"] == "authorization_code" else { return .oauthError("unsupported_grant_type") }
            try await self.exchangeHook.value?()
            let (challenge, nonce, override) = self.flow()
            guard let verifier = form["code_verifier"], PKCE.challenge(for: verifier) == challenge else {
                return .oauthError("invalid_grant", description: "PKCE verification failed")
            }
            let access = "at-1"
            let idToken = TestSigner.shared.idToken(nonce: override ?? nonce, accessToken: access)
            return .tokens(access: access, refresh: "rt-1", idToken: idToken)
        }
    }

    /// The browser for this server: records what the authorization request
    /// carried, then signs in.
    func browser(_ then: StubBrowser = .signsIn()) -> StubBrowser {
        StubBrowser { [unowned self] url in
            let query = Dictionary(queryItems(of: url).map { ($0.name, $0.value) }, uniquingKeysWith: { a, _ in a })
            self.record(challenge: query["code_challenge"], nonce: query["nonce"])
            return try then.behaviourForTests(url)
        }
    }

    private func record(challenge: String?, nonce: String?) {
        lock.lock()
        defer { lock.unlock() }
        self.challenge = challenge
        self.nonce = nonce
    }

    private func flow() -> (String?, String?, String?) {
        lock.lock()
        defer { lock.unlock() }
        return (challenge, nonce, idTokenNonceOverride)
    }
}

extension StubBrowser {
    func behaviourForTests(_ url: URL) throws -> URL { try behaviour(url) }
}

// MARK: - The Keychain

/// An in-memory store that records every write, and can be told to fail.
final class SpyStore: TokenStore, @unchecked Sendable {
    private let lock = NSLock()
    private var data: Data?
    private(set) var writes: [StoredSession] = []
    var failReads = false
    var failDeletes = false
    /// Fail the write whose 1-based index is in this set.
    var failWrites: Set<Int> = []
    private var writeCount = 0

    init(_ session: StoredSession? = nil) {
        data = try! session?.encoded()
    }

    func read() throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        if failReads { throw ProtelesAuthError.storage("simulated: Keychain unavailable before first unlock") }
        return data
    }

    func write(_ data: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        writeCount += 1
        if failWrites.contains(writeCount) { throw ProtelesAuthError.storage("simulated write failure") }
        self.data = data
        writes.append(try StoredSession.decode(data))
    }

    func delete() throws {
        lock.lock()
        defer { lock.unlock() }
        if failDeletes { throw ProtelesAuthError.storage("simulated delete failure") }
        data = nil
    }

    var session: StoredSession? {
        lock.lock()
        defer { lock.unlock() }
        return try! data.map(StoredSession.decode)
    }
}

extension StoredSession {
    /// A signed-in session as `signIn` would have stored it at `receivedAt`.
    static func signedIn(
        at receivedAt: Date = Fixture.t0,
        accessToken: String = "at-1",
        refreshToken: String? = "rt-1",
        expiresIn: TimeInterval = 900
    ) -> StoredSession {
        let idToken = TestSigner.shared.idToken(nonce: "n", accessToken: accessToken, issuedAt: receivedAt)
        return StoredSession(
            issuer: Fixture.issuer,
            clientId: Fixture.clientId,
            refreshToken: refreshToken,
            accessToken: accessToken,
            accessTokenReceivedAt: receivedAt,
            accessTokenExpiresAt: receivedAt.addingTimeInterval(expiresIn),
            idToken: idToken,
            claims: [
                "iss": .string(Fixture.issuer),
                "sub": .string(Fixture.subject),
                "aud": .string(Fixture.clientId),
                "email": .string("user-1@example.test"),
            ],
            scope: "openid profile email"
        )
    }
}

/// A lock file in a fresh temporary directory.
func temporaryLockURL() -> URL {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("protelesauth-tests-\(UUID().uuidString)", isDirectory: true)
    try! FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    return directory.appendingPathComponent("refresh.lock")
}

/// A client wired to stubs, with a unique in-process lock key so parallel
/// tests never contend.
func makeClient(
    server: StubServer,
    store: any TokenStore,
    clock: TestClock = TestClock(),
    configuration: ProtelesConfiguration? = nil,
    lock: (any RefreshLock)? = nil,
    backgroundActivity: any BackgroundActivity = ManualActivity()
) throws -> ProtelesClient {
    try ProtelesClient(
        configuration: configuration ?? Fixture.configuration(),
        transport: server,
        store: store,
        lock: lock ?? InProcessRefreshLock(key: UUID().uuidString),
        now: clock.function,
        backgroundActivity: backgroundActivity
    )
}

// MARK: - Locks, background time, and waiting

/// A lock that counts how often it is taken.
final class CountingLock: RefreshLock, @unchecked Sendable {
    private let inner: any RefreshLock
    private let lock = NSLock()
    private var taken = 0

    init(_ inner: any RefreshLock = InProcessRefreshLock(key: UUID().uuidString)) {
        self.inner = inner
    }

    var acquisitions: Int {
        lock.lock()
        defer { lock.unlock() }
        return taken
    }

    func withLock<T: Sendable>(_ body: @Sendable () async throws -> T) async throws -> T {
        try await inner.withLock {
            self.count()
            return try await body()
        }
    }

    private func count() {
        lock.lock()
        defer { lock.unlock() }
        taken += 1
    }
}

/// A lock that can never be taken — as a timeout, a lock file that cannot be
/// opened, or a cancelled wait looks to the client.
struct UnavailableLock: RefreshLock {
    let error: ProtelesAuthError
    init(_ error: ProtelesAuthError = .network("timed out after 60 s waiting for another process's refresh")) {
        self.error = error
    }
    func withLock<T: Sendable>(_ body: @Sendable () async throws -> T) async throws -> T {
        throw error
    }
}

/// Another process holding the lock file: `flock` on a descriptor of its own.
final class HeldLockFile: @unchecked Sendable {
    private var fd: Int32

    init(_ url: URL) {
        fd = open(url.path, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        precondition(fd >= 0 && flock(fd, LOCK_EX) == 0, "cannot hold the test lock file")
    }

    func release() {
        guard fd >= 0 else { return }
        flock(fd, LOCK_UN)
        close(fd)
        fd = -1
    }

    deinit { release() }
}

/// Background time the test ends by hand, standing in for the system saying
/// the process is about to be suspended.
final class ManualActivity: BackgroundActivity, @unchecked Sendable {
    private let lock = NSLock()
    private var handlers: [@Sendable () -> Void] = []
    private var begun = 0
    private var ended = 0

    func begin(reason: String, expire: @escaping @Sendable () -> Void) -> @Sendable () -> Void {
        lock.lock()
        defer { lock.unlock() }
        begun += 1
        handlers.append(expire)
        return { self.end() }
    }

    private func end() {
        lock.lock()
        defer { lock.unlock() }
        ended += 1
    }

    /// The system is about to suspend the process.
    func expire() {
        lock.lock()
        let pending = handlers
        handlers = []
        lock.unlock()
        pending.forEach { $0() }
    }

    var counts: (begun: Int, ended: Int) {
        lock.lock()
        defer { lock.unlock() }
        return (begun, ended)
    }
}

/// A one-way gate: `wait` returns once `open` has been called.
final class Gate: @unchecked Sendable {
    private let lock = NSLock()
    private var isOpen = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func open() {
        lock.lock()
        isOpen = true
        let waiting = waiters
        waiters = []
        lock.unlock()
        waiting.forEach { $0.resume() }
    }

    func wait() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            lock.lock()
            if isOpen {
                lock.unlock()
                continuation.resume()
            } else {
                waiters.append(continuation)
                lock.unlock()
            }
        }
    }

    var opened: Bool {
        lock.lock()
        defer { lock.unlock() }
        return isOpen
    }
}

/// A value set from a stub handler and read by the test.
final class Recorded<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Value

    init(_ value: Value) { stored = value }

    var value: Value {
        get {
            lock.lock()
            defer { lock.unlock() }
            return stored
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            stored = newValue
        }
    }
}

/// A browser the test holds open: it says when it is showing, and returns
/// what `then` returns once the test lets it.
final class GatedBrowser: AuthorizationBrowser, @unchecked Sendable {
    let showing = Gate()
    let release = Gate()
    private let then: StubBrowser

    init(then: StubBrowser) {
        self.then = then
    }

    @MainActor
    func open(_ url: URL, redirectURI: URL) async throws -> URL {
        showing.open()
        await release.wait()
        return try then.behaviourForTests(url)
    }
}

/// A lock that says, through `held`, when a body is running under it.
struct FlaggingLock: RefreshLock {
    let held: Recorded<Bool>
    private let inner = InProcessRefreshLock(key: UUID().uuidString)

    init(_ held: Recorded<Bool>) {
        self.held = held
    }

    func withLock<T: Sendable>(_ body: @Sendable () async throws -> T) async throws -> T {
        try await inner.withLock {
            held.value = true
            defer { held.value = false }
            return try await body()
        }
    }
}

/// A store that records, for every delete, whether `held` said the lock was
/// held at the time.
final class WitnessStore: TokenStore, @unchecked Sendable {
    private let inner: SpyStore
    private let held: Recorded<Bool>
    private let recorded = Recorded<[Bool]>([])

    init(_ inner: SpyStore, held: Recorded<Bool>) {
        self.inner = inner
        self.held = held
    }

    var deletes: [Bool] { recorded.value }

    func read() throws -> Data? { try inner.read() }
    func write(_ data: Data) throws { try inner.write(data) }
    func delete() throws {
        try inner.delete()
        recorded.value.append(held.value)
    }
}
