import Foundation
import Testing
@testable import ProtelesAuth

@Suite("The key set (§5 step 2, §5.2 rule 7)")
struct KeySetTests {
    private let jwksURL = URL(string: "https://auth.example.test/.well-known/jwks.json")!

    private func expectations(now: Date = Fixture.t0) -> IDTokenExpectations {
        IDTokenExpectations(issuer: Fixture.issuer, audience: Fixture.clientId, nonce: .required("n"), accessToken: "at", now: now)
    }

    private func token(_ signer: TestSigner) -> String {
        signer.idToken(nonce: "n", accessToken: "at")
    }

    /// A JWKS endpoint that answers after `delay`, counting its fetches, and
    /// publishes whatever `keys` says at the time.
    final class KeyServer: HTTPTransport, @unchecked Sendable {
        private let lock = NSLock()
        private var _fetches = 0
        var response: @Sendable () -> HTTPResponse
        let delay: UInt64

        init(delay: UInt64 = 0, _ response: @escaping @Sendable () -> HTTPResponse) {
            self.delay = delay
            self.response = response
        }

        var fetches: Int {
            lock.lock()
            defer { lock.unlock() }
            return _fetches
        }

        func send(_ request: HTTPRequest) async throws -> HTTPResponse {
            let response = count()
            if delay > 0 { try await Task.sleep(nanoseconds: delay) }
            return response()
        }

        private func count() -> @Sendable () -> HTTPResponse {
            lock.lock()
            defer { lock.unlock() }
            _fetches += 1
            return response
        }
    }

    @Test("concurrent verifications against an empty cache collapse into ONE fetch")
    func concurrentRefreshesCollapse() async throws {
        let jwks = TestSigner.jwks(.shared)
        let server = KeyServer(delay: 200_000_000) { HTTPResponse(status: 200, body: jwks) }
        let cache = JWKSCache(uri: jwksURL, transport: server, now: { Fixture.t0 })
        let token = token(.shared)
        let expectations = expectations()
        let subjects = try await withThrowingTaskGroup(of: String.self) { group in
            for _ in 0..<25 {
                group.addTask { try await IDTokenVerifier.verify(token, expecting: expectations, keys: cache).subject }
            }
            return try await group.reduce(into: [String]()) { $0.append($1) }
        }
        #expect(subjects.count == 25 && Set(subjects) == [Fixture.subject])
        #expect(server.fetches == 1)
        #expect(await cache.fetchCount == 1)
    }

    @Test("an unknown kid refreshes the set — that is what a rotation looks like")
    func unknownKidRefreshes() async throws {
        let before = TestSigner.jwks(.shared)
        let after = TestSigner.jwks(.shared, .rotated)
        let rotated = Counter()
        let server = KeyServer { rotated.next() == 1 ? HTTPResponse(status: 200, body: before) : HTTPResponse(status: 200, body: after) }
        let cache = JWKSCache(uri: jwksURL, transport: server, now: { Fixture.t0 })

        _ = try await IDTokenVerifier.verify(token(.shared), expecting: expectations(), keys: cache)
        _ = try await IDTokenVerifier.verify(token(.shared), expecting: expectations(), keys: cache)
        #expect(server.fetches == 1, "a known kid inside the cache's age is not refetched")
        _ = try await IDTokenVerifier.verify(token(.rotated), expecting: expectations(), keys: cache)
        #expect(server.fetches == 2)
    }

    @Test("a kid still unknown after the refresh is refused")
    func unknownAfterRefresh() async throws {
        let jwks = TestSigner.jwks(.shared)
        let server = KeyServer { HTTPResponse(status: 200, body: jwks) }
        let cache = JWKSCache(uri: jwksURL, transport: server, now: { Fixture.t0 })
        await #expect(throws: ProtelesAuthError.idTokenRejected(.noUsableKey)) {
            _ = try await IDTokenVerifier.verify(token(.rotated), expecting: expectations(), keys: cache)
        }
    }

    @Test("a failed refresh falls back to a stale key that is still present")
    func staleFallback() async throws {
        let jwks = TestSigner.jwks(.shared)
        let healthy = Counter()
        let server = KeyServer { healthy.next() == 1 ? HTTPResponse(status: 200, body: jwks) : HTTPResponse(status: 503) }
        let clock = TestClock()
        let cache = JWKSCache(uri: jwksURL, transport: server, now: clock.function, maxAge: 60)
        _ = try await IDTokenVerifier.verify(token(.shared), expecting: expectations(), keys: cache)
        clock.advance(120) // past the cache's age: a refetch is attempted and fails
        _ = try await IDTokenVerifier.verify(token(.shared), expecting: expectations(now: clock.now), keys: cache)
        #expect(server.fetches == 2)
        // …but an unknown kid has nothing to fall back to.
        await #expect(throws: ProtelesAuthError.self) {
            _ = try await IDTokenVerifier.verify(token(.rotated), expecting: expectations(now: clock.now), keys: cache)
        }
    }

    @Test("a document with no usable key is an error, and the cache keeps what it had")
    func noUsableKey() async throws {
        let good = TestSigner.jwks(.shared)
        var encryptionOnly = TestSigner.shared.jwk.objectValue!
        encryptionOnly["use"] = .string("enc")
        let bad = TestSigner.encode(.object(["keys": .array([.object(encryptionOnly)])]))
        let calls = Counter()
        let server = KeyServer { calls.next() == 1 ? HTTPResponse(status: 200, body: bad) : HTTPResponse(status: 200, body: good) }
        let cache = JWKSCache(uri: jwksURL, transport: server, now: { Fixture.t0 })
        do {
            _ = try await IDTokenVerifier.verify(token(.shared), expecting: expectations(), keys: cache)
            Issue.record("expected a network error")
        } catch ProtelesAuthError.network(let message, let status) {
            #expect(message.contains("no usable RS256 signing key"))
            #expect(status == nil)
        }
        _ = try await IDTokenVerifier.verify(token(.shared), expecting: expectations(), keys: cache)
    }

    @Test(
        "a key set that answers with anything but 200 is the network error, carrying the status — never a verdict on the token",
        arguments: [301, 403, 404, 500, 503]
    )
    func anErrorAnswer(_ status: Int) async throws {
        let server = KeyServer { HTTPResponse(status: status) }
        let cache = JWKSCache(uri: jwksURL, transport: server, now: { Fixture.t0 })
        do {
            _ = try await IDTokenVerifier.verify(token(.shared), expecting: expectations(), keys: cache)
            Issue.record("expected a network error")
        } catch ProtelesAuthError.network(_, let answered) {
            #expect(answered == status)
        }
    }

    @Test("a key set that is not a JSON object is the network error")
    func notJSON() async throws {
        let server = KeyServer { HTTPResponse(status: 200, body: Data("<html>login</html>".utf8)) }
        let cache = JWKSCache(uri: jwksURL, transport: server, now: { Fixture.t0 })
        do {
            _ = try await IDTokenVerifier.verify(token(.shared), expecting: expectations(), keys: cache)
            Issue.record("expected a network error")
        } catch ProtelesAuthError.network(let message, let status) {
            #expect(message.contains("not a JSON object"))
            #expect(status == nil)
        }
    }

    @Test("a fetched set is trusted for ten minutes, then fetched again, as the Android SDK's is")
    func tenMinutes() async throws {
        #expect(JWKSCache.defaultMaxAge == 600)
        let jwks = TestSigner.jwks(.shared)
        let server = KeyServer { HTTPResponse(status: 200, body: jwks) }
        let clock = TestClock()
        let cache = JWKSCache(uri: jwksURL, transport: server, now: clock.function)
        _ = try await IDTokenVerifier.verify(token(.shared), expecting: expectations(now: clock.now), keys: cache)
        clock.advance(599)
        _ = try await IDTokenVerifier.verify(token(.shared), expecting: expectations(now: clock.now), keys: cache)
        #expect(server.fetches == 1)
        clock.advance(1)
        _ = try await IDTokenVerifier.verify(token(.shared), expecting: expectations(now: clock.now), keys: cache)
        #expect(server.fetches == 2, "a key the issuer withdrew stops verifying within ten minutes")
    }

    @Test("a 429 from the key set is rate limiting, with its Retry-After — not a key-set failure")
    func rateLimited() async throws {
        let server = KeyServer { HTTPResponse(status: 429, headers: ["Retry-After": "30"]) }
        let cache = JWKSCache(uri: jwksURL, transport: server, now: { Fixture.t0 })
        await #expect(throws: ProtelesAuthError.rateLimited(retryAfter: 30)) {
            _ = try await IDTokenVerifier.verify(token(.shared), expecting: expectations(), keys: cache)
        }
    }

    @Test("a 5xx from the key set is the network error, carrying the status (§10.9 item 4)")
    func anOutage() async throws {
        let server = KeyServer { HTTPResponse(status: 503) }
        let cache = JWKSCache(uri: jwksURL, transport: server, now: { Fixture.t0 })
        do {
            _ = try await IDTokenVerifier.verify(token(.shared), expecting: expectations(), keys: cache)
            Issue.record("expected a network error")
        } catch ProtelesAuthError.network(_, let status) {
            #expect(status == 503)
        }
    }

    @Test("an RSA key below 2048 bits, or with an exponent below three or even, is not a verification key (§5.2)")
    func soundKeysOnly() {
        let exactly2048 = Data([0x80] + [UInt8](repeating: 0x01, count: 255))
        let bits2047 = Data([0x7F] + [UInt8](repeating: 0x01, count: 255))
        let paddedTo2040 = Data([0x00] + [UInt8](repeating: 0xFF, count: 255))
        let f4 = Data([0x01, 0x00, 0x01])
        #expect(RSAVerificationKey.isSound(modulus: exactly2048, exponent: f4))
        #expect(!RSAVerificationKey.isSound(modulus: bits2047, exponent: f4))
        #expect(!RSAVerificationKey.isSound(modulus: paddedTo2040, exponent: f4), "leading zero bytes are not bits")
        #expect(!RSAVerificationKey.isSound(modulus: Data(), exponent: f4))
        for (exponent, sound) in [
            ([], false), ([0x00], false), ([0x01], false), ([0x02], false),
            ([0x03], true), ([0x00, 0x03], true), ([0x01, 0x00], false), ([0x01, 0x01], true),
        ] as [([UInt8], Bool)] {
            #expect(RSAVerificationKey.isSound(modulus: exactly2048, exponent: Data(exponent)) == sound, "e = \(exponent)")
        }
        // Through the JWK filter, with a real modulus.
        let base = TestSigner.shared.jwk.objectValue!
        func jwk(kid: String, e: String) -> JSONValue {
            var jwk = base
            jwk["kid"] = .string(kid)
            jwk["e"] = .string(e)
            return .object(jwk)
        }
        let set = JSONWebKeySet(json: .object(["keys": .array([
            jwk(kid: "e1", e: "AQ"), jwk(kid: "e2", e: "Ag"), jwk(kid: "e3", e: "Aw"), jwk(kid: "f4", e: "AQAB"),
        ])]))
        #expect(set.keys.map(\.kid) == ["e3", "f4"])
    }

    @Test func theFilterKeepsOnlyRS256SigningKeys() {
        let base = TestSigner.shared.jwk.objectValue!
        func with(_ changes: [String: JSONValue?]) -> JSONValue {
            var jwk = base
            for (key, value) in changes { jwk[key] = value } // nil removes the member
            return .object(jwk)
        }
        let set = JSONWebKeySet(json: .object(["keys": .array([
            with(["kid": .string("ok")]),
            with(["kid": .string("no-use-no-alg"), "use": nil, "alg": nil]),
            with(["kid": .string("enc"), "use": .string("enc")]),
            with(["kid": .string("rs512"), "alg": .string("RS512")]),
            with(["kid": .string("ec"), "kty": .string("EC")]),
            with(["kid": .string("null-use"), "use": .null]),
            with(["kid": .string("bad-n"), "n": .string("not base64url!")]),
            with(["kid": nil]),
        ])]))
        #expect(set.keys.map(\.kid) == ["ok", "no-use-no-alg"])
    }
}

@Suite("The refresh lock (§10.6)")
struct LockTests {
    /// Records whether two critical sections ever overlapped.
    actor Overlap {
        private var inside = 0
        private(set) var maximum = 0
        func enter() {
            inside += 1
            maximum = max(maximum, inside)
        }
        func leave() { inside -= 1 }
    }

    private func contend(_ locks: [any RefreshLock]) async throws -> Int {
        let overlap = Overlap()
        try await withThrowingTaskGroup(of: Void.self) { group in
            for (index, lock) in locks.enumerated() {
                group.addTask {
                    try await lock.withLock {
                        await overlap.enter()
                        try await Task.sleep(nanoseconds: 30_000_000 + UInt64(index) * 1_000_000)
                        await overlap.leave()
                    }
                }
            }
            try await group.waitForAll()
        }
        return await overlap.maximum
    }

    @Test("flock excludes separate descriptors on one file, as it does separate processes")
    func fileLockExcludes() async throws {
        let url = temporaryLockURL()
        let maximum = try await contend((0..<6).map { _ in FileRefreshLock(url: url) })
        #expect(maximum == 1)
    }

    @Test func inProcessLockExcludesAcrossClientsWithOneKey() async throws {
        let key = UUID().uuidString
        let maximum = try await contend((0..<6).map { _ in InProcessRefreshLock(key: key) })
        #expect(maximum == 1)
    }

    @Test func aLockIsReleasedWhenTheBodyThrows() async throws {
        let url = temporaryLockURL()
        struct Boom: Error {}
        await #expect(throws: Boom.self) {
            try await FileRefreshLock(url: url).withLock { throw Boom() }
        }
        let value = try await FileRefreshLock(url: url, timeout: 1).withLock { 42 }
        #expect(value == 42)
    }

    #if os(macOS)
    /// Another process holding the lock file: this process gives up after its
    /// timeout, and otherwise waits until the other process lets go. The
    /// holder releases only when told to, so nothing here depends on timing.
    @Test("a real second process holding the lock is waited for")
    func anotherProcess() async throws {
        let url = temporaryLockURL()
        let directory = url.deletingLastPathComponent()
        let held = directory.appendingPathComponent("held")
        let release = directory.appendingPathComponent("release")
        let holder = Process()
        holder.executableURL = URL(fileURLWithPath: "/usr/bin/perl")
        holder.arguments = [
            "-e",
            """
            use Fcntl ':flock';
            open(my $f, '>>', $ARGV[0]) or die; flock($f, LOCK_EX) or die;
            open(my $h, '>', $ARGV[1]) or die; close($h);
            for (1..1000) { last if -e $ARGV[2]; select(undef, undef, undef, 0.01); }
            """,
            url.path, held.path, release.path,
        ]
        try holder.run()
        defer { if holder.isRunning { holder.terminate() } }
        while !FileManager.default.fileExists(atPath: held.path) {
            try await Task.sleep(nanoseconds: 10_000_000)
        }

        await #expect(throws: ProtelesAuthError.self, "a short timeout gives up while the other process holds it") {
            try await FileRefreshLock(url: url, timeout: 0.2).withLock {}
        }
        #expect(holder.isRunning)

        let waiter = Task { () -> Date in
            try await FileRefreshLock(url: url, timeout: 30).withLock { Date() }
        }
        try await Task.sleep(nanoseconds: 100_000_000)
        let releasedAt = Date()
        FileManager.default.createFile(atPath: release.path, contents: nil)
        let acquiredAt = try await waiter.value
        #expect(acquiredAt >= releasedAt, "acquired only after the other process let go")
    }
    #endif
}
