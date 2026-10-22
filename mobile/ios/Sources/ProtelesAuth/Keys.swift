import Foundation
import Security

/// An RS256 verification key, held as the PKCS#1 `RSAPublicKey` DER that
/// `SecKeyCreateWithData` takes. Kept as bytes rather than a `SecKey` so it is
/// plainly `Sendable`; the `SecKey` is made per verification, which costs
/// microseconds.
struct RSAVerificationKey: Sendable, Equatable {
    let kid: String
    let der: Data

    /// The server's own floor for keys it trusts (`MIN_CLIENT_KEY_BITS`), and
    /// §5.2's: a smaller modulus can be factored.
    static let minimumModulusBits = 2048

    /// The key from a JWK's `n` and `e`, or `nil` when they do not make one a
    /// verifier may trust (§5.2, settled 2026-09-25): a modulus below 2048
    /// bits, or an exponent below three or even, is not a verification key.
    /// With `e = 1` the "signature" is the padded digest itself, which anybody
    /// can write.
    init?(kid: String, modulus n: String, exponent e: String) {
        guard let modulus = Base64URL.decode(n), let exponent = Base64URL.decode(e),
              Self.isSound(modulus: modulus, exponent: exponent) else { return nil }
        let der = DER.rsaPublicKey(modulus: modulus, exponent: exponent)
        // Import once here, so a key the platform will not take is filtered out
        // of the set like any other unusable key instead of failing later.
        guard Self.makeSecKey(der) != nil else { return nil }
        self.kid = kid
        self.der = der
    }

    func secKey() -> SecKey? { Self.makeSecKey(der) }

    /// `reference-verify.mjs`'s `rsaKeyIsSound`, on big-endian magnitudes.
    static func isSound(modulus: Data, exponent: Data) -> Bool {
        let n = Array(modulus.drop(while: { $0 == 0 }))
        let e = Array(exponent.drop(while: { $0 == 0 }))
        guard let top = n.first, let last = e.last else { return false }
        let bits = (n.count - 1) * 8 + (8 - top.leadingZeroBitCount)
        let atLeastThree = e.count > 1 || e[0] >= 3
        return bits >= minimumModulusBits && atLeastThree && last & 1 == 1
    }

    private static func makeSecKey(_ der: Data) -> SecKey? {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
        ]
        return SecKeyCreateWithData(der as CFData, attributes as CFDictionary, nil)
    }

    /// RSASSA-PKCS1-v1_5 with SHA-256 over `message`, exactly as given.
    func verify(signature: Data, over message: Data) -> Bool {
        guard let key = secKey() else { return false }
        return SecKeyVerifySignature(key, .rsaSignatureMessagePKCS1v15SHA256, message as CFData, signature as CFData, nil)
    }
}

/// Just enough DER to write `RSAPublicKey ::= SEQUENCE { modulus INTEGER,
/// publicExponent INTEGER }` (RFC 8017 §A.1.1).
enum DER {
    static func rsaPublicKey(modulus: Data, exponent: Data) -> Data {
        sequence(integer(modulus) + integer(exponent))
    }

    /// A non-negative INTEGER from big-endian magnitude bytes: minimal (no
    /// leading zero bytes), with one `0x00` restored when the top bit is set
    /// so it is not read as negative. JWK's `n` is unsigned and never carries
    /// that byte; DER must.
    static func integer(_ magnitude: Data) -> Data {
        var bytes = Array(magnitude.drop(while: { $0 == 0 }))
        if bytes.isEmpty { bytes = [0] }
        if bytes[0] & 0x80 != 0 { bytes.insert(0, at: 0) }
        return Data([0x02] + length(bytes.count) + bytes)
    }

    static func sequence(_ content: Data) -> Data {
        Data([0x30] + length(content.count)) + content
    }

    static func length(_ count: Int) -> [UInt8] {
        if count < 0x80 { return [UInt8(count)] }
        var bytes: [UInt8] = []
        var remaining = count
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0xFF), at: 0)
            remaining >>= 8
        }
        return [0x80 | UInt8(bytes.count)] + bytes
    }
}

/// Where the verifier gets the key for a `kid`.
protocol SigningKeyProvider: Sendable {
    /// The usable key published under `kid`. Throws
    /// `.idTokenRejected(.noUsableKey)` when there is none.
    func signingKey(kid: String) async throws -> RSAVerificationKey
}

/// A JWK Set, reduced to the keys fit to verify an RS256 signature (§5 step
/// 2, §5.2 rule 5): `kty` is `RSA`, `use` absent or `sig`, `alg` absent or
/// `RS256`, with a `kid`, and an `n` and `e` that make a sound key (at least
/// 2048 bits, an odd exponent of at least three). Anything else is not an
/// error — it is simply not a verification key.
struct JSONWebKeySet: Sendable, SigningKeyProvider {
    /// Usable keys, in document order.
    let keys: [RSAVerificationKey]

    init(keys: [RSAVerificationKey]) {
        self.keys = keys
    }

    init(json: JSONValue) {
        let entries = json.objectValue?["keys"]?.arrayValue ?? []
        keys = entries.compactMap { entry in
            guard let jwk = entry.objectValue,
                  jwk["kty"] == .string("RSA"),
                  jwk["use"] == nil || jwk["use"] == .string("sig"),
                  jwk["alg"] == nil || jwk["alg"] == .string("RS256"),
                  let kid = jwk["kid"]?.stringValue,
                  let n = jwk["n"]?.stringValue,
                  let e = jwk["e"]?.stringValue else { return nil }
            return RSAVerificationKey(kid: kid, modulus: n, exponent: e)
        }
    }

    /// The first usable key with this `kid`, as the reference's `find` does.
    func key(for kid: String) -> RSAVerificationKey? {
        keys.first { bytesEqual($0.kid, kid) }
    }

    func signingKey(kid: String) async throws -> RSAVerificationKey {
        guard let key = key(for: kid) else { throw ProtelesAuthError.idTokenRejected(.noUsableKey) }
        return key
    }
}

/// The tenant's published keys, fetched from discovery's `jwks_uri` and
/// cached (§5 step 2):
///
/// - an unknown `kid` refreshes the set — that is what a key rotation looks
///   like from here;
/// - concurrent refreshes collapse into **one** fetch (§5.2 rule 7);
/// - a refresh that fails falls back to a stale key that is still present,
///   rather than signing everybody out during a brief outage;
/// - a document with no usable key is an error, never an empty cache: the
///   previous keys are kept.
///
/// A fetched set is trusted for `defaultMaxAge` (ten minutes, the Android
/// SDK's), so a key the issuer has withdrawn stops verifying within that.
///
/// Every failure to get a usable set is `.network`, as in the Android SDK:
/// an answer other than `200` (carrying its status — §10.9 item 4 for a 5xx),
/// a body that is not JSON, or a set with no usable key. None of them is a
/// verdict on a token, so none is `.idTokenRejected`. A 429 closes the
/// client's rate-limit gate and is `.rateLimited`.
actor JWKSCache: SigningKeyProvider {
    /// How long a fetched set is used before it is fetched again.
    static let defaultMaxAge: TimeInterval = 600

    private let uri: URL
    private let transport: any HTTPTransport
    private let now: @Sendable () -> Date
    private let maxAge: TimeInterval
    private let gate: RateLimitGate

    private var set = JSONWebKeySet(keys: [])
    private var fetchedAt: Date?
    private var inFlight: Task<Void, any Error>?

    /// How many fetches this cache has made. For tests.
    private(set) var fetchCount = 0

    init(
        uri: URL,
        transport: any HTTPTransport,
        now: @escaping @Sendable () -> Date,
        maxAge: TimeInterval = JWKSCache.defaultMaxAge,
        gate: RateLimitGate? = nil
    ) {
        self.uri = uri
        self.transport = transport
        self.now = now
        self.maxAge = maxAge
        self.gate = gate ?? RateLimitGate(now: now)
    }

    func signingKey(kid: String) async throws -> RSAVerificationKey {
        let cached = set.key(for: kid)
        if let cached, let fetchedAt, now().timeIntervalSince(fetchedAt) < maxAge, now() >= fetchedAt {
            return cached
        }
        do {
            try await refresh()
        } catch {
            // Stale beats signing everybody out — but only for a key we hold.
            if let stale = set.key(for: kid) ?? cached { return stale }
            throw asProtelesError(error)
        }
        guard let fresh = set.key(for: kid) else { throw ProtelesAuthError.idTokenRejected(.noUsableKey) }
        return fresh
    }

    /// One fetch, however many callers are waiting for it.
    private func refresh() async throws {
        if let running = inFlight {
            try await running.value
            return
        }
        let task = Task { try await self.fetchAndInstall() }
        inFlight = task
        defer { inFlight = nil }
        try await task.value
    }

    private func fetchAndInstall() async throws {
        fetchCount += 1
        let request = HTTPRequest(method: "GET", url: uri, headers: ["Accept": "application/json"])
        let response: HTTPResponse
        do {
            response = try await transport.send(request)
        } catch {
            throw asProtelesError(error)
        }
        guard response.status == 200 else {
            // Rate limited like any other request (§4 "honour Retry-After"),
            // and the whole client waits it out (§10.9 item 3).
            if response.status == 429 { throw gate.close(response) }
            throw ProtelesAuthError.network("the key set at \(uri.absoluteString) answered HTTP \(response.status)", status: response.status)
        }
        guard let json = JSONValue.parseObject(response.body) else {
            throw ProtelesAuthError.network("the key set at \(uri.absoluteString) is not a JSON object")
        }
        let fetched = JSONWebKeySet(json: .object(json))
        guard !fetched.keys.isEmpty else {
            throw ProtelesAuthError.network("the key set at \(uri.absoluteString) publishes no usable RS256 signing key")
        }
        set = fetched
        fetchedAt = now()
    }
}
