import CryptoKit
import Foundation

/// What a caller expects of an ID token.
struct IDTokenExpectations: Sendable {
    enum Nonce: Sendable, Equatable {
        /// A sign-in: the token must carry exactly this nonce. An empty
        /// string is an expectation that cannot be met — a sign-in whose nonce
        /// was lost — never a skip.
        case required(String)
        /// The refresh grant, which mints no nonce. The only way to skip the
        /// comparison, and it has to be said (§5 step 5, §5.2 rule 4).
        case skippedForRefreshGrant
    }

    /// The configured issuer; compared byte for byte.
    var issuer: String
    /// This app's `client_id`.
    var audience: String
    var nonce: Nonce
    /// The access token from the same response, whose `at_hash` the token
    /// must carry (M3); `nil` only when the caller holds none.
    var accessToken: String?
    var now: Date
    /// Whether `exp` and `iat` are held to `now`. `false` only for a
    /// refresh-minted token (§10.9 item 2): it arrived over TLS in the
    /// response that minted it, and `at_hash` binds it to the new access
    /// token, so a device clock that is wrong is not a reason to refuse it.
    /// `exp` must still be present.
    var judgesClock = true
}

/// A verified ID token.
struct VerifiedIDToken: Sendable, Equatable {
    let raw: String
    let claims: [String: JSONValue]
    var subject: String { claims["sub"]?.stringValue ?? "" }
}

/// ID-token verification, in the order docs/mobile-SDKs.md §5 gives and
/// `mobile/vectors/reference-verify.mjs` runs. **The order is the
/// security property**: nothing in the payload is read until the signature
/// over the bytes as they arrived has verified.
enum IDTokenVerifier {
    /// Clock skew, on `exp` and on `iat` in the future (§5.2 rule 1).
    static let clockSkew: TimeInterval = 60

    static func verify(
        _ token: String,
        expecting expected: IDTokenExpectations,
        keys: any SigningKeyProvider
    ) async throws -> VerifiedIDToken {
        func refuse(_ reason: IDTokenRejection) -> ProtelesAuthError { .idTokenRejected(reason) }

        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { throw refuse(.notThreeSegments) }
        let (headerSegment, payloadSegment, signatureSegment) = (parts[0], parts[1], parts[2])

        guard let headerBytes = Base64URL.decode(headerSegment) else { throw refuse(.headerNotBase64URL) }
        let header: [String: JSONValue]
        do {
            header = try JSONValue.parseStrictObject(headerBytes)
        } catch JSONParseFailure.duplicateMember {
            throw refuse(.duplicateMember)
        } catch {
            throw refuse(.headerNotJSON)
        }

        // 1. The algorithm, first: before any key is looked up or any claim
        //    read. `none` is no signature; `HS256` is an HMAC keyed with a
        //    public key anyone can fetch.
        guard header["alg"] == .string("RS256") else { throw refuse(.algorithm) }
        // A header extension marked critical must be understood to accept the
        // token (RFC 7515 §4.1.11), and this verifier understands none. Its
        // presence is enough, whatever its value.
        guard header["crit"] == nil else { throw refuse(.criticalHeader) }

        // 2. The key, by `kid`, from keys fit for signature verification.
        guard let kid = header["kid"]?.stringValue, !kid.isEmpty else { throw refuse(.kidMissing) }
        let key = try await keys.signingKey(kid: kid)

        // 3. The signature, over the bytes exactly as they arrived — never a
        //    re-encoding of parsed values.
        guard let signature = Base64URL.decode(signatureSegment) else { throw refuse(.signatureNotBase64URL) }
        guard let payloadBytes = Base64URL.decode(payloadSegment) else { throw refuse(.payloadNotBase64URL) }
        let signingInput = Data(token.utf8.prefix(headerSegment.utf8.count + 1 + payloadSegment.utf8.count))
        guard key.verify(signature: signature, over: signingInput) else { throw refuse(.signature) }

        // 4. Only now, the claims.
        let claims: [String: JSONValue]
        do {
            claims = try JSONValue.parseStrictObject(payloadBytes)
        } catch JSONParseFailure.duplicateMember {
            throw refuse(.duplicateMember)
        } catch {
            throw refuse(.payloadNotJSON)
        }

        guard let iss = claims["iss"]?.stringValue, bytesEqual(iss, expected.issuer) else { throw refuse(.issuer) }

        // `aud` may be an array, but only as one element naming this client:
        // several audiences need `azp`, which this issuer never sends.
        let audiences: [JSONValue]
        switch claims["aud"] {
        case .array(let values)?: audiences = values
        case let value?: audiences = [value]
        case nil: audiences = []
        }
        guard audiences.count == 1, let aud = audiences[0].stringValue, bytesEqual(aud, expected.audience) else {
            throw refuse(.audience)
        }

        guard let sub = claims["sub"]?.stringValue, !sub.isEmpty else { throw refuse(.subject) }

        guard claims["exp"]?.numberValue != nil else { throw refuse(.expirationMissing) }
        if expected.judgesClock, let reason = clockRejection(claims, now: expected.now) { throw refuse(reason) }

        // 5. The nonce. Only the refresh grant skips it, and says so.
        if case .required(let nonce) = expected.nonce {
            guard !nonce.isEmpty, let actual = claims["nonce"]?.stringValue, bytesEqual(actual, nonce) else {
                throw refuse(.nonce)
            }
        }

        // 6. at_hash, whenever the caller holds the access token (M3).
        if let accessToken = expected.accessToken {
            guard let atHash = claims["at_hash"]?.stringValue, bytesEqual(atHash, Self.atHash(accessToken)) else {
                throw refuse(.atHash)
            }
        }

        return VerifiedIDToken(raw: token, claims: claims)
    }

    /// What `now` makes of the claims' `exp` and `iat` (§5.2 rule 1: 60 s of
    /// skew on `exp`, and on `iat` in the future), or `nil` when both are
    /// within it. A refresh verifies without judging the clock and asks this
    /// afterwards, to decide whether to adopt the claims.
    static func clockRejection(_ claims: [String: JSONValue], now date: Date) -> IDTokenRejection? {
        let now = date.timeIntervalSince1970
        guard let exp = claims["exp"]?.numberValue else { return .expirationMissing }
        if now > exp + clockSkew { return .expired }
        if let iat = claims["iat"]?.numberValue, iat > now + clockSkew { return .issuedInTheFuture }
        return nil
    }

    /// OpenID Connect Core §3.1.3.6: base64url of the left half of
    /// SHA-256 over the access token's ASCII bytes.
    static func atHash(_ accessToken: String) -> String {
        let digest = Array(SHA256.hash(data: Data(accessToken.utf8)))
        return Base64URL.encode(Data(digest[..<(digest.count / 2)]))
    }
}
