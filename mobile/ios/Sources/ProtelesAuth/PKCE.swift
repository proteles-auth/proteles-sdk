import CryptoKit
import Foundation
import Security

/// A PKCE pair (RFC 7636), S256 only (docs/mobile-SDKs.md §2.2).
///
/// The verifier is 32 random bytes as base64url without padding — 43
/// characters — and the challenge is base64url(SHA-256(verifier)), also 43
/// characters. The server requires exactly 43 for the challenge (trap 5) and
/// refuses a missing method rather than defaulting to `plain` (trap 6), so the
/// method is always sent.
public struct PKCE: Sendable, Equatable {
    public let verifier: String
    public let challenge: String
    public var method: String { "S256" }

    /// A fresh pair from the system CSPRNG.
    public static func generate() throws -> PKCE {
        PKCE(verifierBytes: try SecureRandom.bytes(32))
    }

    /// The pair for a given verifier's entropy. `generate()` is the only
    /// caller outside tests; RFC 7636 Appendix B's known answer uses this.
    init(verifierBytes: Data) {
        let verifier = Base64URL.encode(verifierBytes)
        self.verifier = verifier
        self.challenge = PKCE.challenge(for: verifier)
    }

    /// base64url(SHA-256(ASCII(verifier))).
    public static func challenge(for verifier: String) -> String {
        Base64URL.encode(Data(SHA256.hash(data: Data(verifier.utf8))))
    }
}

/// `SecRandomCopyBytes`, and the 32-byte base64url tokens used for `state`
/// and `nonce` (§10.2 step 2).
enum SecureRandom {
    static func bytes(_ count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
        }
        guard status == errSecSuccess else {
            // Never continue with weaker randomness: a guessable state, nonce
            // or verifier is the attack each of them exists to stop.
            throw ProtelesAuthError.configuration("the system random number generator failed (OSStatus \(status))")
        }
        return data
    }

    static func token() throws -> String {
        Base64URL.encode(try bytes(32))
    }
}
