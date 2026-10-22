import Foundation
import Security

/// Where the session record lives (docs/mobile-SDKs.md §10.5).
///
/// The record is opaque bytes: the SDK encodes and decodes it, a store only
/// keeps it. The default is `KeychainTokenStore`; tests and unusual apps supply
/// their own. **Never** back one with `UserDefaults` or a plain file — the
/// record holds a refresh token that is good for thirty days after sign-in.
///
/// Throw when the store cannot be read. Returning `nil` means "there is no
/// session" and signs the user out; a Keychain that is merely unavailable
/// (before first unlock) must throw instead.
public protocol TokenStore: Sendable {
    func read() throws -> Data?
    func write(_ data: Data) throws
    func delete() throws
}

/// The Keychain: a generic password under service
/// `com.proteles.auth.<clientId>`, readable after the first unlock and never
/// migrated to another device (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`),
/// optionally in a shared access group so the app's extensions see it.
public struct KeychainTokenStore: TokenStore {
    public let service: String
    public let account: String
    public let accessGroup: String?

    public init(service: String, account: String = "session", accessGroup: String? = nil) {
        self.service = service
        self.account = account
        self.accessGroup = accessGroup
    }

    public init(configuration: ProtelesConfiguration) {
        self.init(service: configuration.keychainService, accessGroup: configuration.keychainAccessGroup)
    }

    private var baseQuery: [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
            // On macOS, the iOS-style keychain; on iOS, what there already is.
            kSecUseDataProtectionKeychain: true,
        ]
        if let accessGroup { query[kSecAttrAccessGroup] = accessGroup }
        return query
    }

    public func read() throws -> Data? {
        var query = baseQuery
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else { throw ProtelesAuthError.storage("the Keychain returned no data") }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw ProtelesAuthError.storage("Keychain read failed (OSStatus \(status))")
        }
    }

    public func write(_ data: Data) throws {
        let attributes: [CFString: Any] = [
            kSecValueData: data,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        var status = SecItemUpdate(baseQuery as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var add = baseQuery
            add.merge(attributes) { _, new in new }
            status = SecItemAdd(add as CFDictionary, nil)
            if status == errSecDuplicateItem {
                // Another process added it between our update and our add.
                status = SecItemUpdate(baseQuery as CFDictionary, attributes as CFDictionary)
            }
        }
        guard status == errSecSuccess else {
            throw ProtelesAuthError.storage("Keychain write failed (OSStatus \(status))")
        }
    }

    public func delete() throws {
        let status = SecItemDelete(baseQuery as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw ProtelesAuthError.storage("Keychain delete failed (OSStatus \(status))")
        }
    }
}

/// A store in memory, for tests and previews. Nothing survives the process.
public final class InMemoryTokenStore: TokenStore, @unchecked Sendable {
    private let lock = NSLock()
    private var data: Data?

    public init(data: Data? = nil) {
        self.data = data
    }

    public func read() throws -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return data
    }

    public func write(_ data: Data) throws {
        lock.lock()
        defer { lock.unlock() }
        self.data = data
    }

    public func delete() throws {
        lock.lock()
        defer { lock.unlock() }
        data = nil
    }
}

/// The record the SDK keeps. Internal: a store sees bytes.
struct StoredSession: Codable, Sendable, Equatable {
    var version = 1
    /// The configuration the session was signed in with. The Keychain service
    /// is keyed by `clientId` alone (§10.5), so a client reconfigured to
    /// another issuer with the same `clientId` — a multi-tenant app whose
    /// `client_id` is its bundle identifier — reads the same record. A record
    /// that does not name this client's issuer and `clientId` byte for byte is
    /// not its session: it is never handed out, refreshed or revoked here
    /// (sign-out deletes it, sign-in overwrites it), as in the Android SDK. A
    /// record written before these fields existed does not decode, and reads
    /// the same way.
    var issuer: String
    var clientId: String
    /// The current refresh token — rotated on every refresh (§2.3).
    var refreshToken: String?
    /// The access token. A rotation is persisted before its new ID token is
    /// verified, and until that completes the record keeps the *previous*
    /// access token and its times: rotation spends the refresh token, not the
    /// access tokens already issued, so it is still good at the server while
    /// it lasts — and it is past half its life, so every reader refreshes
    /// again. Optional only so an older record still decodes.
    var accessToken: String?
    /// When the access token's lifetime started — just before the request
    /// that obtained it was sent, so time spent in flight counts against it
    /// (the conservative end, as the Android SDK's refresh takes it) — and
    /// when it expires by the response's `expires_in`. Local times, so the
    /// device's offset from the server's clock does not matter.
    var accessTokenReceivedAt: Date
    var accessTokenExpiresAt: Date
    /// The latest verified ID token, for `id_token_hint` at end-session. Its
    /// own validity is irrelevant after verification (trap 7).
    var idToken: String?
    /// The verified claims — the user record.
    var claims: [String: JSONValue]
    var scope: String?

    var subject: String { claims["sub"]?.stringValue ?? "" }

    /// Whether this record was written for `configuration` (see `issuer`).
    func belongs(to configuration: ProtelesConfiguration) -> Bool {
        bytesEqual(issuer, configuration.issuer) && bytesEqual(clientId, configuration.clientId)
    }

    func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        encoder.outputFormatting = .sortedKeys
        return try encoder.encode(self)
    }

    static func decode(_ data: Data) throws -> StoredSession {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return try decoder.decode(StoredSession.self, from: data)
    }

    /// Past half its life, or unknowable (§4 "refresh early").
    func needsRefresh(at now: Date) -> Bool {
        guard accessToken != nil else { return true }
        // A clock set back further than the skew past the start of the
        // lifetime makes every interval below meaningless: refresh rather
        // than trust it. Within the skew — an NTP correction — it is noise,
        // not a reason to rotate, as in the Android SDK.
        guard now >= accessTokenReceivedAt.addingTimeInterval(-IDTokenVerifier.clockSkew) else { return true }
        let halfLife = accessTokenExpiresAt.timeIntervalSince(accessTokenReceivedAt) / 2
        return now >= accessTokenReceivedAt.addingTimeInterval(halfLife)
    }

    /// The access token while it has not expired — what a failed refresh hands
    /// out instead of an error (§10.3, §10.9 item 1). Expiry exactly as the
    /// contract and the Android SDK read it, with no margin: a token with a
    /// few seconds left is still the caller's to use.
    func unexpiredAccessToken(at now: Date) -> String? {
        now < accessTokenExpiresAt ? accessToken : nil
    }
}
