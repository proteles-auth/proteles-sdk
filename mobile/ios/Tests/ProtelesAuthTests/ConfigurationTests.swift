import Foundation
import Testing
@testable import ProtelesAuth

@Suite("Configuration (§10.1): refused at construction, not at first sign-in")
struct ConfigurationTests {
    private func make(
        issuer: String = Fixture.issuer,
        clientId: String = Fixture.clientId,
        redirectURI: String = Fixture.redirectURI,
        scopes: [String] = ProtelesConfiguration.defaultScopes,
        postLogoutRedirectURI: String? = nil
    ) throws -> ProtelesConfiguration {
        try ProtelesConfiguration(
            issuer: issuer, clientId: clientId, redirectURI: redirectURI,
            scopes: scopes, postLogoutRedirectURI: postLogoutRedirectURI
        )
    }

    private func refusal(_ body: () throws -> ProtelesConfiguration) -> String? {
        do {
            _ = try body()
            return nil
        } catch ProtelesAuthError.configuration(let message) {
            return message
        } catch {
            return "unexpected \(error)"
        }
    }

    @Test(arguments: [
        "https://app.example.com/oauth/cb",       // a Universal Link
        "https://app.example.com:8443/oauth/cb",  // on a non-default port
    ])
    func acceptedRedirects(_ uri: String) throws {
        let configuration = try make(redirectURI: uri)
        #expect(configuration.redirectURI == uri, "kept byte for byte")
    }

    @Test("no private-use scheme is a redirect, reverse-DNS included (M7)", arguments: [
        "com.example.app:/oauth/callback",
        "com.example.app://oauth/callback",
        "myapp://callback",
        "myapp:/callback",
        "oauth:/redirect",
    ])
    func privateUseScheme(_ uri: String) {
        let message = refusal { try make(redirectURI: uri) }
        #expect(message?.contains("private-use scheme") == true, "\(uri): \(message ?? "accepted")")
        #expect(message?.contains("Universal Link") == true, "\(uri): says what to use instead")
    }

    @Test("http://localhost is refused, with a port or without (trap 1)", arguments: [
        "http://localhost:51004/cb",
        "http://localhost/cb",
        "http://LOCALHOST:8080/cb",
    ])
    func localhost(_ uri: String) {
        let message = refusal { try make(redirectURI: uri) }
        #expect(message?.contains("localhost") == true, "\(uri): \(message ?? "accepted")")
    }

    @Test("a loopback redirect is refused too: neither SDK can receive one (§10.1, settled 2026-09-25)", arguments: [
        "http://127.0.0.1/cb",
        "http://127.0.0.1:51004/cb",
        "http://[::1]:51004/cb",
        "http://[::1]/cb",
    ])
    func loopbackRedirect(_ uri: String) {
        let message = refusal { try make(redirectURI: uri) }
        #expect(message?.contains("loopback") == true, "\(uri): \(message ?? "accepted")")
        #expect(refusal { try make(postLogoutRedirectURI: uri) }?.contains("loopback") == true)
    }

    @Test(arguments: [
        "http://10.0.0.1/cb",                 // cleartext off loopback
        "http://app.example.com/cb",
        "http://127.0.0.1@evil.example/cb",   // userinfo that only looks like loopback
        "com.example.app:/cb#frag",           // fragment
        "https://app.example.com/cb#x",
        "com.example.app:callback",           // opaque, not hierarchical
        "javascript:alert(1)",
        "data:text/html,x",
        "mailto:a@example.com",
        "/relative/cb",
        "",
        "https://app.example.com/c b",        // not visible ASCII
    ])
    func otherRefusedRedirects(_ uri: String) {
        #expect(refusal { try make(redirectURI: uri) } != nil, "\(uri) was accepted")
    }

    @Test func thePostLogoutRedirectIsHeldToTheSameRules() throws {
        #expect(refusal { try make(postLogoutRedirectURI: "com.example.app:/signed-out") }?.contains("private-use scheme") == true)
        #expect(refusal { try make(postLogoutRedirectURI: "http://localhost:8080/out") } != nil)
        #expect(try make(postLogoutRedirectURI: Fixture.postLogoutRedirectURI).postLogoutRedirectURI == Fixture.postLogoutRedirectURI)
    }

    @Test(arguments: [
        "https://auth.example.test",
        "https://auth.example.test/",          // kept as given; compared byte for byte later
        "https://auth.example.test/tenants/acme",
        "http://127.0.0.1:8080",
        "http://[::1]:8080",
        "http://localhost:8080",               // a development server by name
    ])
    func acceptedIssuers(_ issuer: String) throws {
        #expect(try make(issuer: issuer).issuer == issuer)
    }

    @Test(arguments: [
        "http://auth.example.test",            // cleartext off loopback
        "auth.example.test",
        "https://auth.example.test?tenant=a",
        "https://auth.example.test#x",
        "https://user@auth.example.test",
        "ftp://auth.example.test",
        "",
    ])
    func refusedIssuers(_ issuer: String) {
        #expect(refusal { try make(issuer: issuer) } != nil, "\(issuer) was accepted")
    }

    @Test("an issuer's scheme, and a loopback host, only as the server spells them: lower case", arguments: [
        "HTTPS://auth.example.test",
        "Https://auth.example.test",
        "HTTP://127.0.0.1:8080",
        "http://LOCALHOST:8080",
        "http://LocalHost:8080",
    ])
    func issuerSpelling(_ issuer: String) {
        let message = refusal { try make(issuer: issuer) }
        #expect(message?.contains("lower case") == true, "\(issuer): \(message ?? "accepted")")
    }

    @Test("an https redirect carrying userinfo is refused, for both redirects")
    func userinfoOnAnHTTPSRedirect() {
        #expect(refusal { try make(redirectURI: "https://user@app.example.com/cb") }?.contains("userinfo") == true)
        #expect(refusal { try make(redirectURI: "https://user:pw@app.example.com/cb") }?.contains("userinfo") == true)
        #expect(refusal { try make(postLogoutRedirectURI: "https://user@app.example.com/out") }?.contains("userinfo") == true)
    }

    @Test func clientIdAndScopes() {
        #expect(refusal { try make(scopes: ["openid", "email", "openid"]) }?.contains("repeat") == true)
        #expect(refusal { try make(clientId: "") } != nil)
        #expect(refusal { try make(clientId: "has space") } != nil)
        #expect(refusal { try make(scopes: []) } != nil)
        #expect(refusal { try make(scopes: ["profile", "email"]) }?.contains("openid") == true)
        #expect(refusal { try make(scopes: ["openid profile"]) } != nil, "one token per element")
        #expect(refusal { try make(scopes: ["openid", ""]) } != nil)
    }

    @Test func derivedValues() throws {
        let configuration = try make()
        #expect(configuration.scopes == ["openid", "profile", "email"])
        #expect(configuration.keychainService == "com.proteles.auth.com.example.mobile")
        #expect(configuration.discoveryURL.absoluteString == "https://auth.example.test/.well-known/openid-configuration")
        #expect(try make(issuer: "https://auth.example.test/").discoveryURL.absoluteString
            == "https://auth.example.test/.well-known/openid-configuration")
    }

    @Test(
        "a session shared across processes with only an in-process lock is refused at construction (§10.9 item 9)",
        arguments: [
            ("TEAMID.com.example.shared", nil),
            (nil, "group.com.example.shared"),
            ("TEAMID.com.example.shared", "group.com.example.shared"),
        ] as [(String?, String?)]
    )
    func aSharedStoreNeedsTheFileLock(_ accessGroup: String?, _ appGroup: String?) throws {
        let shared = try ProtelesConfiguration(
            issuer: Fixture.issuer, clientId: Fixture.clientId, redirectURI: Fixture.redirectURI,
            keychainAccessGroup: accessGroup, appGroupIdentifier: appGroup
        )
        // Two processes, one record, only an in-process lock: a refresh in one
        // spends the token the other is about to present (§4, §10.6). Not
        // even when the app asks for it.
        #expect(throws: ProtelesAuthError.self) {
            _ = try ProtelesClient(
                configuration: shared, transport: StubServer(), store: InMemoryTokenStore(),
                lock: InProcessRefreshLock(key: shared.keychainService)
            )
        }
        if appGroup == nil {
            #expect(throws: ProtelesAuthError.self, "no lock given, and no App Group to make one in") {
                _ = try ProtelesClient(configuration: shared, transport: StubServer(), store: InMemoryTokenStore())
            }
        }
        // A file lock, or one of the app's own, is accepted.
        let url = temporaryLockURL()
        let locked = try ProtelesClient(
            configuration: shared, transport: StubServer(), store: InMemoryTokenStore(), lock: FileRefreshLock(url: url)
        )
        #expect(locked.lockScope == .crossProcess(lockFile: url))
        let custom = try ProtelesClient(
            configuration: shared, transport: StubServer(), store: InMemoryTokenStore(), lock: CountingLock()
        )
        #expect(custom.lockScope == .custom)
    }

    @Test func anUnsharedSessionMayUseTheInProcessLock() throws {
        let client = try ProtelesClient(
            configuration: Fixture.configuration(), transport: StubServer(), store: InMemoryTokenStore(),
            lock: InProcessRefreshLock(key: UUID().uuidString)
        )
        #expect(client.lockScope == .inProcess)
    }

    @Test func theLockScopeFollowsTheAppGroup() throws {
        let client = try ProtelesClient(configuration: Fixture.configuration(), transport: StubServer(), store: InMemoryTokenStore())
        #expect(client.lockScope == .inProcess)

        let grouped = try Fixture.configuration(appGroupIdentifier: "group.com.example.not-entitled")
        #if os(iOS)
        // Without the App Groups entitlement iOS returns no container, and a
        // configured group that cannot be used is refused, not ignored.
        #expect(throws: ProtelesAuthError.self) {
            _ = try ProtelesClient(configuration: grouped, transport: StubServer(), store: InMemoryTokenStore())
        }
        #else
        // macOS hands an unsandboxed process a container path whether or not
        // it is entitled; the lock file goes there.
        let client2 = try ProtelesClient(configuration: grouped, transport: StubServer(), store: InMemoryTokenStore())
        guard case .crossProcess(let lockFile) = client2.lockScope else {
            Issue.record("expected a cross-process lock, got \(client2.lockScope)")
            return
        }
        #expect(lockFile.lastPathComponent == "com.proteles.auth.com.example.mobile.refresh.lock")
        #endif
    }
}
