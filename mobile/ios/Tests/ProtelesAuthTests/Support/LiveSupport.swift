import Foundation
@testable import ProtelesAuth

// What the live tests stand in for against a real server: the person at the
// browser, and the server-side view a test needs to check the SDK's work
// (userinfo, a refresh token presented by hand, the published key set).
// `mobile/live/run-live.sh` starts the server and exports PROTELES_LIVE_*.

enum Live {
    private static let environment = ProcessInfo.processInfo.environment

    /// Set by `run-live.sh`; without it every live test is skipped.
    static let isConfigured = !(environment["PROTELES_LIVE_ISSUER"] ?? "").isEmpty

    static func value(_ name: String) throws -> String {
        guard let value = environment[name], !value.isEmpty else {
            throw LiveFailure("\(name) is not set: run through mobile/live/run-live.sh -- …")
        }
        return value
    }

    static func issuer() throws -> String { try value("PROTELES_LIVE_ISSUER") }
    static func clientId() throws -> String { try value("PROTELES_LIVE_CLIENT_ID") }
    static func username() throws -> String { try value("PROTELES_LIVE_USERNAME") }

    /// The seeded client, exactly as `run-live.sh` registered it.
    static func configuration(withPostLogoutRedirect: Bool = false) throws -> ProtelesConfiguration {
        try ProtelesConfiguration(
            issuer: issuer(),
            clientId: clientId(),
            redirectURI: value("PROTELES_LIVE_REDIRECT_URI"),
            postLogoutRedirectURI: withPostLogoutRedirect ? value("PROTELES_LIVE_POST_LOGOUT_REDIRECT_URI") : nil
        )
    }

    static func browser() throws -> LiveBrowser {
        guard let issuer = URL(string: try issuer()) else { throw LiveFailure("PROTELES_LIVE_ISSUER is not a URL") }
        return LiveBrowser(issuer: issuer, username: try username(), password: try value("PROTELES_LIVE_PASSWORD"))
    }

    /// A JWT's payload, read without verifying it — only for comparing what
    /// the SDK already verified and stored.
    static func claims(of jwt: String) -> [String: JSONValue] {
        let parts = jwt.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3, let payload = Base64URL.decode(parts[1]) else { return [:] }
        return JSONValue.parseObject(payload) ?? [:]
    }

    static func query(_ url: URL) -> [String: String] {
        Dictionary(queryItems(of: url).map { ($0.name, $0.value) }, uniquingKeysWith: { _, _ in "<repeated>" })
    }
}

struct LiveFailure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

// MARK: - The server, as a test sees it

/// The endpoints a test calls itself, from the real discovery document.
struct LiveServer: Sendable {
    let issuer: String
    let clientId: String
    let tokenEndpoint: URL
    let userinfoEndpoint: URL
    let revocationEndpoint: URL
    let jwksURI: URL
    private let transport = URLSessionTransport()

    static func discover() async throws -> LiveServer {
        let issuer = try Live.issuer()
        let transport = URLSessionTransport()
        let response = try await transport.send(HTTPRequest(method: "GET", url: URL(string: issuer + "/.well-known/openid-configuration")!))
        guard response.status == 200, let document = JSONValue.parseObject(response.body) else {
            throw LiveFailure("discovery answered HTTP \(response.status)")
        }
        func endpoint(_ name: String) throws -> URL {
            guard let value = document[name]?.stringValue, let url = URL(string: value) else {
                throw LiveFailure("discovery has no \(name)")
            }
            return url
        }
        return LiveServer(
            issuer: issuer,
            clientId: try Live.clientId(),
            tokenEndpoint: try endpoint("token_endpoint"),
            userinfoEndpoint: try endpoint("userinfo_endpoint"),
            revocationEndpoint: try endpoint("revocation_endpoint"),
            jwksURI: try endpoint("jwks_uri")
        )
    }

    private init(issuer: String, clientId: String, tokenEndpoint: URL, userinfoEndpoint: URL, revocationEndpoint: URL, jwksURI: URL) {
        self.issuer = issuer
        self.clientId = clientId
        self.tokenEndpoint = tokenEndpoint
        self.userinfoEndpoint = userinfoEndpoint
        self.revocationEndpoint = revocationEndpoint
        self.jwksURI = jwksURI
    }

    /// `GET userinfo` with the access token: whether the server accepts it.
    func userinfo(_ accessToken: String) async throws -> (status: Int, claims: [String: JSONValue]) {
        let response = try await transport.send(HTTPRequest(
            method: "GET", url: userinfoEndpoint,
            headers: ["Authorization": "Bearer \(accessToken)", "Accept": "application/json"]))
        return (response.status, JSONValue.parseObject(response.body) ?? [:])
    }

    /// Presents a refresh token at the token endpoint by hand — as a stale
    /// process, or someone who copied it, would.
    func presentRefreshToken(_ refreshToken: String) async throws -> (status: Int, error: String?) {
        let response = try await transport.send(HTTPRequest(
            method: "POST", url: tokenEndpoint,
            headers: ["Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"],
            body: Data(FormEncoding.encode([
                ("grant_type", "refresh_token"), ("refresh_token", refreshToken), ("client_id", clientId),
            ]).utf8)))
        return (response.status, JSONValue.parseObject(response.body)?["error"]?.stringValue)
    }

    /// Revokes a refresh token by hand — the family ending somewhere the SDK
    /// cannot see (another copy of the app signing out, an administrator).
    func revoke(_ refreshToken: String) async throws -> Int {
        let response = try await transport.send(HTTPRequest(
            method: "POST", url: revocationEndpoint,
            headers: ["Content-Type": "application/x-www-form-urlencoded"],
            body: Data(FormEncoding.encode([
                ("token", refreshToken), ("token_type_hint", "refresh_token"), ("client_id", clientId),
            ]).utf8)))
        return response.status
    }

    /// The published key set, reduced to verification keys as the SDK reduces it.
    func keySet() async throws -> JSONWebKeySet {
        let response = try await transport.send(HTTPRequest(method: "GET", url: jwksURI))
        guard response.status == 200, let json = JSONValue.parse(response.body) else {
            throw LiveFailure("the key set answered HTTP \(response.status)")
        }
        return JSONWebKeySet(json: json)
    }
}

/// The SDK's own transport, recording what it sent and what came back.
final class RecordingTransport: HTTPTransport, @unchecked Sendable {
    private let inner = URLSessionTransport()
    private let lock = NSLock()
    private var recorded: [(request: HTTPRequest, response: HTTPResponse)] = []

    func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        let response = try await inner.send(request)
        record(request, response)
        return response
    }

    private func record(_ request: HTTPRequest, _ response: HTTPResponse) {
        lock.lock()
        defer { lock.unlock() }
        recorded.append((request, response))
    }

    func exchanges(to path: String) -> [(request: HTTPRequest, response: HTTPResponse)] {
        lock.lock()
        defer { lock.unlock() }
        return recorded.filter { $0.request.url.path == path }
    }

    /// Token-endpoint exchanges of one grant type.
    func tokenRequests(_ grantType: String) -> [(request: HTTPRequest, response: HTTPResponse)] {
        exchanges(to: "/oauth/token").filter { $0.request.form["grant_type"] == grantType }
    }
}

// MARK: - The person at the browser

/// Stands in for the person at `ASWebAuthenticationSession`, over URLSession:
/// it GETs the authorization (or end-session) URL, fills in and posts the
/// server's own forms — the login form, and a consent or sign-out
/// confirmation when one is shown — and follows the server's redirects one at
/// a time until a `Location` is the redirect URI's `https` host and path,
/// which it returns without following, as `ASWebAuthenticationSession` does
/// for `.https(host:path:)`.
///
/// One instance is one browser: its cookies outlive an `open`, so a second
/// sign-in rides the browser session the first one started, as it would in
/// Safari.
///
/// The session is ephemeral (no URL cache, no credential store) and follows no
/// redirect by itself. Its cookies are kept here rather than in an
/// `HTTPCookieStorage`: the server sets `__Host-` cookies with `Secure` even
/// on `http://localhost`, and Foundation's store will not keep a `Secure`
/// cookie from plain http — the ephemeral store stays empty after the login
/// page sets `__Host-login_csrf` (checked against this server). A browser
/// treats `http://localhost` as a secure context and keeps them, so this jar
/// does too, for the issuer's origin only.
final class LiveBrowser: AuthorizationBrowser, @unchecked Sendable {
    struct Step: Sendable, CustomStringConvertible {
        let method: String
        let url: URL
        let status: Int
        var description: String { "\(method) \(url.absoluteString) → \(status)" }
    }

    static let maximumSteps = 12

    private let issuer: URL
    private let username: String
    private let password: String
    private let session: URLSession
    private let lock = NSLock()
    private var jar: [String: String] = [:]
    private var steps: [Step] = []
    private var credentialPosts = 0
    private var opened: [URL] = []
    private var returned: [URL] = []

    init(issuer: URL, username: String, password: String) {
        self.issuer = issuer
        self.username = username
        self.password = password
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 30
        session = URLSession(configuration: configuration, delegate: StopAtEveryRedirect(), delegateQueue: nil)
    }

    /// How many times the person typed their password.
    var credentialsPosted: Int { locked { credentialPosts } }
    /// The URLs the SDK opened, and the callbacks handed back.
    var openedURLs: [URL] { locked { opened } }
    var callbacks: [URL] { locked { returned } }
    var history: [Step] { locked { steps } }

    @MainActor
    func open(_ url: URL, redirectURI: URL) async throws -> URL {
        try await walk(from: url, until: redirectURI)
    }

    /// The match `ASWebAuthenticationSession.Callback.https(host:path:)` makes:
    /// an `https` URL on the redirect's host, at its path. Its query is the
    /// response, so it is not compared.
    static func isCallback(_ url: URL, for redirectURI: URL) -> Bool {
        url.scheme?.lowercased() == "https"
            && url.host?.lowercased() == redirectURI.host?.lowercased()
            && url.path == (redirectURI.path.isEmpty ? "/" : redirectURI.path)
    }

    /// The target of the server's leaving page: its
    /// `<meta http-equiv="refresh" content="0;url=…">`, unescaped exactly as
    /// the server escaped it, `&amp;` last. Nil for any other page.
    static func leavingPageTarget(_ html: String) -> String? {
        let mark = "<meta http-equiv=\"refresh\" content=\"0;url="
        guard let start = html.range(of: mark)?.upperBound,
              let end = html[start...].firstIndex(of: "\"") else { return nil }
        return String(html[start..<end])
            .replacingOccurrences(of: "&#x27;", with: "'")
            .replacingOccurrences(of: "&quot;", with: "\"")
            .replacingOccurrences(of: "&gt;", with: ">")
            .replacingOccurrences(of: "&lt;", with: "<")
            .replacingOccurrences(of: "&amp;", with: "&")
    }

    private func walk(from start: URL, until redirectURI: URL) async throws -> URL {
        locked { opened.append(start) }
        var request = URLRequest(url: start)
        var loginShown = false
        for _ in 0..<Self.maximumSteps {
            let (body, response) = try await send(request)
            let here = request.url ?? start
            switch response.statusCode {
            case 301, 302, 303, 307, 308:
                guard let location = response.value(forHTTPHeaderField: "Location"),
                      let next = URL(string: location, relativeTo: here)?.absoluteURL else {
                    throw failure("a redirect with no usable Location", here, response, body)
                }
                if Self.isCallback(next, for: redirectURI) {
                    locked { returned.append(next) }
                    return next
                }
                guard ["http", "https"].contains(next.scheme?.lowercased() ?? "") else {
                    throw failure("a redirect to \(next.absoluteString), which is neither the web nor the redirect URI", here, response, body)
                }
                if response.statusCode == 307 || response.statusCode == 308 {
                    request.url = next
                } else {
                    request = URLRequest(url: next)
                }
            case 200:
                let html = String(decoding: body, as: UTF8.self)
                // The page the server answers a sign-in, consent or logout form
                // with when its chain can end at the app: it moves on by meta
                // refresh rather than a 303,
                // and is followed as a browser follows it.
                if let target = Self.leavingPageTarget(html),
                   let next = URL(string: target, relativeTo: here)?.absoluteURL {
                    if Self.isCallback(next, for: redirectURI) {
                        locked { returned.append(next) }
                        return next
                    }
                    request = URLRequest(url: next)
                    continue
                }
                guard let form = HTMLForm.all(in: html).first(where: { $0.method == "post" }) else {
                    throw failure("a page with no form to submit", here, response, body)
                }
                if form.isLogin {
                    // The same form again is a refused password, not a step.
                    guard !loginShown else { throw failure("the login form came back: the credentials were refused", here, response, body) }
                    loginShown = true
                    locked { credentialPosts += 1 }
                }
                guard let action = URL(string: form.action.isEmpty ? here.absoluteString : form.action, relativeTo: here)?.absoluteURL else {
                    throw failure("a form whose action is not a URL", here, response, body)
                }
                var post = URLRequest(url: action)
                post.httpMethod = "POST"
                post.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
                post.httpBody = Data(FormEncoding.encode(form.submission(username: username, password: password)).utf8)
                request = post
            default:
                throw failure("an unexpected answer", here, response, body)
            }
        }
        throw LiveFailure("no redirect to \(redirectURI.absoluteString) within \(Self.maximumSteps) steps: \(history)")
    }

    private func send(_ original: URLRequest) async throws -> (Data, HTTPURLResponse) {
        var request = original
        let sameOrigin = isIssuerOrigin(request.url)
        if sameOrigin {
            let cookies = locked { jar.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: "; ") }
            if !cookies.isEmpty { request.setValue(cookies, forHTTPHeaderField: "Cookie") }
        }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw LiveFailure("\(request.url?.absoluteString ?? "?") answered without HTTP") }
        if sameOrigin, let header = http.value(forHTTPHeaderField: "Set-Cookie") { absorb(header) }
        locked { steps.append(Step(method: request.httpMethod ?? "GET", url: request.url!, status: http.statusCode)) }
        return (data, http)
    }

    private func isIssuerOrigin(_ url: URL?) -> Bool {
        guard let url else { return false }
        return url.scheme == issuer.scheme && url.host == issuer.host && url.port == issuer.port
    }

    /// `Set-Cookie`, as Foundation hands it over: several headers joined with
    /// ", ". Split only where the next piece starts a `name=` pair, so the
    /// comma inside an `Expires` date stays with its cookie.
    private func absorb(_ header: String) {
        let splitter = try! NSRegularExpression(pattern: ",\\s*(?=[!#$%&'*+.^_`|~0-9A-Za-z-]+=)")
        let whole = NSRange(header.startIndex..., in: header)
        var pieces: [String] = []
        var start = header.startIndex
        for match in splitter.matches(in: header, range: whole) {
            let range = Range(match.range, in: header)!
            pieces.append(String(header[start..<range.lowerBound]))
            start = range.upperBound
        }
        pieces.append(String(header[start...]))
        locked {
            for piece in pieces {
                let attributes = piece.split(separator: ";").map { $0.trimmingCharacters(in: .whitespaces) }
                guard let pair = attributes.first, let equals = pair.firstIndex(of: "=") else { continue }
                let name = String(pair[..<equals])
                let value = String(pair[pair.index(after: equals)...])
                let expired = attributes.dropFirst().contains { $0.lowercased() == "max-age=0" }
                if expired || value.isEmpty { jar[name] = nil } else { jar[name] = value }
            }
        }
    }

    private func failure(_ what: String, _ url: URL, _ response: HTTPURLResponse, _ body: Data) -> LiveFailure {
        let text = String(decoding: body.prefix(600), as: UTF8.self)
        return LiveFailure("\(what): \(url.absoluteString) answered \(response.statusCode) \(text) — steps so far: \(history)")
    }

    private func locked<T>(_ body: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return body()
    }
}

private final class StopAtEveryRedirect: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

/// Just enough HTML to submit the server's forms as a person would.
struct HTMLForm: Equatable {
    struct Field: Equatable {
        let name: String
        let type: String
        let value: String
    }

    let action: String
    let method: String
    let inputs: [Field]
    let buttons: [Field]

    /// A form that asks for a password: the login form.
    var isLogin: Bool { inputs.contains { $0.type == "password" } }

    static func all(in html: String) -> [HTMLForm] {
        matches(#"<form\b([^>]*)>(.*?)</form>"#, in: html).map { groups in
            let attributes = Self.attributes(groups[0])
            let inner = groups[1]
            func fields(_ tag: String) -> [Field] {
                matches("<\(tag)\\b([^>]*)>", in: inner).map { tagGroups in
                    let a = Self.attributes(tagGroups[0])
                    return Field(name: a["name"] ?? "", type: (a["type"] ?? (tag == "button" ? "submit" : "text")).lowercased(), value: a["value"] ?? "")
                }
            }
            return HTMLForm(
                action: attributes["action"] ?? "",
                method: (attributes["method"] ?? "get").lowercased(),
                inputs: fields("input"),
                buttons: fields("button")
            )
        }
    }

    /// What pressing the form's submit button sends: every hidden field as
    /// served, the username and password on a login form, and — on a consent
    /// page — the button that allows.
    func submission(username: String, password: String) -> [(String, String)] {
        var fields: [(String, String)] = []
        for input in inputs where !input.name.isEmpty {
            switch input.type {
            case "hidden": fields.append((input.name, input.value))
            case "password": fields.append((input.name, password))
            case "text", "email": if isLogin { fields.append((input.name, username)) }
            default: break
            }
        }
        let named = buttons.filter { !$0.name.isEmpty && $0.type == "submit" }
        if let press = named.first(where: { ["allow", "approve", "accept"].contains($0.value.lowercased()) }) ?? (named.count == 1 ? named.first : nil) {
            fields.append((press.name, press.value))
        }
        return fields
    }

    private static func attributes(_ text: String) -> [String: String] {
        var result: [String: String] = [:]
        for groups in matches(#"([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*"([^"]*)""#, in: text) {
            result[groups[0].lowercased()] = decodeEntities(groups[1])
        }
        return result
    }

    private static func matches(_ pattern: String, in text: String) -> [[String]] {
        let regex = try! NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators, .caseInsensitive])
        return regex.matches(in: text, range: NSRange(text.startIndex..., in: text)).map { match in
            (1..<match.numberOfRanges).map { index in
                Range(match.range(at: index), in: text).map { String(text[$0]) } ?? ""
            }
        }
    }

    /// The character references an attribute value may carry, decoded in one
    /// pass so `&amp;lt;` stays `&lt;`.
    static func decodeEntities(_ text: String) -> String {
        let regex = try! NSRegularExpression(pattern: "&(#[xX][0-9A-Fa-f]+|#[0-9]+|amp|lt|gt|quot|apos);")
        var out = ""
        var cursor = text.startIndex
        for match in regex.matches(in: text, range: NSRange(text.startIndex..., in: text)) {
            let whole = Range(match.range, in: text)!
            let name = String(text[Range(match.range(at: 1), in: text)!])
            out += text[cursor..<whole.lowerBound]
            let scalar: Unicode.Scalar?
            switch name {
            case "amp": scalar = "&"
            case "lt": scalar = "<"
            case "gt": scalar = ">"
            case "quot": scalar = "\""
            case "apos": scalar = "'"
            default:
                let hex = name.hasPrefix("#x") || name.hasPrefix("#X")
                let digits = name.dropFirst(hex ? 2 : 1)
                scalar = UInt32(digits, radix: hex ? 16 : 10).flatMap(Unicode.Scalar.init)
            }
            if let scalar { out.unicodeScalars.append(scalar) } else { out += text[whole] }
            cursor = whole.upperBound
        }
        out += text[cursor...]
        return out
    }
}
