import Foundation

/// The parts of `/.well-known/openid-configuration` the SDK uses (§10.2 step 1).
struct DiscoveryDocument: Sendable, Equatable {
    let issuer: String
    let authorizationEndpoint: URL
    let tokenEndpoint: URL
    let jwksURI: URL
    let revocationEndpoint: URL?
    let endSessionEndpoint: URL?

    static func fetch(_ configuration: ProtelesConfiguration, transport: any HTTPTransport, gate: RateLimitGate) async throws -> DiscoveryDocument {
        let request = HTTPRequest(method: "GET", url: configuration.discoveryURL, headers: ["Accept": "application/json"])
        let response: HTTPResponse
        do {
            response = try await transport.send(request)
        } catch {
            throw asProtelesError(error)
        }
        switch response.status {
        case 200:
            return try parse(response.body, configuration: configuration)
        case 429:
            throw gate.close(response)
        case 500...:
            throw ProtelesAuthError.network("discovery at \(configuration.discoveryURL.absoluteString) answered HTTP \(response.status)", status: response.status)
        default:
            throw ProtelesAuthError.configuration("discovery at \(configuration.discoveryURL.absoluteString) answered HTTP \(response.status); is the issuer right?")
        }
    }

    static func parse(_ data: Data, configuration: ProtelesConfiguration) throws -> DiscoveryDocument {
        guard let document = JSONValue.parseObject(data) else {
            throw ProtelesAuthError.configuration("the discovery document is not a JSON object")
        }
        // Byte for byte, like every other issuer comparison (§5.2 rule 2).
        let issuer = document["issuer"]?.stringValue
        guard let issuer, bytesEqual(issuer, configuration.issuer) else {
            throw ProtelesAuthError.issuerMismatch(expected: configuration.issuer, received: issuer)
        }
        /// An endpoint is absent (`null` counts), or a string naming an
        /// absolute `https` URL with no fragment — or, for a loopback
        /// development issuer, an `http` URL on loopback too. As the Android
        /// SDK reads it: a member of another type is refused, not ignored.
        func endpoint(_ name: String, required: Bool) throws -> URL? {
            let value: String
            switch document[name] {
            case nil, .null?:
                if required { throw ProtelesAuthError.configuration("the discovery document has no \(name)") }
                return nil
            case .string(let string)?:
                value = string
            default:
                throw ProtelesAuthError.configuration("discovery's \(name) is not a string")
            }
            guard !value.contains("#"), let url = URL(string: value), let parts = URLComponents(string: value),
                  let scheme = parts.scheme, let host = parts.host, !host.isEmpty else {
                throw ProtelesAuthError.configuration("discovery's \(name) \"\(value)\" is not an absolute URL without a fragment")
            }
            // A cleartext endpoint is where a code, a verifier or a refresh
            // token is read by anyone on the path. Only a loopback development
            // issuer may point at one, and only at this machine: never a
            // cleartext hop to a host elsewhere. The scheme and host are
            // compared as spelled, like the issuer's (§10.1).
            switch scheme {
            case "https":
                return url
            case "http" where configuration.issuerIsLoopbackHTTP && ProtelesConfiguration.loopbackIssuerHosts.contains(host):
                return url
            default:
                throw ProtelesAuthError.configuration("discovery's \(name) \"\(value)\" is not https")
            }
        }
        return DiscoveryDocument(
            issuer: issuer,
            authorizationEndpoint: try endpoint("authorization_endpoint", required: true)!,
            tokenEndpoint: try endpoint("token_endpoint", required: true)!,
            jwksURI: try endpoint("jwks_uri", required: true)!,
            revocationEndpoint: try endpoint("revocation_endpoint", required: false),
            endSessionEndpoint: try endpoint("end_session_endpoint", required: false)
        )
    }
}

/// RFC 9110 §10.2.3: `Retry-After` is either delay-seconds or an HTTP-date.
///
/// Capped at an hour. Proteles sends small integers, but a 429 from a proxy or
/// CDN in front of it is parsed the same way, and an unbounded value would
/// stop refreshes until the process restarts — `99999999999999999999` is
/// 1e20 seconds, and three hundred digits is infinity.
enum RetryAfter {
    static let maximum: TimeInterval = 3600

    static func parse(_ value: String?, now: Date) -> TimeInterval? {
        guard let value = value?.trimmingCharacters(in: .whitespaces), !value.isEmpty else { return nil }
        if value.utf8.allSatisfy({ (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0) }) {
            // All digits: a delay. Too many digits for a Double is "a long
            // time", which the cap turns into an hour.
            let seconds = TimeInterval(value) ?? .infinity
            return seconds.isFinite ? min(seconds, maximum) : maximum
        }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "GMT")
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
        guard let date = formatter.date(from: value) else { return nil }
        return min(max(0, date.timeIntervalSince(now)), maximum)
    }
}
