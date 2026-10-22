import Foundation

/// One HTTP request, as the SDK makes it.
public struct HTTPRequest: Sendable, Equatable {
    public var method: String
    public var url: URL
    public var headers: [String: String]
    public var body: Data?

    public init(method: String, url: URL, headers: [String: String] = [:], body: Data? = nil) {
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
    }

    /// The body as a string, for tests and diagnostics.
    public var bodyString: String? { body.map { String(decoding: $0, as: UTF8.self) } }

    /// The body decoded as a form, for tests and diagnostics.
    public var formFields: [(name: String, value: String)] { FormEncoding.decode(bodyString ?? "") }
}

/// One HTTP response. Header names are case-insensitive.
public struct HTTPResponse: Sendable, Equatable {
    public var status: Int
    public var headers: [String: String]
    public var body: Data

    public init(status: Int, headers: [String: String] = [:], body: Data = Data()) {
        self.status = status
        self.headers = Dictionary(headers.map { ($0.key.lowercased(), $0.value) }, uniquingKeysWith: { _, last in last })
        self.body = body
    }

    public func header(_ name: String) -> String? { headers[name.lowercased()] }
}

/// How the SDK talks to the server. `URLSessionTransport` is the default;
/// tests and unusual apps (certificate pinning, a custom proxy) supply their
/// own. Throw for a request that got no HTTP response at all; return any
/// response that arrived, whatever its status.
public protocol HTTPTransport: Sendable {
    func send(_ request: HTTPRequest) async throws -> HTTPResponse
}

/// `URLSession`, ephemeral: no cookie jar, no URL cache, no credential store —
/// the token endpoint's answers are secrets, and none of them belongs on disk
/// outside the Keychain. Redirects are not followed: none of the endpoints the
/// SDK calls redirects, and a `307` would re-send a refresh token to wherever
/// it pointed.
///
/// A response body is read up to `maximumResponseBytes` — 1 MiB, the Android
/// SDK's cap — and a larger one is a `.network` error, whichever session is
/// used: nothing the SDK fetches is within a thousandth of it, and a proxy or
/// a misconfigured endpoint streaming without end would otherwise be held in
/// memory whole.
public struct URLSessionTransport: HTTPTransport {
    /// 1 MiB.
    public static let defaultMaximumResponseBytes = 1 << 20

    private let session: URLSession
    private let maximumResponseBytes: Int

    public init(timeout: TimeInterval = 30, maximumResponseBytes: Int = URLSessionTransport.defaultMaximumResponseBytes) {
        self.maximumResponseBytes = maximumResponseBytes
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = timeout
        configuration.timeoutIntervalForResource = timeout * 2
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        self.session = URLSession(configuration: configuration, delegate: RefuseRedirects(), delegateQueue: nil)
    }

    /// An app-supplied session, for pinning or proxies. The caller owns its
    /// cache, cookie and redirect policy; the response cap still applies.
    public init(session: URLSession, maximumResponseBytes: Int = URLSessionTransport.defaultMaximumResponseBytes) {
        self.session = session
        self.maximumResponseBytes = maximumResponseBytes
    }

    public func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        var urlRequest = URLRequest(url: request.url)
        urlRequest.httpMethod = request.method
        urlRequest.httpBody = request.body
        urlRequest.cachePolicy = .reloadIgnoringLocalCacheData
        for (name, value) in request.headers {
            urlRequest.setValue(value, forHTTPHeaderField: name)
        }
        func failed(_ error: any Error) -> ProtelesAuthError {
            .network("\(request.method) \(request.url.absoluteString): \(error.localizedDescription)")
        }
        let tooLarge = ProtelesAuthError.network(
            "\(request.url.absoluteString) answered with more than \(maximumResponseBytes) bytes")
        let stream: URLSession.AsyncBytes
        let response: URLResponse
        do {
            (stream, response) = try await session.bytes(for: urlRequest)
        } catch {
            throw failed(error)
        }
        guard let http = response as? HTTPURLResponse else {
            stream.task.cancel()
            throw ProtelesAuthError.network("\(request.url.absoluteString) answered without an HTTP response")
        }
        // Refused before reading when the server says how much is coming;
        // otherwise counted as it arrives.
        if http.expectedContentLength > Int64(maximumResponseBytes) {
            stream.task.cancel()
            throw tooLarge
        }
        var data = Data()
        data.reserveCapacity(Int(max(0, min(http.expectedContentLength, Int64(maximumResponseBytes)))))
        do {
            for try await byte in stream {
                guard data.count < maximumResponseBytes else {
                    stream.task.cancel()
                    throw tooLarge
                }
                data.append(byte)
            }
        } catch let error as ProtelesAuthError {
            throw error
        } catch {
            throw failed(error)
        }
        var headers: [String: String] = [:]
        for (name, value) in http.allHeaderFields {
            if let name = name as? String, let value = value as? String {
                headers[name.lowercased()] = value
            }
        }
        return HTTPResponse(status: http.statusCode, headers: headers, body: data)
    }
}

private final class RefuseRedirects: NSObject, URLSessionTaskDelegate, Sendable {
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
