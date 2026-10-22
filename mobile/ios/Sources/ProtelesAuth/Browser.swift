import Foundation

#if canImport(AuthenticationServices)
import AuthenticationServices
#endif

/// The browser hop (§10.2 step 3): show `url` in a browser the app cannot
/// script, and return the URL the server redirected to.
///
/// `SystemBrowser` (`ASWebAuthenticationSession`) is the implementation; the
/// protocol exists so tests can stand in for the user. **Never implement it
/// with a WKWebView**: an embedded web view lets the app read the password
/// the user types, which is the thing OAuth exists to prevent (RFC 8252 §8.12).
public protocol AuthorizationBrowser: Sendable {
    /// - Parameters:
    ///   - url: the authorization or end-session URL.
    ///   - redirectURI: the URI whose arrival ends the hop.
    /// - Returns: the full callback URL, query included.
    /// - Throws: `ProtelesAuthError.cancelled` when the user dismisses it.
    @MainActor func open(_ url: URL, redirectURI: URL) async throws -> URL
}

/// One browser hop's continuation, resumed exactly once — by the browser's
/// completion, a failed start, or the awaiting task's cancellation, whichever
/// comes first; anything later is ignored.
///
/// Cancellation dismisses the browser *and* resumes, rather than dismissing
/// and waiting for the browser to call back: `ASWebAuthenticationSession`
/// does not document that `cancel()` runs its completion handler, and if it
/// did not, a cancelled sign-in would never return.
final class BrowserHop: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<URL, any Error>?
    private var dismiss: (@MainActor () -> Void)?

    fileprivate func install(_ continuation: CheckedContinuation<URL, any Error>) {
        lock.lock()
        defer { lock.unlock() }
        self.continuation = continuation
    }

    fileprivate func onDismiss(_ dismiss: @escaping @MainActor () -> Void) {
        lock.lock()
        defer { lock.unlock() }
        self.dismiss = dismiss
    }

    /// Delivers the hop's result, the first time only. Any thread.
    func finish(_ result: Result<URL, any Error>) {
        lock.lock()
        let continuation = self.continuation
        self.continuation = nil
        lock.unlock()
        continuation?.resume(with: result)
    }

    /// Dismisses the browser and ends the hop as cancelled.
    @MainActor fileprivate func cancel() {
        lock.lock()
        let dismiss = self.dismiss
        self.dismiss = nil
        lock.unlock()
        dismiss?()
        finish(.failure(ProtelesAuthError.cancelled))
    }

    /// Runs one hop: `start` presents the browser, arranges for the browser's
    /// outcome to reach `hop.finish`, and returns how to dismiss it — or
    /// throws when it could not start. Returns the callback URL.
    @MainActor
    static func run(_ start: (_ hop: BrowserHop) throws -> (@MainActor () -> Void)) async throws -> URL {
        if Task.isCancelled { throw ProtelesAuthError.cancelled }
        let hop = BrowserHop()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                hop.install(continuation)
                do {
                    hop.onDismiss(try start(hop))
                } catch {
                    hop.finish(.failure(error))
                }
            }
        } onCancel: {
            Task { @MainActor in hop.cancel() }
        }
    }
}

#if canImport(AuthenticationServices) && (os(iOS) || os(macOS))

/// `ASWebAuthenticationSession`: the system browser, sharing Safari's cookies
/// unless `prefersEphemeralWebBrowserSession` is set, presented over
/// `presentationAnchor`.
///
/// The redirect it intercepts is an `https` Universal Link, through
/// `ASWebAuthenticationSession.Callback.https(host:path:)` (iOS 17.4, macOS
/// 14.4, the package's floor). The server registers no private-use scheme
/// (M7), and the session cannot intercept a loopback `http` redirect, so
/// `ProtelesConfiguration` refuses both (§10.1).
///
/// One instance shows one browser at a time: a second `open` while the first
/// is showing throws `.alreadyInProgress`. Cancelling the task that awaits
/// `open` dismisses the browser and throws `.cancelled`. When the system will
/// not show a browser at all it throws `.browserUnavailable` (§10.7).
@MainActor
public final class SystemBrowser: NSObject, AuthorizationBrowser, ASWebAuthenticationPresentationContextProviding {
    private let anchor: ASPresentationAnchor
    public let prefersEphemeralWebBrowserSession: Bool
    private var presenting = false

    /// - Parameters:
    ///   - presentationAnchor: the window to present over.
    ///   - prefersEphemeralWebBrowserSession: `true` shares no cookies with
    ///     Safari, so the user types credentials every time and sign-out never
    ///     needs the browser half; `false` (the default) gives single sign-on,
    ///     and a sign-out that wants the next sign-in to ask again must also
    ///     end the browser session (§10.4).
    public init(presentationAnchor: ASPresentationAnchor, prefersEphemeralWebBrowserSession: Bool = false) {
        self.anchor = presentationAnchor
        self.prefersEphemeralWebBrowserSession = prefersEphemeralWebBrowserSession
        super.init()
    }

    public func open(_ url: URL, redirectURI: URL) async throws -> URL {
        guard redirectURI.scheme?.lowercased() == "https", let host = redirectURI.host, !host.isEmpty else {
            throw ProtelesAuthError.configuration(
                "the redirect must be an https Universal Link; ProtelesConfiguration refuses anything else (§10.1, M7)")
        }
        guard !presenting else { throw ProtelesAuthError.alreadyInProgress }
        presenting = true
        defer { presenting = false }

        return try await BrowserHop.run { hop in
            // @Sendable, so it carries no main-actor isolation the system
            // could trip over by calling it from another queue. Weak: the hop
            // is over once `run` returns, and a late callback has no one to tell.
            let completion: @Sendable (URL?, (any Error)?) -> Void = { [weak hop] callback, error in
                hop?.finish(Self.outcome(callback: callback, error: error))
            }
            let path = redirectURI.path.isEmpty ? "/" : redirectURI.path
            let session = ASWebAuthenticationSession(
                url: url, callback: .https(host: host, path: path), completionHandler: completion)
            session.presentationContextProvider = self
            session.prefersEphemeralWebBrowserSession = prefersEphemeralWebBrowserSession
            try Self.requireStarted(session.start())
            return { session.cancel() }
        }
    }

    /// `ASWebAuthenticationSession.start()` returning `false`: the system
    /// would not show a browser — nothing can open the sign-in page (§10.7).
    nonisolated static func requireStarted(_ started: Bool) throws {
        guard started else {
            throw ProtelesAuthError.browserUnavailable("ASWebAuthenticationSession did not start")
        }
    }

    /// The session's completion as the hop's result: the user dismissing it is
    /// `.cancelled`; a presentation anchor the app did not provide, or one it
    /// cannot use, is the app's `.configuration`; any other failure is a
    /// browser that could not show the page, `.browserUnavailable`.
    nonisolated static func outcome(callback: URL?, error: (any Error)?) -> Result<URL, any Error> {
        if let callback { return .success(callback) }
        guard let error else { return .failure(ProtelesAuthError.cancelled) }
        if let error = error as? ASWebAuthenticationSessionError {
            switch error.code {
            case .canceledLogin:
                return .failure(ProtelesAuthError.cancelled)
            case .presentationContextNotProvided, .presentationContextInvalid:
                return .failure(ProtelesAuthError.configuration("the browser cannot be presented: \(error.localizedDescription)"))
            @unknown default:
                break
            }
        }
        return .failure(ProtelesAuthError.browserUnavailable("the browser failed: \(error.localizedDescription)"))
    }

    public nonisolated func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        MainActor.assumeIsolated { anchor }
    }
}

extension ProtelesClient {
    /// Signs in through `ASWebAuthenticationSession` presented over `window`.
    @MainActor
    public func signIn(
        presentationAnchor window: ASPresentationAnchor,
        prefersEphemeralWebBrowserSession: Bool = false
    ) async throws -> UserClaims {
        let browser = SystemBrowser(
            presentationAnchor: window,
            prefersEphemeralWebBrowserSession: prefersEphemeralWebBrowserSession
        )
        return try await signIn(using: browser)
    }

    /// Signs out, and also ends the browser session through
    /// `ASWebAuthenticationSession` presented over `window` — call it from a
    /// user gesture (§10.4, M5).
    @MainActor
    @discardableResult
    public func signOut(endSessionPresentingFrom window: ASPresentationAnchor) async throws -> SignOutResult {
        try await signOut(endSession: SystemBrowser(presentationAnchor: window))
    }
}

#endif
