import Foundation
import Testing
@testable import ProtelesAuth

/// The machinery `SystemBrowser` runs `ASWebAuthenticationSession` in, with
/// the session played by the test: a browser that presents, may or may not
/// call back, and records being dismissed. The session itself needs a
/// simulator.
@Suite("The browser hop (§10.2 step 3)")
@MainActor
struct BrowserHopTests {
    private let callback = URL(string: "\(Fixture.redirectURI)?code=c&state=s")!

    @Test("cancelling the awaiting task dismisses the browser and throws .cancelled — even if the browser never calls back")
    func cancelledWithoutACallback() async throws {
        let presented = Gate()
        let dismissed = Recorded(false)
        let hop = Task { @MainActor in
            try await BrowserHop.run { _ in
                presented.open()
                return { dismissed.value = true } // and never calls back
            }
        }
        await presented.wait()
        hop.cancel()
        await #expect(throws: ProtelesAuthError.cancelled) { _ = try await hop.value }
        #expect(dismissed.value)
    }

    @Test("a callback after cancellation is ignored")
    func lateCallback() async throws {
        let presented = Gate()
        let running = Recorded<BrowserHop?>(nil)
        let hop = Task { @MainActor in
            try await BrowserHop.run { hop in
                running.value = hop
                presented.open()
                return {}
            }
        }
        await presented.wait()
        hop.cancel()
        await #expect(throws: ProtelesAuthError.cancelled) { _ = try await hop.value }
        // What ASWebAuthenticationSession may do after cancel(): resuming a
        // second time would trap.
        running.value?.finish(.success(callback))
        running.value?.finish(.failure(ProtelesAuthError.cancelled))
    }

    @Test("the browser's own outcome is returned, once")
    func completes() async throws {
        let callback = self.callback
        let url = try await BrowserHop.run { hop in
            hop.finish(.success(callback))
            hop.finish(.failure(ProtelesAuthError.cancelled)) // ignored
            return {}
        }
        #expect(url == callback)
    }

    @Test("a browser that calls back from another thread")
    func completesOffTheMainThread() async throws {
        let callback = self.callback
        let url = try await BrowserHop.run { hop in
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.05) { hop.finish(.success(callback)) }
            return {}
        }
        #expect(url == callback)
    }

    @Test("a browser that cannot start is the hop's error")
    func cannotStart() async throws {
        await #expect(throws: ProtelesAuthError.browserUnavailable("ASWebAuthenticationSession did not start")) {
            _ = try await BrowserHop.run { _ in
                #if canImport(AuthenticationServices)
                try SystemBrowser.requireStarted(false)
                #else
                throw ProtelesAuthError.browserUnavailable("ASWebAuthenticationSession did not start")
                #endif
                return {}
            }
        }
    }

    @Test("a task already cancelled never presents the browser")
    func alreadyCancelled() async throws {
        let presented = Recorded(false)
        let hop = Task { @MainActor in
            withUnsafeCurrentTask { $0?.cancel() }
            return try await BrowserHop.run { _ in
                presented.value = true
                return {}
            }
        }
        await #expect(throws: ProtelesAuthError.cancelled) { _ = try await hop.value }
        #expect(!presented.value)
    }
}

#if canImport(AuthenticationServices)
import AuthenticationServices

/// How `SystemBrowser` reads `ASWebAuthenticationSession`'s outcomes (§10.7).
/// The session itself needs a simulator; the reading does not.
@Suite("The system browser's outcomes")
struct SystemBrowserOutcomeTests {
    private func error(_ result: Result<URL, any Error>) -> ProtelesAuthError? {
        guard case .failure(let error) = result else { return nil }
        return error as? ProtelesAuthError
    }

    @Test("a session the system will not start is browser unavailable, not a configuration error")
    func didNotStart() {
        #expect(throws: ProtelesAuthError.browserUnavailable("ASWebAuthenticationSession did not start")) {
            try SystemBrowser.requireStarted(false)
        }
        #expect(throws: Never.self) { try SystemBrowser.requireStarted(true) }
    }

    @Test func outcomes() throws {
        let callback = URL(string: "\(Fixture.redirectURI)?code=c")!
        #expect(try SystemBrowser.outcome(callback: callback, error: nil).get() == callback)
        #expect(error(SystemBrowser.outcome(callback: nil, error: ASWebAuthenticationSessionError(.canceledLogin))) == .cancelled)
        #expect(error(SystemBrowser.outcome(callback: nil, error: nil)) == .cancelled)
        guard case .configuration? = error(SystemBrowser.outcome(callback: nil, error: ASWebAuthenticationSessionError(.presentationContextInvalid))) else {
            Issue.record("an unusable presentation anchor is the app's configuration")
            return
        }
        guard case .browserUnavailable? = error(SystemBrowser.outcome(callback: nil, error: URLError(.cannotLoadFromNetwork))) else {
            Issue.record("any other failure is a browser that could not show the page")
            return
        }
    }
}
#endif
