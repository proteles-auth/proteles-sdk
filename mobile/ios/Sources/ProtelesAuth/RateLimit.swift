import Foundation

/// After a 429 — from the token endpoint, the code exchange, revocation,
/// discovery or the key set, on any path — no token request is sent, no
/// refresh is attempted and no sign-in opens the browser until the wait has
/// passed (docs/mobile-SDKs.md §10.9 items 3 and 8; §2.5: a request into a
/// latched bucket keeps it latched). The wait is `Retry-After`, capped at an
/// hour, or `defaultWait` when the server sent none this SDK can read.
///
/// One per client, in memory, shared by everything that talks to the server —
/// the Android SDK's `RateLimitGate`. Revocation is not held back by it: a
/// person signing out is always allowed to try.
final class RateLimitGate: @unchecked Sendable {
    /// How long to hold off after a 429 whose `Retry-After` cannot be read
    /// (§10.9 item 3).
    static let defaultWait: TimeInterval = 60

    private let now: @Sendable () -> Date
    private let lock = NSLock()
    private var notBefore: Date?

    init(now: @escaping @Sendable () -> Date) {
        self.now = now
    }

    /// Seconds until requests may be sent again, or `nil` when they may be
    /// sent now.
    func remaining() -> TimeInterval? {
        let at = now()
        lock.lock()
        defer { lock.unlock() }
        guard let notBefore, at < notBefore else { return nil }
        return notBefore.timeIntervalSince(at)
    }

    /// Closes the gate for `response`, a 429, and returns the error that
    /// reports the wait this client now observes.
    func close(_ response: HTTPResponse) -> ProtelesAuthError {
        let at = now()
        let wait = RetryAfter.parse(response.header("Retry-After"), now: at) ?? Self.defaultWait
        let until = at.addingTimeInterval(wait)
        lock.lock()
        // Two 429s in flight at once: the later deadline stands.
        if notBefore.map({ until > $0 }) ?? true { notBefore = until }
        lock.unlock()
        return .rateLimited(retryAfter: wait)
    }
}
