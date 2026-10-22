import Foundation

/// Keeps the process running while a refresh is in flight, and says when the
/// system is about to suspend it anyway.
///
/// A refresh can hold the App Group lock file across its requests, and iOS
/// terminates a suspended process that holds a file lock in a shared
/// container (`0xdead10cc`). So the client asks for background time around
/// every refresh, and when that time runs out with a lock that may be
/// cross-process it cancels the refresh: the requests fail, the lock is
/// released, and the process suspends cleanly. With only the in-process lock
/// it lets the refresh finish when the process resumes instead: there is no
/// file lock to release, and an abandoned rotation loses its refresh token.
protocol BackgroundActivity: Sendable {
    /// Begins an activity. `expire` is called at most once, on any thread,
    /// when the system is about to suspend the process; the work must then
    /// stop quickly. Returns the function that ends the activity — call it
    /// once, when the work is done.
    func begin(reason: String, expire: @escaping @Sendable () -> Void) -> @Sendable () -> Void
}

/// On iOS, `ProcessInfo.performExpiringActivity`, which apps and app
/// extensions can both use (`UIApplication.beginBackgroundTask` is
/// unavailable in an extension). The assertion lasts as long as its block
/// runs, so the block waits — on a thread of its own, never one of Swift
/// concurrency's — until the activity is ended.
///
/// On macOS, nothing: a Mac app is not suspended in the background, so there
/// is no `0xdead10cc` to avoid, and the API does not exist there.
struct ProcessBackgroundActivity: BackgroundActivity {
    func begin(reason: String, expire: @escaping @Sendable () -> Void) -> @Sendable () -> Void {
        #if os(iOS)
        let state = ActivityState(expire: expire)
        ProcessInfo.processInfo.performExpiringActivity(withReason: reason) { expired in
            if expired {
                state.expire()
            } else {
                state.waitUntilEnded()
            }
        }
        return { state.end() }
        #else
        return {}
        #endif
    }
}

#if os(iOS)
private final class ActivityState: @unchecked Sendable {
    private let ended = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var onExpire: (@Sendable () -> Void)?

    init(expire: @escaping @Sendable () -> Void) {
        onExpire = expire
    }

    func expire() {
        lock.lock()
        let handler = onExpire
        onExpire = nil
        lock.unlock()
        handler?()
    }

    func waitUntilEnded() {
        ended.wait()
    }

    func end() {
        lock.lock()
        onExpire = nil
        lock.unlock()
        ended.signal()
    }
}
#endif
