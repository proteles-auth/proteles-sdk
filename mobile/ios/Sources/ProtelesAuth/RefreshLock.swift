import Foundation

/// Serialises refreshes (docs/mobile-SDKs.md §10.6).
///
/// Two processes of one app — the app and its share extension — share one
/// Keychain record, and rotation is single-use: two concurrent refreshes
/// leave one of them holding a dead token (§4). Everything that reads the
/// stored refresh token and writes its successor runs inside this lock, and
/// re-reads the store once it holds it.
///
/// `withLock` throws only when the lock cannot be taken (a timeout, a lock
/// file that cannot be opened, cancellation) or when `body` throws. When it
/// cannot be taken (§10.9 items 7 and 9): sign-out clears anyway, a refresh
/// re-reads the store and hands out a usable token if one is there, and a
/// sign-in fails and revokes the tokens it could not safely store.
public protocol RefreshLock: Sendable {
    func withLock<T: Sendable>(_ body: @Sendable () async throws -> T) async throws -> T
}

/// Which lock a client is using, so an app can say so in its diagnostics.
public enum RefreshLockScope: Sendable, Equatable {
    /// `flock` on a file every process of the app can reach.
    case crossProcess(lockFile: URL)
    /// Only this process. An extension refreshing at the same moment can
    /// still burn the session; configure an App Group to close that.
    case inProcess
    /// A lock the app supplied.
    case custom
}

/// `flock(2)` on a lock file — in the App Group container, so every process
/// of the app contends for the same one.
///
/// The wait polls with `LOCK_NB` rather than blocking a thread in `flock`, so
/// it never parks a cooperative-pool thread and a cancelled task stops
/// waiting. Each `withLock` opens its own descriptor: `flock` locks belong to
/// the open file description, so two clients in one process also exclude each
/// other.
///
/// iOS terminates a suspended app that holds a file lock in a shared container
/// (`0xdead10cc`). A refresh holds this lock across the token request and, when
/// the new ID token names a key the client has not fetched, a key-set request —
/// each bounded by the transport's timeouts. `ProtelesClient` runs every
/// refresh under a background-execution assertion
/// (`ProcessInfo.performExpiringActivity`, which works in apps and extensions)
/// and cancels the refresh — releasing the lock — when the system says the
/// time is up. Sign-in and sign-out hold the lock only for a Keychain write.
///
/// A waiter gives up after `timeout`; the holder is not affected.
public struct FileRefreshLock: RefreshLock {
    public let url: URL
    public let timeout: TimeInterval

    public init(url: URL, timeout: TimeInterval = 60) {
        self.url = url
        self.timeout = timeout
    }

    /// The lock file for a client in an App Group container, or `nil` when the
    /// app is not entitled to that group — on iOS. macOS names a container
    /// whether or not the app is entitled, and the file is not opened here to
    /// find out: touching another app's group container can wait on a privacy
    /// prompt, and this runs at launch. A lock that cannot be opened fails
    /// each refresh's wait instead, which the client survives (see
    /// `RefreshLock`).
    public static func appGroup(_ identifier: String, clientId: String) -> FileRefreshLock? {
        guard let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: identifier) else {
            return nil
        }
        let name = "com.proteles.auth.\(clientId).refresh.lock"
            .replacingOccurrences(of: "/", with: "_")
        return FileRefreshLock(url: container.appendingPathComponent(name, isDirectory: false))
    }

    private func openLockFile() throws -> Int32 {
        var fd = open(url.path, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        if fd < 0, errno == ENOENT {
            // A group container macOS named but has not created yet.
            try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            fd = open(url.path, O_RDWR | O_CREAT | O_CLOEXEC, 0o600)
        }
        guard fd >= 0 else {
            throw ProtelesAuthError.storage("cannot open the refresh lock at \(url.path) (errno \(errno))")
        }
        return fd
    }

    public func withLock<T: Sendable>(_ body: @Sendable () async throws -> T) async throws -> T {
        let fd = try openLockFile()
        defer { close(fd) }

        let deadline = Date().addingTimeInterval(timeout)
        while flock(fd, LOCK_EX | LOCK_NB) != 0 {
            let error = errno
            guard error == EWOULDBLOCK || error == EINTR else {
                throw ProtelesAuthError.storage("flock on \(url.path) failed (errno \(error))")
            }
            guard Date() < deadline else {
                throw ProtelesAuthError.network("timed out after \(Int(timeout)) s waiting for another process's refresh")
            }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        defer { flock(fd, LOCK_UN) }
        return try await body()
    }
}

/// An async mutex shared by every client in this process with the same key.
/// Used when no App Group is configured.
public struct InProcessRefreshLock: RefreshLock {
    private let mutex: AsyncMutex

    public init(key: String) {
        mutex = AsyncMutex.shared(for: key)
    }

    public func withLock<T: Sendable>(_ body: @Sendable () async throws -> T) async throws -> T {
        await mutex.lock()
        do {
            let value = try await body()
            await mutex.unlock()
            return value
        } catch {
            await mutex.unlock()
            throw error
        }
    }
}

/// FIFO async mutex.
actor AsyncMutex {
    private var locked = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func lock() async {
        guard locked else {
            locked = true
            return
        }
        await withCheckedContinuation { waiters.append($0) }
    }

    func unlock() {
        if waiters.isEmpty {
            locked = false
        } else {
            // Ownership passes straight to the next waiter; `locked` stays true.
            waiters.removeFirst().resume()
        }
    }

    private static let registryLock = NSLock()
    nonisolated(unsafe) private static var registry: [String: AsyncMutex] = [:]

    static func shared(for key: String) -> AsyncMutex {
        registryLock.lock()
        defer { registryLock.unlock() }
        if let existing = registry[key] { return existing }
        let created = AsyncMutex()
        registry[key] = created
        return created
    }
}
