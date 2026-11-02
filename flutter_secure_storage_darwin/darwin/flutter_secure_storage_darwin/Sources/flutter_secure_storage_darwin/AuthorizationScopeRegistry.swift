import Foundation

/// Engine-owned identity and revocation boundary. Never queues close/revoke.
final class AuthorizationScopeRegistry {
    private let lock = NSLock()
    private var epoch: Int64 = 0
    private var current: BoundedAuthorizationScope?

    func open(ownerEpoch: Int64, make: () throws -> BoundedAuthorizationScope) throws -> BoundedAuthorizationScope {
        lock.lock(); defer { lock.unlock() }
        guard ownerEpoch == epoch else { throw ScopeFailure("revoked") }
        // A terminal scope can be retired, but its namespace stays leased while
        // any worker still retains it. This prevents overlap after cancellation.
        if let active = current, (try? active.checkActive()) != nil { throw ScopeFailure("busy") }
        current = nil
        let scope = try make()
        current = scope
        return scope
    }
    func lookup(handle: String, ownerEpoch: Int64) throws -> BoundedAuthorizationScope {
        lock.lock(); defer { lock.unlock() }
        guard let current = current, current.handle == handle else { throw ScopeFailure("unknownScope") }
        guard ownerEpoch == epoch else { throw ScopeFailure("revoked") }
        return current
    }
    func close(handle: String, ownerEpoch: Int64) throws {
        lock.lock(); defer { lock.unlock() }
        guard let current = current, current.handle == handle else { return }
        guard ownerEpoch == epoch else { throw ScopeFailure("revoked") }
        current.close()
        self.current = nil
    }
    func revoke(nextEpoch: Int64) throws {
        lock.lock(); defer { lock.unlock() }
        guard nextEpoch > epoch else { throw ScopeFailure("invalidPlan") }
        epoch = nextEpoch
        current?.close()
        current = nil
    }
    func cancel() {
        lock.lock(); defer { lock.unlock() }
        current?.close()
        current = nil
    }
    deinit { cancel() }
}
