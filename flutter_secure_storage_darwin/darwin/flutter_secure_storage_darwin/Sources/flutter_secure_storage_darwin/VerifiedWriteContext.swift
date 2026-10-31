import Foundation
import LocalAuthentication

/// One context per native call; queued work is invalidated by cancellation too.
final class VerifiedWriteContexts {
    private let lock = NSLock()
    private var generation: UInt64 = 0
    private var suspended = Set<String>()
    private var active: LAContext?

    func ticket() -> UInt64 {
        lock.lock(); defer { lock.unlock() }
        return generation
    }

    func begin(_ ticket: UInt64) -> LAContext? {
        lock.lock(); defer { lock.unlock() }
        guard generation == ticket, suspended.isEmpty, active == nil else { return nil }
        let context = LAContext()
        // Do not reuse an authentication from a previous action/device unlock.
        context.touchIDAuthenticationAllowableReuseDuration = 0
        active = context
        return context
    }

    func isValid(_ ticket: UInt64, _ context: LAContext) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return generation == ticket && suspended.isEmpty && active === context
    }

    func isCurrent(_ ticket: UInt64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return generation == ticket && suspended.isEmpty
    }

    func end(_ context: LAContext) {
        lock.lock()
        if active === context { active = nil }
        lock.unlock()
        context.invalidate()
    }

    func cancel(suspending reason: String? = nil) {
        lock.lock()
        generation &+= 1
        if let reason = reason { suspended.insert(reason) }
        let context = active
        active = nil
        lock.unlock()
        context?.invalidate()
    }

    func resume(_ reason: String) {
        lock.lock(); defer { lock.unlock() }
        suspended.remove(reason)
    }
}
