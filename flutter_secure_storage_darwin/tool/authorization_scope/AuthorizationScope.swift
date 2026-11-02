import Foundation
import LocalAuthentication
import Security
#if !AUTH_SCOPE_PROBE
@testable import StorageCore
#endif

/// Experimental native-only scope. Not exported through the Flutter plugin.
/// Calls are serialized; revocation and the deadline do not wait for that queue.
final class AuthorizationScope {
    enum Permission { case read, writeVerified }
    private let contexts: VerifiedWriteContexts
    private let ticket: UInt64
    private let context: LAContext
    private let params: KeychainQueryParameters
    private let plan: [String: Set<Permission>]
    private let reason: String
    private let deadline: UInt64
    private let maximumCalls: Int
    private let state = NSLock()
    private let execution = NSLock()
    private var closed = false
    private var calls = 0
    private var timer: DispatchSourceTimer?
    private let manager: FlutterSecureStorage

    init?(contexts: VerifiedWriteContexts, params: KeychainQueryParameters,
          plan: [String: Set<Permission>], reason: String,
          timeout: TimeInterval = 120, maximumCalls: Int = 64,
          keychain: VerifiedKeychain = SystemVerifiedKeychain(),
          authentication: VerifiedAuthentication = SystemVerifiedAuthentication()) {
        guard !plan.isEmpty, plan.count <= 32,
              plan.allSatisfy({ !$0.key.isEmpty && !$0.value.isEmpty }),
              timeout.isFinite, timeout > 0, timeout <= 120,
              maximumCalls > 0, maximumCalls <= 64,
              params.useSecureEnclave != true,
              params.authenticationContext == nil,
              params.authenticationUIBehavior == nil,
              params.shouldReturnPersistentReference != true,
              params.service?.isEmpty == false,
              !reason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
        let ticket = contexts.ticket()
        guard let context = contexts.begin(ticket) else { return nil }
        self.contexts = contexts; self.ticket = ticket; self.context = context
        self.params = params; self.plan = plan; self.reason = reason
        self.maximumCalls = maximumCalls
        self.deadline = DispatchTime.now().uptimeNanoseconds + UInt64(timeout * 1_000_000_000)
        self.manager = FlutterSecureStorage(verifiedKeychain: keychain,
            verifiedAuthentication: OnceAuthentication(base: authentication, context: context))
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .userInitiated))
        self.timer = timer
        timer.schedule(deadline: DispatchTime(uptimeNanoseconds: deadline))
        timer.setEventHandler { [weak self] in self?.close() }
        timer.resume()
    }

    var isValid: Bool {
        state.lock()
        let valid = !closed && DispatchTime.now().uptimeNanoseconds < deadline
        state.unlock()
        return valid && contexts.isValid(ticket, context)
    }

    func close() {
        state.lock()
        guard !closed else { state.unlock(); return }
        closed = true
        let timer = self.timer; self.timer = nil
        state.unlock()
        timer?.cancel()
        contexts.end(context)
    }

    deinit { close() }

    private func admit(_ key: String, _ permission: Permission) -> OSStatus {
        guard isValid else { close(); return errSecUserCanceled }
        state.lock()
        let allowed = plan[key]?.contains(permission) == true && calls < maximumCalls
        if allowed { calls += 1 }
        state.unlock()
        guard allowed else { close(); return errSecParam }
        return errSecSuccess
    }

    func read(_ key: String) -> (OSStatus, String?) {
        execution.lock(); defer { execution.unlock() }
        let status = admit(key, .read)
        guard status == errSecSuccess else { return (status, nil) }
        let result = manager.readBatch(params: params, keys: [key], context: context,
            localizedReason: reason, isCancelled: { !self.isValid })
        guard isValid else { close(); return (errSecUserCanceled, nil) }
        guard result.0 == errSecSuccess else { close(); return (result.0, nil) }
        return (errSecSuccess, result.1?[key] ?? nil)
    }

    func writeVerified(_ key: String, value: String) -> OSStatus {
        execution.lock(); defer { execution.unlock() }
        let status = admit(key, .writeVerified)
        guard status == errSecSuccess else { return status }
        var params = self.params; params.key = key
        let result = manager.writeAndVerify(params: params, value: value, context: context,
            localizedReason: reason, isCancelled: { !self.isValid })
        guard isValid else { close(); return errSecUserCanceled }
        if result.status != errSecSuccess { close() }
        return result.status
    }
}

/// Accessed only by the scope's serialized operations, with immutable ACL options.
/// Actual item ACLs remain enforced by every noninteractive Keychain operation.
private final class OnceAuthentication: VerifiedAuthentication {
    private let base: VerifiedAuthentication
    private let context: LAContext
    private var outcome: OSStatus?
    init(base: VerifiedAuthentication, context: LAContext) {
        self.base = base; self.context = context
    }
    func authorize(_ context: LAContext, accessControl: SecAccessControl, reason: String) -> OSStatus {
        guard context === self.context else { return errSecParam }
        if let outcome = outcome { return outcome }
        context.interactionNotAllowed = false
        let status = base.authorize(context, accessControl: accessControl, reason: reason)
        context.interactionNotAllowed = true
        outcome = status
        return status
    }
}
