import Foundation
import LocalAuthentication
import Security

struct ScopeFailure: Error {
    let code: String
    let mutationMayHaveOccurred: Bool
    init(_ code: String, mutationMayHaveOccurred: Bool = false) {
        self.code = code
        self.mutationMayHaveOccurred = mutationMayHaveOccurred
    }
}

struct ScopeSlotRule {
    let key: String
    let read: Bool
    let writeVerified: Bool
    let createVerified: Bool
    let maxReads: Int
    let maxWrites: Int
}

/// Process-local exclusion only. No values or authentication are shared.
/// An unspecified legacy service/group overlaps the corresponding namespaces.
final class KeychainNamespaceLease {
    private struct Entry {
        let id: UUID
        let service: String?
        let group: String?
        let dataProtection: Bool
    }
    private static let lock = NSLock()
    private static var entries: [Entry] = []
    private let id: UUID
    private init(_ id: UUID) { self.id = id }
    static func acquire(_ params: KeychainQueryParameters) -> KeychainNamespaceLease? {
        lock.lock(); defer { lock.unlock() }
        #if os(macOS)
        let dataProtection = params.usesDataProtectionKeychain
        #else
        let dataProtection = true
        #endif
        guard !entries.contains(where: {
            $0.dataProtection == dataProtection &&
            ($0.service == nil || params.service == nil || $0.service == params.service) &&
            ($0.group == nil || params.accessGroup == nil || $0.group == params.accessGroup)
        }) else { return nil }
        let id = UUID()
        entries.append(Entry(id: id, service: params.service, group: params.accessGroup,
                             dataProtection: dataProtection))
        return KeychainNamespaceLease(id)
    }
    deinit {
        Self.lock.lock(); defer { Self.lock.unlock() }
        Self.entries.removeAll { $0.id == id }
    }
}

/// One finite action. Execute calls on a serial worker; close bypasses that worker.
/// The lease survives close until in-flight calls release the scope itself.
final class BoundedAuthorizationScope {
    static let maximumSlots = 23
    static let maximumOperations = 28
    let handle = UUID().uuidString
    let ownerEpoch: Int64
    private let lease: KeychainNamespaceLease
    private let contexts: VerifiedWriteContexts
    private let ticket: UInt64
    private let context: LAContext
    private let params: KeychainQueryParameters
    private let reason: String
    private let deadline: UInt64
    private let rules: [String: ScopeSlotRule]
    private let state = NSLock()
    private let execution = NSLock()
    private var terminal: String?
    private var lastSequence: Int64 = 0
    private var reads: [String: Int] = [:]
    private var writes: [String: Int] = [:]
    private var timer: DispatchSourceTimer?
    private let tracking: ScopeTrackingKeychain
    private let manager: FlutterSecureStorage

    init(contexts: VerifiedWriteContexts, params: KeychainQueryParameters,
         slots: [ScopeSlotRule], reason: String, lifetime: TimeInterval, ownerEpoch: Int64,
         keychain: VerifiedKeychain = SystemVerifiedKeychain(),
         authentication: VerifiedAuthentication = SystemVerifiedAuthentication(),
         evaluation: @escaping (Bool) -> Void = { _ in }) throws {
        guard ownerEpoch >= 0, lifetime.isFinite, lifetime > 0, lifetime <= 120,
              !slots.isEmpty, slots.count <= Self.maximumSlots,
              Set(slots.map(\.key)).count == slots.count,
              slots.allSatisfy({ !$0.key.isEmpty && ($0.read || $0.writeVerified || $0.createVerified) && $0.maxReads >= 0 && $0.maxReads <= Self.maximumOperations &&
                  $0.maxWrites >= 0 && $0.maxWrites <= Self.maximumOperations &&
                  $0.read == ($0.maxReads > 0) &&
                  ($0.writeVerified || $0.createVerified) == ($0.maxWrites > 0) }),
              slots.reduce(0, { $0 + $1.maxReads + $1.maxWrites }) <= Self.maximumOperations,
              params.service?.isEmpty == false, params.authenticationContext == nil,
              params.authenticationUIBehavior == nil, params.useSecureEnclave != true,
              params.shouldReturnPersistentReference != true,
              !reason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw ScopeFailure("invalidPlan")
        }
        guard let lease = KeychainNamespaceLease.acquire(params) else { throw ScopeFailure("busy") }
        let ticket = contexts.ticket()
        guard let context = contexts.begin(ticket) else { throw ScopeFailure("revoked") }
        self.lease = lease; self.contexts = contexts; self.ticket = ticket; self.context = context
        self.params = params; self.reason = reason; self.ownerEpoch = ownerEpoch
        self.rules = Dictionary(uniqueKeysWithValues: slots.map { ($0.key, $0) })
        self.deadline = DispatchTime.now().uptimeNanoseconds + UInt64(lifetime * 1_000_000_000)
        let tracking = ScopeTrackingKeychain(base: keychain)
        self.tracking = tracking
        self.manager = FlutterSecureStorage(verifiedKeychain: tracking,
            verifiedAuthentication: ScopeAuthentication(base: authentication, evaluation: evaluation))
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .userInitiated))
        self.timer = timer
        timer.schedule(deadline: DispatchTime(uptimeNanoseconds: deadline))
        timer.setEventHandler { [weak self] in self?.close("expired") }
        timer.resume()
    }

    func close(_ code: String = "revoked") {
        state.lock()
        guard terminal == nil else { state.unlock(); return }
        terminal = code
        let timer = self.timer; self.timer = nil
        state.unlock()
        timer?.cancel()
        contexts.end(context)
    }
    deinit { close() }

    /// Also used immediately before delivery on the platform main thread.
    func checkActive() throws {
        state.lock()
        let failure = terminal ?? (DispatchTime.now().uptimeNanoseconds >= deadline ? "expired" : nil)
        state.unlock()
        if let failure = failure { close(failure); throw ScopeFailure(failure) }
        guard contexts.isValid(ticket, context) else { close(); throw ScopeFailure("revoked") }
    }

    private func admit(epoch: Int64, sequence: Int64) throws {
        try checkActive()
        state.lock()
        let valid = epoch == ownerEpoch && sequence > 0 && lastSequence < Int64.max && sequence == lastSequence + 1
        if valid { lastSequence = sequence }
        state.unlock()
        guard valid else { close("invalidPlan"); throw ScopeFailure("invalidPlan") }
    }

    private func fail(_ code: String, mutation: Bool = false) throws -> Never {
        close(code)
        throw ScopeFailure(code, mutationMayHaveOccurred: mutation)
    }
    private func requireSuccess(_ status: OSStatus, mutation: Bool = false) throws {
        do { try checkActive() }
        catch let failure as ScopeFailure {
            throw ScopeFailure(failure.code, mutationMayHaveOccurred: mutation)
        }
        guard status != errSecSuccess else { return }
        let code: String
        switch status {
        case errSecInteractionNotAllowed: code = "interactionRequired"
        case errSecDuplicateItem: code = "duplicateItem"
        case VerifiedAuthenticationStatus.userCancelled: code = "userCancelled"
        case VerifiedAuthenticationStatus.interrupted, errSecUserCanceled: code = "interrupted"
        case errSecAuthFailed: code = "denied"
        case errSecDecode: code = "verificationFailed"
        case errSecParam: code = "invalidPlan"
        default: code = "storageFailure"
        }
        try fail(code, mutation: mutation)
    }
    private var cancelled: Bool { (try? checkActive()) == nil }

    func check(epoch: Int64, sequence: Int64) throws {
        execution.lock(); defer { execution.unlock() }
        try admit(epoch: epoch, sequence: sequence)
    }
    func readBatch(_ keys: [String], epoch: Int64, sequence: Int64) throws -> [String: String?] {
        execution.lock(); defer { execution.unlock() }
        try admit(epoch: epoch, sequence: sequence)
        guard !keys.isEmpty, Set(keys).count == keys.count,
              keys.allSatisfy({ key in
                  guard let rule = rules[key] else { return false }
                  return rule.read && reads[key, default: 0] < rule.maxReads
              }) else { try fail("invalidPlan") }
        for key in keys { reads[key, default: 0] += 1 }
        let (status, values) = manager.readBatch(params: params, keys: keys, context: context,
            localizedReason: reason, isCancelled: { self.cancelled })
        try requireSuccess(status)
        guard let values = values else { try fail("verificationFailed") }
        return values
    }
    func write(_ key: String, value: String, createOnly: Bool, epoch: Int64, sequence: Int64) throws {
        execution.lock(); defer { execution.unlock() }
        try admit(epoch: epoch, sequence: sequence)
        guard let rule = rules[key],
              createOnly ? rule.createVerified : rule.writeVerified,
              writes[key, default: 0] < rule.maxWrites else { try fail("invalidPlan") }
        writes[key, default: 0] += 1
        tracking.mutationAttempted = false
        var scoped = params; scoped.key = key
        let result = manager.writeAndVerify(params: scoped, value: value, context: context,
            localizedReason: reason, createOnly: createOnly, isCancelled: { self.cancelled })
        try requireSuccess(result.status, mutation: tracking.mutationAttempted)
    }
}

private final class ScopeAuthentication: VerifiedAuthentication {
    private let base: VerifiedAuthentication
    private let evaluation: (Bool) -> Void
    private var outcome: OSStatus?
    init(base: VerifiedAuthentication, evaluation: @escaping (Bool) -> Void) {
        self.base = base; self.evaluation = evaluation
    }
    func authorize(_ context: LAContext, accessControl: SecAccessControl, reason: String) -> OSStatus {
        if let outcome = outcome { return outcome }
        evaluation(true)
        defer { evaluation(false) }
        context.interactionNotAllowed = false
        let result = base.authorize(context, accessControl: accessControl, reason: reason)
        context.interactionNotAllowed = true
        outcome = result
        return result
    }
}

private final class ScopeTrackingKeychain: VerifiedKeychain {
    let base: VerifiedKeychain
    var mutationAttempted = false
    init(base: VerifiedKeychain) { self.base = base }
    func update(_ query: [CFString: Any], _ attributes: [CFString: Any]) -> OSStatus {
        mutationAttempted = true
        return base.update(query, attributes)
    }
    func add(_ query: [CFString: Any]) -> OSStatus {
        mutationAttempted = true
        return base.add(query)
    }
    func read(_ query: [CFString: Any]) -> (OSStatus, Data?) { base.read(query) }
}
