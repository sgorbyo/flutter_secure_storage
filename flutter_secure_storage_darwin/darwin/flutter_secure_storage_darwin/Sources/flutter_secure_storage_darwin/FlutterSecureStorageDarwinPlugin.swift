//
//  FlutterSecureStorageDarwinPlugin.swift
//

import LocalAuthentication
#if os(iOS)
import Flutter
import UIKit
#else
import AppKit
import FlutterMacOS
#endif

public class FlutterSecureStorageDarwinPlugin: NSObject, FlutterPlugin, FlutterStreamHandler {

    private let flutterSecureStorageManager: FlutterSecureStorage = FlutterSecureStorage()
    private let verifiedContexts = VerifiedWriteContexts()
    private let scopes = AuthorizationScopeRegistry()
    private let scopeEvents = ScopeEvaluationEvents()
    private var secStoreAvailabilitySink: FlutterEventSink?
    private let serialExecutionQueue = DispatchQueue(label: "flutter_secure_storage_service")

    #if os(iOS)
    private var applicationLifecycle: VerifiedWriteLifecycle?

    public override init() {
        super.init()
        // UIApplication notifications describe the aggregate app state even
        // with UIScene. Legacy UIApplicationDelegate UI callbacks do not.
        applicationLifecycle = VerifiedWriteLifecycle(
            contexts: verifiedContexts,
            center: .default,
            transitions: [
                (UIApplication.didEnterBackgroundNotification, "background", true),
                (UIApplication.willEnterForegroundNotification, "background", false)
            ])
    }

    public func detachFromEngine(for registrar: FlutterPluginRegistrar) {
        scopes.cancel()
        verifiedContexts.cancel(suspending: "detached")
    }

    deinit { scopes.cancel(); verifiedContexts.cancel() }
    #endif

    #if os(macOS)
    private var workspaceObservers: [NSObjectProtocol] = []
    private var visibilityLifecycle: VerifiedWriteLifecycle?

    public override init() {
        super.init()
        visibilityLifecycle = VerifiedWriteLifecycle(contexts: verifiedContexts, center: .default,
            transitions: [(NSApplication.didHideNotification, "hidden", true),
                          (NSApplication.didUnhideNotification, "hidden", false)])
        let center = NSWorkspace.shared.notificationCenter
        for (notification, reason) in [(NSWorkspace.willSleepNotification, "sleep"),
                                       (NSWorkspace.sessionDidResignActiveNotification, "session")] {
            workspaceObservers.append(center.addObserver(forName: notification, object: nil, queue: .main) { [weak self] _ in
                self?.verifiedContexts.cancel(suspending: reason)
            })
        }
        for (notification, reason) in [(NSWorkspace.didWakeNotification, "sleep"),
                                       (NSWorkspace.sessionDidBecomeActiveNotification, "session")] {
            workspaceObservers.append(center.addObserver(forName: notification, object: nil, queue: .main) { [weak self] _ in
                self?.verifiedContexts.resume(reason)
            })
        }
    }

    deinit {
        for observer in workspaceObservers { NSWorkspace.shared.notificationCenter.removeObserver(observer) }
        scopes.cancel()
        verifiedContexts.cancel()
    }
    #endif

    public static func register(with registrar: FlutterPluginRegistrar) {
        #if os(iOS)
        let messenger = registrar.messenger()
        #else
        let messenger = registrar.messenger
        #endif

        let channel = FlutterMethodChannel(name: "plugins.it_nomads.com/flutter_secure_storage", binaryMessenger: messenger)
        let eventChannel = FlutterEventChannel(name: "plugins.it_nomads.com/flutter_secure_storage/events", binaryMessenger: messenger)
        let instance = FlutterSecureStorageDarwinPlugin()
        registrar.addMethodCallDelegate(instance, channel: channel)
        registrar.addApplicationDelegate(instance)
        eventChannel.setStreamHandler(instance)
        FlutterEventChannel(name: "plugins.it_nomads.com/flutter_secure_storage/scope_events",
            binaryMessenger: messenger).setStreamHandler(instance.scopeEvents)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        func handleResult(_ value: Any?) {
            DispatchQueue.main.async {
                result(value)
            }
        }

        if call.method.hasPrefix("scope") {
            handleScope(call, result: result)
            return
        }
        // Cancellation must bypass the serial queue blocked by a native prompt.
        if call.method == "cancelVerifiedWrites" {
            scopes.cancel()
            verifiedContexts.cancel()
            handleResult(nil)
            return
        }
        let ticket = verifiedContexts.ticket()
        serialExecutionQueue.async { [weak self] in
            guard let self = self else {
                handleResult(FlutterError(code: "revoked", message: nil, details: nil)); return
            }
            // Legacy access cannot interleave with a bounded action, including
            // a read that might independently show authentication UI.
            var lease: KeychainNamespaceLease?
            if ["read", "write", "delete", "deleteAll", "readAll", "containsKey", "readBatch", "writeAndVerify"].contains(call.method) {
                guard call.arguments is [String: Any] else {
                    handleResult(FlutterError(code: "invalidPlan", message: nil, details: nil)); return
                }
                let (params, _) = Self.parseCall(call)
                lease = KeychainNamespaceLease.acquire(params)
                guard lease != nil else {
                    handleResult(FlutterError(code: "busy", message: nil, details: nil)); return
                }
            }
            defer { withExtendedLifetime(lease) {} }
            switch call.method {
            case "readBatch":
                self.readBatch(call, ticket: ticket) { value in
                    DispatchQueue.main.async {
                        guard self.verifiedContexts.isCurrent(ticket) else {
                            result(FlutterError(code: "Protected read cancelled", message: nil, details: nil))
                            return
                        }
                        result(value)
                    }
                }
            case "writeAndVerify":
                self.writeAndVerify(call, ticket: ticket) { value in
                    DispatchQueue.main.async {
                        guard self.verifiedContexts.isCurrent(ticket) else {
                            result(FlutterError(code: "Verified write cancelled", message: nil, details: nil))
                            return
                        }
                        result(value)
                    }
                }
            case "read":
                self.read(call, handleResult)
            case "write":
                self.write(call, handleResult)
            case "delete":
                self.delete(call, handleResult)
            case "deleteAll":
                self.deleteAll(call, handleResult)
            case "readAll":
                self.readAll(call, handleResult)
            case "containsKey":
                self.containsKey(call, handleResult)
            case "isProtectedDataAvailable":
                DispatchQueue.main.async {
                    #if os(iOS)
                    result(UIApplication.shared.isProtectedDataAvailable)
                    #else
                    if #available(macOS 12.0, *) {
                        result(NSApplication.shared.isProtectedDataAvailable)
                    } else {
                        result(true)
                    }
                    #endif
                }
            default:
                handleResult(FlutterMethodNotImplemented)
            }
        }
    }

    private func handleScope(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        func deliver(_ error: Error) {
            let failure = error as? ScopeFailure ?? ScopeFailure("storageFailure")
            result(FlutterError(code: failure.code, message: nil,
                details: ["mutationMayHaveOccurred": failure.mutationMayHaveOccurred]))
        }
        guard let args = call.arguments as? [String: Any] else { deliver(ScopeFailure("invalidPlan")); return }
        // Both branches run on main, bypassing a worker blocked in authentication.
        if call.method == "scopeRevoke" {
            do {
                guard let epoch = args["nextOwnerEpoch"] as? Int64 else { throw ScopeFailure("invalidPlan") }
                try scopes.revoke(nextEpoch: epoch)
                verifiedContexts.cancel()
                result(nil)
            } catch { deliver(error) }
            return
        }
        if call.method == "scopeClose" {
            do {
                guard let handle = args["handle"] as? String, let epoch = args["ownerEpoch"] as? Int64 else {
                    throw ScopeFailure("invalidPlan")
                }
                try scopes.close(handle: handle, ownerEpoch: epoch)
                result(nil)
            } catch { deliver(error) }
            return
        }
        let ticket = verifiedContexts.ticket()
        serialExecutionQueue.async { [contexts = verifiedContexts, scopes = scopes, events = scopeEvents] in
            var scope: BoundedAuthorizationScope?
            var mutation = false
            do {
                guard contexts.isCurrent(ticket) else { throw ScopeFailure("revoked") }
                guard let epoch = args["ownerEpoch"] as? Int64 else { throw ScopeFailure("invalidPlan") }
                var value: Any?
                if call.method == "scopeOpen" {
                    guard let reason = args["localizedReason"] as? String,
                          let nonce = args["actionNonce"] as? String, UUID(uuidString: nonce) != nil,
                          let milliseconds = args["lifetimeMilliseconds"] as? Int,
                          let raw = args["slots"] as? [[String: Any]],
                          args["options"] is [String: String] else { throw ScopeFailure("invalidPlan") }
                    let slots = try raw.map { row -> ScopeSlotRule in
                        guard let key = row["key"] as? String, let access = row["access"] as? [String],
                              Set(access).count == access.count,
                              access.allSatisfy({ ["read", "writeVerified", "createVerified"].contains($0) }),
                              let reads = row["maxReads"] as? Int, let writes = row["maxWrites"] as? Int else {
                            throw ScopeFailure("invalidPlan")
                        }
                        return ScopeSlotRule(key: key, read: access.contains("read"),
                            writeVerified: access.contains("writeVerified"), createVerified: access.contains("createVerified"),
                            maxReads: reads, maxWrites: writes)
                    }
                    let (params, _) = Self.parseCall(call)
                    scope = try scopes.open(ownerEpoch: epoch) {
                        try BoundedAuthorizationScope(contexts: contexts, params: params,
                            slots: slots, reason: reason, lifetime: Double(milliseconds) / 1000, ownerEpoch: epoch,
                            evaluation: { [weak events] active in
                                events?.emit(nonce: nonce, epoch: epoch, active: active)
                            })
                    }
                    value = scope!.handle
                } else {
                    guard let handle = args["handle"] as? String, let sequence = args["sequence"] as? Int64 else {
                        throw ScopeFailure("invalidPlan")
                    }
                    let active = try scopes.lookup(handle: handle, ownerEpoch: epoch)
                    scope = active
                    switch call.method {
                    case "scopeReadBatch":
                        guard let keys = args["keys"] as? [String] else { throw ScopeFailure("invalidPlan") }
                        value = try active.readBatch(keys, epoch: epoch, sequence: sequence).mapValues { $0 as Any? ?? NSNull() }
                    case "scopeWriteVerified", "scopeCreateVerified":
                        guard let key = args["key"] as? String, let text = args["value"] as? String else {
                            throw ScopeFailure("invalidPlan")
                        }
                        try active.write(key, value: text, createOnly: call.method == "scopeCreateVerified", epoch: epoch, sequence: sequence)
                        mutation = true
                    case "scopeCheck": try active.check(epoch: epoch, sequence: sequence)
                    default: throw ScopeFailure("invalidPlan")
                    }
                }
                let deliveredScope = scope, deliveredValue = value, mutated = mutation
                DispatchQueue.main.async {
                    do {
                        guard let deliveredScope = deliveredScope else { throw ScopeFailure("unknownScope") }
                        try deliveredScope.checkActive()
                        result(deliveredValue)
                    } catch let failure as ScopeFailure {
                        deliver(ScopeFailure(failure.code, mutationMayHaveOccurred: mutated))
                    } catch { deliver(error) }
                }
            } catch {
                scope?.close((error as? ScopeFailure)?.code ?? "storageFailure")
                DispatchQueue.main.async { deliver(error) }
            }
        }
    }

    public func onListen(withArguments arguments: Any?,
                         eventSink: @escaping FlutterEventSink) -> FlutterError? {
        self.secStoreAvailabilitySink = eventSink
        return nil
    }

    public func onCancel(withArguments arguments: Any?) -> FlutterError? {
        self.secStoreAvailabilitySink = nil
        return nil
    }

    #if os(iOS)
    public func applicationProtectedDataDidBecomeAvailable(_ application: UIApplication) {
        verifiedContexts.resume("protectedData")
        secStoreAvailabilitySink?(true)
    }

    public func applicationProtectedDataWillBecomeUnavailable(_ application: UIApplication) {
        verifiedContexts.cancel(suspending: "protectedData")
        secStoreAvailabilitySink?(false)
    }
    #else
    @objc @available(macOS 12.0, *)
    public func applicationProtectedDataDidBecomeAvailable(_ notification: Notification) {
        verifiedContexts.resume("protectedData")
        secStoreAvailabilitySink?(true)
    }

    @objc @available(macOS 12.0, *)
    public func applicationProtectedDataWillBecomeUnavailable(_ notification: Notification) {
        verifiedContexts.cancel(suspending: "protectedData")
        secStoreAvailabilitySink?(false)
    }
    #endif

    private func writeAndVerify(_ call: FlutterMethodCall, ticket: UInt64, _ result: @escaping FlutterResult) {
        guard let arguments = call.arguments as? [String: Any],
              let key = arguments["key"] as? String, !key.isEmpty,
              arguments["value"] is String,
              let reason = arguments["localizedReason"] as? String,
              !reason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              let options = arguments["options"] as? [String: String],
              options["useSecureEnclave"] != "true" else {
            result(FlutterError(code: "Invalid verified write", message: "Requires key, value, options and non-Enclave storage", details: nil))
            return
        }
        guard let context = verifiedContexts.begin(ticket) else {
            result(FlutterError(code: "Verified write cancelled", message: nil, details: nil))
            return
        }
        defer { verifiedContexts.end(context) }
        let (params, value) = Self.parseCall(call)
        let response = flutterSecureStorageManager.writeAndVerify(
            params: params, value: value!, context: context, localizedReason: reason,
            isCancelled: { !self.verifiedContexts.isValid(ticket, context) }
        )
        handleResponse(response, result)
    }

    private func readBatch(_ call: FlutterMethodCall, ticket: UInt64, _ result: @escaping FlutterResult) {
        guard let arguments = call.arguments as? [String: Any],
              let keys = arguments["keys"] as? [String],
              let reason = arguments["localizedReason"] as? String,
              let options = arguments["options"] as? [String: String],
              !keys.isEmpty, keys.count <= 32, Set(keys).count == keys.count,
              keys.allSatisfy({ !$0.isEmpty }), !reason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              options["useSecureEnclave"] != "true" else {
            result(FlutterError(code: "Invalid protected read", message: nil, details: nil)); return
        }
        guard let context = verifiedContexts.begin(ticket) else {
            result(FlutterError(code: "Protected read cancelled", message: nil, details: nil)); return
        }
        defer { verifiedContexts.end(context) }
        let (params, _) = Self.parseCall(call)
        let (status, values) = flutterSecureStorageManager.readBatch(params: params, keys: keys,
            context: context, localizedReason: reason,
            isCancelled: { !self.verifiedContexts.isValid(ticket, context) })
        guard status == errSecSuccess, let values = values else {
            result(FlutterError(code: "Protected read failed", message: String(status), details: nil)); return
        }
        result(values.mapValues { $0 as Any? ?? NSNull() })
    }

    private func read(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let (params, _) = Self.parseCall(call)
        guard let _ = params.key else {
            result(FlutterError(code: "Missing Parameter", message: "read requires key parameter", details: nil))
            return
        }

        let response = flutterSecureStorageManager.read(params: params)
        handleResponse(response, result)
    }

    private func write(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let (params, value) = Self.parseCall(call)
        guard let _ = params.key, let value = value else {
            result(FlutterError(code: "Missing Parameter", message: "write requires key and value parameters", details: nil))
            return
        }

        let response = flutterSecureStorageManager.write(params: params, value: value)
        handleResponse(response, result)
    }

    private func delete(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let (params, _) = Self.parseCall(call)
        guard let _ = params.key else {
            result(FlutterError(code: "Missing Parameter", message: "delete requires key parameter", details: nil))
            return
        }

        let response = flutterSecureStorageManager.delete(params: params)
        handleResponse(response, result)
    }

    private func deleteAll(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let (params, _) = Self.parseCall(call)
        let response = flutterSecureStorageManager.deleteAll(params: params)
        handleResponse(response, result)
    }

    private func readAll(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let (params, _) = Self.parseCall(call)
        let response = flutterSecureStorageManager.readAll(params: params)
        handleResponse(response, result)
    }

    private func containsKey(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let (params, _) = Self.parseCall(call)
        guard let _ = params.key else {
            result(FlutterError(code: "Missing Parameter", message: "containsKey requires key parameter", details: nil))
            return
        }

        let response = flutterSecureStorageManager.containsKey(params: params)

        switch response {
        case .success(let exists):
            result(exists)
        case .failure(let error):
            let errorMessage = SecCopyErrorMessageString(error.status, nil) ?? "Unknown security result code: \(error.status)" as CFString
            result(FlutterError(code: "Unexpected security result code", message: errorMessage as String, details: error.status))
        }
    }

    private static func parseCall(_ call: FlutterMethodCall) -> (KeychainQueryParameters, String?) {
        let arguments = call.arguments as! [String: Any?]
        let options = arguments["options"] as? [String: Any?] ?? [:]

        let value = arguments["value"] as? String

        var parameters = KeychainQueryParameters(
            key: arguments["key"] as? String,
            accessGroup: options["groupId"] as? String,
            service: options["accountName"] as? String,
            isSynchronizable: (options["synchronizable"] as? String).flatMap { Bool($0) },
            accessibilityLevel: options["accessibility"] as? String,
            usesDataProtectionKeychain: (options["usesDataProtectionKeychain"] as? String).flatMap { Bool($0) } ?? true,
            shouldReturnData: true, // Default behavior for most operations.
            itemLabel: options["label"] as? String,
            itemDescription: options["description"] as? String,
            itemComment: options["comment"] as? String,
            isHidden: (options["isHidden"] as? String).flatMap { Bool($0) },
            isPlaceholder: (options["isPlaceholder"] as? String).flatMap { Bool($0) },
            shouldReturnPersistentReference: (options["persistentReference"] as? String).flatMap { Bool($0) },
            authenticationUIBehavior: options["authenticationUIBehavior"] as? String,
            accessControlFlags: options["accessControlFlags"] as? String,
            useSecureEnclave: (options["useSecureEnclave"] as? String).flatMap { Bool($0) }
        )

        // Reuse a single authentication context to avoid multiple prompts per call
        // when Secure Enclave is explicitly enabled.
        if parameters.useSecureEnclave == true {
            if #available(iOS 9.0, macOS 10.12, *) {
                let context = LAContext()
                context.touchIDAuthenticationAllowableReuseDuration = 30
                parameters.authenticationContext = context
            }
        }

        return (parameters, value)
    }

    private func handleResponse(_ response: FlutterSecureStorageResponse, _ result: @escaping FlutterResult) {
        let status = response.status
        if status != noErr {
            let errorMessage: String
            if #available(iOS 11.3, *) {
                if let errMsg = SecCopyErrorMessageString(status, nil) {
                    errorMessage = "Code: \(status), Message: \(errMsg)"
                } else {
                    errorMessage = "Unknown security result code: \(status)"
                }
            } else {
                errorMessage = "Unknown security result code: \(status)"
            }
            result(FlutterError(code: "Unexpected security result code", message: errorMessage as String, details: status))
        } else {
            result(response.value)
        }
    }
}

/// Separate stream so the existing protected-data boolean stream stays compatible.
private final class ScopeEvaluationEvents: NSObject, FlutterStreamHandler {
    private var sink: FlutterEventSink?
    private var sequence: Int64 = 0
    func emit(nonce: String, epoch: Int64, active: Bool) {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.sequence += 1
            self.sink?(["actionNonce": nonce, "ownerEpoch": epoch,
                        "sequence": self.sequence, "active": active])
        }
    }
    func onListen(withArguments arguments: Any?, eventSink: @escaping FlutterEventSink) -> FlutterError? {
        sink = eventSink
        return nil
    }
    func onCancel(withArguments arguments: Any?) -> FlutterError? { sink = nil; return nil }
}
