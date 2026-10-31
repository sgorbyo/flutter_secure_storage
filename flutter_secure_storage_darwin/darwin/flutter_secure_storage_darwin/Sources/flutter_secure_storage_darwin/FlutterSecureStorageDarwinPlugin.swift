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
    private var secStoreAvailabilitySink: FlutterEventSink?
    private let serialExecutionQueue = DispatchQueue(label: "flutter_secure_storage_service")

    #if os(macOS)
    private var workspaceObservers: [NSObjectProtocol] = []

    public override init() {
        super.init()
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
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        func handleResult(_ value: Any?) {
            DispatchQueue.main.async {
                result(value)
            }
        }

        // Cancellation must bypass the serial queue blocked by a native prompt.
        if call.method == "cancelVerifiedWrites" {
            verifiedContexts.cancel()
            handleResult(nil)
            return
        }
        let ticket = verifiedContexts.ticket()
        serialExecutionQueue.async {
            switch call.method {
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
    public func applicationDidEnterBackground(_ application: UIApplication) {
        verifiedContexts.cancel(suspending: "background")
    }

    public func applicationWillEnterForeground(_ application: UIApplication) {
        verifiedContexts.resume("background")
    }

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
        let (params, value) = parseCall(call)
        let response = flutterSecureStorageManager.writeAndVerify(
            params: params, value: value!, context: context,
            isCancelled: { !self.verifiedContexts.isValid(ticket, context) }
        )
        handleResponse(response, result)
    }

    private func read(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let (params, _) = parseCall(call)
        guard let _ = params.key else {
            result(FlutterError(code: "Missing Parameter", message: "read requires key parameter", details: nil))
            return
        }

        let response = flutterSecureStorageManager.read(params: params)
        handleResponse(response, result)
    }

    private func write(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let (params, value) = parseCall(call)
        guard let _ = params.key, let value = value else {
            result(FlutterError(code: "Missing Parameter", message: "write requires key and value parameters", details: nil))
            return
        }

        let response = flutterSecureStorageManager.write(params: params, value: value)
        handleResponse(response, result)
    }

    private func delete(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let (params, _) = parseCall(call)
        guard let _ = params.key else {
            result(FlutterError(code: "Missing Parameter", message: "delete requires key parameter", details: nil))
            return
        }

        let response = flutterSecureStorageManager.delete(params: params)
        handleResponse(response, result)
    }

    private func deleteAll(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let (params, _) = parseCall(call)
        let response = flutterSecureStorageManager.deleteAll(params: params)
        handleResponse(response, result)
    }

    private func readAll(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let (params, _) = parseCall(call)
        let response = flutterSecureStorageManager.readAll(params: params)
        handleResponse(response, result)
    }

    private func containsKey(_ call: FlutterMethodCall, _ result: @escaping FlutterResult) {
        let (params, _) = parseCall(call)
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

    private func parseCall(_ call: FlutterMethodCall) -> (KeychainQueryParameters, String?) {
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
