// Noninteractive channel contract checks: no Keychain writes or protected reads.
import AppKit
import FlutterMacOS
import Foundation

@main
struct ScopeBridgeChecks {
    static func main() {
        let plugin = FlutterSecureStorageDarwinPlugin()
        let namespace = "scope.bridge.test." + UUID().uuidString
        func invoke(_ method: String, _ args: [String: Any]) -> Any? {
            var complete = false
            var output: Any?
            let codec = FlutterStandardMethodCodec.sharedInstance()
            let encoded = codec.encode(FlutterMethodCall(methodName: method, arguments: args))
            plugin.handle(codec.decodeMethodCall(encoded)) { value in
                output = value; complete = true
            }
            let deadline = Date().addingTimeInterval(5)
            while !complete && Date() < deadline {
                RunLoop.current.run(until: Date().addingTimeInterval(0.005))
            }
            precondition(complete, "channel did not deliver a result")
            return output
        }
        func plan(epoch: Int64 = 0) -> [String: Any] {
            ["options": ["accountName": namespace, "accessControlFlags": "userPresence",
                          "usesDataProtectionKeychain": "false"],
             "slots": [["key": "synthetic", "access": ["read", "createVerified"], "maxReads": 1, "maxWrites": 1]],
             "localizedReason": "Noninteractive channel test", "lifetimeMilliseconds": 1000,
             "ownerEpoch": epoch, "actionNonce": UUID().uuidString]
        }
        func failure(_ value: Any?, _ code: String) {
            precondition((value as? FlutterError)?.code == code, "unexpected normalized error")
        }
        let first = invoke("scopeOpen", plan()) as! String
        failure(invoke("scopeOpen", plan()), "busy")
        failure(invoke("read", ["key": "synthetic", "options": ["accountName": namespace,
                      "usesDataProtectionKeychain": "false"]]), "busy")
        precondition(invoke("scopeCheck", ["handle": first, "ownerEpoch": Int64(0), "sequence": Int64(1)]) == nil)
        failure(invoke("scopeCheck", ["handle": "unknown", "ownerEpoch": Int64(0), "sequence": Int64(1)]), "unknownScope")
        failure(invoke("scopeReadBatch", ["handle": first, "ownerEpoch": Int64(0), "sequence": Int64(2), "keys": ["outside"]]), "invalidPlan")
        precondition(invoke("scopeClose", ["handle": first, "ownerEpoch": Int64(0)]) == nil)
        let next = invoke("scopeOpen", plan()) as! String
        precondition(next != first)
        precondition(invoke("scopeRevoke", ["nextOwnerEpoch": Int64(1)]) == nil)
        failure(invoke("scopeOpen", plan()), "revoked")
        let current = invoke("scopeOpen", plan(epoch: 1)) as! String
        precondition(invoke("scopeClose", ["handle": first, "ownerEpoch": Int64(0)]) == nil)
        precondition(invoke("scopeCheck", ["handle": current, "ownerEpoch": Int64(1), "sequence": Int64(1)]) == nil)
        NotificationCenter.default.post(name: NSApplication.didHideNotification, object: nil)
        failure(invoke("scopeCheck", ["handle": current, "ownerEpoch": Int64(1), "sequence": Int64(2)]), "revoked")
        NotificationCenter.default.post(name: NSApplication.didUnhideNotification, object: nil)
        precondition(invoke("scopeClose", ["handle": current, "ownerEpoch": Int64(1)]) == nil)
        print("PASS: native Flutter channel open/busy/check/unknown/invalid-plan/close/revoke/owner/lifecycle; no Keychain access")
    }
}
