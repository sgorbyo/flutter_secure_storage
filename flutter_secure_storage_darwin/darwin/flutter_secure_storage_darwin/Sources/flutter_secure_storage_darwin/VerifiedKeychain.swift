import Foundation
import Security

/// Narrow injection boundary for verifying failure handling without real secrets.
protocol VerifiedKeychain {
    func update(_ query: [CFString: Any], _ attributes: [CFString: Any]) -> OSStatus
    func add(_ query: [CFString: Any]) -> OSStatus
    func read(_ query: [CFString: Any]) -> (OSStatus, Data?)
}

struct SystemVerifiedKeychain: VerifiedKeychain {
    func update(_ query: [CFString: Any], _ attributes: [CFString: Any]) -> OSStatus {
        SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
    }
    func add(_ query: [CFString: Any]) -> OSStatus {
        SecItemAdd(query as CFDictionary, nil)
    }
    func read(_ query: [CFString: Any]) -> (OSStatus, Data?) {
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        return (status, result as? Data)
    }
}
