import Foundation
import LocalAuthentication
import Security

protocol VerifiedAuthentication {
    func authorize(_ context: LAContext, accessControl: SecAccessControl, reason: String) -> OSStatus
}

// Internal statuses come only from explicit LA evaluation. Raw Keychain
// cancellation does not prove that the user chose Cancel.
enum VerifiedAuthenticationStatus {
    static let userCancelled: OSStatus = -100001
    static let interrupted: OSStatus = -100002
}

struct SystemVerifiedAuthentication: VerifiedAuthentication {
    static func status(success: Bool, error: Error?) -> OSStatus {
        if success { return errSecSuccess }
        guard let error = error as? LAError else { return errSecAuthFailed }
        switch error.code {
        case .userCancel: return VerifiedAuthenticationStatus.userCancelled
        case .appCancel, .systemCancel, .invalidContext:
            return VerifiedAuthenticationStatus.interrupted
        default: return errSecAuthFailed
        }
    }
    /// Runs only on the plugin's serial worker, never on the UI thread.
    /// LA owns this evaluation, so invalidating this exact context cancels its UI.
    func authorize(_ context: LAContext, accessControl: SecAccessControl, reason: String) -> OSStatus {
        let completed = DispatchSemaphore(value: 0)
        var status = errSecAuthFailed
        context.evaluateAccessControl(accessControl, operation: .useItem, localizedReason: reason) { success, error in
            status = Self.status(success: success, error: error)
            completed.signal()
        }
        completed.wait()
        return status
    }
}
