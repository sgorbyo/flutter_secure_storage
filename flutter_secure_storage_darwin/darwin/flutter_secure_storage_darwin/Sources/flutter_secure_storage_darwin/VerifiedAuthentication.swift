import Foundation
import LocalAuthentication
import Security

protocol VerifiedAuthentication {
    func authorize(_ context: LAContext, accessControl: SecAccessControl, reason: String) -> OSStatus
}

struct SystemVerifiedAuthentication: VerifiedAuthentication {
    /// Runs only on the plugin's serial worker, never on the UI thread.
    /// LA owns this evaluation, so invalidating this exact context cancels its UI.
    func authorize(_ context: LAContext, accessControl: SecAccessControl, reason: String) -> OSStatus {
        let completed = DispatchSemaphore(value: 0)
        var status = errSecAuthFailed
        context.evaluateAccessControl(accessControl, operation: .useItem, localizedReason: reason) { success, error in
            if success {
                status = errSecSuccess
            } else if let error = error as? LAError,
                      [.appCancel, .systemCancel, .userCancel, .invalidContext].contains(error.code) {
                status = errSecUserCanceled
            }
            completed.signal()
        }
        completed.wait()
        return status
    }
}
