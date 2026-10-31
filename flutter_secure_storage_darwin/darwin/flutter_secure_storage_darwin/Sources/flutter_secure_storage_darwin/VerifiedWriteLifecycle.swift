import Foundation

/// Owns notification subscriptions so lifecycle revocation also works when
/// UIKit routes UI lifecycle through scenes instead of the legacy app delegate.
final class VerifiedWriteLifecycle {
    private let center: NotificationCenter
    private var observers: [NSObjectProtocol] = []

    init(contexts: VerifiedWriteContexts, center: NotificationCenter,
         transitions: [(Notification.Name, String, Bool)]) {
        self.center = center
        for (name, reason, suspending) in transitions {
            observers.append(center.addObserver(forName: name, object: nil, queue: .main) { [weak contexts] _ in
                if suspending {
                    contexts?.cancel(suspending: reason)
                } else {
                    contexts?.resume(reason)
                }
            })
        }
    }

    deinit {
        for observer in observers { center.removeObserver(observer) }
    }
}
