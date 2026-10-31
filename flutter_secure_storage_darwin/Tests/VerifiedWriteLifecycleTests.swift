import XCTest
@testable import StorageCore

final class VerifiedWriteLifecycleTests: XCTestCase {
    let background = Notification.Name("synthetic.background")
    let foreground = Notification.Name("synthetic.foreground")

    func testNotificationsRevokeActiveAndQueuedWorkUntilForeground() {
        let center = NotificationCenter(), contexts = VerifiedWriteContexts()
        let lifecycle = VerifiedWriteLifecycle(contexts: contexts, center: center,
            transitions: [(background, "background", true), (foreground, "background", false)])
        let ticket = contexts.ticket()
        let context = contexts.begin(ticket)!
        center.post(name: background, object: nil)
        XCTAssertFalse(contexts.isValid(ticket, context))
        XCTAssertNil(contexts.begin(ticket))
        XCTAssertNil(contexts.begin(contexts.ticket()))
        center.post(name: foreground, object: nil)
        XCTAssertNil(contexts.begin(ticket))
        XCTAssertNotNil(contexts.begin(contexts.ticket()))
        withExtendedLifetime(lifecycle) {}
    }

    func testForegroundDoesNotOverrideProtectedDataSuspension() {
        let center = NotificationCenter(), contexts = VerifiedWriteContexts()
        let lifecycle = VerifiedWriteLifecycle(contexts: contexts, center: center,
            transitions: [(background, "background", true), (foreground, "background", false)])
        center.post(name: background, object: nil)
        contexts.cancel(suspending: "protectedData")
        center.post(name: foreground, object: nil)
        XCTAssertNil(contexts.begin(contexts.ticket()))
        contexts.resume("protectedData")
        XCTAssertNotNil(contexts.begin(contexts.ticket()))
        withExtendedLifetime(lifecycle) {}
    }

    func testDisposalRemovesLifecycleObservers() {
        let center = NotificationCenter(), contexts = VerifiedWriteContexts()
        var lifecycle: VerifiedWriteLifecycle? = VerifiedWriteLifecycle(contexts: contexts, center: center,
            transitions: [(background, "background", true)])
        XCTAssertNotNil(lifecycle)
        lifecycle = nil
        let ticket = contexts.ticket()
        center.post(name: background, object: nil)
        XCTAssertNotNil(contexts.begin(ticket))
    }
}
