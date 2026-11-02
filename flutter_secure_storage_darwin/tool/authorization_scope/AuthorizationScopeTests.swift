import XCTest
import LocalAuthentication
import Security
@testable import StorageCore

private final class MemoryKeychain: VerifiedKeychain {
    var values = ["journal": Data("before".utf8)]
    var authorized = false
    var deny = false
    var contexts = [LAContext]()
    var afterWrite: (() -> Void)?
    var afterRead: (() -> Void)?
    func check(_ q: [CFString: Any]) -> OSStatus {
        let context = q[kSecUseAuthenticationContext] as! LAContext
        contexts.append(context)
        XCTAssertTrue(context.interactionNotAllowed)
        return authorized && !deny ? errSecSuccess : errSecInteractionNotAllowed
    }
    func update(_ q: [CFString: Any], _ a: [CFString: Any]) -> OSStatus {
        let status = check(q); guard status == errSecSuccess else { return status }
        let key = q[kSecAttrAccount] as! String
        guard values[key] != nil else { return errSecItemNotFound }
        values[key] = a[kSecValueData] as? Data; afterWrite?(); return errSecSuccess
    }
    func add(_ q: [CFString: Any]) -> OSStatus {
        let status = check(q); guard status == errSecSuccess else { return status }
        let key = q[kSecAttrAccount] as! String
        guard values[key] == nil else { return errSecDuplicateItem }
        values[key] = q[kSecValueData] as? Data; afterWrite?(); return errSecSuccess
    }
    func read(_ q: [CFString: Any]) -> (OSStatus, Data?) {
        let status = check(q)
        let key = q[kSecAttrAccount] as! String
        guard let value = values[key] else { return (errSecItemNotFound, nil) }
        guard status == errSecSuccess else { return (status, nil) }
        afterRead?(); return (errSecSuccess, value)
    }
}
private final class Authentication: VerifiedAuthentication {
    var calls = 0
    var action: () -> OSStatus = { errSecSuccess }
    func authorize(_ context: LAContext, accessControl: SecAccessControl, reason: String) -> OSStatus {
        calls += 1; return action()
    }
}
final class AuthorizationScopeTests: XCTestCase {
    private func parameters() -> KeychainQueryParameters {
        KeychainQueryParameters(service: "synthetic", isSynchronizable: false,
            accessibilityLevel: "unlocked_this_device", usesDataProtectionKeychain: false,
            accessControlFlags: "userPresence", useSecureEnclave: false)
    }
    private func scope(_ contexts: VerifiedWriteContexts,
                       _ keychain: MemoryKeychain, _ auth: Authentication,
                       timeout: TimeInterval = 120, calls: Int = 64) -> AuthorizationScope {
        AuthorizationScope(contexts: contexts, params: parameters(),
            plan: ["journal": [.read, .writeVerified], "copy": [.read, .writeVerified], "readOnly": [.read]],
            reason: "Synthetic test", timeout: timeout, maximumCalls: calls,
            keychain: keychain, authentication: auth)!
    }
    func testReadUpdateAddReadShareOneAuthorizationAndContext() {
        let keychain = MemoryKeychain(), auth = Authentication()
        auth.action = { keychain.authorized = true; return errSecSuccess }
        let s = scope(VerifiedWriteContexts(), keychain, auth)
        XCTAssertEqual(s.read("journal").1, "before")
        XCTAssertEqual(s.writeVerified("journal", value: "after"), errSecSuccess)
        XCTAssertEqual(s.writeVerified("copy", value: "copy value"), errSecSuccess)
        XCTAssertEqual(s.read("copy").1, "copy value")
        XCTAssertEqual(auth.calls, 1)
        XCTAssertTrue(keychain.contexts.allSatisfy { $0 === keychain.contexts.first })
        s.close(); XCTAssertFalse(s.isValid)
    }
    func testWriteFirstThenReadAndWriteDoesNotReauthenticate() {
        let keychain = MemoryKeychain(), auth = Authentication()
        auth.action = { keychain.authorized = true; return errSecSuccess }
        let s = scope(VerifiedWriteContexts(), keychain, auth)
        XCTAssertEqual(s.writeVerified("copy", value: "value"), errSecSuccess)
        XCTAssertEqual(s.read("journal").1, "before")
        XCTAssertEqual(s.writeVerified("journal", value: "next"), errSecSuccess)
        XCTAssertEqual(auth.calls, 1)
    }
    func testAbsentItemDoesNotAuthorize() {
        let keychain = MemoryKeychain(), auth = Authentication(), s = scope(VerifiedWriteContexts(), keychain, auth)
        let result = s.read("copy")
        XCTAssertEqual(result.0, errSecSuccess); XCTAssertNil(result.1)
        XCTAssertEqual(auth.calls, 0)
    }
    func testUnknownSlotOrWrongPermissionRevokesWholeScope() {
        for key in ["outside", "readOnly"] {
            let keychain = MemoryKeychain(), auth = Authentication(), s = scope(VerifiedWriteContexts(), keychain, auth)
            XCTAssertEqual(s.writeVerified(key, value: "value"), errSecParam)
            XCTAssertEqual(s.read("journal").0, errSecUserCanceled)
            XCTAssertEqual(auth.calls, 0); XCTAssertTrue(keychain.contexts.isEmpty)
        }
    }
    func testLimitRevokesWithoutExtraAccess() {
        let keychain = MemoryKeychain(), auth = Authentication(), s = scope(VerifiedWriteContexts(), keychain, auth, calls: 1)
        XCTAssertEqual(s.read("copy").0, errSecSuccess)
        XCTAssertEqual(s.read("copy").0, errSecParam)
        XCTAssertEqual(keychain.contexts.count, 1)
    }
    func testDeniedAuthorizationNeverMutatesAndRetryUsesNewContext() {
        let contexts = VerifiedWriteContexts(), keychain = MemoryKeychain(), auth = Authentication()
        auth.action = { errSecUserCanceled }
        let first = scope(contexts, keychain, auth)
        XCTAssertEqual(first.writeVerified("journal", value: "bad"), errSecUserCanceled)
        XCTAssertFalse(first.isValid)
        auth.action = { keychain.authorized = true; return errSecSuccess }
        let second = scope(contexts, keychain, auth)
        XCTAssertEqual(second.writeVerified("journal", value: "good"), errSecSuccess)
        XCTAssertEqual(auth.calls, 2)
    }
    func testStricterACLDoesNotTriggerSecondAuthorization() {
        let keychain = MemoryKeychain(), auth = Authentication()
        auth.action = { keychain.authorized = true; return errSecSuccess }
        let s = scope(VerifiedWriteContexts(), keychain, auth)
        XCTAssertEqual(s.read("journal").0, errSecSuccess)
        keychain.deny = true
        XCTAssertEqual(s.read("journal").0, errSecInteractionNotAllowed)
        XCTAssertEqual(auth.calls, 1); XCTAssertFalse(s.isValid)
    }
    func testRevocationDuringAuthorizationPreventsWrite() {
        let contexts = VerifiedWriteContexts(), keychain = MemoryKeychain(), auth = Authentication()
        auth.action = { contexts.cancel(); return errSecSuccess }
        let s = scope(contexts, keychain, auth)
        XCTAssertEqual(s.writeVerified("journal", value: "bad"), errSecUserCanceled)
        XCTAssertEqual(keychain.values["journal"], Data("before".utf8))
        XCTAssertTrue(keychain.contexts.isEmpty)
    }
    func testCancellationAfterWriteKeepsDurableValueButDiscardsSuccess() {
        let contexts = VerifiedWriteContexts(), keychain = MemoryKeychain(), auth = Authentication()
        auth.action = { keychain.authorized = true; return errSecSuccess }
        keychain.afterWrite = { contexts.cancel() }
        let s = scope(contexts, keychain, auth)
        XCTAssertEqual(s.writeVerified("journal", value: "after"), errSecUserCanceled)
        XCTAssertEqual(keychain.values["journal"], Data("after".utf8))
        XCTAssertEqual(keychain.contexts.count, 1)
    }
    func testCancellationAfterReadDoesNotDeliverValue() {
        let contexts = VerifiedWriteContexts(), keychain = MemoryKeychain(), auth = Authentication()
        keychain.authorized = true; keychain.afterRead = { contexts.cancel() }
        let s = scope(contexts, keychain, auth), result = s.read("journal")
        XCTAssertEqual(result.0, errSecUserCanceled); XCTAssertNil(result.1)
    }
    func testTimeoutWhileIdleReleasesContextWithoutAnotherCall() {
        let contexts = VerifiedWriteContexts(), keychain = MemoryKeychain(), auth = Authentication()
        let s = scope(contexts, keychain, auth, timeout: 0.02)
        let done = expectation(description: "deadline")
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.1) {
            XCTAssertFalse(s.isValid)
            let next = contexts.begin(contexts.ticket())
            XCTAssertNotNil(next)
            if let next = next { contexts.end(next) }
            done.fulfill()
        }
        wait(for: [done], timeout: 2)
    }
    func testDeadlineDuringBlockedAuthorizationRejectsQueuedWork() {
        let contexts = VerifiedWriteContexts(), keychain = MemoryKeychain(), auth = Authentication()
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        auth.action = { entered.signal(); release.wait(); return errSecSuccess }
        let s = scope(contexts, keychain, auth, timeout: 0.05)
        let completed = expectation(description: "active"), queued = expectation(description: "queued")
        DispatchQueue.global().async {
            XCTAssertEqual(s.writeVerified("journal", value: "bad"), errSecUserCanceled)
            completed.fulfill()
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 1), .success)
        DispatchQueue.global().async {
            XCTAssertEqual(s.read("journal").0, errSecUserCanceled); queued.fulfill()
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.15) { release.signal() }
        wait(for: [completed, queued], timeout: 2)
        XCTAssertTrue(keychain.contexts.isEmpty); XCTAssertEqual(auth.calls, 1)
    }
    func testIndependentManagersAndConcurrentScopeRejection() {
        let contexts = VerifiedWriteContexts(), keychain = MemoryKeychain(), auth = Authentication()
        let s = scope(contexts, keychain, auth)
        XCTAssertNil(AuthorizationScope(contexts: contexts, params: parameters(),
            plan: ["journal": [.read]], reason: "test"))
        let independent = scope(VerifiedWriteContexts(), keychain, auth)
        contexts.cancel(suspending: "background")
        XCTAssertFalse(s.isValid); XCTAssertTrue(independent.isValid)
        contexts.resume("background"); XCTAssertFalse(s.isValid)
    }
    func testInvalidPlanFailsBeforeContextAcquisition() {
        let contexts = VerifiedWriteContexts()
        for timeout in [0.0, -1, 121, Double.nan, Double.infinity] {
            XCTAssertNil(AuthorizationScope(contexts: contexts, params: parameters(),
                plan: ["journal": [.read]], reason: "test", timeout: timeout))
        }
        XCTAssertNil(AuthorizationScope(contexts: contexts, params: parameters(), plan: [:], reason: "test"))
        let c = contexts.begin(contexts.ticket()); XCTAssertNotNil(c)
        if let c = c { contexts.end(c) }
    }
}
