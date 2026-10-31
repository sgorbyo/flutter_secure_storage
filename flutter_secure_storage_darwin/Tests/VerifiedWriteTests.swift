import XCTest
import LocalAuthentication
import Security
@testable import StorageCore

final class FakeKeychain: VerifiedKeychain {
    var updateStatus = errSecSuccess
    var addStatus = errSecSuccess
    var readStatus = errSecSuccess
    var value: Data? = Data("synthetic".utf8)
    var calls = [String]()
    var queries = [[CFString: Any]]()
    var afterCall: (() -> Void)?
    func update(_ query: [CFString: Any], _ attributes: [CFString: Any]) -> OSStatus {
        calls.append("update"); queries.append(query); afterCall?(); return updateStatus
    }
    func add(_ query: [CFString: Any]) -> OSStatus {
        calls.append("add"); queries.append(query); afterCall?(); return addStatus
    }
    func read(_ query: [CFString: Any]) -> (OSStatus, Data?) {
        calls.append("read"); queries.append(query); afterCall?(); return (readStatus, value)
    }
}

final class FakeAuthentication: VerifiedAuthentication {
    var status = errSecSuccess
    var calls = 0
    var afterAuthorize: (() -> Void)?
    func authorize(_ context: LAContext, accessControl: SecAccessControl, reason: String) -> OSStatus {
        calls += 1
        afterAuthorize?()
        return status
    }
}

final class VerifiedWriteTests: XCTestCase {
    func params() -> KeychainQueryParameters {
        KeychainQueryParameters(key: "synthetic", service: "test", isSynchronizable: false,
            accessibilityLevel: "unlocked_this_device", usesDataProtectionKeychain: false,
            shouldReturnData: true, accessControlFlags: "userPresence", useSecureEnclave: false)
    }
    func testNoninteractiveOptionNeverPromptsOrMutates() {
        let fake = FakeKeychain(), auth = FakeAuthentication()
        var p = params(); p.authenticationUIBehavior = kSecUseAuthenticationUIFail as String
        let manager = FlutterSecureStorage(verifiedKeychain: fake, verifiedAuthentication: auth)
        let result = manager.writeAndVerify(params: p, value: "synthetic", context: LAContext(), localizedReason: "Test", isCancelled: { false })
        XCTAssertEqual(result.status, errSecInteractionNotAllowed)
        XCTAssertEqual(auth.calls, 0); XCTAssertTrue(fake.calls.isEmpty)
    }
    func testAuthenticationDenialDoesNotReachKeychain() {
        let fake = FakeKeychain(), auth = FakeAuthentication()
        auth.status = errSecUserCanceled
        let manager = FlutterSecureStorage(verifiedKeychain: fake, verifiedAuthentication: auth)
        let result = manager.writeAndVerify(params: params(), value: "synthetic", context: LAContext(), localizedReason: "Test", isCancelled: { false })
        XCTAssertEqual(result.status, errSecUserCanceled)
        XCTAssertEqual(auth.calls, 1)
        XCTAssertTrue(fake.calls.isEmpty)
    }
    func testSuspensionDuringAuthorizationDoesNotMutate() {
        let fake = FakeKeychain(), auth = FakeAuthentication(), contexts = VerifiedWriteContexts()
        let ticket = contexts.ticket(), context = contexts.begin(contexts.ticket())!
        auth.afterAuthorize = { contexts.cancel(suspending: "sleep") }
        let manager = FlutterSecureStorage(verifiedKeychain: fake, verifiedAuthentication: auth)
        let result = manager.writeAndVerify(params: params(), value: "synthetic", context: context, localizedReason: "Test", isCancelled: { !contexts.isValid(ticket, context) })
        XCTAssertEqual(result.status, errSecUserCanceled)
        XCTAssertTrue(fake.calls.isEmpty)
        contexts.end(context)
    }
    func testStricterStoredACLDoesNotOpenAnotherPrompt() {
        let fake = FakeKeychain(), auth = FakeAuthentication(), context = LAContext()
        fake.updateStatus = errSecInteractionNotAllowed
        let manager = FlutterSecureStorage(verifiedKeychain: fake, verifiedAuthentication: auth)
        let result = manager.writeAndVerify(params: params(), value: "synthetic", context: context, localizedReason: "Test", isCancelled: { false })
        XCTAssertEqual(result.status, errSecInteractionNotAllowed)
        XCTAssertEqual(fake.calls, ["update"])
        XCTAssertTrue(context.interactionNotAllowed)
    }
    func testUpdateAndReadShareContextAndPreserveACL() {
        let fake = FakeKeychain(), context = LAContext()
        let result = FlutterSecureStorage(verifiedKeychain: fake, verifiedAuthentication: FakeAuthentication()).writeAndVerify(params: params(), value: "synthetic", context: context, localizedReason: "Synthetic test", isCancelled: { false })
        XCTAssertEqual(result.status, errSecSuccess)
        XCTAssertEqual(fake.calls, ["update", "read"])
        for query in fake.queries {
            XCTAssertTrue(query[kSecUseAuthenticationContext] as? LAContext === context)
            XCTAssertTrue(context.interactionNotAllowed)
            XCTAssertNotNil(query[kSecAttrAccessControl])
            XCTAssertEqual(query[kSecAttrService] as? String, "test")
        }
    }
    func testNewItemAddsOnlyWhenMissing() {
        let fake = FakeKeychain(); fake.updateStatus = errSecItemNotFound
        let result = FlutterSecureStorage(verifiedKeychain: fake, verifiedAuthentication: FakeAuthentication()).writeAndVerify(params: params(), value: "synthetic", context: LAContext(), localizedReason: "Synthetic test", isCancelled: { false })
        XCTAssertEqual(result.status, errSecSuccess)
        XCTAssertEqual(fake.calls, ["update", "add", "read"])
    }
    func testDeniedUpdateNeverAddsOrReads() {
        let fake = FakeKeychain(); fake.updateStatus = errSecUserCanceled
        let result = FlutterSecureStorage(verifiedKeychain: fake, verifiedAuthentication: FakeAuthentication()).writeAndVerify(params: params(), value: "synthetic", context: LAContext(), localizedReason: "Synthetic test", isCancelled: { false })
        XCTAssertEqual(result.status, errSecUserCanceled)
        XCTAssertEqual(fake.calls, ["update"])
    }
    func testAddFailureDoesNotReadOrRetry() {
        let fake = FakeKeychain(); fake.updateStatus = errSecItemNotFound; fake.addStatus = errSecDuplicateItem
        let result = FlutterSecureStorage(verifiedKeychain: fake, verifiedAuthentication: FakeAuthentication()).writeAndVerify(params: params(), value: "synthetic", context: LAContext(), localizedReason: "Synthetic test", isCancelled: { false })
        XCTAssertEqual(result.status, errSecDuplicateItem)
        XCTAssertEqual(fake.calls, ["update", "add"])
    }
    func testCorruptAndMissingReadbackFailClosed() {
        for bytes in [Data("wrong".utf8), nil] {
            let fake = FakeKeychain(); fake.value = bytes
            let result = FlutterSecureStorage(verifiedKeychain: fake, verifiedAuthentication: FakeAuthentication()).writeAndVerify(params: params(), value: "synthetic", context: LAContext(), localizedReason: "Synthetic test", isCancelled: { false })
            XCTAssertEqual(result.status, errSecDecode)
        }
    }
    func testReadDenialIsNotSuccess() {
        let fake = FakeKeychain(); fake.readStatus = errSecAuthFailed
        let result = FlutterSecureStorage(verifiedKeychain: fake, verifiedAuthentication: FakeAuthentication()).writeAndVerify(params: params(), value: "synthetic", context: LAContext(), localizedReason: "Synthetic test", isCancelled: { false })
        XCTAssertEqual(result.status, errSecAuthFailed)
    }
    func testCancellationAfterWritePreventsFurtherCalls() {
        let fake = FakeKeychain(); var cancelled = false
        fake.afterCall = { cancelled = true }
        let result = FlutterSecureStorage(verifiedKeychain: fake, verifiedAuthentication: FakeAuthentication()).writeAndVerify(params: params(), value: "synthetic", context: LAContext(), localizedReason: "Synthetic test", isCancelled: { cancelled })
        XCTAssertEqual(result.status, errSecUserCanceled)
        XCTAssertEqual(fake.calls, ["update"])
    }
    func testCancellationBeforeStartDoesNotMutate() {
        let fake = FakeKeychain()
        let result = FlutterSecureStorage(verifiedKeychain: fake, verifiedAuthentication: FakeAuthentication()).writeAndVerify(params: params(), value: "synthetic", context: LAContext(), localizedReason: "Synthetic test", isCancelled: { true })
        XCTAssertEqual(result.status, errSecUserCanceled); XCTAssertTrue(fake.calls.isEmpty)
    }
    func testCancellationAfterReadIsNotLateSuccess() {
        let fake = FakeKeychain(); var cancelled = false
        fake.afterCall = { if fake.calls.last == "read" { cancelled = true } }
        let result = FlutterSecureStorage(verifiedKeychain: fake, verifiedAuthentication: FakeAuthentication()).writeAndVerify(params: params(), value: "synthetic", context: LAContext(), localizedReason: "Synthetic test", isCancelled: { cancelled })
        XCTAssertEqual(result.status, errSecUserCanceled)
        XCTAssertEqual(fake.calls, ["update", "read"])
        fake.afterCall = nil
    }
    func testRetryAfterDenialUsesFreshContext() {
        let contexts = VerifiedWriteContexts(), fake = FakeKeychain()
        let manager = FlutterSecureStorage(verifiedKeychain: fake, verifiedAuthentication: FakeAuthentication())
        let first = contexts.begin(contexts.ticket())!
        fake.updateStatus = errSecAuthFailed
        XCTAssertEqual(manager.writeAndVerify(params: params(), value: "synthetic", context: first, localizedReason: "Synthetic test", isCancelled: { false }).status, errSecAuthFailed)
        contexts.end(first)
        let next = contexts.begin(contexts.ticket())!
        XCTAssertFalse(first === next)
        fake.updateStatus = errSecSuccess
        XCTAssertEqual(manager.writeAndVerify(params: params(), value: "synthetic", context: next, localizedReason: "Synthetic test", isCancelled: { false }).status, errSecSuccess)
        contexts.end(next)
    }
    func testEnclaveRejectedWithoutMutation() {
        let fake = FakeKeychain(); var p = params(); p.useSecureEnclave = true
        let result = FlutterSecureStorage(verifiedKeychain: fake, verifiedAuthentication: FakeAuthentication()).writeAndVerify(params: p, value: "synthetic", context: LAContext(), localizedReason: "Synthetic test", isCancelled: { false })
        XCTAssertEqual(result.status, errSecParam); XCTAssertTrue(fake.calls.isEmpty)
    }
    func testContextsNeverSharedAndQueuedTicketsCancelled() {
        let contexts = VerifiedWriteContexts(), ticket = UInt64(0)
        let first = contexts.begin(ticket)!
        XCTAssertEqual(first.touchIDAuthenticationAllowableReuseDuration, 0)
        XCTAssertNil(contexts.begin(ticket))
        contexts.end(first)
        let second = contexts.begin(ticket)!
        XCTAssertFalse(first === second)
        contexts.cancel()
        XCTAssertFalse(contexts.isValid(ticket, second))
        XCTAssertNil(contexts.begin(ticket))
        let next = contexts.begin(contexts.ticket())!
        contexts.end(next)
    }
    func testBackgroundAndProtectedDataRequireBothResumes() {
        let contexts = VerifiedWriteContexts()
        contexts.cancel(suspending: "background")
        contexts.cancel(suspending: "protectedData")
        XCTAssertNil(contexts.begin(contexts.ticket()))
        contexts.resume("background")
        XCTAssertNil(contexts.begin(contexts.ticket()))
        contexts.resume("protectedData")
        let next = contexts.begin(contexts.ticket())!
        contexts.end(next)
    }
}
