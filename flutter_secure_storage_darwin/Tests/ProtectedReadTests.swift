import XCTest
import LocalAuthentication
import Security
@testable import StorageCore

final class BatchKeychain: VerifiedKeychain {
    var unlocked = false
    var missing = false
    var denied = false
    var keys = [String]()
    var contexts = [LAContext]()
    var afterRead: (() -> Void)?
    func update(_ q: [CFString: Any], _ a: [CFString: Any]) -> OSStatus { XCTFail("read must not write"); return errSecParam }
    func add(_ q: [CFString: Any]) -> OSStatus { XCTFail("read must not add"); return errSecParam }
    func read(_ q: [CFString: Any]) -> (OSStatus, Data?) {
        keys.append(q[kSecAttrAccount] as! String)
        let c = q[kSecUseAuthenticationContext] as! LAContext
        contexts.append(c)
        XCTAssertTrue(c.interactionNotAllowed)
        afterRead?()
        if missing { return (errSecItemNotFound, nil) }
        if !unlocked || denied { return (errSecInteractionNotAllowed, nil) }
        return (errSecSuccess, Data("synthetic".utf8))
    }
}
final class ProtectedReadTests: XCTestCase {
    func params() -> KeychainQueryParameters {
        KeychainQueryParameters(service: "test", isSynchronizable: false,
            accessibilityLevel: "unlocked_this_device", usesDataProtectionKeychain: false,
            shouldReturnData: true, accessControlFlags: "userPresence", useSecureEnclave: false)
    }
    func testOneAuthorizationForTwoRecordsAndNoWrites() {
        let fake = BatchKeychain(), auth = FakeAuthentication(), context = LAContext()
        auth.afterAuthorize = { fake.unlocked = true }
        let result = FlutterSecureStorage(verifiedKeychain: fake, verifiedAuthentication: auth).readBatch(
            params: params(), keys: ["journal", "receipt"], context: context, localizedReason: "Test", isCancelled: { false })
        XCTAssertEqual(result.0, errSecSuccess); XCTAssertEqual(result.1?.count, 2)
        XCTAssertEqual(auth.calls, 1); XCTAssertEqual(fake.keys, ["journal", "journal", "receipt"])
        XCTAssertTrue(fake.contexts.allSatisfy { $0 === context })
    }
    func testAbsentRecordsDoNotPrompt() {
        let fake = BatchKeychain(), auth = FakeAuthentication(); fake.missing = true
        let result = FlutterSecureStorage(verifiedKeychain: fake, verifiedAuthentication: auth).readBatch(
            params: params(), keys: ["journal"], context: LAContext(), localizedReason: "Test", isCancelled: { false })
        XCTAssertEqual(result.0, errSecSuccess); XCTAssertEqual(result.1?.count, 1); XCTAssertEqual(auth.calls, 0)
    }
    func testDenialNeverReturnsPartialValues() {
        let fake = BatchKeychain(), auth = FakeAuthentication(); auth.status = errSecUserCanceled
        let result = FlutterSecureStorage(verifiedKeychain: fake, verifiedAuthentication: auth).readBatch(
            params: params(), keys: ["journal"], context: LAContext(), localizedReason: "Test", isCancelled: { false })
        XCTAssertEqual(result.0, errSecUserCanceled); XCTAssertNil(result.1)
    }
    func testStricterACLDoesNotOpenSecondPrompt() {
        let fake = BatchKeychain(), auth = FakeAuthentication(); fake.denied = true
        let result = FlutterSecureStorage(verifiedKeychain: fake, verifiedAuthentication: auth).readBatch(
            params: params(), keys: ["journal"], context: LAContext(), localizedReason: "Test", isCancelled: { false })
        XCTAssertEqual(result.0, errSecInteractionNotAllowed); XCTAssertNil(result.1); XCTAssertEqual(auth.calls, 1)
    }
    func testCancellationDuringAuthorizationDiscardsResult() {
        let fake = BatchKeychain(), auth = FakeAuthentication(), contexts = VerifiedWriteContexts()
        let ticket = contexts.ticket(), context = contexts.begin(contexts.ticket())!
        auth.afterAuthorize = { contexts.cancel(suspending: "background"); fake.unlocked = true }
        let result = FlutterSecureStorage(verifiedKeychain: fake, verifiedAuthentication: auth).readBatch(
            params: params(), keys: ["journal"], context: context, localizedReason: "Test", isCancelled: { !contexts.isValid(ticket, context) })
        XCTAssertEqual(result.0, errSecUserCanceled); XCTAssertNil(result.1); XCTAssertEqual(fake.keys.count, 1)
    }
    func testCancellationAfterReadDiscardsPartialBatch() {
        let fake = BatchKeychain(), auth = FakeAuthentication(); fake.unlocked = true
        var cancelled = false
        fake.afterRead = { cancelled = true }
        let result = FlutterSecureStorage(verifiedKeychain: fake, verifiedAuthentication: auth).readBatch(
            params: params(), keys: ["journal", "receipt"], context: LAContext(), localizedReason: "Test", isCancelled: { cancelled })
        XCTAssertEqual(result.0, errSecUserCanceled); XCTAssertNil(result.1); XCTAssertEqual(fake.keys.count, 1)
    }
}
