import XCTest
import Security
import LocalAuthentication
@testable import StorageCore

final class BoundedAuthorizationScopeTests: XCTestCase {
    func params() -> KeychainQueryParameters {
        KeychainQueryParameters(service: UUID().uuidString, isSynchronizable: false,
            accessibilityLevel: "unlocked_this_device", usesDataProtectionKeychain: false,
            shouldReturnData: true, accessControlFlags: "userPresence", useSecureEnclave: false)
    }
    func rule(_ key: String = "synthetic", reads: Int = 1, writes: Int = 1) -> ScopeSlotRule {
        ScopeSlotRule(key: key, read: reads > 0, writeVerified: writes > 0,
            createVerified: writes > 0, maxReads: reads, maxWrites: writes)
    }
    func scope(_ fake: FakeKeychain, _ auth: FakeAuthentication = FakeAuthentication(),
               contexts: VerifiedWriteContexts = VerifiedWriteContexts(),
               lifetime: TimeInterval = 120, slots: [ScopeSlotRule]? = nil) throws -> BoundedAuthorizationScope {
        try BoundedAuthorizationScope(contexts: contexts, params: params(), slots: slots ?? [rule()],
            reason: "Synthetic test", lifetime: lifetime, ownerEpoch: 0, keychain: fake, authentication: auth)
    }
    func failure(_ code: String, _ body: () throws -> Void) {
        XCTAssertThrowsError(try body()) { error in XCTAssertEqual((error as? ScopeFailure)?.code, code) }
    }
    func testAuthenticationOutcomesRemainDistinctThroughScope() throws {
        for (status, code): (OSStatus, String) in [
            (VerifiedAuthenticationStatus.userCancelled, "userCancelled"),
            (VerifiedAuthenticationStatus.interrupted, "interrupted"),
            (errSecUserCanceled, "interrupted"), (errSecAuthFailed, "denied")
        ] {
            let fake = FakeKeychain(), auth = FakeAuthentication()
            auth.status = status
            let subject = try scope(fake, auth)
            failure(code) { try subject.write("synthetic", value: "synthetic", createOnly: false, epoch: 0, sequence: 1) }
            XCTAssertTrue(fake.calls.isEmpty)
            failure(code) { try subject.checkActive() }
            XCTAssertEqual(auth.calls, 1)
        }
    }
    func testOnlyExplicitUserCancellationHasUserCancelledStatus() {
        XCTAssertEqual(SystemVerifiedAuthentication.status(success: true, error: nil), errSecSuccess)
        XCTAssertEqual(SystemVerifiedAuthentication.status(success: false, error: LAError(.userCancel)), VerifiedAuthenticationStatus.userCancelled)
        for code: LAError.Code in [.appCancel, .systemCancel, .invalidContext] {
            XCTAssertEqual(SystemVerifiedAuthentication.status(success: false, error: LAError(code)), VerifiedAuthenticationStatus.interrupted)
        }
        for code: LAError.Code in [.authenticationFailed, .biometryLockout, .userFallback, .notInteractive] {
            XCTAssertEqual(SystemVerifiedAuthentication.status(success: false, error: LAError(code)), errSecAuthFailed)
        }
    }
    func testMixedCallsUseOneEvaluationAndRealReadbacks() throws {
        let fake = FakeKeychain(), auth = FakeAuthentication()
        let subject = try scope(fake, auth, slots: [rule(reads: 2, writes: 2)])
        try subject.write("synthetic", value: "synthetic", createOnly: false, epoch: 0, sequence: 1)
        _ = try subject.readBatch(["synthetic"], epoch: 0, sequence: 2)
        try subject.write("synthetic", value: "synthetic", createOnly: true, epoch: 0, sequence: 3)
        _ = try subject.readBatch(["synthetic"], epoch: 0, sequence: 4)
        XCTAssertEqual(auth.calls, 1)
        XCTAssertEqual(fake.calls, ["update", "read", "read", "add", "read", "read"])
    }
    func testCreateCollisionNeverUpdates() throws {
        let fake = FakeKeychain(); fake.addStatus = errSecDuplicateItem
        let subject = try scope(fake)
        failure("duplicateItem") { try subject.write("synthetic", value: "synthetic", createOnly: true, epoch: 0, sequence: 1) }
        XCTAssertEqual(fake.calls, ["add"])
        failure("duplicateItem") { try subject.checkActive() }
    }
    func testOutOfPlanBatchDoesNotReadEvenAllowedPrefix() throws {
        let fake = FakeKeychain(), subject = try scope(fake)
        failure("invalidPlan") { _ = try subject.readBatch(["synthetic", "outside"], epoch: 0, sequence: 1) }
        XCTAssertTrue(fake.calls.isEmpty)
    }
    func testReadQuotaRevokesWholeAction() throws {
        let fake = FakeKeychain(), subject = try scope(fake)
        _ = try subject.readBatch(["synthetic"], epoch: 0, sequence: 1)
        failure("invalidPlan") { _ = try subject.readBatch(["synthetic"], epoch: 0, sequence: 2) }
        failure("invalidPlan") { try subject.write("synthetic", value: "synthetic", createOnly: false, epoch: 0, sequence: 3) }
        XCTAssertEqual(fake.calls, ["read"])
    }
    func testCreateAndUpdateShareWriteQuota() throws {
        let fake = FakeKeychain(), subject = try scope(fake)
        try subject.write("synthetic", value: "synthetic", createOnly: true, epoch: 0, sequence: 1)
        failure("invalidPlan") { try subject.write("synthetic", value: "synthetic", createOnly: false, epoch: 0, sequence: 2) }
        XCTAssertEqual(fake.calls, ["add", "read"])
    }
    func testWrongEpochAndReplayRejectedBeforeAccess() throws {
        for epoch: Int64 in [0, 1] {
            let fake = FakeKeychain(), subject = try scope(fake)
            failure("invalidPlan") { try subject.check(epoch: epoch, sequence: epoch == 0 ? 2 : 1) }
            XCTAssertTrue(fake.calls.isEmpty)
        }
    }
    func testCloseRejectsQueuedWork() throws {
        let fake = FakeKeychain(), subject = try scope(fake)
        subject.close(); subject.close()
        failure("revoked") { try subject.write("synthetic", value: "synthetic", createOnly: false, epoch: 0, sequence: 1) }
        XCTAssertTrue(fake.calls.isEmpty)
    }
    func testLifecycleRevocationAndResumeDoNotReviveScope() throws {
        let fake = FakeKeychain(), contexts = VerifiedWriteContexts()
        let subject = try scope(fake, contexts: contexts)
        contexts.cancel(suspending: "hidden"); contexts.resume("hidden")
        failure("revoked") { _ = try subject.readBatch(["synthetic"], epoch: 0, sequence: 1) }
        XCTAssertTrue(fake.calls.isEmpty)
    }
    func testRevocationDuringEvaluationPreventsMutation() throws {
        let fake = FakeKeychain(), auth = FakeAuthentication(), contexts = VerifiedWriteContexts()
        let subject = try scope(fake, auth, contexts: contexts)
        auth.afterAuthorize = { contexts.cancel() }
        failure("revoked") { try subject.write("synthetic", value: "synthetic", createOnly: false, epoch: 0, sequence: 1) }
        XCTAssertTrue(fake.calls.isEmpty)
    }
    func testRevocationAfterMutationReportsUncertainty() throws {
        let fake = FakeKeychain(), subject = try scope(fake)
        fake.afterCall = { subject.close() }
        XCTAssertThrowsError(try subject.write("synthetic", value: "synthetic", createOnly: false, epoch: 0, sequence: 1)) {
            XCTAssertEqual(($0 as? ScopeFailure)?.code, "revoked")
            XCTAssertEqual(($0 as? ScopeFailure)?.mutationMayHaveOccurred, true)
        }
        XCTAssertEqual(fake.calls, ["update"])
        fake.afterCall = nil
    }
    func testDeadlineExpiresWithoutSubsequentCalls() throws {
        let fake = FakeKeychain(), contexts = VerifiedWriteContexts()
        let ticket = contexts.ticket()
        let subject = try scope(fake, contexts: contexts, lifetime: 0.02)
        let expired = expectation(description: "independent timer")
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.1) {
            self.failure("expired") { try subject.checkActive() }
            // The context slot has already been released, with no storage call.
            let next = contexts.begin(ticket)
            XCTAssertNotNil(next)
            if let next = next { contexts.end(next) }
            expired.fulfill()
        }
        wait(for: [expired], timeout: 2)
        XCTAssertTrue(fake.calls.isEmpty)
    }
    func testNamespaceExclusionAcrossEnginesAndRelease() throws {
        let parameters = params()
        var first: BoundedAuthorizationScope? = try BoundedAuthorizationScope(contexts: VerifiedWriteContexts(),
            params: parameters, slots: [rule()], reason: "Test", lifetime: 1, ownerEpoch: 0)
        XCTAssertNil(KeychainNamespaceLease.acquire(parameters))
        first?.close()
        XCTAssertNil(KeychainNamespaceLease.acquire(parameters))
        first = nil
        XCTAssertNotNil(KeychainNamespaceLease.acquire(parameters))
    }
    func testEvaluationEventsOnlyBracketFirstEvaluation() throws {
        var events: [Bool] = []
        let subject = try BoundedAuthorizationScope(contexts: VerifiedWriteContexts(), params: params(),
            slots: [rule(writes: 2)], reason: "Test", lifetime: 1, ownerEpoch: 0,
            keychain: FakeKeychain(), authentication: FakeAuthentication(), evaluation: { events.append($0) })
        try subject.write("synthetic", value: "synthetic", createOnly: false, epoch: 0, sequence: 1)
        try subject.write("synthetic", value: "synthetic", createOnly: false, epoch: 0, sequence: 2)
        XCTAssertEqual(events, [true, false])
    }
    func testInvalidPlanDoesNotAcquireContext() throws {
        let contexts = VerifiedWriteContexts()
        failure("invalidPlan") {
            _ = try BoundedAuthorizationScope(contexts: contexts, params: params(),
                slots: [rule(reads: 29)], reason: "Test", lifetime: 1, ownerEpoch: 0)
        }
        let context = contexts.begin(contexts.ticket())
        XCTAssertNotNil(context)
        if let context = context { contexts.end(context) }
    }
}
