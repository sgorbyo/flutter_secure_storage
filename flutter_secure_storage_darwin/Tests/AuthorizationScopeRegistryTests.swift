import XCTest
@testable import StorageCore

final class AuthorizationScopeRegistryTests: XCTestCase {
    func make(_ contexts: VerifiedWriteContexts, epoch: Int64 = 0) throws -> BoundedAuthorizationScope {
        try BoundedAuthorizationScope(contexts: contexts,
            params: KeychainQueryParameters(service: UUID().uuidString, usesDataProtectionKeychain: false),
            slots: [ScopeSlotRule(key: "synthetic", read: true, writeVerified: false, createVerified: false,
                                 maxReads: 1, maxWrites: 0)], reason: "Test", lifetime: 1, ownerEpoch: epoch)
    }
    func testConcurrentOpenRejectedAndUnknownHandleDoesNotRevokeCurrent() throws {
        let registry = AuthorizationScopeRegistry(), contexts = VerifiedWriteContexts()
        let current = try registry.open(ownerEpoch: 0) { try make(contexts) }
        XCTAssertThrowsError(try registry.open(ownerEpoch: 0) { try make(contexts) }) {
            XCTAssertEqual(($0 as? ScopeFailure)?.code, "busy")
        }
        XCTAssertThrowsError(try registry.lookup(handle: "unknown", ownerEpoch: 0))
        try registry.close(handle: "unknown", ownerEpoch: 0)
        try current.checkActive()
    }
    func testOwnerChangeRejectsOldRequestsAndNeedsNewEpoch() throws {
        let registry = AuthorizationScopeRegistry(), contexts = VerifiedWriteContexts()
        let old = try registry.open(ownerEpoch: 0) { try make(contexts) }
        try registry.revoke(nextEpoch: 1)
        XCTAssertThrowsError(try old.checkActive())
        XCTAssertThrowsError(try registry.open(ownerEpoch: 0) { try make(contexts) })
        let fresh = try registry.open(ownerEpoch: 1) { try make(contexts, epoch: 1) }
        try registry.close(handle: old.handle, ownerEpoch: 0)
        try fresh.checkActive()
        XCTAssertThrowsError(try registry.revoke(nextEpoch: 1))
        try fresh.checkActive()
    }
    func testEngineTeardownInvalidatesRetainedWorkerScope() throws {
        let contexts = VerifiedWriteContexts()
        var registry: AuthorizationScopeRegistry? = AuthorizationScopeRegistry()
        let pending = try registry!.open(ownerEpoch: 0) { try make(contexts) }
        registry = nil
        XCTAssertThrowsError(try pending.checkActive())
    }
    func testCancelKeepsEpochButRequiresFreshScope() throws {
        let registry = AuthorizationScopeRegistry(), contexts = VerifiedWriteContexts()
        let old = try registry.open(ownerEpoch: 0) { try make(contexts) }
        registry.cancel()
        XCTAssertThrowsError(try old.checkActive())
        let fresh = try registry.open(ownerEpoch: 0) { try make(contexts) }
        XCTAssertNotEqual(old.handle, fresh.handle)
        try fresh.checkActive()
    }
}
