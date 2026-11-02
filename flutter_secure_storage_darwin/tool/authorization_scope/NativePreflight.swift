import Foundation
import LocalAuthentication
import Security

/// Runs against a fresh synthetic service with interaction explicitly disabled.
/// It checks entitlement-dependent creation, protected denial and exact cleanup.
func nativePreflight() -> Bool {
    let service = "cloud.igenogram.authscope.preflight." + UUID().uuidString
    let context = LAContext(); context.interactionNotAllowed = true
    defer { context.invalidate() }
    guard let acl = SecAccessControlCreateWithFlags(nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .userPresence, nil) else { return false }
    let selector: [CFString: Any] = [kSecClass: kSecClassGenericPassword,
        kSecAttrService: service, kSecAttrAccount: "preflight",
        kSecUseAuthenticationContext: context, kSecAttrAccessControl: acl]
    var add = selector
    add[kSecAttrAccessControl] = acl
    add[kSecValueData] = Data("synthetic preflight".utf8)
    let added = SecItemAdd(add as CFDictionary, nil)
    print("preflight.add status=\(added)")
    guard added == errSecSuccess else { return false }
    var query = selector
    query[kSecReturnData] = true; query[kSecMatchLimit] = kSecMatchLimitOne
    var value: CFTypeRef?
    let read = SecItemCopyMatching(query as CFDictionary, &value)
    print("preflight.unauthorizedRead status=\(read)")
    let deleted = SecItemDelete(selector as CFDictionary)
    print("preflight.cleanup status=\(deleted)")
    // A device's recent authentication must not make this fresh context usable.
    return read == errSecInteractionNotAllowed && deleted == errSecSuccess
}
