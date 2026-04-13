// SPDX-License-Identifier: MIT
// KeychainStorage.swift — iOS Keychain persistence for identity private keys
//
// SECURITY: Uses kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly to prevent
// key access before first device unlock. No iCloud sync (kSecAttrSynchronizable not set).

import Foundation
import Security

public enum KeychainStorage {
    private static let servicePrefix = "network.reticulum.identity"

    /// Store identity private key bytes in Keychain.
    ///
    /// - Parameters:
    ///   - privateKeyBytes: The 64-byte private key bundle to store.
    ///   - forIdentityHash: The identity hash string used as the account key.
    /// - Throws: `ReticulumError.keychainStoreFailed` if the Keychain operation fails.
    public static func store(privateKeyBytes: Data, forIdentityHash: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: servicePrefix,
            kSecAttrAccount as String: forIdentityHash,
            kSecValueData as String: privateKeyBytes,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]

        // Delete existing if present
        SecItemDelete(query as CFDictionary)

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw ReticulumError.keychainStoreFailed(status: status)
        }
    }

    /// Load identity private key bytes from Keychain.
    ///
    /// - Parameter forIdentityHash: The identity hash string used as the account key.
    /// - Returns: The stored private key bytes, or nil if not found.
    public static func load(forIdentityHash: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: servicePrefix,
            kSecAttrAccount as String: forIdentityHash,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { return nil }
        return result as? Data
    }

    /// Delete identity from Keychain.
    ///
    /// - Parameter forIdentityHash: The identity hash string used as the account key.
    public static func delete(forIdentityHash: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: servicePrefix,
            kSecAttrAccount as String: forIdentityHash
        ]
        SecItemDelete(query as CFDictionary)
    }
}
