// SPDX-License-Identifier: MIT
// KeychainStorageTests.swift — Keychain persistence tests
//
// NOTE: Keychain operations require Keychain access, which works in `swift test`
// on macOS but may fail in sandboxed CI environments or iOS simulators without
// a host app. If tests fail with -25300 (errSecItemNotFound) in CI, they may
// need to be skipped in that environment.

import Testing
import Foundation
@testable import ReticulumKit

@Suite("KeychainStorage Tests")
struct KeychainStorageTests {

    /// Generate a unique identity hash for test isolation
    private func testIdentityHash() -> String {
        "test-\(UUID().uuidString)"
    }

    @Test("store then load returns same 64-byte key data")
    func storeAndLoad() throws {
        let hash = testIdentityHash()
        let keyData = Data(repeating: 0xAB, count: 64)

        defer { KeychainStorage.delete(forIdentityHash: hash) }

        try KeychainStorage.store(privateKeyBytes: keyData, forIdentityHash: hash)
        let loaded = KeychainStorage.load(forIdentityHash: hash)
        #expect(loaded == keyData)
    }

    @Test("delete removes stored key")
    func deleteRemovesKey() throws {
        let hash = testIdentityHash()
        let keyData = Data(repeating: 0xCD, count: 64)

        try KeychainStorage.store(privateKeyBytes: keyData, forIdentityHash: hash)
        KeychainStorage.delete(forIdentityHash: hash)

        let loaded = KeychainStorage.load(forIdentityHash: hash)
        #expect(loaded == nil)
    }

    @Test("load for non-existent key returns nil")
    func loadNonExistent() {
        let hash = testIdentityHash()
        let loaded = KeychainStorage.load(forIdentityHash: hash)
        #expect(loaded == nil)
    }

    @Test("store overwrites existing key")
    func storeOverwrites() throws {
        let hash = testIdentityHash()
        let keyData1 = Data(repeating: 0x11, count: 64)
        let keyData2 = Data(repeating: 0x22, count: 64)

        defer { KeychainStorage.delete(forIdentityHash: hash) }

        try KeychainStorage.store(privateKeyBytes: keyData1, forIdentityHash: hash)
        try KeychainStorage.store(privateKeyBytes: keyData2, forIdentityHash: hash)

        let loaded = KeychainStorage.load(forIdentityHash: hash)
        #expect(loaded == keyData2)
    }
}
