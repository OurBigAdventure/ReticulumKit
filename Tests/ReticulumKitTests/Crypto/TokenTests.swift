// SPDX-License-Identifier: MIT
// TokenTests.swift — Token encrypt/decrypt tests

import Testing
import Foundation
@testable import ReticulumKit

@Suite("Token Tests")
struct TokenTests {

    // MARK: - Initialization

    @Test("Token init with 32-byte key succeeds (AES-128 mode)")
    func init32ByteKey() throws {
        let key = Data(repeating: 0xAA, count: 32)
        let token = try Token(key: key)
        _ = token // should not throw
    }

    @Test("Token init with 64-byte key succeeds (AES-256 mode)")
    func init64ByteKey() throws {
        let key = Data(repeating: 0xBB, count: 64)
        let token = try Token(key: key)
        _ = token // should not throw
    }

    @Test("Token init with other key sizes throws invalidTokenKeySize")
    func initInvalidKeySize() {
        for size in [0, 1, 16, 48, 63, 65, 128] {
            let key = Data(repeating: 0xCC, count: size)
            #expect(throws: ReticulumError.self) {
                _ = try Token(key: key)
            }
        }
    }

    // MARK: - Encrypt

    @Test("encrypt produces output of length >= plaintext.count + 48")
    func encryptOutputLength() throws {
        let key = Data(repeating: 0x42, count: 32)
        let token = try Token(key: key)
        let plaintext = Data("hello world".utf8)

        let encrypted = try token.encrypt(plaintext)
        #expect(encrypted.count >= plaintext.count + TokenConstants.overhead)
    }

    @Test("encrypt output starts with 16-byte IV, ends with 32-byte HMAC")
    func encryptFormat() throws {
        let key = Data(repeating: 0x42, count: 64)
        let token = try Token(key: key)
        let plaintext = Data("test message".utf8)

        let encrypted = try token.encrypt(plaintext)
        // Must have at least 48 bytes overhead
        #expect(encrypted.count > TokenConstants.overhead)
        // Last 32 bytes are HMAC
        let hmacPart = encrypted.suffix(32)
        #expect(hmacPart.count == 32)
        // First 16 bytes are IV
        let ivPart = encrypted.prefix(16)
        #expect(ivPart.count == 16)
    }

    @Test("encrypt of empty data works (produces IV + padded-block + HMAC)")
    func encryptEmptyData() throws {
        let key = Data(repeating: 0x42, count: 32)
        let token = try Token(key: key)

        let encrypted = try token.encrypt(Data())
        // Empty plaintext with PKCS7 produces 16 bytes ciphertext (one block of padding)
        // Total: 16 (IV) + 16 (padded block) + 32 (HMAC) = 64
        #expect(encrypted.count == 64)
    }

    // MARK: - Decrypt (round-trip)

    @Test("decrypt of encrypt(plaintext) returns original plaintext (32-byte key)")
    func roundTrip32ByteKey() throws {
        let key = Data(repeating: 0xAA, count: 32)
        let token = try Token(key: key)
        let plaintext = Data("The quick brown fox jumps over the lazy dog".utf8)

        let encrypted = try token.encrypt(plaintext)
        let decrypted = try token.decrypt(encrypted)
        #expect(decrypted == plaintext)
    }

    @Test("decrypt of encrypt(plaintext) returns original plaintext (64-byte key)")
    func roundTrip64ByteKey() throws {
        let key = Data(repeating: 0xBB, count: 64)
        let token = try Token(key: key)
        let plaintext = Data("AES-256 round trip test".utf8)

        let encrypted = try token.encrypt(plaintext)
        let decrypted = try token.decrypt(encrypted)
        #expect(decrypted == plaintext)
    }

    // MARK: - Tamper Detection

    @Test("decrypt with tampered ciphertext throws hmacVerificationFailed")
    func decryptTamperedCiphertext() throws {
        let key = Data(repeating: 0x42, count: 64)
        let token = try Token(key: key)
        let plaintext = Data("sensitive data".utf8)

        var encrypted = try token.encrypt(plaintext)
        // Tamper with a byte in the ciphertext region (between IV and HMAC)
        let tamperIndex = 20 // after IV (16), in ciphertext
        encrypted[tamperIndex] ^= 0xFF

        #expect(throws: ReticulumError.self) {
            _ = try token.decrypt(encrypted)
        }
    }

    @Test("decrypt with tampered HMAC throws hmacVerificationFailed")
    func decryptTamperedHMAC() throws {
        let key = Data(repeating: 0x42, count: 32)
        let token = try Token(key: key)
        let plaintext = Data("authenticated data".utf8)

        var encrypted = try token.encrypt(plaintext)
        // Tamper with last byte (HMAC region)
        encrypted[encrypted.count - 1] ^= 0xFF

        #expect(throws: ReticulumError.self) {
            _ = try token.decrypt(encrypted)
        }
    }

    @Test("decrypt with too-short token throws tokenTooShort")
    func decryptTooShort() throws {
        let key = Data(repeating: 0x42, count: 32)
        let token = try Token(key: key)

        // Token overhead is 48 bytes; anything <= 48 is too short
        let shortData = Data(repeating: 0x00, count: 48)
        #expect(throws: ReticulumError.self) {
            _ = try token.decrypt(shortData)
        }

        let emptyData = Data()
        #expect(throws: ReticulumError.self) {
            _ = try token.decrypt(emptyData)
        }
    }
}
