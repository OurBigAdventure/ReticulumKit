// SPDX-License-Identifier: MIT
// Token.swift — Fernet-like encrypt/decrypt format
//
// Wire format: [IV:16][Ciphertext:variable][HMAC-SHA256:32]
// SECURITY: HMAC is ALWAYS verified BEFORE decryption to prevent padding oracle attacks.

import Foundation
import CryptoKit

public struct Token: Sendable {
    private let signingKey: Data
    private let encryptionKey: Data

    /// Create a Token with a symmetric key.
    ///
    /// - Parameter key: 32 bytes (AES-128: 16 signing + 16 encryption)
    ///                  or 64 bytes (AES-256: 32 signing + 32 encryption).
    /// - Throws: `ReticulumError.invalidTokenKeySize` for other key sizes.
    public init(key: Data) throws {
        switch key.count {
        case 32:  // AES-128-CBC mode
            self.signingKey = Data(key.prefix(16))
            self.encryptionKey = Data(key.suffix(16))
        case 64:  // AES-256-CBC mode
            self.signingKey = Data(key.prefix(32))
            self.encryptionKey = Data(key.suffix(32))
        default:
            throw ReticulumError.invalidTokenKeySize(key.count)
        }
    }

    /// Encrypt plaintext into token format: [IV:16][Ciphertext:var][HMAC:32]
    ///
    /// - Parameter plaintext: Data to encrypt (may be empty).
    /// - Returns: Encrypted token with IV prefix and HMAC suffix.
    public func encrypt(_ plaintext: Data) throws -> Data {
        let iv = try CryptoEngine.randomBytes(count: 16)
        let ciphertext = try CryptoEngine.aesCBCEncrypt(plaintext, key: encryptionKey, iv: iv)
        let signedParts = iv + ciphertext
        let hmac = CryptoEngine.hmacSHA256(key: signingKey, data: signedParts)
        return signedParts + hmac
    }

    /// Decrypt a token back to plaintext.
    ///
    /// SECURITY: HMAC is verified before decryption (constant-time comparison).
    ///
    /// - Parameter token: Token data in [IV:16][Ciphertext:var][HMAC:32] format.
    /// - Returns: Decrypted plaintext.
    /// - Throws: `ReticulumError.tokenTooShort` if token is too small,
    ///           `ReticulumError.hmacVerificationFailed` if HMAC check fails.
    public func decrypt(_ token: Data) throws -> Data {
        guard token.count > TokenConstants.overhead else {
            throw ReticulumError.tokenTooShort
        }

        let hmacStart = token.count - 32
        let providedHMAC = Data(token[hmacStart...])
        let signedParts = Data(token[..<hmacStart])

        // CRITICAL: Verify HMAC BEFORE decryption (constant-time)
        guard CryptoEngine.verifyHMAC(providedHMAC, key: signingKey, data: signedParts) else {
            throw ReticulumError.hmacVerificationFailed
        }

        let iv = Data(signedParts.prefix(16))
        let ciphertext = Data(signedParts.dropFirst(16))
        return try CryptoEngine.aesCBCDecrypt(ciphertext, key: encryptionKey, iv: iv)
    }
}
