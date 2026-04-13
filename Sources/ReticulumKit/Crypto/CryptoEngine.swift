// SPDX-License-Identifier: MIT
// CryptoEngine.swift — Stateless facade over CryptoKit + CommonCrypto
//
// Internal API: consumers use higher-level types (Identity, Token).
// Tests access via @testable import ReticulumKit.
//
// SECURITY: This module must NEVER log raw key material or plaintext.

import Foundation
import CryptoKit
import CommonCrypto

internal enum CryptoEngine {

    // MARK: - Hashing

    /// SHA-256 full hash (32 bytes).
    static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    /// SHA-256 truncated to 16 bytes (ReticulumConstants.truncatedHashLength).
    static func truncatedHash(_ data: Data) -> Data {
        Data(SHA256.hash(data: data).prefix(ReticulumConstants.truncatedHashLength))
    }

    // MARK: - AES-CBC

    /// AES-CBC encrypt. Key length determines mode: 16 bytes = AES-128, 32 bytes = AES-256.
    /// IV must be exactly 16 bytes. Returns ciphertext with PKCS7 padding.
    ///
    /// - Parameters:
    ///   - plaintext: Data to encrypt.
    ///   - key: 16-byte (AES-128) or 32-byte (AES-256) encryption key.
    ///   - iv: 16-byte initialization vector. Must be unique per encryption.
    /// - Returns: Encrypted ciphertext including PKCS7 padding.
    /// - Throws: `ReticulumError.encryptionFailed` if CCCrypt fails.
    static func aesCBCEncrypt(_ plaintext: Data, key: Data, iv: Data) throws -> Data {
        let bufferSize = plaintext.count + kCCBlockSizeAES128
        var buffer = Data(count: bufferSize)
        var bytesEncrypted = 0

        let status = buffer.withUnsafeMutableBytes { bufferPtr in
            plaintext.withUnsafeBytes { plaintextPtr in
                key.withUnsafeBytes { keyPtr in
                    iv.withUnsafeBytes { ivPtr in
                        CCCrypt(
                            CCOperation(kCCEncrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyPtr.baseAddress, key.count,
                            ivPtr.baseAddress,
                            plaintextPtr.baseAddress, plaintext.count,
                            bufferPtr.baseAddress, bufferSize,
                            &bytesEncrypted
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            throw ReticulumError.encryptionFailed(status: status)
        }
        return buffer.prefix(bytesEncrypted)
    }

    /// AES-CBC decrypt. Returns plaintext with PKCS7 padding removed.
    ///
    /// - Parameters:
    ///   - ciphertext: Data to decrypt (must be multiple of 16 bytes).
    ///   - key: 16-byte (AES-128) or 32-byte (AES-256) decryption key.
    ///   - iv: 16-byte initialization vector used during encryption.
    /// - Returns: Decrypted plaintext.
    /// - Throws: `ReticulumError.decryptionFailed` if CCCrypt fails.
    static func aesCBCDecrypt(_ ciphertext: Data, key: Data, iv: Data) throws -> Data {
        let bufferSize = ciphertext.count + kCCBlockSizeAES128
        var buffer = Data(count: bufferSize)
        var bytesDecrypted = 0

        let status = buffer.withUnsafeMutableBytes { bufferPtr in
            ciphertext.withUnsafeBytes { ciphertextPtr in
                key.withUnsafeBytes { keyPtr in
                    iv.withUnsafeBytes { ivPtr in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyPtr.baseAddress, key.count,
                            ivPtr.baseAddress,
                            ciphertextPtr.baseAddress, ciphertext.count,
                            bufferPtr.baseAddress, bufferSize,
                            &bytesDecrypted
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            throw ReticulumError.decryptionFailed(status: status)
        }
        return buffer.prefix(bytesDecrypted)
    }

    // MARK: - HMAC

    /// HMAC-SHA256 producing 32-byte authentication code.
    static func hmacSHA256(key: Data, data: Data) -> Data {
        let hmacKey = SymmetricKey(data: key)
        let mac = HMAC<SHA256>.authenticationCode(for: data, using: hmacKey)
        return Data(mac)
    }

    /// Constant-time HMAC verification using CryptoKit's built-in comparison.
    static func verifyHMAC(_ mac: Data, key: Data, data: Data) -> Bool {
        let hmacKey = SymmetricKey(data: key)
        return HMAC<SHA256>.isValidAuthenticationCode(mac, authenticating: data, using: hmacKey)
    }

    // MARK: - HKDF

    /// HKDF-SHA256 key derivation.
    ///
    /// - Parameters:
    ///   - length: Output key material length in bytes.
    ///   - inputKeyMaterial: The input keying material.
    ///   - salt: Optional salt. Defaults to 32 zero bytes when nil (Reticulum convention).
    ///   - context: Optional context/info. Defaults to empty Data when nil.
    /// - Returns: Derived key material of requested length.
    static func hkdf(length: Int, inputKeyMaterial: Data, salt: Data? = nil, context: Data? = nil) -> Data {
        let ikm = SymmetricKey(data: inputKeyMaterial)
        let actualSalt = salt ?? Data(repeating: 0, count: 32)
        let actualContext = context ?? Data()
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: actualSalt,
            info: actualContext,
            outputByteCount: length
        )
        return derived.withUnsafeBytes { Data($0) }
    }

    // MARK: - Ed25519

    /// Sign data with Ed25519 private key. Returns 64-byte signature.
    static func sign(_ message: Data, with privateKey: Curve25519.Signing.PrivateKey) throws -> Data {
        try privateKey.signature(for: message)
    }

    /// Verify Ed25519 signature against a public key.
    static func verify(signature: Data, message: Data, publicKey: Curve25519.Signing.PublicKey) -> Bool {
        publicKey.isValidSignature(signature, for: message)
    }

    // MARK: - X25519

    /// Perform X25519 ECDH key agreement. Returns SharedSecret for further derivation.
    static func keyAgreement(
        privateKey: Curve25519.KeyAgreement.PrivateKey,
        publicKey: Curve25519.KeyAgreement.PublicKey
    ) throws -> SharedSecret {
        try privateKey.sharedSecretFromKeyAgreement(with: publicKey)
    }

    // MARK: - Random

    /// Generate cryptographically secure random bytes using SecRandomCopyBytes.
    ///
    /// - Parameter count: Number of random bytes to generate.
    /// - Returns: Data containing `count` random bytes.
    /// - Throws: `ReticulumError.randomGenerationFailed` if the system RNG fails.
    static func randomBytes(count: Int) throws -> Data {
        var bytes = Data(count: count)
        let status = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw ReticulumError.randomGenerationFailed
        }
        return bytes
    }
}
