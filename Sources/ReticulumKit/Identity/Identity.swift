// SPDX-License-Identifier: MIT
// Identity.swift — Curve25519 keypair generation, hash derivation, sign/verify, encrypt/decrypt
//
// SECURITY: Private key bytes are only exposed for Keychain storage.
// Never log raw key material.

import Foundation
import CryptoKit

public struct Identity: Sendable {
    public let signingPrivateKey: Curve25519.Signing.PrivateKey
    public let agreementPrivateKey: Curve25519.KeyAgreement.PrivateKey

    public var signingPublicKey: Curve25519.Signing.PublicKey {
        _verificationOnlySigningPublicKey ?? signingPrivateKey.publicKey
    }

    public var agreementPublicKey: Curve25519.KeyAgreement.PublicKey {
        _verificationOnlyAgreementPublicKey ?? agreementPrivateKey.publicKey
    }

    /// Combined public key: X25519 (32 bytes) + Ed25519 (32 bytes) = 64 bytes
    /// IMPORTANT: X25519 FIRST, Ed25519 SECOND -- do NOT reverse
    public var publicKeyBytes: Data {
        Data(agreementPublicKey.rawRepresentation) + Data(signingPublicKey.rawRepresentation)
    }

    /// Combined private key: X25519 (32 bytes) + Ed25519 (32 bytes) = 64 bytes
    public var privateKeyBytes: Data {
        Data(agreementPrivateKey.rawRepresentation) + Data(signingPrivateKey.rawRepresentation)
    }

    /// Identity hash: SHA-256(publicKeyBytes) truncated to 16 bytes
    public var hash: TruncatedHash {
        let fullHash = CryptoEngine.truncatedHash(publicKeyBytes)
        return try! TruncatedHash(fullHash)
    }

    /// Generate new random identity
    public init() {
        self.signingPrivateKey = Curve25519.Signing.PrivateKey()
        self.agreementPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        self._verificationOnlySigningPublicKey = nil
        self._verificationOnlyAgreementPublicKey = nil
    }

    /// Reconstruct from stored 64-byte private key bundle
    ///
    /// - Parameter privateKeyBytes: 64 bytes (X25519_prv:32 + Ed25519_prv:32)
    /// - Throws: `ReticulumError.invalidKeySize` if not exactly 64 bytes
    public init(privateKeyBytes: Data) throws {
        guard privateKeyBytes.count == IdentityConstants.keySize else {
            throw ReticulumError.invalidKeySize(privateKeyBytes.count)
        }
        // X25519 private key = first 32 bytes
        self.agreementPrivateKey = try Curve25519.KeyAgreement.PrivateKey(
            rawRepresentation: privateKeyBytes.prefix(32)
        )
        // Ed25519 private key = last 32 bytes
        self.signingPrivateKey = try Curve25519.Signing.PrivateKey(
            rawRepresentation: privateKeyBytes.suffix(32)
        )
        self._verificationOnlySigningPublicKey = nil
        self._verificationOnlyAgreementPublicKey = nil
    }

    /// Reconstruct a verification-only Identity from 64-byte public key bundle.
    ///
    /// This creates an Identity that can verify signatures but cannot sign or decrypt.
    /// The private keys are freshly generated and unrelated to the public keys --
    /// only the public key properties are meaningful.
    ///
    /// - Parameter publicKeyBytes: 64 bytes (X25519_pub:32 + Ed25519_pub:32)
    /// - Throws: `ReticulumError.invalidKeySize` if not exactly 64 bytes
    public init(publicKeyBytes: Data) throws {
        guard publicKeyBytes.count == IdentityConstants.keySize else {
            throw ReticulumError.invalidKeySize(publicKeyBytes.count)
        }
        // We need CryptoKit public key objects for verification.
        // Store the public keys by creating dummy private keys and replacing the public accessors.
        // Unfortunately CryptoKit doesn't let us create signing keys from just public bytes
        // in the Signing.PrivateKey type, so we use a wrapper approach.
        //
        // Since Identity.verify() uses CryptoEngine.verify(signature:message:publicKey:)
        // which takes a Curve25519.Signing.PublicKey, we need a real public key object.
        // We create dummy private keys but override the verification to use the provided public key.

        // Create dummy private keys (not used for signing/decryption)
        self.signingPrivateKey = Curve25519.Signing.PrivateKey()
        self.agreementPrivateKey = Curve25519.KeyAgreement.PrivateKey()

        // Store the actual public keys for verification
        let signingPubBytes = Data(publicKeyBytes.suffix(32))
        let agreementPubBytes = Data(publicKeyBytes.prefix(32))
        self._verificationOnlySigningPublicKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: signingPubBytes
        )
        self._verificationOnlyAgreementPublicKey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: agreementPubBytes
        )
    }

    // Storage for verification-only public keys (nil for normal identities)
    private var _verificationOnlySigningPublicKey: Curve25519.Signing.PublicKey?
    private var _verificationOnlyAgreementPublicKey: Curve25519.KeyAgreement.PublicKey?

    /// Sign data with Ed25519 key
    public func sign(_ data: Data) throws -> Data {
        try CryptoEngine.sign(data, with: signingPrivateKey)
    }

    /// Verify Ed25519 signature
    public func verify(signature: Data, for data: Data) -> Bool {
        CryptoEngine.verify(signature: signature, message: data, publicKey: signingPublicKey)
    }

    /// Encrypt data to a recipient using their X25519 public key.
    /// Performs ECDH + HKDF to derive shared Token key, then Token.encrypt.
    public func encrypt(plaintext: Data, for recipientPublicKey: Curve25519.KeyAgreement.PublicKey) throws -> Data {
        let sharedSecret = try CryptoEngine.keyAgreement(
            privateKey: agreementPrivateKey,
            publicKey: recipientPublicKey
        )
        let derivedKey = CryptoEngine.hkdf(
            length: 64,  // 32 signing + 32 encryption for AES-256
            inputKeyMaterial: sharedSecret.withUnsafeBytes { Data($0) },
            salt: nil,
            context: nil
        )
        let token = try Token(key: derivedKey)
        return try token.encrypt(plaintext)
    }

    /// Decrypt data from a sender using their X25519 public key.
    public func decrypt(ciphertext: Data, from senderPublicKey: Curve25519.KeyAgreement.PublicKey) throws -> Data {
        let sharedSecret = try CryptoEngine.keyAgreement(
            privateKey: agreementPrivateKey,
            publicKey: senderPublicKey
        )
        let derivedKey = CryptoEngine.hkdf(
            length: 64,
            inputKeyMaterial: sharedSecret.withUnsafeBytes { Data($0) },
            salt: nil,
            context: nil
        )
        let token = try Token(key: derivedKey)
        return try token.decrypt(ciphertext)
    }
}
