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

    /// Encrypt data for a recipient using Reticulum/Python-RNS-compatible wire format.
    ///
    /// Wire format: `[ephemeral_pub:32] + [iv:16] + [ciphertext:var] + [hmac:32]`
    ///
    /// Procedure (matches `RNS.Identity.encrypt` in Python RNS):
    /// 1. Generate an ephemeral X25519 keypair.
    /// 2. ECDH(ephemeral_priv, recipient.agreementPublicKey) → shared secret.
    /// 3. HKDF-SHA256(shared, salt = recipient.hash, length = 64) → 64-byte derived key.
    /// 4. Token.encrypt(plaintext) with the derived key (32 sign + 32 enc for AES-256-CBC).
    /// 5. Output = ephemeral_pub_bytes(32) + token.
    ///
    /// The `recipient` parameter must carry both the X25519 agreement public key AND the
    /// Ed25519 signing public key so the recipient identity hash (used as HKDF salt) can
    /// be reconstructed. Pass a verification-only Identity (constructed via
    /// `init(publicKeyBytes:)`) when only public keys are known.
    ///
    /// Note: when `ratchetPublicKey` is nil this is the static-identity path.
    /// When set, ECDH uses that announce ratchet (Python `Identity.encrypt` ratchet=).
    ///
    /// - Parameters:
    ///   - plaintext: Data to encrypt.
    ///   - recipient: The recipient's identity (public-key form is sufficient).
    ///   - ratchetPublicKey: Optional 32-byte X25519 ratchet pub from their announce.
    ///     Python `Identity.encrypt(..., ratchet=)` ECDHs against this key when set;
    ///     HKDF salt remains the recipient identity hash.
    /// - Returns: Encrypted token in Reticulum wire format.
    public func encrypt(plaintext: Data, for recipient: Identity, ratchetPublicKey: Data? = nil) throws -> Data {
        let ephemeralPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let ephemeralPubBytes = Data(ephemeralPrivateKey.publicKey.rawRepresentation)

        let agreementKey: Curve25519.KeyAgreement.PublicKey
        if let ratchetPublicKey, ratchetPublicKey.count == 32,
           let ratchetKey = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: ratchetPublicKey) {
            agreementKey = ratchetKey
        } else {
            agreementKey = recipient.agreementPublicKey
        }

        let sharedSecret = try CryptoEngine.keyAgreement(
            privateKey: ephemeralPrivateKey,
            publicKey: agreementKey
        )
        let derivedKey = CryptoEngine.hkdf(
            length: 64,
            inputKeyMaterial: sharedSecret.withUnsafeBytes { Data($0) },
            salt: recipient.hash.data,
            context: nil
        )
        let token = try Token(key: derivedKey)
        let ciphertext = try token.encrypt(plaintext)
        return ephemeralPubBytes + ciphertext
    }

    /// Decrypt data sent to this identity using Reticulum/Python-RNS-compatible wire format.
    ///
    /// Wire format expected: `[ephemeral_pub:32] + [iv:16] + [ciphertext:var] + [hmac:32]`
    ///
    /// Procedure (matches `RNS.Identity.decrypt` in Python RNS):
    /// 1. Strip the leading 32 bytes as the sender's ephemeral X25519 public key.
    /// 2. ECDH(self.agreementPrivateKey, ephemeral_pub) → shared secret.
    /// 3. HKDF-SHA256(shared, salt = self.hash, length = 64) → 64-byte derived key.
    /// 4. Token.decrypt(remaining bytes) → plaintext.
    ///
    /// - Parameter ciphertext: Encrypted token in Reticulum wire format.
    /// - Returns: Decrypted plaintext.
    /// - Throws: `ReticulumError.tokenTooShort` if input is shorter than the ephemeral
    ///   pubkey + minimum token overhead, or any error from underlying ECDH / token
    ///   decryption (HMAC failure, padding, etc).
    public func decrypt(ciphertext: Data) throws -> Data {
        // Need at least 32 (ephemeral pubkey) + Token.overhead (48) bytes.
        guard ciphertext.count > 32 + TokenConstants.overhead else {
            throw ReticulumError.tokenTooShort
        }

        let ephemeralPubBytes = Data(ciphertext.prefix(32))
        let tokenBytes = Data(ciphertext.dropFirst(32))

        let ephemeralPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephemeralPubBytes)
        let sharedSecret = try CryptoEngine.keyAgreement(
            privateKey: agreementPrivateKey,
            publicKey: ephemeralPub
        )
        let derivedKey = CryptoEngine.hkdf(
            length: 64,
            inputKeyMaterial: sharedSecret.withUnsafeBytes { Data($0) },
            salt: hash.data,
            context: nil
        )
        let token = try Token(key: derivedKey)
        return try token.decrypt(tokenBytes)
    }
}
