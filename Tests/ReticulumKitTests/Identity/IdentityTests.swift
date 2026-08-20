// SPDX-License-Identifier: MIT
// IdentityTests.swift — Identity and Destination tests

import Testing
import Foundation
import CryptoKit
@testable import ReticulumKit

@Suite("Identity Tests")
struct IdentityTests {

    // MARK: - Keypair Generation

    @Test("Identity generates keypairs with 32-byte raw representations")
    func keypairSizes() {
        let identity = Identity()
        #expect(identity.agreementPublicKey.rawRepresentation.count == 32)
        #expect(identity.signingPublicKey.rawRepresentation.count == 32)
        #expect(identity.agreementPrivateKey.rawRepresentation.count == 32)
        #expect(identity.signingPrivateKey.rawRepresentation.count == 32)
    }

    @Test("Identity.publicKeyBytes is 64 bytes (X25519:32 + Ed25519:32)")
    func publicKeyBytesLength() {
        let identity = Identity()
        #expect(identity.publicKeyBytes.count == 64)
    }

    @Test("Identity.publicKeyBytes has X25519 pub first, Ed25519 pub second")
    func publicKeyBytesOrder() {
        let identity = Identity()
        let pubBytes = identity.publicKeyBytes
        let x25519Part = Data(pubBytes.prefix(32))
        let ed25519Part = Data(pubBytes.suffix(32))
        #expect(x25519Part == Data(identity.agreementPublicKey.rawRepresentation))
        #expect(ed25519Part == Data(identity.signingPublicKey.rawRepresentation))
    }

    @Test("Identity.privateKeyBytes is 64 bytes (X25519:32 + Ed25519:32)")
    func privateKeyBytesLength() {
        let identity = Identity()
        #expect(identity.privateKeyBytes.count == 64)
    }

    // MARK: - Identity Hash

    @Test("Identity.hash is a TruncatedHash (16 bytes)")
    func hashLength() {
        let identity = Identity()
        #expect(identity.hash.data.count == ReticulumConstants.truncatedHashLength)
    }

    @Test("Identity.hash is deterministic for same keys")
    func hashDeterministic() {
        let identity = Identity()
        let hash1 = identity.hash
        let hash2 = identity.hash
        #expect(hash1 == hash2)
    }

    // MARK: - Private Key Reconstruction

    @Test("Identity init from 64-byte privateKeyBytes reconstructs same public keys")
    func reconstructFromPrivateKey() throws {
        let original = Identity()
        let keyData = original.privateKeyBytes

        let reconstructed = try Identity(privateKeyBytes: keyData)
        #expect(reconstructed.publicKeyBytes == original.publicKeyBytes)
        #expect(reconstructed.hash == original.hash)
    }

    @Test("Identity init with wrong key size throws invalidKeySize")
    func invalidKeySizeThrows() {
        for size in [0, 32, 63, 65, 128] {
            #expect(throws: ReticulumError.self) {
                _ = try Identity(privateKeyBytes: Data(repeating: 0, count: size))
            }
        }
    }

    // MARK: - Sign / Verify

    @Test("Identity.sign produces 64-byte signature that verify accepts")
    func signAndVerify() throws {
        let identity = Identity()
        let message = Data("test message for signing".utf8)

        let signature = try identity.sign(message)
        #expect(signature.count == IdentityConstants.sigLength)
        #expect(identity.verify(signature: signature, for: message) == true)
    }

    @Test("RFC 8032 Ed25519 is deterministic and verifies with CryptoKit")
    func rfc8032Deterministic() throws {
        let identity = Identity()
        let message = Data("ifac-compat".utf8)
        let seed = Data(identity.signingPrivateKey.rawRepresentation)
        let a = try CryptoEngine.signRFC8032(message, seed: seed)
        let b = try CryptoEngine.signRFC8032(message, seed: seed)
        #expect(a == b)
        #expect(a.count == IdentityConstants.sigLength)
        #expect(identity.verify(signature: a, for: message) == true)
    }

    @Test("Identity.verify rejects tampered message")
    func verifyRejectsTampered() throws {
        let identity = Identity()
        let message = Data("original".utf8)
        let tampered = Data("tampered".utf8)

        let signature = try identity.sign(message)
        #expect(identity.verify(signature: signature, for: tampered) == false)
    }

    // MARK: - Encrypt / Decrypt

    @Test("Identity encrypt/decrypt between two identities round-trips (RNS-compatible wire format)")
    func encryptDecryptBetweenIdentities() throws {
        let alice = Identity()
        let bob = Identity()
        let plaintext = Data("secret message from Alice to Bob".utf8)

        // Alice encrypts FOR bob (using bob's identity, including hash for HKDF salt).
        // The ciphertext is [ephemeral_pub:32] + [iv:16] + [ciphertext:var] + [hmac:32].
        let ciphertext = try alice.encrypt(plaintext: plaintext, for: bob)

        // Wire-format check: ephemeral pubkey prefix is present.
        #expect(ciphertext.count >= 32 + TokenConstants.overhead)

        // Bob decrypts using only his own private key — no sender public key needed
        // (the ephemeral pubkey is embedded in the ciphertext, like Python RNS).
        let decrypted = try bob.decrypt(ciphertext: ciphertext)
        #expect(decrypted == plaintext)
    }

    @Test("Identity encrypt produces fresh ephemeral key each call (forward secrecy)")
    func encryptUsesFreshEphemeralKey() throws {
        let alice = Identity()
        let bob = Identity()
        let plaintext = Data("hello".utf8)

        let c1 = try alice.encrypt(plaintext: plaintext, for: bob)
        let c2 = try alice.encrypt(plaintext: plaintext, for: bob)

        // First 32 bytes are the ephemeral public key — must differ across calls.
        #expect(c1.prefix(32) != c2.prefix(32))

        // Both must still decrypt back to the same plaintext.
        #expect(try bob.decrypt(ciphertext: c1) == plaintext)
        #expect(try bob.decrypt(ciphertext: c2) == plaintext)
    }

    @Test("Identity decrypt rejects tampered ciphertext via HMAC")
    func decryptRejectsTamperedCiphertext() throws {
        let alice = Identity()
        let bob = Identity()
        let plaintext = Data("important".utf8)

        var ciphertext = try alice.encrypt(plaintext: plaintext, for: bob)
        // Flip a byte in the AES ciphertext region (after ephemeral pubkey + IV).
        let flipIndex = ciphertext.startIndex + 32 + 16 + 1
        ciphertext[flipIndex] ^= 0xFF

        #expect(throws: (any Error).self) {
            _ = try bob.decrypt(ciphertext: ciphertext)
        }
    }

    @Test("Identity decrypt rejects too-short input")
    func decryptRejectsTooShortInput() throws {
        let bob = Identity()
        let tiny = Data(repeating: 0, count: 32 + TokenConstants.overhead)  // exactly at threshold, must reject (> not >=)
        #expect(throws: (any Error).self) {
            _ = try bob.decrypt(ciphertext: tiny)
        }
    }
}

@Suite("Destination Tests")
struct DestinationTests {

    @Test("Destination.expandedName for appName='test' aspects=['echo'] is 'test.echo'")
    func expandedName() {
        let identity = Identity()
        let dest = Destination(identity: identity, direction: .out, appName: "test", aspects: ["echo"])
        #expect(dest.expandedName == "test.echo")
    }

    @Test("Destination.expandedName with multiple aspects")
    func expandedNameMultipleAspects() {
        let identity = Identity()
        let dest = Destination(identity: identity, direction: .out, appName: "app", aspects: ["a", "b", "c"])
        #expect(dest.expandedName == "app.a.b.c")
    }

    @Test("Destination.nameHash is 10 bytes (ReticulumConstants.nameHashLength)")
    func nameHashLength() {
        let identity = Identity()
        let dest = Destination(identity: identity, direction: .out, appName: "test", aspects: ["echo"])
        #expect(dest.nameHash.count == ReticulumConstants.nameHashLength)
    }

    @Test("Destination.hash is a TruncatedHash (16 bytes)")
    func hashLength() {
        let identity = Identity()
        let dest = Destination(identity: identity, direction: .in, appName: "test", aspects: ["echo"])
        #expect(dest.hash.data.count == ReticulumConstants.truncatedHashLength)
    }

    @Test("Destination.hash is deterministic for same identity + name")
    func hashDeterministic() {
        let identity = Identity()
        let dest1 = Destination(identity: identity, direction: .in, appName: "test", aspects: ["echo"])
        let dest2 = Destination(identity: identity, direction: .in, appName: "test", aspects: ["echo"])
        #expect(dest1.hash == dest2.hash)
    }
}
