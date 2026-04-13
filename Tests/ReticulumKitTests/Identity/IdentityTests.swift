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

    @Test("Identity.verify rejects tampered message")
    func verifyRejectsTampered() throws {
        let identity = Identity()
        let message = Data("original".utf8)
        let tampered = Data("tampered".utf8)

        let signature = try identity.sign(message)
        #expect(identity.verify(signature: signature, for: tampered) == false)
    }

    // MARK: - Encrypt / Decrypt

    @Test("Identity encrypt/decrypt between two identities round-trips")
    func encryptDecryptBetweenIdentities() throws {
        let alice = Identity()
        let bob = Identity()
        let plaintext = Data("secret message from Alice to Bob".utf8)

        let ciphertext = try alice.encrypt(plaintext: plaintext, for: bob.agreementPublicKey)
        let decrypted = try bob.decrypt(ciphertext: ciphertext, from: alice.agreementPublicKey)
        #expect(decrypted == plaintext)
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
