import Testing
import Foundation
import CryptoKit
@testable import ReticulumKit

@Suite("CryptoEngine Tests")
struct CryptoEngineTests {

    // MARK: - SHA-256

    @Test("sha256 produces 32-byte hash")
    func sha256Length() {
        let result = CryptoEngine.sha256(Data("hello world".utf8))
        #expect(result.count == 32)
    }

    @Test("sha256 of known input produces expected hash")
    func sha256KnownInput() {
        // SHA-256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
        let result = CryptoEngine.sha256(Data("hello world".utf8))
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        let hex = result.map { String(format: "%02x", $0) }.joined()
        #expect(hex == expected)
    }

    // MARK: - Truncated Hash

    @Test("truncatedHash produces first 16 bytes of SHA-256")
    func truncatedHashLength() {
        let data = Data("test input".utf8)
        let full = CryptoEngine.sha256(data)
        let truncated = CryptoEngine.truncatedHash(data)
        #expect(truncated.count == 16)
        #expect(truncated == full.prefix(16))
    }

    // MARK: - AES-256-CBC

    @Test("AES-256-CBC encrypt then decrypt round-trips")
    func aes256RoundTrip() throws {
        let key = Data(repeating: 0x42, count: 32)
        let iv = Data(repeating: 0x00, count: 16)
        let plaintext = Data("The quick brown fox jumps over the lazy dog".utf8)

        let ciphertext = try CryptoEngine.aesCBCEncrypt(plaintext, key: key, iv: iv)
        #expect(ciphertext != plaintext)
        #expect(!ciphertext.isEmpty)

        let decrypted = try CryptoEngine.aesCBCDecrypt(ciphertext, key: key, iv: iv)
        #expect(decrypted == plaintext)
    }

    // MARK: - AES-128-CBC

    @Test("AES-128-CBC encrypt then decrypt round-trips")
    func aes128RoundTrip() throws {
        let key = Data(repeating: 0x33, count: 16)
        let iv = Data(repeating: 0x11, count: 16)
        let plaintext = Data("AES-128 test message".utf8)

        let ciphertext = try CryptoEngine.aesCBCEncrypt(plaintext, key: key, iv: iv)
        let decrypted = try CryptoEngine.aesCBCDecrypt(ciphertext, key: key, iv: iv)
        #expect(decrypted == plaintext)
    }

    @Test("AES-CBC with wrong key does not produce original plaintext")
    func aesCBCWrongKey() throws {
        let key = Data(repeating: 0x42, count: 32)
        let wrongKey = Data(repeating: 0x43, count: 32)
        let iv = Data(repeating: 0x00, count: 16)
        let plaintext = Data("secret message".utf8)

        let ciphertext = try CryptoEngine.aesCBCEncrypt(plaintext, key: key, iv: iv)

        // Decrypting with wrong key should either throw or produce different output
        do {
            let decrypted = try CryptoEngine.aesCBCDecrypt(ciphertext, key: wrongKey, iv: iv)
            #expect(decrypted != plaintext)
        } catch {
            // Decryption failure is also acceptable
        }
    }

    // MARK: - HMAC-SHA256

    @Test("HMAC-SHA256 produces 32-byte authentication code")
    func hmacLength() {
        let key = Data(repeating: 0xAA, count: 32)
        let data = Data("authenticate me".utf8)
        let mac = CryptoEngine.hmacSHA256(key: key, data: data)
        #expect(mac.count == 32)
    }

    @Test("verifyHMAC returns true for valid MAC")
    func hmacVerifyValid() {
        let key = Data(repeating: 0xBB, count: 32)
        let data = Data("verify this".utf8)
        let mac = CryptoEngine.hmacSHA256(key: key, data: data)
        #expect(CryptoEngine.verifyHMAC(mac, key: key, data: data) == true)
    }

    @Test("verifyHMAC returns false for tampered data")
    func hmacVerifyTampered() {
        let key = Data(repeating: 0xCC, count: 32)
        let data = Data("original message".utf8)
        let mac = CryptoEngine.hmacSHA256(key: key, data: data)

        let tampered = Data("tampered message".utf8)
        #expect(CryptoEngine.verifyHMAC(mac, key: key, data: tampered) == false)
    }

    // MARK: - HKDF

    @Test("HKDF with explicit 32 zero-byte salt produces deterministic output")
    func hkdfDeterministic() {
        let ikm = Data(repeating: 0x0B, count: 32)
        let salt = Data(repeating: 0x00, count: 32)

        let derived1 = CryptoEngine.hkdf(length: 32, inputKeyMaterial: ikm, salt: salt, context: nil)
        let derived2 = CryptoEngine.hkdf(length: 32, inputKeyMaterial: ikm, salt: salt, context: nil)

        #expect(derived1.count == 32)
        #expect(derived1 == derived2)
    }

    @Test("HKDF with nil salt defaults to 32 zero bytes (same output as explicit)")
    func hkdfNilSaltDefault() {
        let ikm = Data(repeating: 0x0B, count: 32)
        let explicitSalt = Data(repeating: 0x00, count: 32)

        let withExplicit = CryptoEngine.hkdf(length: 32, inputKeyMaterial: ikm, salt: explicitSalt, context: nil)
        let withNil = CryptoEngine.hkdf(length: 32, inputKeyMaterial: ikm, salt: nil, context: nil)

        #expect(withExplicit == withNil)
    }

    // MARK: - Ed25519

    @Test("Ed25519 sign produces 64-byte signature")
    func ed25519SignLength() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let message = Data("sign this message".utf8)

        let signature = try CryptoEngine.sign(message, with: privateKey)
        #expect(signature.count == 64)
    }

    @Test("Ed25519 verify returns true for valid signature")
    func ed25519VerifyValid() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let message = Data("authentic message".utf8)

        let signature = try CryptoEngine.sign(message, with: privateKey)
        #expect(CryptoEngine.verify(signature: signature, message: message, publicKey: publicKey) == true)
    }

    @Test("Ed25519 verify returns false for tampered message")
    func ed25519VerifyTampered() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey
        let message = Data("original".utf8)

        let signature = try CryptoEngine.sign(message, with: privateKey)

        let tampered = Data("tampered".utf8)
        #expect(CryptoEngine.verify(signature: signature, message: tampered, publicKey: publicKey) == false)
    }

    // MARK: - X25519

    @Test("X25519 shared secret is symmetric after HKDF")
    func x25519SharedSecretSymmetric() throws {
        let alicePrivate = Curve25519.KeyAgreement.PrivateKey()
        let bobPrivate = Curve25519.KeyAgreement.PrivateKey()

        let sharedAB = try CryptoEngine.keyAgreement(
            privateKey: alicePrivate,
            publicKey: bobPrivate.publicKey
        )
        let sharedBA = try CryptoEngine.keyAgreement(
            privateKey: bobPrivate,
            publicKey: alicePrivate.publicKey
        )

        // Derive keys from shared secrets using HKDF to get comparable Data
        let derivedAB = sharedAB.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(repeating: 0, count: 32),
            sharedInfo: Data(),
            outputByteCount: 32
        )
        let derivedBA = sharedBA.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(repeating: 0, count: 32),
            sharedInfo: Data(),
            outputByteCount: 32
        )

        let dataAB = derivedAB.withUnsafeBytes { Data($0) }
        let dataBA = derivedBA.withUnsafeBytes { Data($0) }

        #expect(dataAB == dataBA)
    }

    // MARK: - Random

    @Test("Random bytes produces requested length")
    func randomBytesLength() throws {
        let bytes = try CryptoEngine.randomBytes(count: 32)
        #expect(bytes.count == 32)
    }

    @Test("Random bytes are not all zeros")
    func randomBytesNotAllZeros() throws {
        let bytes = try CryptoEngine.randomBytes(count: 32)
        let allZeros = Data(repeating: 0, count: 32)
        #expect(bytes != allZeros)
    }

    @Test("Random bytes of different calls produce different output")
    func randomBytesDifferent() throws {
        let a = try CryptoEngine.randomBytes(count: 32)
        let b = try CryptoEngine.randomBytes(count: 32)
        // Probability of collision is negligible (2^-256)
        #expect(a != b)
    }
}
