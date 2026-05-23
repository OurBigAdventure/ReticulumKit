// SPDX-License-Identifier: MIT
// Announce.swift — Announce creation and validation
//
// Announces are how Reticulum nodes discover each other. A valid announce
// contains the announcing node's public key, name hash, a random hash,
// and an Ed25519 signature over the destination hash + payload fields.
//
// Wire payload layout (no ratchet — context_flag = 0 in header):
//   publicKey(64) + nameHash(10) + randomHash(10) + signature(64) + appData(var)
//   Minimum 148 bytes without appData.
//
// Wire payload layout (with ratchet — context_flag = 1 in header):
//   publicKey(64) + nameHash(10) + randomHash(10) + ratchet(32) + signature(64) + appData(var)
//   Minimum 180 bytes without appData.
//
// Signed data layout (destHash is signed but NOT in payload, ratchet is empty
// when not present):
//   destHash(16) + publicKey(64) + nameHash(10) + randomHash(10) + ratchet(0|32) + appData(var)
//
// randomHash is exactly 10 bytes: 5 random bytes + 5-byte big-endian Unix
// timestamp (seconds). This format is fixed across all current Python RNS
// versions (1.x and 2.x). See Python `RNS/Destination.py::announce()`:
//   random_hash = RNS.Identity.get_random_hash()[0:5] + int(time.time()).to_bytes(5, "big")
//
// IMPORTANT: an earlier version of this file packed 42 bytes (32 random + 10
// pseudo-ratchet) into the random_hash field with context_flag=0. Python
// Reticulum then mis-sliced our payload (reading bytes 84-148 as the
// signature when the actual signature lived at 116-180), the signature
// failed to verify, and our announces were silently dropped on every
// official RNS peer (Sideband / MeshChat / Columba / nomadnet).

import Foundation
import CryptoKit
import Security

/// Result of validating an incoming announce packet.
public struct AnnounceResult: Sendable {
    /// The destination hash from the packet header
    public let destinationHash: TruncatedHash
    /// Combined public key: X25519(32) + Ed25519(32) = 64 bytes
    public let publicKey: Data
    /// Name hash: SHA-256(expandedName)[:10] = 10 bytes
    public let nameHash: Data
    /// Random hash: 5 random bytes + 5 timestamp bytes = 10 bytes
    public let randomHash: Data
    /// Optional ratchet public key (32 bytes if context_flag set, nil otherwise)
    public let ratchet: Data?
    /// Ed25519 signature: 64 bytes
    public let signature: Data
    /// Optional application data
    public let appData: Data?
}

/// Errors from announce validation.
public enum AnnounceError: Error, Sendable {
    /// Packet data is shorter than the minimum 148 bytes
    case tooShort
    /// Reconstructed destination hash does not match packet destination hash
    case destinationHashMismatch
    /// Ed25519 signature verification failed
    case signatureInvalid
}

/// Stateless namespace for announce creation and validation.
public enum Announce {

    /// Public key field length: X25519(32) + Ed25519(32) = 64 bytes
    private static let keySize = IdentityConstants.keySize             // 64
    /// Name hash field length: 10 bytes (SHA-256(name)[:10])
    private static let nameHashLen = ReticulumConstants.nameHashLength // 10
    /// Random hash field length: 5 random bytes + 5 timestamp bytes = 10 bytes (FIXED)
    private static let randomHashLen = 10
    /// Ed25519 signature length: 64 bytes
    private static let sigLen = IdentityConstants.sigLength            // 64
    /// Ratchet X25519 public key length: 32 bytes (only present when context_flag = 1)
    private static let ratchetLen = 32

    /// Minimum announce payload size (no ratchet, no appData):
    /// publicKey(64) + nameHash(10) + randomHash(10) + signature(64) = 148
    private static let minPayloadSize = keySize + nameHashLen + randomHashLen + sigLen

    /// Create a signed announce packet for a destination.
    ///
    /// Produces a Python-RNS-compatible announce with no ratchet field
    /// (context_flag = 0). Wire-format-verified against canonical Python
    /// Reticulum 1.x / 2.x peers (Sideband, MeshChat, Columba, nomadnet).
    ///
    /// - Parameters:
    ///   - destination: The destination to announce.
    ///   - appData: Optional application data to include.
    /// - Returns: A signed announce `Packet` ready for transmission.
    /// - Throws: If signing fails or random generation fails.
    public static func create(destination: Destination, appData: Data? = nil) throws -> Packet {
        let publicKey = destination.identity.publicKeyBytes  // 64 bytes
        let nameHash = destination.nameHash                  // 10 bytes

        // Build random_hash exactly as Python RNS does (Destination.py L282):
        //   random_hash = get_random_hash()[0:5] + int(time.time()).to_bytes(5, "big")
        // = 5 random bytes + 5-byte big-endian Unix-seconds timestamp = 10 bytes total.
        let randomBytes = try CryptoEngine.randomBytes(count: 5)
        let timestamp = UInt64(Date().timeIntervalSince1970)
        // Big-endian 5-byte timestamp (low 5 bytes of the UInt64).
        var tsBytes = Data(count: 5)
        tsBytes[0] = UInt8((timestamp >> 32) & 0xFF)
        tsBytes[1] = UInt8((timestamp >> 24) & 0xFF)
        tsBytes[2] = UInt8((timestamp >> 16) & 0xFF)
        tsBytes[3] = UInt8((timestamp >> 8) & 0xFF)
        tsBytes[4] = UInt8(timestamp & 0xFF)
        let randomHash = randomBytes + tsBytes  // 10 bytes total

        // No ratchet support yet — context_flag = 0, ratchet field omitted.
        // Ratchets are signed-but-not-included logic in Python; with no ratchet
        // the signed buffer has an empty-string slot for the ratchet field.

        // Build signed data: destHash(16) + publicKey(64) + nameHash(10) + randomHash(10) [+ appData]
        // Python signs over: hash + public_key + name_hash + random_hash + ratchet + app_data
        // where ratchet = b"" when not present, so it concatenates to the same bytes.
        var signedData = Data()
        signedData.append(destination.hash.data)  // 16 bytes
        signedData.append(publicKey)               // 64 bytes
        signedData.append(nameHash)                // 10 bytes
        signedData.append(randomHash)              // 10 bytes
        // ratchet = empty when context_flag=0
        if let appData {
            signedData.append(appData)
        }

        // Sign with Ed25519
        let signature = try destination.identity.sign(signedData)  // 64 bytes

        // Build payload: publicKey(64) + nameHash(10) + randomHash(10) + signature(64) [+ appData]
        // (no ratchet bytes when context_flag=0)
        var payload = Data()
        payload.append(publicKey)    // 64 bytes
        payload.append(nameHash)     // 10 bytes
        payload.append(randomHash)   // 10 bytes
        payload.append(signature)    // 64 bytes
        if let appData {
            payload.append(appData)
        }

        // Create packet header. context_flag = false (no ratchet field).
        let header = PacketHeader(
            headerType: .type1,
            contextFlag: false,
            propagationType: .broadcast,
            destinationType: .single,
            packetType: .announce
        )

        return Packet(
            header: header,
            destinationHash: destination.hash,
            transportId: nil,
            context: .none,
            data: payload
        )
    }

    /// Validate an incoming announce packet.
    ///
    /// Verifies the destination hash matches the announced public key + name hash,
    /// and verifies the Ed25519 signature over the signed data. Honours the
    /// header `context_flag` to determine whether a 32-byte ratchet field is
    /// present between random_hash and signature.
    ///
    /// - Parameter packet: The announce packet to validate.
    /// - Returns: An `AnnounceResult` with the extracted fields.
    /// - Throws: `AnnounceError` if validation fails.
    public static func validate(packet: Packet) throws -> AnnounceResult {
        let data = packet.data

        // 1. Check minimum size
        guard data.count >= minPayloadSize else {
            throw AnnounceError.tooShort
        }

        // 2. Parse fixed-offset fields. Python RNS layout (Identity.py L405-423):
        //    pubKey[0..64] | nameHash[64..74] | randomHash[74..84]
        //    if context_flag: ratchet[84..116] | signature[116..180] | appData[180..]
        //    else:            signature[84..148] | appData[148..]
        let publicKey  = Data(data[0..<keySize])
        let nameHash   = Data(data[keySize..<keySize + nameHashLen])
        let randomHash = Data(data[keySize + nameHashLen..<keySize + nameHashLen + randomHashLen])

        let hasRatchet = packet.header.contextFlag

        let ratchet: Data?
        let signature: Data
        let appData: Data?

        if hasRatchet {
            let ratchetStart = keySize + nameHashLen + randomHashLen          // 84
            let sigStart = ratchetStart + ratchetLen                          // 116
            let sigEnd = sigStart + sigLen                                    // 180
            guard data.count >= sigEnd else {
                throw AnnounceError.tooShort
            }
            ratchet = Data(data[ratchetStart..<sigStart])
            signature = Data(data[sigStart..<sigEnd])
            appData = sigEnd < data.count ? Data(data[sigEnd...]) : nil
        } else {
            let sigStart = keySize + nameHashLen + randomHashLen              // 84
            let sigEnd = sigStart + sigLen                                    // 148
            guard data.count >= sigEnd else {
                throw AnnounceError.tooShort
            }
            ratchet = nil
            signature = Data(data[sigStart..<sigEnd])
            appData = sigEnd < data.count ? Data(data[sigEnd...]) : nil
        }

        // 3. Verify Ed25519 signature.
        // Signed data layout per Python (Identity.py L425):
        //   destination_hash + public_key + name_hash + random_hash + ratchet + app_data
        // ratchet contributes 32 bytes when present, empty when not.
        let announceDestHash = packet.destinationHash.data
        let signingKeyBytes = publicKey[32..<64]
        let signingKey = try Curve25519.Signing.PublicKey(rawRepresentation: Data(signingKeyBytes))

        var signedData = Data()
        signedData.append(announceDestHash)
        signedData.append(publicKey)
        signedData.append(nameHash)
        signedData.append(randomHash)
        if let ratchet { signedData.append(ratchet) }
        if let appData { signedData.append(appData) }

        guard signingKey.isValidSignature(signature, for: signedData) else {
            throw AnnounceError.signatureInvalid
        }

        // 4. Verify destination hash reconstruction
        let identityHash = CryptoEngine.truncatedHash(publicKey)
        let expectedHash = CryptoEngine.truncatedHash(nameHash + identityHash)
        guard expectedHash == announceDestHash else {
            throw AnnounceError.destinationHashMismatch
        }

        // 5. Return validated result
        let resultDestHash = try TruncatedHash(announceDestHash)
        return AnnounceResult(
            destinationHash: resultDestHash,
            publicKey: publicKey,
            nameHash: nameHash,
            randomHash: randomHash,
            ratchet: ratchet,
            signature: signature,
            appData: appData
        )
    }
}
