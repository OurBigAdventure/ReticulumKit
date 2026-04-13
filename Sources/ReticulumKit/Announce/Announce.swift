// SPDX-License-Identifier: MIT
// Announce.swift — Announce creation and validation
//
// Announces are how Reticulum nodes discover each other. A valid announce
// contains the announcing node's public key, name hash, a random hash,
// and an Ed25519 signature over the destination hash + payload fields.
//
// Wire payload layout:
//   publicKey(64) + nameHash(10) + randomHash(10) + signature(64) + appData(var)
//   Minimum 148 bytes without appData.
//
// Signed data layout (destHash is signed but NOT in payload):
//   destHash(16) + publicKey(64) + nameHash(10) + randomHash(10) + appData(var)

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

    /// Minimum announce payload size: publicKey(64) + nameHash(10) + randomHash(10) + signature(64)
    private static let minPayloadSize = IdentityConstants.keySize + ReticulumConstants.nameHashLength + 10 + IdentityConstants.sigLength  // 148
    private static let ratchetKeySize = 32

    /// Create a signed announce packet for a destination.
    ///
    /// - Parameters:
    ///   - destination: The destination to announce.
    ///   - appData: Optional application data to include.
    /// - Returns: A signed announce `Packet` ready for transmission.
    /// - Throws: If signing fails or random generation fails.
    public static func create(destination: Destination, appData: Data? = nil) throws -> Packet {
        let publicKey = destination.identity.publicKeyBytes  // 64 bytes
        let nameHash = destination.nameHash                  // 10 bytes

        // Random hash: 5 random bytes + last 5 bytes of UInt64 big-endian Unix timestamp
        let randomBytes = try CryptoEngine.randomBytes(count: 5)
        var timestampBE = UInt64(Date().timeIntervalSince1970).bigEndian
        let timestampData = withUnsafeBytes(of: &timestampBE) { Data($0) }
        let randomHash = randomBytes + timestampData.suffix(5)  // 10 bytes

        // Build signed data: destHash(16) + publicKey(64) + nameHash(10) + randomHash(10) [+ appData]
        var signedData = Data()
        signedData.append(destination.hash.data)  // 16 bytes
        signedData.append(publicKey)               // 64 bytes
        signedData.append(nameHash)                // 10 bytes
        signedData.append(randomHash)              // 10 bytes
        if let appData {
            signedData.append(appData)
        }

        // Sign with Ed25519
        let signature = try destination.identity.sign(signedData)  // 64 bytes

        // Build payload: publicKey(64) + nameHash(10) + randomHash(10) + signature(64) [+ appData]
        var payload = Data()
        payload.append(publicKey)    // 64 bytes
        payload.append(nameHash)     // 10 bytes
        payload.append(randomHash)   // 10 bytes
        payload.append(signature)    // 64 bytes
        if let appData {
            payload.append(appData)
        }

        // Create packet header
        let header = PacketHeader(
            headerType: .type1,
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
    /// and verifies the Ed25519 signature over the signed data.
    ///
    /// - Parameter packet: The announce packet to validate.
    /// - Returns: An `AnnounceResult` with the extracted fields.
    /// - Throws: `AnnounceError` if validation fails.
    public static func validate(packet: Packet) throws -> AnnounceResult {
        let data = packet.data

        // 1. Check minimum size
        guard data.count >= minPayloadSize else {
            // print("[DEBUG-ANNOUNCE] Too short: \(data.count) < \(minPayloadSize)")
            throw AnnounceError.tooShort
        }

        // 2. Parse fields — payload layout is the same for type1 and type2.
        //
        // Wire layout: pubKey(64) + nameHash(10) + randomHash(variable) + signature(64) + appData
        //
        // In Python RNS 1.1.x, randomHash = full SHA-256(32) + ratchetId(10) = 42 bytes.
        // The signature is always the LAST 64 bytes before appData.
        // We find the signature by working backwards: appData is detected by trying to
        // verify the signature with different split points.
        //
        // Fixed approach: pubKey(64) + nameHash(10) = 74 bytes prefix.
        // Remaining = randomHash + signature(64) + appData.
        // Since signature is 64 bytes, and we know SIGLENGTH=64:
        //   randomHash ends at (data.count - 64 - appDataLen) offset from 74.
        //
        // In practice: the "random hash" portion is everything between nameHash and signature.
        // We identify the signature as the 64 bytes that, when used with Ed25519, verify
        // the signed data. Python RNS uses variable random hash sizes across versions,
        // so we detect dynamically.

        let publicKey = Data(data[0..<64])
        let nameHash  = Data(data[64..<74])
        let announceDestHash = packet.destinationHash.data

        // Dynamic signature detection: try to find the 64-byte signature
        // by testing from the most likely position backwards.
        // randomHash = data[74 ..< sigStart], signature = data[sigStart ..< sigStart+64], appData = data[sigStart+64 ...]
        let signingKeyBytes = publicKey[32..<64]
        let signingKey = try Curve25519.Signing.PublicKey(rawRepresentation: Data(signingKeyBytes))

        var foundRandomHash: Data?
        var foundSignature: Data?
        var foundAppData: Data?

        // Try common random hash sizes: 42 (RNS 1.1.x), 10 (older), 32 (theoretical)
        for rhLen in [42, 10, 32, 16] {
            let sigStart = 74 + rhLen
            let sigEnd = sigStart + 64
            guard sigEnd <= data.count else { continue }

            let candidateRandomHash = Data(data[74..<sigStart])
            let candidateSignature = Data(data[sigStart..<sigEnd])
            let candidateAppData: Data? = sigEnd < data.count ? Data(data[sigEnd...]) : nil

            var signedData = Data()
            signedData.append(announceDestHash)
            signedData.append(publicKey)
            signedData.append(nameHash)
            signedData.append(candidateRandomHash)
            if let candidateAppData {
                signedData.append(candidateAppData)
            }

            if signingKey.isValidSignature(candidateSignature, for: signedData) {
                foundRandomHash = candidateRandomHash
                foundSignature = candidateSignature
                foundAppData = candidateAppData
                // print("[DEBUG-ANNOUNCE] Signature verified with randomHash=\(rhLen) bytes")
                break
            }
        }

        guard let randomHash = foundRandomHash,
              let signature = foundSignature else {
            // print("[DEBUG-ANNOUNCE] No valid signature found at any randomHash offset")
            throw AnnounceError.signatureInvalid
        }
        let appData = foundAppData

        // 3. Verify destination hash reconstruction
        let identityHash = CryptoEngine.truncatedHash(publicKey)
        let expectedHash = CryptoEngine.truncatedHash(nameHash + identityHash)
        guard expectedHash == announceDestHash else {
            throw AnnounceError.destinationHashMismatch
        }

        // Debug logging removed

        // 4. Return validated result
        let resultDestHash = try TruncatedHash(announceDestHash)
        return AnnounceResult(
            destinationHash: resultDestHash,
            publicKey: publicKey,
            nameHash: nameHash,
            randomHash: randomHash,
            signature: signature,
            appData: appData
        )
    }
}
