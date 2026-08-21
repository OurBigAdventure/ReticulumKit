// SPDX-License-Identifier: MIT
// Packet.swift — Reticulum packet pack/unpack and validation

import Foundation
import CryptoKit

/// A Reticulum network packet with header, addressing, context, and data payload.
///
/// Wire format (Header Type 1 — single destination):
/// ```
/// [Flags:1][Hops:1][DestHash:16][Context:1][Data:0-481]
/// ```
///
/// Wire format (Header Type 2 — transport):
/// ```
/// [Flags:1][Hops:1][TransportID:16][DestHash:16][Context:1][Data:0-465]
/// ```
///
/// Total packet size must not exceed `ReticulumConstants.MTU` (500 bytes).
public struct Packet: Sendable, Equatable {
    public let header: PacketHeader
    public let destinationHash: TruncatedHash
    public let transportId: TruncatedHash?  // Only for Header Type 2
    public let context: PacketContext
    public let data: Data

    public init(
        header: PacketHeader,
        destinationHash: TruncatedHash,
        transportId: TruncatedHash? = nil,
        context: PacketContext = .none,
        data: Data = Data()
    ) {
        self.header = header
        self.destinationHash = destinationHash
        self.transportId = transportId
        self.context = context
        self.data = data
    }

    /// Pack into wire format bytes.
    ///
    /// - Throws: `ReticulumError.missingTransportId` if header type 2 but no transport ID.
    /// - Throws: `ReticulumError.packetTooLong` if packed size exceeds MTU.
    /// - Returns: The packed wire-format bytes.
    public func pack() throws -> Data {
        var raw = Data()

        // Header (2 bytes)
        raw.append(contentsOf: header.encode())

        // Addresses
        switch header.headerType {
        case .type1:
            // [DestHash:16]
            raw.append(destinationHash.data)
        case .type2:
            // [TransportID:16][DestHash:16]
            guard let tid = transportId else {
                throw ReticulumError.missingTransportId
            }
            raw.append(tid.data)
            raw.append(destinationHash.data)
        }

        // Context byte
        raw.append(context.rawValue)

        // Data payload
        raw.append(data)

        // Validate total size
        guard raw.count <= ReticulumConstants.MTU else {
            throw ReticulumError.packetTooLong(raw.count)
        }

        return raw
    }

    /// Unpack from wire format bytes.
    ///
    /// - Parameter raw: Raw wire-format bytes (at least `ReticulumConstants.headerMinSize` bytes).
    /// - Throws: `ReticulumError.packetTooShort` if too few bytes.
    /// - Throws: `ReticulumError.packetTooLong` if exceeds MTU.
    /// - Returns: A decoded `Packet`.
    public static func unpack(_ raw: Data) throws -> Packet {
        // Validate minimum size
        guard raw.count >= ReticulumConstants.headerMinSize else {
            throw ReticulumError.packetTooShort
        }

        // Validate maximum size
        guard raw.count <= ReticulumConstants.MTU else {
            throw ReticulumError.packetTooLong(raw.count)
        }

        // Decode header (first 2 bytes)
        let header = try PacketHeader.decode(raw)
        var offset = 2

        // Parse addresses based on header type
        let transportId: TruncatedHash?
        let destinationHash: TruncatedHash

        switch header.headerType {
        case .type1:
            // [DestHash:16]
            guard raw.count >= offset + 16 else {
                throw ReticulumError.packetTooShort
            }
            destinationHash = try TruncatedHash(Data(raw[offset..<offset + 16]))
            transportId = nil
            offset += 16

        case .type2:
            // [TransportID:16][DestHash:16]
            guard raw.count >= offset + 32 else {
                throw ReticulumError.packetTooShort
            }
            transportId = try TruncatedHash(Data(raw[offset..<offset + 16]))
            offset += 16
            destinationHash = try TruncatedHash(Data(raw[offset..<offset + 16]))
            offset += 16
        }

        // Context byte
        guard raw.count > offset else {
            throw ReticulumError.packetTooShort
        }
        guard let context = PacketContext(rawValue: raw[offset]) else {
            throw ReticulumError.invalidPacketContext(raw[offset])
        }
        offset += 1

        // Remaining bytes are data payload
        let payload = (offset < raw.count) ? Data(raw[offset...]) : Data()

        return Packet(
            header: header,
            destinationHash: destinationHash,
            transportId: transportId,
            context: context,
            data: payload
        )
    }

    /// Compute the hashable part of a raw packet for link ID derivation.
    ///
    /// Per Python RNS/Packet.py `get_hashable_part()` for **link-request** packets,
    /// plus signalling trim used when deriving link IDs:
    /// - Byte 0 is masked to lower 4 bits (removing IFAC flag and header type)
    /// - Byte 1 (hops) is skipped
    /// - For type2, the transport ID (16 bytes after flags+hops) is also skipped
    /// - If the data portion exceeds `LinkConstants.ecPubSize` (64 bytes),
    ///   the trailing signalling bytes are trimmed from the result
    ///
    /// For delivery proofs and `Link.request` ids, use ``dataPacketHashablePart(raw:headerType:)``
    /// / ``truncatedPacketHash(raw:headerType:)`` instead — those match Python's
    /// untrimmed `get_hashable_part()`.
    ///
    /// - Parameters:
    ///   - raw: Raw wire-format packet bytes.
    ///   - headerType: The header type of the packet.
    /// - Returns: The hashable bytes used for packet hash / link ID computation.
    public static func hashablePart(raw: Data, headerType: HeaderType) -> Data {
        var result = dataPacketHashablePart(raw: raw, headerType: headerType)

        // Check if data portion exceeds ecPubSize; if so, trim signalling bytes
        let headerSize: Int
        switch headerType {
        case .type1:
            headerSize = 2 + ReticulumConstants.truncatedHashLength + 1
        case .type2:
            headerSize = 2 + ReticulumConstants.truncatedHashLength + ReticulumConstants.truncatedHashLength + 1
        }
        let dataLength = raw.count - headerSize
        if dataLength > LinkConstants.ecPubSize {
            let excessBytes = dataLength - LinkConstants.ecPubSize
            result = Data(result.prefix(result.count - excessBytes))
        }

        return result
    }

    /// Python `Packet.get_hashable_part()` without link-request signalling trim.
    ///
    /// Used for delivery proofs and `Link.request` / RESPONSE `request_id`
    /// (`packet.getTruncatedHash()`).
    public static func dataPacketHashablePart(raw: Data, headerType: HeaderType) -> Data {
        guard !raw.isEmpty else { return Data() }

        let maskedFlags = raw[raw.startIndex] & 0x0F
        let skipOffset: Int
        switch headerType {
        case .type1:
            skipOffset = 2
        case .type2:
            skipOffset = 2 + ReticulumConstants.truncatedHashLength
        }

        var result = Data([maskedFlags])
        if raw.count > skipOffset {
            result.append(raw.suffix(from: raw.startIndex + skipOffset))
        }
        return result
    }

    /// Python `Packet.getTruncatedHash()` — first 16 bytes of SHA-256 over
    /// ``dataPacketHashablePart(raw:headerType:)``.
    public static func truncatedPacketHash(raw: Data, headerType: HeaderType) -> Data {
        CryptoEngine.truncatedHash(dataPacketHashablePart(raw: raw, headerType: headerType))
    }

    /// Full SHA-256 of ``dataPacketHashablePart(raw:headerType:)`` (Python `Packet.get_hash()`).
    public static func fullPacketHash(raw: Data, headerType: HeaderType) -> Data {
        Data(SHA256.hash(data: dataPacketHashablePart(raw: raw, headerType: headerType)))
    }

    /// Truncated hash of this packet after packing (Python `getTruncatedHash()`).
    public func truncatedHash() throws -> Data {
        let raw = try pack()
        return Self.truncatedPacketHash(raw: raw, headerType: header.headerType)
    }

    /// Validate packet integrity.

    ///
    /// Checks header type consistency with transport ID presence and MTU compliance.
    /// - Throws: `ReticulumError` if validation fails.
    public func validate() throws {
        // Header type consistency
        if header.headerType == .type2 && transportId == nil {
            throw ReticulumError.missingTransportId
        }
        if header.headerType == .type1 && transportId != nil {
            throw ReticulumError.unexpectedTransportId
        }

        // Size bounds
        let packed = try pack()
        if packed.count > ReticulumConstants.MTU {
            throw ReticulumError.packetTooLong(packed.count)
        }
    }
}
