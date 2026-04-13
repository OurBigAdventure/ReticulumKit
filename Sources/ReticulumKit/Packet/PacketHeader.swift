// SPDX-License-Identifier: MIT
// PacketHeader.swift — 2-byte Reticulum packet header encode/decode

import Foundation

/// The 2-byte header that begins every Reticulum packet.
///
/// Byte 0 bit layout:
/// ```
/// [7: IFAC flag] [6: headerType] [5: contextFlag] [4: propType] [3-2: destType] [1-0: packetType]
/// ```
/// Byte 1: hop count
///
/// Note: `encode()` does NOT set bit 7 (IFAC). The IFAC flag is ORed in by the
/// interface layer when actually sending. `decode()` DOES read bit 7 so incoming
/// packets with IFAC set are correctly parsed.
public struct PacketHeader: Sendable, Equatable {
    public let ifacFlag: Bool           // bit 7 (set by interface layer, not pack)
    public let headerType: HeaderType   // bit 6
    public let contextFlag: Bool        // bit 5
    public let propagationType: PropagationType  // bit 4
    public let destinationType: DestinationType  // bits 3-2
    public let packetType: PacketType   // bits 1-0
    public let hops: UInt8              // byte 1

    public init(
        ifacFlag: Bool = false,
        headerType: HeaderType,
        contextFlag: Bool = false,
        propagationType: PropagationType,
        destinationType: DestinationType,
        packetType: PacketType,
        hops: UInt8 = 0
    ) {
        self.ifacFlag = ifacFlag
        self.headerType = headerType
        self.contextFlag = contextFlag
        self.propagationType = propagationType
        self.destinationType = destinationType
        self.packetType = packetType
        self.hops = hops
    }

    /// Encode to 2 bytes. IFAC flag is NOT included (set by interface layer).
    /// Bit layout byte 0: [7:0(reserved for IFAC)][6:headerType][5:contextFlag][4:propType][3-2:destType][1-0:pktType]
    public func encode() -> Data {
        var flags: UInt8 = 0
        flags |= headerType.rawValue << 6
        flags |= (contextFlag ? 1 : 0) << 5
        flags |= propagationType.rawValue << 4
        flags |= destinationType.rawValue << 2
        flags |= packetType.rawValue
        return Data([flags, hops])
    }

    /// Decode from 2+ bytes of raw packet data.
    /// - Parameter data: At least 2 bytes of raw packet data.
    /// - Throws: `ReticulumError.packetTooShort` if fewer than 2 bytes.
    /// - Returns: A decoded `PacketHeader`.
    public static func decode(_ data: Data) throws -> PacketHeader {
        guard data.count >= 2 else {
            throw ReticulumError.packetTooShort
        }
        let flags = data[data.startIndex]
        let hops = data[data.startIndex + 1]

        guard let headerType = HeaderType(rawValue: (flags & 0b01000000) >> 6) else {
            throw ReticulumError.invalidHeaderType
        }
        guard let packetType = PacketType(rawValue: flags & 0b00000011) else {
            throw ReticulumError.invalidPacketType
        }
        guard let destType = DestinationType(rawValue: (flags & 0b00001100) >> 2) else {
            throw ReticulumError.invalidDestinationType
        }
        guard let propType = PropagationType(rawValue: (flags & 0b00010000) >> 4) else {
            throw ReticulumError.invalidPropagationType
        }

        return PacketHeader(
            ifacFlag:        (flags & 0b10000000) != 0,
            headerType:      headerType,
            contextFlag:     (flags & 0b00100000) != 0,
            propagationType: propType,
            destinationType: destType,
            packetType:      packetType,
            hops:            hops
        )
    }
}
