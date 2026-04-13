// SPDX-License-Identifier: MIT
// PacketTests.swift — Tests for Packet pack/unpack and validation

import Testing
import Foundation
@testable import ReticulumKit

/// Helper to create a 16-byte TruncatedHash from a repeating byte value.
private func makeHash(_ byte: UInt8) -> TruncatedHash {
    try! TruncatedHash(Data(repeating: byte, count: 16))
}

@Suite("Packet Type 1 Tests")
struct PacketType1Tests {

    @Test("Type 1 packs to [Flags:1][Hops:1][DestHash:16][Context:1][Data:var]")
    func type1WireFormat() throws {
        let destHash = makeHash(0xAA)
        let header = PacketHeader(
            headerType: .type1,
            propagationType: .broadcast,
            destinationType: .single,
            packetType: .data
        )
        let packet = Packet(
            header: header,
            destinationHash: destHash,
            context: .none,
            data: Data([0x01, 0x02, 0x03])
        )
        let packed = try packet.pack()

        // Total: 2 (header) + 16 (dest) + 1 (context) + 3 (data) = 22 bytes
        #expect(packed.count == 22)

        // Byte 0: flags (type1=0, broadcast=0, single=0, data=0 => 0x00)
        #expect(packed[0] == 0x00)
        // Byte 1: hops = 0
        #expect(packed[1] == 0x00)
        // Bytes 2-17: destination hash (0xAA repeated)
        for i in 2..<18 {
            #expect(packed[i] == 0xAA)
        }
        // Byte 18: context = none = 0x00
        #expect(packed[18] == 0x00)
        // Bytes 19-21: data
        #expect(packed[19] == 0x01)
        #expect(packed[20] == 0x02)
        #expect(packed[21] == 0x03)
    }

    @Test("Type 1 unpack round-trips with pack")
    func type1RoundTrip() throws {
        let destHash = makeHash(0xBB)
        let header = PacketHeader(
            headerType: .type1,
            propagationType: .broadcast,
            destinationType: .plain,
            packetType: .announce,
            hops: 3
        )
        let original = Packet(
            header: header,
            destinationHash: destHash,
            context: .channel,
            data: Data([0xFF, 0xFE])
        )
        let packed = try original.pack()
        let unpacked = try Packet.unpack(packed)

        #expect(unpacked.header.headerType == .type1)
        #expect(unpacked.header.packetType == .announce)
        #expect(unpacked.header.destinationType == .plain)
        #expect(unpacked.header.propagationType == .broadcast)
        #expect(unpacked.header.hops == 3)
        #expect(unpacked.destinationHash == destHash)
        #expect(unpacked.transportId == nil)
        #expect(unpacked.context == .channel)
        #expect(unpacked.data == Data([0xFF, 0xFE]))
    }

    @Test("Type 1 with empty data is valid (minimum header-only packet)")
    func type1EmptyData() throws {
        let header = PacketHeader(
            headerType: .type1,
            propagationType: .broadcast,
            destinationType: .single,
            packetType: .data
        )
        let packet = Packet(
            header: header,
            destinationHash: makeHash(0x11),
            context: .none,
            data: Data()
        )
        let packed = try packet.pack()
        // 2 (header) + 16 (dest) + 1 (context) = 19 bytes (minimum)
        #expect(packed.count == 19)

        let unpacked = try Packet.unpack(packed)
        #expect(unpacked.data.isEmpty)
    }

    @Test("Type 1 maximum data (464 bytes) packs within MTU")
    func type1MaxData() throws {
        let header = PacketHeader(
            headerType: .type1,
            propagationType: .broadcast,
            destinationType: .single,
            packetType: .data
        )
        // Max payload for type1: 500 - 2 - 16 - 1 = 481 bytes
        // But MDU is 464 (500 - 35 - 1), which is conservative
        // The actual limit for type1 is 500 - 19 = 481
        let maxPayload = Data(repeating: 0x42, count: 481)
        let packet = Packet(
            header: header,
            destinationHash: makeHash(0xCC),
            context: .none,
            data: maxPayload
        )
        let packed = try packet.pack()
        #expect(packed.count == 500)  // exactly MTU
    }
}

@Suite("Packet Type 2 Tests")
struct PacketType2Tests {

    @Test("Type 2 packs to [Flags:1][Hops:1][TransportID:16][DestHash:16][Context:1][Data:var]")
    func type2WireFormat() throws {
        let destHash = makeHash(0xDD)
        let transportId = makeHash(0xEE)
        let header = PacketHeader(
            headerType: .type2,
            propagationType: .transport,
            destinationType: .single,
            packetType: .data
        )
        let packet = Packet(
            header: header,
            destinationHash: destHash,
            transportId: transportId,
            context: .none,
            data: Data([0x0A])
        )
        let packed = try packet.pack()

        // Total: 2 (header) + 16 (transport) + 16 (dest) + 1 (context) + 1 (data) = 36 bytes
        #expect(packed.count == 36)

        // Bytes 2-17: transport ID (0xEE repeated)
        for i in 2..<18 {
            #expect(packed[i] == 0xEE)
        }
        // Bytes 18-33: destination hash (0xDD repeated)
        for i in 18..<34 {
            #expect(packed[i] == 0xDD)
        }
        // Byte 34: context = none = 0x00
        #expect(packed[34] == 0x00)
        // Byte 35: data
        #expect(packed[35] == 0x0A)
    }

    @Test("Type 2 unpack round-trips with pack")
    func type2RoundTrip() throws {
        let destHash = makeHash(0x55)
        let transportId = makeHash(0x66)
        let header = PacketHeader(
            headerType: .type2,
            propagationType: .transport,
            destinationType: .group,
            packetType: .proof,
            hops: 10
        )
        let original = Packet(
            header: header,
            destinationHash: destHash,
            transportId: transportId,
            context: .resource,
            data: Data(repeating: 0xAB, count: 50)
        )
        let packed = try original.pack()
        let unpacked = try Packet.unpack(packed)

        #expect(unpacked.header.headerType == .type2)
        #expect(unpacked.header.packetType == .proof)
        #expect(unpacked.header.destinationType == .group)
        #expect(unpacked.header.propagationType == .transport)
        #expect(unpacked.header.hops == 10)
        #expect(unpacked.destinationHash == destHash)
        #expect(unpacked.transportId == transportId)
        #expect(unpacked.context == .resource)
        #expect(unpacked.data == Data(repeating: 0xAB, count: 50))
    }

    @Test("Type 2 with transportId=nil throws missingTransportId")
    func type2MissingTransportIdThrows() {
        let header = PacketHeader(
            headerType: .type2,
            propagationType: .transport,
            destinationType: .single,
            packetType: .data
        )
        let packet = Packet(
            header: header,
            destinationHash: makeHash(0x11)
        )
        #expect(throws: ReticulumError.self) {
            _ = try packet.pack()
        }
    }
}

@Suite("Packet All Types Tests")
struct PacketAllTypesTests {

    @Test("All 4 packet types (data, announce, linkRequest, proof) can be created and round-trip")
    func allPacketTypes() throws {
        for pt in [PacketType.data, .announce, .linkRequest, .proof] {
            let header = PacketHeader(
                headerType: .type1,
                propagationType: .broadcast,
                destinationType: .single,
                packetType: pt
            )
            let packet = Packet(
                header: header,
                destinationHash: makeHash(0x33),
                context: .none,
                data: Data([0x01])
            )
            let packed = try packet.pack()
            let unpacked = try Packet.unpack(packed)
            #expect(unpacked.header.packetType == pt)
        }
    }

    @Test("All 4 destination types (single, group, plain, link) are handled")
    func allDestinationTypes() throws {
        for dt in [DestinationType.single, .group, .plain, .link] {
            let header = PacketHeader(
                headerType: .type1,
                propagationType: .broadcast,
                destinationType: dt,
                packetType: .data
            )
            let packet = Packet(
                header: header,
                destinationHash: makeHash(0x44),
                context: .none,
                data: Data([0x02])
            )
            let packed = try packet.pack()
            let unpacked = try Packet.unpack(packed)
            #expect(unpacked.header.destinationType == dt)
        }
    }
}

@Suite("Packet Validation Tests")
struct PacketValidationTests {

    @Test("Reject packets exceeding MTU (500 bytes)")
    func rejectOversizedPacket() {
        let header = PacketHeader(
            headerType: .type1,
            propagationType: .broadcast,
            destinationType: .single,
            packetType: .data
        )
        // 2 + 16 + 1 + 482 = 501 > 500
        let packet = Packet(
            header: header,
            destinationHash: makeHash(0xFF),
            context: .none,
            data: Data(repeating: 0x00, count: 482)
        )
        #expect(throws: ReticulumError.self) {
            _ = try packet.pack()
        }
    }

    @Test("Reject unpack of data exceeding MTU")
    func rejectOversizedUnpack() {
        let raw = Data(repeating: 0x00, count: 501)
        #expect(throws: ReticulumError.self) {
            _ = try Packet.unpack(raw)
        }
    }

    @Test("Reject packets below minimum header size (19 for type1)")
    func rejectUndersizedPacket() {
        let raw = Data(repeating: 0x00, count: 18)
        #expect(throws: ReticulumError.self) {
            _ = try Packet.unpack(raw)
        }
    }

    @Test("Reject packets below minimum header size (35 for type2)")
    func rejectUndersizedType2() {
        // Build raw bytes that look like type2 header but too short
        // headerType=type2 means bit 6 set: 0b01000000 = 0x40
        var raw = Data(repeating: 0x00, count: 34)
        raw[0] = 0x40  // type2 header flag
        #expect(throws: ReticulumError.self) {
            _ = try Packet.unpack(raw)
        }
    }

    @Test("Validate rejects type2 with nil transportId")
    func validateType2MissingTransport() {
        let header = PacketHeader(
            headerType: .type2,
            propagationType: .transport,
            destinationType: .single,
            packetType: .data
        )
        let packet = Packet(
            header: header,
            destinationHash: makeHash(0x11)
        )
        #expect(throws: ReticulumError.self) {
            try packet.validate()
        }
    }

    @Test("Validate rejects type1 with unexpected transportId")
    func validateType1WithTransport() {
        let header = PacketHeader(
            headerType: .type1,
            propagationType: .broadcast,
            destinationType: .single,
            packetType: .data
        )
        let packet = Packet(
            header: header,
            destinationHash: makeHash(0x11),
            transportId: makeHash(0x22)
        )
        #expect(throws: ReticulumError.self) {
            try packet.validate()
        }
    }
}
