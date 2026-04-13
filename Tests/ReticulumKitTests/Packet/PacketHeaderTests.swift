// SPDX-License-Identifier: MIT
// PacketHeaderTests.swift — Tests for packet type enums and PacketHeader encode/decode

import Testing
import Foundation
@testable import ReticulumKit

@Suite("PacketTypes Enum Tests")
struct PacketTypesTests {

    @Test("HeaderType raw values: type1=0, type2=1")
    func headerTypeRawValues() {
        #expect(HeaderType.type1.rawValue == 0)
        #expect(HeaderType.type2.rawValue == 1)
    }

    @Test("PacketType raw values: data=0, announce=1, linkRequest=2, proof=3")
    func packetTypeRawValues() {
        #expect(PacketType.data.rawValue == 0x00)
        #expect(PacketType.announce.rawValue == 0x01)
        #expect(PacketType.linkRequest.rawValue == 0x02)
        #expect(PacketType.proof.rawValue == 0x03)
    }

    @Test("DestinationType raw values: single=0, group=1, plain=2, link=3")
    func destinationTypeRawValues() {
        #expect(DestinationType.single.rawValue == 0x00)
        #expect(DestinationType.group.rawValue == 0x01)
        #expect(DestinationType.plain.rawValue == 0x02)
        #expect(DestinationType.link.rawValue == 0x03)
    }

    @Test("PropagationType raw values: broadcast=0, transport=1")
    func propagationTypeRawValues() {
        #expect(PropagationType.broadcast.rawValue == 0)
        #expect(PropagationType.transport.rawValue == 1)
    }

    @Test("PacketContext none=0x00, channel=0x0E")
    func packetContextValues() {
        #expect(PacketContext.none.rawValue == 0x00)
        #expect(PacketContext.channel.rawValue == 0x0E)
    }
}

@Suite("PacketHeader Encode/Decode Tests")
struct PacketHeaderTests {

    @Test("encode() produces exactly 2 bytes")
    func encodeProduces2Bytes() {
        let header = PacketHeader(
            headerType: .type1,
            propagationType: .broadcast,
            destinationType: .single,
            packetType: .data
        )
        let encoded = header.encode()
        #expect(encoded.count == 2)
    }

    @Test("Known byte values: headerType=type1, announce, single, broadcast => flags=0x01, hops=0")
    func knownByteValues() {
        // headerType=0 (bit6=0), contextFlag=false (bit5=0), propType=broadcast=0 (bit4=0),
        // destType=single=0 (bits3-2=00), packetType=announce=1 (bits1-0=01)
        // flags = 0b00000001 = 0x01
        let header = PacketHeader(
            headerType: .type1,
            propagationType: .broadcast,
            destinationType: .single,
            packetType: .announce
        )
        let encoded = header.encode()
        #expect(encoded[0] == 0x01)
        #expect(encoded[1] == 0x00)
    }

    @Test("Known byte values: headerType=type2, transport, group, linkRequest")
    func knownByteValuesType2() {
        // headerType=1 (bit6=1), contextFlag=false (bit5=0), propType=transport=1 (bit4=1),
        // destType=group=1 (bits3-2=01), packetType=linkRequest=2 (bits1-0=10)
        // flags = 0b01010110 = 0x56
        let header = PacketHeader(
            headerType: .type2,
            propagationType: .transport,
            destinationType: .group,
            packetType: .linkRequest,
            hops: 5
        )
        let encoded = header.encode()
        #expect(encoded[0] == 0x56)
        #expect(encoded[1] == 5)
    }

    @Test("Round-trip encode/decode for all header type combinations")
    func roundTripAllCombinations() throws {
        for ht in [HeaderType.type1, .type2] {
            for pt in [PacketType.data, .announce, .linkRequest, .proof] {
                for dt in [DestinationType.single, .group, .plain, .link] {
                    for prop in [PropagationType.broadcast, .transport] {
                        let original = PacketHeader(
                            headerType: ht,
                            propagationType: prop,
                            destinationType: dt,
                            packetType: pt,
                            hops: 7
                        )
                        let encoded = original.encode()
                        let decoded = try PacketHeader.decode(encoded)
                        // IFAC flag is not set by encode, so decoded should have ifacFlag=false
                        #expect(decoded.ifacFlag == false)
                        #expect(decoded.headerType == original.headerType)
                        #expect(decoded.contextFlag == original.contextFlag)
                        #expect(decoded.propagationType == original.propagationType)
                        #expect(decoded.destinationType == original.destinationType)
                        #expect(decoded.packetType == original.packetType)
                        #expect(decoded.hops == original.hops)
                    }
                }
            }
        }
    }

    @Test("IFAC flag bit 7 is decoded separately")
    func ifacFlagDecoded() throws {
        // Manually set bit 7 in encoded data
        var encoded = Data([0b10000001, 3])  // IFAC set, announce, hops=3
        let decoded = try PacketHeader.decode(encoded)
        #expect(decoded.ifacFlag == true)
        #expect(decoded.packetType == .announce)
        #expect(decoded.hops == 3)
    }

    @Test("Hops byte is preserved through encode/decode")
    func hopsPreserved() throws {
        for hops: UInt8 in [0, 1, 127, 255] {
            let header = PacketHeader(
                headerType: .type1,
                propagationType: .broadcast,
                destinationType: .single,
                packetType: .data,
                hops: hops
            )
            let decoded = try PacketHeader.decode(header.encode())
            #expect(decoded.hops == hops)
        }
    }

    @Test("contextFlag is encoded and decoded correctly")
    func contextFlagRoundTrip() throws {
        let header = PacketHeader(
            headerType: .type1,
            contextFlag: true,
            propagationType: .broadcast,
            destinationType: .single,
            packetType: .data
        )
        let encoded = header.encode()
        // bit 5 should be set
        #expect(encoded[0] & 0b00100000 != 0)
        let decoded = try PacketHeader.decode(encoded)
        #expect(decoded.contextFlag == true)
    }

    @Test("decode with < 2 bytes throws packetTooShort")
    func decodeTooShortThrows() {
        #expect(throws: ReticulumError.self) {
            _ = try PacketHeader.decode(Data([0x00]))
        }
        #expect(throws: ReticulumError.self) {
            _ = try PacketHeader.decode(Data())
        }
    }
}
