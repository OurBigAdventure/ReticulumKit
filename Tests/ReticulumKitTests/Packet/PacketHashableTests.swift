// SPDX-License-Identifier: MIT
// PacketHashableTests.swift — Tests for Packet.hashablePart computation

import Testing
import Foundation
@testable import ReticulumKit

/// Helper to create a 16-byte TruncatedHash from a repeating byte value.
private func makeHash(_ byte: UInt8) -> TruncatedHash {
    try! TruncatedHash(Data(repeating: byte, count: 16))
}

@Suite("Packet hashablePart")
struct PacketHashableTests {

    @Test("Type1 hashablePart masks byte 0 to lower 4 bits and skips hops byte")
    func type1BasicMasking() throws {
        // Build a type1 packet raw: [flags:1][hops:1][destHash:16][context:1][data:N]
        // Flags = 0b01001000 = headerType=type1(bit6=1), destType=plain(bits3-2=10), packetType=data(bits1-0=00)
        // With upper bits: IFAC=0, headerType=1, contextFlag=0, propType=0, destType=2, packetType=0
        // = 0b01001000 = 0x48
        let flags: UInt8 = 0x48
        let hops: UInt8 = 0x05
        let destHash = Data(repeating: 0xAA, count: 16)
        let context: UInt8 = 0x00
        let payload = Data([0x01, 0x02, 0x03])

        var raw = Data()
        raw.append(flags)
        raw.append(hops)
        raw.append(destHash)
        raw.append(context)
        raw.append(payload)

        let hashable = Packet.hashablePart(raw: raw, headerType: .type1)

        // First byte should be flags & 0x0F = 0x48 & 0x0F = 0x08
        #expect(hashable[0] == 0x08)

        // Should skip byte 1 (hops), so next bytes are raw[2...] = destHash + context + payload
        let expected = Data([0x08]) + destHash + Data([context]) + payload
        #expect(hashable == expected)
    }

    @Test("Type2 hashablePart skips hops byte and transport ID")
    func type2SkipsTransportId() throws {
        // Type2 raw: [flags:1][hops:1][transportID:16][destHash:16][context:1][data:N]
        let flags: UInt8 = 0x50  // headerType=type1... actually for type2 we need bit6=1 => no, type2=1 so bit6=1...
        // Wait: HeaderType.type2 = 1, so bit 6 = 1. But we pass headerType as parameter, so the actual bit doesn't matter
        // for the function logic. Let's just use 0x50 as flags.
        let hops: UInt8 = 0x03
        let transportId = Data(repeating: 0xBB, count: 16)
        let destHash = Data(repeating: 0xCC, count: 16)
        let context: UInt8 = 0x00
        let payload = Data([0x04, 0x05])

        var raw = Data()
        raw.append(flags)
        raw.append(hops)
        raw.append(transportId)
        raw.append(destHash)
        raw.append(context)
        raw.append(payload)

        let hashable = Packet.hashablePart(raw: raw, headerType: .type2)

        // First byte should be flags & 0x0F = 0x50 & 0x0F = 0x00
        #expect(hashable[0] == 0x00)

        // Should skip hops (byte 1) AND transportID (bytes 2-17)
        // So: masked_flags + raw[18...] = destHash + context + payload
        let expected = Data([0x00]) + destHash + Data([context]) + payload
        #expect(hashable == expected)
    }

    @Test("hashablePart of link request with exactly 64 bytes data returns full hashable bytes")
    func linkRequestExact64Bytes() throws {
        // Type1 link request: [flags:1][hops:1][destHash:16][context:1][data:64]
        // Total raw = 84 bytes. Data portion = 64 bytes = ecPubSize. No trimming.
        let flags: UInt8 = 0x02  // linkRequest packetType
        let hops: UInt8 = 0x00
        let destHash = Data(repeating: 0xDD, count: 16)
        let context: UInt8 = 0x00
        let payload = Data(repeating: 0xEE, count: 64)

        var raw = Data()
        raw.append(flags)
        raw.append(hops)
        raw.append(destHash)
        raw.append(context)
        raw.append(payload)

        let hashable = Packet.hashablePart(raw: raw, headerType: .type1)

        // 1 (masked flags) + 16 (destHash) + 1 (context) + 64 (payload) = 82
        #expect(hashable.count == 82)
        // No trimming since data portion == ecPubSize
    }

    @Test("hashablePart of link request with 67 bytes data trims last 3 signalling bytes")
    func linkRequestTrimsSignalling() throws {
        // Type1 link request: [flags:1][hops:1][destHash:16][context:1][data:67]
        // Total raw = 87. Data portion = 67 > ecPubSize(64) => trim 3 bytes
        let flags: UInt8 = 0x02  // linkRequest packetType
        let hops: UInt8 = 0x00
        let destHash = Data(repeating: 0xDD, count: 16)
        let context: UInt8 = 0x00
        let payload = Data(repeating: 0xEE, count: 64) + Data([0xAA, 0xBB, 0xCC])  // 67 bytes

        var raw = Data()
        raw.append(flags)
        raw.append(hops)
        raw.append(destHash)
        raw.append(context)
        raw.append(payload)

        let hashable = Packet.hashablePart(raw: raw, headerType: .type1)

        // Should trim last 3 bytes (signalling) from the hashable result
        // 1 (masked flags) + 16 (destHash) + 1 (context) + 64 (payload without signalling) = 82
        #expect(hashable.count == 82)

        // The signalling bytes (0xAA, 0xBB, 0xCC) should NOT be present
        let lastThree = Data([hashable[hashable.count - 3], hashable[hashable.count - 2], hashable[hashable.count - 1]])
        #expect(lastThree == Data(repeating: 0xEE, count: 3), "Last bytes should be payload, not signalling")
    }

    @Test("hashablePart type2 with signalling trims correctly")
    func type2WithSignallingTrim() throws {
        // Type2: [flags:1][hops:1][transportID:16][destHash:16][context:1][data:67]
        // Header size for type2 = 2 + 16 + 16 + 1 = 35
        // Data portion = 67 > ecPubSize(64) => trim 3 bytes
        let flags: UInt8 = 0x52  // type2 bit6=1, linkRequest bits1-0=10
        let hops: UInt8 = 0x00
        let transportId = Data(repeating: 0xAA, count: 16)
        let destHash = Data(repeating: 0xDD, count: 16)
        let context: UInt8 = 0x00
        let payload = Data(repeating: 0xFF, count: 64) + Data([0x01, 0x02, 0x03])

        var raw = Data()
        raw.append(flags)
        raw.append(hops)
        raw.append(transportId)
        raw.append(destHash)
        raw.append(context)
        raw.append(payload)

        let hashable = Packet.hashablePart(raw: raw, headerType: .type2)

        // Hashable: masked_flags(1) + destHash(16) + context(1) + 64 bytes payload = 82
        // Transport ID is skipped
        #expect(hashable.count == 82)
    }
    @Test("truncatedPacketHash uses untrimmed hashable part, not ciphertext alone")
    func truncatedPacketHashForLinkRequest() throws {
        let destHash = try TruncatedHash(Data(repeating: 0x11, count: 16))
        let header = PacketHeader(
            headerType: .type1,
            propagationType: .broadcast,
            destinationType: .link,
            packetType: .data,
            hops: 1
        )
        let ciphertext = Data(repeating: 0x5A, count: 200)
        let packet = Packet(
            header: header,
            destinationHash: destHash,
            context: .request,
            data: ciphertext
        )
        let raw = try packet.pack()
        let expected = CryptoEngine.truncatedHash(Packet.dataPacketHashablePart(raw: raw, headerType: .type1))
        #expect(Packet.truncatedPacketHash(raw: raw, headerType: .type1) == expected)
        #expect(try packet.truncatedHash() == expected)
        #expect(expected != CryptoEngine.truncatedHash(ciphertext))
    }
}
