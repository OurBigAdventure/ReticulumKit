// SPDX-License-Identifier: MIT
// ResourceTests.swift — Advertisement codec and Link.MDU alignment

import Testing
import Foundation
@testable import ReticulumKit

@Suite("Resource advertisement")
struct ResourceAdvertisementTests {
    @Test("pack/unpack round-trips hashmap and flags")
    func packUnpack() throws {
        let adv = ResourceAdvertisement(
            transferSize: 900,
            dataSize: 800,
            partCount: 3,
            hash: Data(repeating: 0xAA, count: 32),
            randomHash: Data(repeating: 0xBB, count: 4),
            originalHash: Data(repeating: 0xAA, count: 32),
            segmentIndex: 1,
            totalSegments: 1,
            requestId: nil,
            flags: 0x01,
            hashmap: Data(repeating: 0xCC, count: 12)
        )
        let packed = try adv.pack()
        #expect(packed.first == 0x8B, "Python umsgpack map with 11 keys")
        let qNil = Data([0xA1, 0x71, 0xC0]) // str "q" + nil
        #expect(packed.range(of: qNil) != nil, "Python unpack requires key q even when nil")
        let unpacked = try ResourceAdvertisement.unpack(packed)
        #expect(unpacked.transferSize == 900)
        #expect(unpacked.partCount == 3)
        #expect(unpacked.hash == adv.hash)
        #expect(unpacked.hashmap == adv.hashmap)
        #expect(unpacked.isEncrypted)
        #expect(!unpacked.isCompressed)
    }

    @Test("compressed flag bit is set when flags include 0x02")
    func compressedFlags() throws {
        let adv = ResourceAdvertisement(
            transferSize: 500,
            dataSize: 800,
            partCount: 2,
            hash: Data(repeating: 0x01, count: 32),
            randomHash: Data(repeating: 0x02, count: 4),
            originalHash: Data(repeating: 0x01, count: 32),
            segmentIndex: 1,
            totalSegments: 1,
            requestId: nil,
            flags: 0x03,
            hashmap: Data(repeating: 0x03, count: 8)
        )
        let packed = try adv.pack()
        let unpacked = try ResourceAdvertisement.unpack(packed)
        #expect(unpacked.isEncrypted)
        #expect(unpacked.isCompressed)
        #expect(unpacked.flags == 0x03)
    }
}

@Suite("Link MDU")
struct LinkMduTests {
    @Test("Link.MDU matches Python default 431")
    func linkMdu() {
        #expect(LinkConstants.mdu == 431)
    }
}
