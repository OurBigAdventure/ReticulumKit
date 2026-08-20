// SPDX-License-Identifier: MIT
// RoutingTableTests.swift — Tests for routing table entry management

import Testing
import Foundation
@testable import ReticulumKit

@Suite("Routing table")
struct RoutingTableTests {

    // MARK: - Helpers

    private func makeHash(_ byte: UInt8) throws -> TruncatedHash {
        try TruncatedHash(Data(repeating: byte, count: 16))
    }

    private func makeEntry(
        hashByte: UInt8,
        hops: UInt8 = 1,
        timestamp: Date = Date(),
        interfaceId: String = "test-iface",
        emittedAt: UInt64 = 1_700_000_000,
        blobSeed: UInt8 = 1
    ) throws -> RouteEntry {
        let blob = Self.randomBlob(emittedAt: emittedAt, seed: blobSeed)
        return RouteEntry(
            destinationHash: try makeHash(hashByte),
            publicKey: Data(repeating: hashByte, count: 64),
            nameHash: Data(repeating: hashByte, count: 10),
            appData: nil,
            hops: hops,
            timestamp: timestamp,
            interfaceId: interfaceId,
            emittedAt: emittedAt,
            randomBlobs: [blob]
        )
    }

    private static func randomBlob(emittedAt: UInt64, seed: UInt8) -> Data {
        var blob = Data(repeating: seed, count: 5)
        var value = emittedAt
        var timeBytes = Data(count: 5)
        for i in (0..<5).reversed() {
            timeBytes[i] = UInt8(value & 0xff)
            value >>= 8
        }
        blob.append(timeBytes)
        return blob
    }

    // MARK: - Tests

    @Test("addEntry + lookup retrieves stored entry")
    func addAndLookup() async throws {
        let table = RoutingTable()
        let entry = try makeEntry(hashByte: 0x01)
        await table.addEntry(entry)
        let result = await table.lookup(entry.destinationHash)
        #expect(result != nil)
        #expect(result?.destinationHash == entry.destinationHash)
        #expect(result?.hops == 1)
    }

    @Test("lookup returns nil for unknown hash")
    func lookupUnknown() async throws {
        let table = RoutingTable()
        let hash = try makeHash(0xFF)
        let result = await table.lookup(hash)
        #expect(result == nil)
    }

    @Test("addEntry with fewer hops replaces existing entry")
    func fewerHopsReplaces() async throws {
        let table = RoutingTable()
        let entry1 = try makeEntry(hashByte: 0x01, hops: 5, emittedAt: 100, blobSeed: 1)
        let entry2 = try makeEntry(hashByte: 0x01, hops: 2, emittedAt: 100, blobSeed: 2)
        await table.addEntry(entry1)
        await table.addEntry(entry2)
        let result = await table.lookup(try makeHash(0x01))
        #expect(result?.hops == 2)
    }

    @Test("addEntry with more hops does NOT replace an equally recent path")
    func moreHopsDoesNotReplace() async throws {
        let table = RoutingTable()
        let entry1 = try makeEntry(hashByte: 0x01, hops: 2, emittedAt: 200, blobSeed: 1)
        let entry2 = try makeEntry(hashByte: 0x01, hops: 5, emittedAt: 200, blobSeed: 2)
        await table.addEntry(entry1)
        await table.addEntry(entry2)
        let result = await table.lookup(try makeHash(0x01))
        #expect(result?.hops == 2)
    }

    @Test("addEntry with more hops DOES replace when the announce was emitted later")
    func newerEmissionReplacesDespiteMoreHops() async throws {
        let table = RoutingTable()
        let entry1 = try makeEntry(hashByte: 0x01, hops: 2, interfaceId: "old", emittedAt: 100, blobSeed: 1)
        let entry2 = try makeEntry(hashByte: 0x01, hops: 5, interfaceId: "new", emittedAt: 200, blobSeed: 2)
        await table.addEntry(entry1)
        await table.addEntry(entry2)
        let result = await table.lookup(try makeHash(0x01))
        #expect(result?.hops == 5)
        #expect(result?.interfaceId == "new")
    }

    @Test("addEntry with equal hops does NOT replace (keep first)")
    func equalHopsKeepsFirst() async throws {
        let table = RoutingTable()
        let entry1 = try makeEntry(hashByte: 0x01, hops: 3, interfaceId: "first", emittedAt: 100, blobSeed: 1)
        let entry2 = try makeEntry(hashByte: 0x01, hops: 3, interfaceId: "second", emittedAt: 100, blobSeed: 2)
        await table.addEntry(entry1)
        await table.addEntry(entry2)
        let result = await table.lookup(try makeHash(0x01))
        #expect(result?.interfaceId == "first")
    }

    @Test("removeEntry removes the entry")
    func removeEntry() async throws {
        let table = RoutingTable()
        let entry = try makeEntry(hashByte: 0x01)
        await table.addEntry(entry)
        let hash = try makeHash(0x01)
        await table.removeEntry(hash)
        let result = await table.lookup(hash)
        #expect(result == nil)
    }

    @Test("allEntries returns all stored entries")
    func allEntries() async throws {
        let table = RoutingTable()
        try await table.addEntry(makeEntry(hashByte: 0x01))
        try await table.addEntry(makeEntry(hashByte: 0x02))
        try await table.addEntry(makeEntry(hashByte: 0x03))
        let all = await table.allEntries()
        #expect(all.count == 3)
    }

    @Test("removeExpired removes old entries but keeps fresh ones")
    func removeExpired() async throws {
        let table = RoutingTable()
        let oldEntry = try makeEntry(
            hashByte: 0x01,
            timestamp: Date().addingTimeInterval(-700_000)  // > 1 week ago
        )
        let freshEntry = try makeEntry(
            hashByte: 0x02,
            timestamp: Date()
        )
        await table.addEntry(oldEntry)
        await table.addEntry(freshEntry)
        await table.removeExpired()
        #expect(await table.count == 1)
        #expect(await table.lookup(try makeHash(0x02)) != nil)
        #expect(await table.lookup(try makeHash(0x01)) == nil)
    }

    @Test("count reflects number of entries")
    func countReflectsEntries() async throws {
        let table = RoutingTable()
        #expect(await table.count == 0)
        try await table.addEntry(makeEntry(hashByte: 0x01))
        #expect(await table.count == 1)
        try await table.addEntry(makeEntry(hashByte: 0x02))
        #expect(await table.count == 2)
    }
}
