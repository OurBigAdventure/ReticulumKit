// SPDX-License-Identifier: MIT
// TransportDropPathTests.swift — Transport.dropPath removes routing entries

import Testing
import Foundation
@testable import ReticulumKit

@Suite("Transport dropPath")
struct TransportDropPathTests {
    private func makeHash(_ byte: UInt8) throws -> TruncatedHash {
        try TruncatedHash(Data(repeating: byte, count: 16))
    }

    @Test("dropPath removes a known destination from the routing table")
    func dropPathRemovesEntry() async throws {
        let transport = Transport()
        let hash = try makeHash(0x42)
        let entry = RouteEntry(
            destinationHash: hash,
            publicKey: Data(repeating: 0x42, count: 64),
            nameHash: Data(repeating: 0x42, count: 10),
            appData: nil,
            hops: 1,
            timestamp: Date(),
            interfaceId: "test-iface"
        )
        await transport.routingTable.addEntry(entry)
        #expect(await transport.routingTable.hasPath(for: hash))
        await transport.dropPath(hash)
        #expect(await transport.routingTable.hasPath(for: hash) == false)
    }
}
