// SPDX-License-Identifier: MIT
// IntegrationTests.swift — End-to-end Phase 2 integration tests
//
// Exercises the full flow: announce creation, Transport dispatch,
// validation, routing table population, and HDLC framing round-trip.

import Testing
import Foundation
@testable import ReticulumKit

@Suite("Phase 2 Integration")
struct IntegrationTests {

    // MARK: - Helpers

    /// Create a MockTransportInterface (same as in TransportTests but accessible here).
    private func makeMock(id: String, bitrate: Int = 10_000_000) -> MockIntegrationInterface {
        MockIntegrationInterface(id: id, bitrate: bitrate)
    }

    // MARK: - Test 1: Full announce round-trip through Transport

    @Test("Full announce round-trip: send through Transport, both interfaces receive")
    func announceRoundTrip() async throws {
        let transport = Transport()
        let ifaceA = makeMock(id: "interface-a")
        let ifaceB = makeMock(id: "interface-b")

        await transport.addInterface(ifaceA)
        await transport.addInterface(ifaceB)

        let identity = Identity()
        let destination = Destination(
            identity: identity,
            direction: .out,
            appName: "test.app",
            aspects: ["messaging"]
        )

        await transport.registerDestination(destination)
        try await transport.sendAnnounce(for: destination)

        // Both interfaces should have received the announce
        let sentA = await ifaceA.sentCount()
        let sentB = await ifaceB.sentCount()
        #expect(sentA == 1, "Interface A should receive the announce")
        #expect(sentB == 1, "Interface B should receive the announce")

        // Unpack the sent data from interface-a and validate
        let sentData = await ifaceA.sentPackets[0]
        let packet = try Packet.unpack(sentData)
        let result = try Announce.validate(packet: packet)
        #expect(result.destinationHash == destination.hash)
        #expect(result.publicKey == identity.publicKeyBytes)
    }

    // MARK: - Test 2: Two nodes exchanging announces via mock interfaces

    @Test("Two nodes exchange announces via mock interfaces")
    func twoNodeExchange() async throws {
        // Node A
        let transportA = Transport()
        let ifaceA = makeMock(id: "node-a-iface")
        await transportA.addInterface(ifaceA)

        let identityA = Identity()
        let destinationA = Destination(
            identity: identityA,
            direction: .out,
            appName: "test.app",
            aspects: ["messaging"]
        )
        await transportA.registerDestination(destinationA)

        // Node B
        let transportB = Transport()
        let ifaceB = makeMock(id: "node-b-iface")
        await transportB.addInterface(ifaceB)

        // Node A sends announce
        try await transportA.sendAnnounce(for: destinationA)

        // Capture the sent packet from Node A's interface
        let sentData = await ifaceA.sentPackets[0]

        // Deliver it to Node B's interface (simulating network delivery)
        await ifaceB.feedPacket(sentData)

        // Wait for async processing
        try await Task.sleep(for: .milliseconds(200))

        // Node B should now have the route
        let count = await transportB.routingTable.count
        #expect(count == 1, "Node B routing table should have 1 entry")

        let entry = await transportB.routingTable.lookup(destinationA.hash)
        #expect(entry != nil, "Node B should find destination A in routing table")
        #expect(entry?.publicKey == identityA.publicKeyBytes, "Public key should match Identity A")
        #expect(entry?.interfaceId == "node-b-iface", "Interface ID should be node-b-iface")

        // Cleanup
        await transportA.shutdown()
        await transportB.shutdown()
    }

    // MARK: - Test 3: HDLC frame round-trip with announce packet

    @Test("HDLC frame round-trip with announce packet")
    func hdlcFrameRoundTrip() async throws {
        let identity = Identity()
        let destination = Destination(
            identity: identity,
            direction: .out,
            appName: "test.app",
            aspects: ["messaging"]
        )

        // Create and pack announce
        let announcePacket = try Announce.create(destination: destination)
        let packedData = try announcePacket.pack()

        // HDLC frame
        let framed = HDLC.frame(packedData)

        // HDLC deframe
        let deframer = HDLCDeframer()
        let deframed = deframer.feed(framed)

        #expect(deframed.count == 1, "Should deframe exactly one packet")
        #expect(deframed[0] == packedData, "Deframed data should match original packed data")

        // Unpack the deframed data
        let unpacked = try Packet.unpack(deframed[0])

        // Validate as announce
        let result = try Announce.validate(packet: unpacked)
        #expect(result.destinationHash == destination.hash, "Destination hash should match")
        #expect(result.publicKey == identity.publicKeyBytes, "Public key should match")
    }
}

// MARK: - Mock Interface for Integration Tests

/// Mock interface for integration testing — captures sent packets, allows feeding incoming packets.
actor MockIntegrationInterface: NetworkInterface {
    nonisolated let interfaceId: String
    nonisolated let bitrate: Int
    nonisolated let incomingPackets: AsyncStream<Data>

    private var _isOnline = true
    var isOnline: Bool { _isOnline }

    private var continuation: AsyncStream<Data>.Continuation?
    private(set) var sentPackets: [Data] = []

    init(id: String, bitrate: Int = 10_000_000) {
        self.interfaceId = id
        self.bitrate = bitrate
        let (stream, cont) = AsyncStream.makeStream(of: Data.self)
        self.incomingPackets = stream
        self.continuation = cont
    }

    func start() async throws {
        _isOnline = true
    }

    func stop() async {
        _isOnline = false
        continuation?.finish()
    }

    func send(_ data: Data) async throws {
        guard _isOnline else { throw ReticulumError.interfaceOffline }
        sentPackets.append(data)
    }

    func feedPacket(_ data: Data) {
        continuation?.yield(data)
    }

    func sentCount() -> Int {
        sentPackets.count
    }
}
