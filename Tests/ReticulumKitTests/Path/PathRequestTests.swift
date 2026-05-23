// SPDX-License-Identifier: MIT
// PathRequestTests.swift — Tests for path request creation and response detection

import Testing
import Foundation
@testable import ReticulumKit

/// Helper to create a 16-byte TruncatedHash from a repeating byte value.
private func makeHash(_ byte: UInt8) -> TruncatedHash {
    try! TruncatedHash(Data(repeating: byte, count: 16))
}

@Suite("PathRequest")
struct PathRequestTests {

    @Test("create produces a broadcast data packet addressed to the target destination hash")
    func createPacket() throws {
        let targetHash = makeHash(0xBB)
        let packet = try PathRequest.create(targetHash: targetHash)

        #expect(packet.header.packetType == .data)
        #expect(packet.header.destinationType == .plain)
        #expect(packet.header.propagationType == .broadcast)
        #expect(packet.context == .none)
        // Per the Reticulum spec, the path request is addressed TO the target
        // destination — any node holding a route to it (most often the target
        // itself) replies with an announce.
        #expect(packet.destinationHash == targetHash)
        #expect(packet.data.count == 10, "request tag should be 10 random bytes")
    }

    @Test("create packet can be packed without error")
    func createPacketPacks() throws {
        let targetHash = makeHash(0xCC)
        let packet = try PathRequest.create(targetHash: targetHash)
        let packed = try packet.pack()
        #expect(packed.count > 0)
    }

    @Test("isPathResponse returns true for announce with pathResponse context")
    func isPathResponseTrue() throws {
        let header = PacketHeader(
            headerType: .type1,
            propagationType: .broadcast,
            destinationType: .single,
            packetType: .announce
        )
        let packet = Packet(
            header: header,
            destinationHash: makeHash(0xDD),
            context: .pathResponse,
            data: Data(repeating: 0, count: 148)
        )
        #expect(PathRequest.isPathResponse(packet) == true)
    }

    @Test("isPathResponse returns false for announce with none context")
    func isPathResponseFalseNoneContext() throws {
        let header = PacketHeader(
            headerType: .type1,
            propagationType: .broadcast,
            destinationType: .single,
            packetType: .announce
        )
        let packet = Packet(
            header: header,
            destinationHash: makeHash(0xDD),
            context: .none,
            data: Data(repeating: 0, count: 148)
        )
        #expect(PathRequest.isPathResponse(packet) == false)
    }

    @Test("isPathResponse returns false for data packet with pathResponse context")
    func isPathResponseFalseDataPacket() throws {
        let header = PacketHeader(
            headerType: .type1,
            propagationType: .broadcast,
            destinationType: .plain,
            packetType: .data
        )
        let packet = Packet(
            header: header,
            destinationHash: makeHash(0xDD),
            context: .pathResponse,
            data: Data([0x01])
        )
        #expect(PathRequest.isPathResponse(packet) == false)
    }
}

// MARK: - Transport Path Request Tests

/// Mock interface for Transport testing (duplicated here to avoid cross-test-file dependency).
/// Captures sent packets and allows external feeding of incoming packets.
private actor PathTestMockInterface: NetworkInterface {
    nonisolated let interfaceId: String
    nonisolated let bitrate: Int
    nonisolated let incomingPackets: AsyncStream<Data>

    private var _isOnline = true
    var isOnline: Bool { _isOnline }

    private var continuation: AsyncStream<Data>.Continuation?
    private(set) var sentPackets: [Data] = []

    init(id: String = "path-mock-\(UUID().uuidString.prefix(4))", bitrate: Int = 10_000_000) {
        self.interfaceId = id
        self.bitrate = bitrate
        let (stream, cont) = AsyncStream.makeStream(of: Data.self)
        self.incomingPackets = stream
        self.continuation = cont
    }

    func start() async throws { _isOnline = true }
    func stop() async { _isOnline = false; continuation?.finish() }

    func send(_ data: Data) async throws {
        guard _isOnline else { throw ReticulumError.interfaceOffline }
        sentPackets.append(data)
    }

    func feedPacket(_ data: Data) { continuation?.yield(data) }
    func sentCount() -> Int { sentPackets.count }
    func lastSentPacket() -> Data? { sentPackets.last }
}

@Suite("Transport Path Requests")
struct TransportPathRequestTests {

    @Test("requestPath sends a path request packet through mock interface")
    func requestPathSendsPacket() async throws {
        let transport = Transport()
        let mock = PathTestMockInterface(id: "path-iface-a")
        await transport.addInterface(mock)

        let targetHash = makeHash(0xAA)
        try await transport.requestPath(to: targetHash)

        let sentCount = await mock.sentCount()
        #expect(sentCount == 1, "Should send exactly one path request packet")

        // Verify the sent packet is a valid path request
        if let sentData = await mock.lastSentPacket() {
            let packet = try Packet.unpack(sentData)
            #expect(packet.header.packetType == .data)
            #expect(packet.header.destinationType == .plain)
            // Path request is addressed to the target destination per the spec.
            #expect(packet.destinationHash == targetHash)
            #expect(packet.data.count == 10, "request tag should be 10 random bytes")
        }
    }

    @Test("requestPath skips sending when destination already in routing table")
    func requestPathSkipsKnownDestination() async throws {
        let transport = Transport()
        let mock = PathTestMockInterface(id: "path-iface-b")
        await transport.addInterface(mock)

        // Create a valid announce and feed it to populate routing table
        let identity = Identity()
        let destination = Destination(identity: identity, direction: .out, appName: "test.app", aspects: ["messaging"])
        let announcePacket = try Announce.create(destination: destination)
        let packedData = try announcePacket.pack()

        await mock.feedPacket(packedData)
        try await Task.sleep(for: .milliseconds(200))

        // Now request path to the known destination -- should not send
        try await transport.requestPath(to: destination.hash)

        // Only the announce was sent (0 path requests sent -- the announce was received, not sent)
        let sentCount = await mock.sentCount()
        #expect(sentCount == 0, "Should not send path request for known destination")
    }

    @Test("rapid re-requests within 20 seconds are suppressed")
    func pathRequestRateLimiting() async throws {
        let transport = Transport()
        let mock = PathTestMockInterface(id: "path-iface-c")
        await transport.addInterface(mock)

        let targetHash = makeHash(0xBB)

        // First request should go through
        try await transport.requestPath(to: targetHash)
        // Second request immediately should be rate-limited
        try await transport.requestPath(to: targetHash)

        let sentCount = await mock.sentCount()
        #expect(sentCount == 1, "Second request within 20 seconds should be suppressed")
    }

    @Test("path response announce is processed and added to routing table")
    func pathResponseUpdatesRoutingTable() async throws {
        let transport = Transport()
        let mock = PathTestMockInterface(id: "path-iface-d")
        await transport.addInterface(mock)

        // Create a valid announce but pack it as a pathResponse
        let identity = Identity()
        let destination = Destination(identity: identity, direction: .out, appName: "test.app", aspects: ["messaging"])
        let announcePacket = try Announce.create(destination: destination)

        // Re-create the packet with pathResponse context
        let pathResponsePacket = Packet(
            header: announcePacket.header,
            destinationHash: announcePacket.destinationHash,
            transportId: announcePacket.transportId,
            context: .pathResponse,
            data: announcePacket.data
        )
        let packedData = try pathResponsePacket.pack()

        await mock.feedPacket(packedData)
        try await Task.sleep(for: .milliseconds(200))

        let count = await transport.routingTable.count
        #expect(count == 1, "Path response announce should be added to routing table")

        let entry = await transport.routingTable.lookup(destination.hash)
        #expect(entry != nil, "Should find route entry for announced destination")
    }
}
