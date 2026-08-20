// SPDX-License-Identifier: MIT
// TransportTests.swift — Transport actor unit tests

import Testing
import Foundation
@testable import ReticulumKit

// MARK: - Mock NetworkInterface for Transport testing

/// A mock interface that captures sent packets and allows external feeding of incoming packets.
actor MockTransportInterface: NetworkInterface {
    nonisolated let interfaceId: String
    nonisolated let bitrate: Int
    nonisolated let incomingPackets: AsyncStream<Data>

    private var _isOnline = true
    var isOnline: Bool { _isOnline }

    private var continuation: AsyncStream<Data>.Continuation?
    private(set) var sentPackets: [Data] = []

    init(id: String = "mock-\(UUID().uuidString.prefix(4))", bitrate: Int = 10_000_000) {
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

    /// Feed a raw packet into the incoming stream (simulates receiving from network).
    func feedPacket(_ data: Data) {
        continuation?.yield(data)
    }

    /// Get count of sent packets.
    func sentCount() -> Int {
        sentPackets.count
    }
}

// MARK: - Transport Tests

@Suite("Transport")
struct TransportTests {

    @Test("Transport adds interface and processes incoming announce into routing table")
    func processIncomingAnnounce() async throws {
        let transport = Transport()
        let mock = MockTransportInterface(id: "iface-a")
        await transport.addInterface(mock)

        // Create a valid announce packet
        let identity = Identity()
        let destination = Destination(identity: identity, direction: .out, appName: "test.app", aspects: ["messaging"])
        let announcePacket = try Announce.create(destination: destination)
        let packedData = try announcePacket.pack()

        // Feed the announce into the mock interface
        await mock.feedPacket(packedData)

        // Wait for async processing
        try await Task.sleep(for: .milliseconds(200))

        let count = await transport.routingTable.count
        #expect(count == 1)
    }

    @Test("Transport rejects announce with invalid signature")
    func rejectInvalidSignature() async throws {
        let transport = Transport()
        let mock = MockTransportInterface(id: "iface-b")
        await transport.addInterface(mock)

        // Create a valid announce then corrupt the signature
        let identity = Identity()
        let destination = Destination(identity: identity, direction: .out, appName: "test.app", aspects: ["messaging"])
        let announcePacket = try Announce.create(destination: destination)
        var packedData = try announcePacket.pack()

        // Signature is at payload offset 84-148 (after 2-byte header + 16-byte destHash + 1-byte context = 19 bytes payload start)
        // Payload starts at byte 19 for type1 header. Signature at payload[84..148] = raw[103..167]
        let sigStart = 19 + 84  // 103
        if packedData.count > sigStart + 10 {
            packedData[sigStart] ^= 0xFF
            packedData[sigStart + 1] ^= 0xFF
        }

        await mock.feedPacket(packedData)

        try await Task.sleep(for: .milliseconds(200))

        let count = await transport.routingTable.count
        #expect(count == 0)
    }

    @Test("Transport rejects duplicate announce with same random hash")
    func rejectDuplicateAnnounce() async throws {
        let transport = Transport()
        let mock = MockTransportInterface(id: "iface-c")
        await transport.addInterface(mock)

        let identity = Identity()
        let destination = Destination(identity: identity, direction: .out, appName: "test.app", aspects: ["messaging"])
        let announcePacket = try Announce.create(destination: destination)
        let packedData = try announcePacket.pack()

        // Feed the same announce twice
        await mock.feedPacket(packedData)
        try await Task.sleep(for: .milliseconds(200))

        await mock.feedPacket(packedData)
        try await Task.sleep(for: .milliseconds(200))

        let count = await transport.routingTable.count
        #expect(count == 1, "Duplicate announce should not create second entry")
    }

    @Test("sendAnnounce sends packed data through mock interface")
    func sendAnnounce() async throws {
        let transport = Transport()
        let mock = MockTransportInterface(id: "iface-d")
        await transport.addInterface(mock)

        let identity = Identity()
        let destination = Destination(identity: identity, direction: .out, appName: "test.app", aspects: ["messaging"])
        await transport.registerDestination(destination)

        try await transport.sendAnnounce(for: destination)

        let sentCount = await mock.sentCount()
        #expect(sentCount == 1)
    }

    @Test("sendAnnounce respects rate limiter on rapid sends")
    func rateLimiterEnforced() async throws {
        // Use a very slow bitrate so rate limiting kicks in hard
        let transport = Transport()
        let mock = MockTransportInterface(id: "iface-e", bitrate: 1_000) // 1 kbps
        await transport.addInterface(mock)

        let identity = Identity()
        let destination = Destination(identity: identity, direction: .out, appName: "test.app", aspects: ["messaging"])
        await transport.registerDestination(destination)

        // First send should succeed
        try await transport.sendAnnounce(for: destination)
        // Second send immediately should be rate-limited
        try await transport.sendAnnounce(for: destination)

        let sentCount = await mock.sentCount()
        #expect(sentCount == 1, "Second announce should be rate-limited")
    }

    @Test("lookup after announce returns correct RouteEntry")
    func lookupAfterAnnounce() async throws {
        let transport = Transport()
        let mock = MockTransportInterface(id: "iface-f")
        await transport.addInterface(mock)

        let identity = Identity()
        let destination = Destination(identity: identity, direction: .out, appName: "test.app", aspects: ["messaging"])
        let announcePacket = try Announce.create(destination: destination)
        let packedData = try announcePacket.pack()

        await mock.feedPacket(packedData)
        try await Task.sleep(for: .milliseconds(200))

        let entry = await transport.routingTable.lookup(destination.hash)
        #expect(entry != nil)
        #expect(entry?.publicKey == identity.publicKeyBytes)
        #expect(entry?.destinationHash == destination.hash)
        #expect(entry?.nextHop == destination.hash)
    }

    @Test("HEADER_2 announce stores transport_id as nextHop")
    func announceType2StoresNextHop() async throws {
        let transport = Transport()
        let mock = MockTransportInterface(id: "iface-hub")
        await transport.addInterface(mock)

        let identity = Identity()
        let destination = Destination(identity: identity, direction: .out, appName: "test.app", aspects: ["messaging"])
        let announcePacket = try Announce.create(destination: destination)
        let type1 = try announcePacket.pack()
        let hubId = try TruncatedHash(Data(repeating: 0x42, count: 16))
        let wrapped = try Packet.insertIntoTransport(type1Raw: type1, nextHop: hubId)

        await mock.feedPacket(wrapped)
        try await Task.sleep(for: .milliseconds(200))

        let entry = await transport.routingTable.lookup(destination.hash)
        #expect(entry?.nextHop == hubId)
        #expect(entry?.interfaceId == "iface-hub")
    }

    @Test("sendPacket wraps HEADER_2 when path hops > 1")
    func sendPacketWrapsWhenHopsGreaterThanOne() async throws {
        let transport = Transport()
        let mock = MockTransportInterface(id: "tcp-hub")
        await transport.addInterface(mock)

        let peer = try TruncatedHash(Data(repeating: 0xAA, count: 16))
        let hub = try TruncatedHash(Data(repeating: 0xBB, count: 16))
        await transport.routingTable.addEntry(RouteEntry(
            destinationHash: peer,
            publicKey: Data(repeating: 0xAA, count: 64),
            nameHash: Data(repeating: 0xAA, count: 10),
            appData: nil,
            hops: 3,
            timestamp: Date(),
            interfaceId: mock.interfaceId,
            nextHop: hub
        ))

        let packet = Packet(
            header: PacketHeader(
                headerType: .type1,
                propagationType: .broadcast,
                destinationType: .single,
                packetType: .data
            ),
            destinationHash: peer,
            data: Data([0x01, 0x02])
        )
        try await transport.sendPacket(packet)

        let sent = await mock.sentPackets[0]
        let unpacked = try Packet.unpack(sent)
        #expect(unpacked.header.headerType == .type2)
        #expect(unpacked.header.propagationType == .transport)
        #expect(unpacked.transportId == hub)
        #expect(unpacked.destinationHash == peer)
        #expect(unpacked.data == Data([0x01, 0x02]))
    }

    @Test("sendPacket stays HEADER_1 when hops > 1 but nextHop is the dest")
    func sendPacketNoWrapWhenNextHopIsDestination() async throws {
        let transport = Transport()
        let mock = MockTransportInterface(id: "tcp-hub")
        await transport.addInterface(mock)

        let peer = try TruncatedHash(Data(repeating: 0xAA, count: 16))
        await transport.routingTable.addEntry(RouteEntry(
            destinationHash: peer,
            publicKey: Data(repeating: 0xAA, count: 64),
            nameHash: Data(repeating: 0xAA, count: 10),
            appData: nil,
            hops: 3,
            timestamp: Date(),
            interfaceId: mock.interfaceId,
            nextHop: peer
        ))

        let packet = Packet(
            header: PacketHeader(
                headerType: .type1,
                propagationType: .broadcast,
                destinationType: .single,
                packetType: .data
            ),
            destinationHash: peer,
            data: Data([0x01, 0x02])
        )
        try await transport.sendPacket(packet)

        let unpacked = try Packet.unpack(await mock.sentPackets[0])
        #expect(unpacked.header.headerType == .type1)
        #expect(unpacked.transportId == nil)
        #expect(unpacked.destinationHash == peer)
    }

    @Test("sendPacket stays HEADER_1 when path hops is 1")
    func sendPacketNoWrapWhenAdjacent() async throws {
        let transport = Transport()
        let mock = MockTransportInterface(id: "tcp-hub")
        await transport.addInterface(mock)

        let peer = try TruncatedHash(Data(repeating: 0xCC, count: 16))
        await transport.routingTable.addEntry(RouteEntry(
            destinationHash: peer,
            publicKey: Data(repeating: 0xCC, count: 64),
            nameHash: Data(repeating: 0xCC, count: 10),
            appData: nil,
            hops: 1,
            timestamp: Date(),
            interfaceId: mock.interfaceId
        ))

        let packet = Packet(
            header: PacketHeader(
                headerType: .type1,
                propagationType: .broadcast,
                destinationType: .single,
                packetType: .data
            ),
            destinationHash: peer,
            data: Data([0x09])
        )
        try await transport.sendPacket(packet)

        let unpacked = try Packet.unpack(await mock.sentPackets[0])
        #expect(unpacked.header.headerType == .type1)
        #expect(unpacked.transportId == nil)
        #expect(unpacked.destinationHash == peer)
    }

    @Test("establishLink uses sendPacket wrap when nextHop is a transport id")
    func establishLinkWrapsWhenNextHopIsHub() async throws {
        let transport = Transport()
        let mock = MockTransportInterface(id: "tcp-hub")
        await transport.addInterface(mock)

        let peer = try TruncatedHash(Data(repeating: 0xAA, count: 16))
        let hub = try TruncatedHash(Data(repeating: 0xBB, count: 16))
        await transport.routingTable.addEntry(RouteEntry(
            destinationHash: peer,
            publicKey: Data(repeating: 0xAA, count: 64),
            nameHash: Data(repeating: 0xAA, count: 10),
            appData: nil,
            hops: 3,
            timestamp: Date(),
            interfaceId: mock.interfaceId,
            nextHop: hub
        ))

        _ = try await transport.establishLink(to: peer, identity: Identity())
        let unpacked = try Packet.unpack(await mock.sentPackets[0])
        #expect(unpacked.header.packetType == .linkRequest)
        #expect(unpacked.header.headerType == .type2)
        #expect(unpacked.transportId == hub)
        #expect(unpacked.destinationHash == peer)
    }
}
