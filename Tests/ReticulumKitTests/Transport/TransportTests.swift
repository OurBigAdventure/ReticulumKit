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
    }

    @Test("IFAC wrap on egress; non-IFAC interface drops IFAC-flagged packets")
    func ifacEgressAndNonIfacDrop() async throws {
        let ifac = try InterfaceAccessCode(networkName: "private-mesh", passphrase: "secret")
        let transportIFAC = Transport()
        let mockIFAC = MockTransportInterface(id: "ifac-iface")
        await transportIFAC.addInterface(mockIFAC, accessCode: ifac)

        let identity = Identity()
        let destination = Destination(identity: identity, direction: .out, appName: "ifac.app", aspects: ["msg"])
        await transportIFAC.registerDestination(destination, identity: identity)
        try await transportIFAC.sendAnnounce(for: destination)

        let sent = await mockIFAC.sentPackets
        #expect(sent.count == 1)
        #expect(sent[0][sent[0].startIndex] & 0x80 == 0x80)
        #expect(ifac.unwrap(sent[0]) != nil)

        // Same IFAC-wrapped frame on a non-IFAC interface must be dropped.
        let transportPlain = Transport()
        let mockPlain = MockTransportInterface(id: "plain-iface")
        await transportPlain.addInterface(mockPlain)
        await mockPlain.feedPacket(sent[0])
        try await Task.sleep(for: .milliseconds(200))
        let entry = await transportPlain.routingTable.lookup(destination.hash)
        #expect(entry == nil)
    }
}
