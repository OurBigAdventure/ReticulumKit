// SPDX-License-Identifier: MIT
// TransportLinkTests.swift -- Tests for Transport link lifecycle management

import Testing
import Foundation
@testable import ReticulumKit

@Suite("Transport Link Tests")
struct TransportLinkTests {

    // MARK: - Establish Link

    @Test("Transport.establishLink sends a linkRequest packet through mock interface")
    func establishLinkSendsRequest() async throws {
        let transport = Transport()
        let mock = MockTransportInterface(id: "link-iface-a")
        await transport.addInterface(mock)

        let initiatorIdentity = Identity()
        let targetHash = Identity().hash

        let link = try await transport.establishLink(to: targetHash, identity: initiatorIdentity)
        let linkStatus = await link.status
        #expect(linkStatus == .pending)

        // Check that a packet was sent
        let sentCount = await mock.sentCount()
        #expect(sentCount == 1)

        // Verify the sent packet is a linkRequest
        let sentData = await mock.sentPackets[0]
        let packet = try Packet.unpack(sentData)
        #expect(packet.header.packetType == .linkRequest)
    }

    // MARK: - End-to-end link establishment between two Transport instances

    @Test("Two Transport instances establish a link through mock interfaces")
    func endToEndLinkEstablishment() async throws {
        // Setup: Transport A (initiator) and Transport B (responder)
        let transportA = Transport()
        let transportB = Transport()
        let mockA = MockTransportInterface(id: "e2e-iface-a")
        let mockB = MockTransportInterface(id: "e2e-iface-b")
        await transportA.addInterface(mockA)
        await transportB.addInterface(mockB)

        // Create identities
        let initiatorIdentity = Identity()
        let responderIdentity = Identity()

        // Register responder destination on Transport B
        let responderDest = Destination(
            identity: responderIdentity,
            direction: .in,
            appName: "test.app",
            aspects: ["messaging"]
        )
        await transportB.registerDestination(responderDest, identity: responderIdentity)

        // Step 1: Initiator establishes link
        let link = try await transportA.establishLink(
            to: responderDest.hash,
            identity: initiatorIdentity
        )

        // Step 2: Shuttle link request from A to B
        let requestData = await mockA.sentPackets[0]
        await mockB.feedPacket(requestData)
        try await Task.sleep(for: .milliseconds(200))

        // Step 3: B should have sent proof packet -- shuttle it to A
        let proofData = await mockB.sentPackets[0]
        // We need to add the responder identity to A's knowledge for proof verification
        // Add a routing entry so A can look up responder's public key
        let routeEntry = RouteEntry(
            destinationHash: responderDest.hash,
            publicKey: responderIdentity.publicKeyBytes,
            nameHash: responderDest.nameHash,
            appData: nil,
            hops: 0,
            timestamp: Date(),
            interfaceId: "e2e-iface-a"
        )
        await transportA.routingTable.addEntry(routeEntry)

        await mockA.feedPacket(proofData)
        try await Task.sleep(for: .milliseconds(200))

        // Step 4: A should have sent RTT packet -- shuttle it to B
        let sentByA = await mockA.sentPackets
        #expect(sentByA.count >= 2, "Transport A should have sent request + RTT")
        let rttData = sentByA[1]
        await mockB.feedPacket(rttData)
        try await Task.sleep(for: .milliseconds(200))

        // Both links should be active
        let linkStatus = await link.status
        #expect(linkStatus == .active)

        // Check responder link is active too
        let linkId = await link.linkId
        let responderLink = await transportB.link(for: linkId)
        #expect(responderLink != nil)
        if let rLink = responderLink {
            let rStatus = await rLink.status
            #expect(rStatus == .active)
        }
    }

    // MARK: - Teardown handling

    @Test("Transport.closeLink sends teardown and removes from activeLinks")
    func closeLinkSendsTeardownAndRemoves() async throws {
        // Setup: complete a link establishment first
        let (transportA, transportB, mockA, mockB, link) = try await setupEstablishedLink()

        let linkId = await link.linkId

        // Close the link from transport A
        try await transportA.closeLink(linkId, reason: .initiatorClosed)

        // Verify link was removed from A
        let linkA = await transportA.link(for: linkId)
        #expect(linkA == nil)

        // Verify teardown packet was sent
        let sentByA = await mockA.sentPackets
        let lastSent = sentByA.last!
        let packet = try Packet.unpack(lastSent)
        #expect(packet.context == .linkClose)

        // Shuttle teardown to B
        await mockB.feedPacket(lastSent)
        try await Task.sleep(for: .milliseconds(200))

        // B should have removed the link
        let linkB = await transportB.link(for: linkId)
        #expect(linkB == nil)
    }

    // MARK: - Keepalive forwarding

    @Test("Transport forwards keepalive packets to the correct Link")
    func keepaliveForwarding() async throws {
        let (transportA, transportB, mockA, mockB, link) = try await setupEstablishedLink()

        let linkId = await link.linkId

        // Create keepalive request from initiator link
        let keepaliveRequest = try await link.createKeepaliveRequest()
        let keepaliveData = try keepaliveRequest.pack()

        // Send keepalive to B
        await mockB.feedPacket(keepaliveData)
        try await Task.sleep(for: .milliseconds(200))

        // B should have sent a keepalive reply
        let sentByB = await mockB.sentPackets
        let lastSentByB = sentByB.last!
        let replyPacket = try Packet.unpack(lastSentByB)
        #expect(replyPacket.context == .keepalive)
    }

    // MARK: - Unregistered destination

    @Test("Link request for unregistered destination is silently dropped")
    func unregisteredDestinationDropped() async throws {
        let transport = Transport()
        let mock = MockTransportInterface(id: "unreg-iface")
        await transport.addInterface(mock)

        // Create a link request for a destination that is NOT registered
        let identity = Identity()
        let targetHash = Identity().hash
        let link = Link.initiator(to: targetHash, identity: identity)
        let (requestPacket, _) = try await link.createRequest()
        let requestData = try requestPacket.pack()

        // Feed it to transport -- should not crash
        await mock.feedPacket(requestData)
        try await Task.sleep(for: .milliseconds(200))

        // No packets should have been sent (no proof)
        let sentCount = await mock.sentCount()
        #expect(sentCount == 0)
    }

    // MARK: - Helpers

    /// Set up two transports with an established link between them.
    private func setupEstablishedLink() async throws -> (
        transportA: Transport,
        transportB: Transport,
        mockA: MockTransportInterface,
        mockB: MockTransportInterface,
        link: Link
    ) {
        let transportA = Transport()
        let transportB = Transport()
        let mockA = MockTransportInterface(id: "setup-iface-a")
        let mockB = MockTransportInterface(id: "setup-iface-b")
        await transportA.addInterface(mockA)
        await transportB.addInterface(mockB)

        let initiatorIdentity = Identity()
        let responderIdentity = Identity()

        let responderDest = Destination(
            identity: responderIdentity,
            direction: .in,
            appName: "test.app",
            aspects: ["messaging"]
        )
        await transportB.registerDestination(responderDest, identity: responderIdentity)

        // Add responder route to A's routing table
        let routeEntry = RouteEntry(
            destinationHash: responderDest.hash,
            publicKey: responderIdentity.publicKeyBytes,
            nameHash: responderDest.nameHash,
            appData: nil,
            hops: 0,
            timestamp: Date(),
            interfaceId: "setup-iface-a"
        )
        await transportA.routingTable.addEntry(routeEntry)

        // Establish link
        let link = try await transportA.establishLink(
            to: responderDest.hash,
            identity: initiatorIdentity
        )

        // Shuttle request A -> B
        let requestData = await mockA.sentPackets[0]
        await mockB.feedPacket(requestData)
        try await Task.sleep(for: .milliseconds(200))

        // Shuttle proof B -> A
        let proofData = await mockB.sentPackets[0]
        await mockA.feedPacket(proofData)
        try await Task.sleep(for: .milliseconds(200))

        // Shuttle RTT A -> B
        let sentByA = await mockA.sentPackets
        let rttData = sentByA[1]
        await mockB.feedPacket(rttData)
        try await Task.sleep(for: .milliseconds(200))

        return (transportA, transportB, mockA, mockB, link)
    }

    @Test("Resource transfers a payload larger than one link packet")
    func resourceTransferRoundTrip() async throws {
        let (transportA, transportB, mockA, mockB, linkA) = try await setupEstablishedLink()
        let linkId = await linkA.linkId
        let linkB = await transportB.link(for: linkId)
        #expect(linkB != nil)
        #expect(await linkA.status == .active)
        #expect(await linkB?.status == .active)

        final class Box: @unchecked Sendable {
            var received: Data?
        }
        let box = Box()
        await transportB.onIncomingResource { data, _ in
            box.received = data
        }

        let payload = Data(repeating: 0x5A, count: 2_400)
        var lastA = await mockA.sentPackets.count
        var lastB = await mockB.sentPackets.count
        var spins = 0
        final class Flag: @unchecked Sendable {
            var done = false
        }
        let flag = Flag()
        let sendTask = Task {
            defer { flag.done = true }
            try await transportA.sendResource(on: linkA, plaintext: payload, timeout: 15)
        }
        // Keep shuttling after the receiver assembles so RESOURCE_PRF reaches the sender.
        while !flag.done && spins < 200 {
            let sentA = await mockA.sentPackets
            if sentA.count > lastA {
                for packet in sentA[lastA..<sentA.count] {
                    await mockB.feedPacket(packet)
                }
                lastA = sentA.count
            }
            let sentB = await mockB.sentPackets
            if sentB.count > lastB {
                for packet in sentB[lastB..<sentB.count] {
                    await mockA.feedPacket(packet)
                }
                lastB = sentB.count
            }
            try await Task.sleep(for: .milliseconds(25))
            spins += 1
        }
        try await sendTask.value
        #expect(box.received == payload)
    }

    @Test("Resource autoCompress round-trips and hashes uncompressed plaintext")
    func resourceAutoCompressRoundTrip() async throws {
        let (transportA, transportB, mockA, mockB, linkA) = try await setupEstablishedLink()
        let linkId = await linkA.linkId
        let linkB = await transportB.link(for: linkId)
        #expect(linkB != nil)

        final class Box: @unchecked Sendable {
            var received: Data?
        }
        let box = Box()
        await transportB.onIncomingResource { data, _ in
            box.received = data
        }

        // Highly compressible so bz2 must shrink and set the ADV compressed bit.
        let payload = Data(repeating: 0x41, count: 4_096)
        #expect(BZip2.compress(payload) != nil)

        var lastA = await mockA.sentPackets.count
        var lastB = await mockB.sentPackets.count
        var spins = 0
        final class Flag: @unchecked Sendable {
            var done = false
        }
        let flag = Flag()
        let sendTask = Task {
            defer { flag.done = true }
            try await transportA.sendResource(
                on: linkA,
                plaintext: payload,
                timeout: 15,
                autoCompress: true
            )
        }
        while !flag.done && spins < 200 {
            let sentA = await mockA.sentPackets
            if sentA.count > lastA {
                for packet in sentA[lastA..<sentA.count] {
                    await mockB.feedPacket(packet)
                }
                lastA = sentA.count
            }
            let sentB = await mockB.sentPackets
            if sentB.count > lastB {
                for packet in sentB[lastB..<sentB.count] {
                    await mockA.feedPacket(packet)
                }
                lastB = sentB.count
            }
            try await Task.sleep(for: .milliseconds(25))
            spins += 1
        }
        try await sendTask.value
        #expect(box.received == payload)
    }
}
