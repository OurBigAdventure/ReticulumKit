// SPDX-License-Identifier: MIT
// ResourceHMUTests.swift — RESOURCE_HMU follow-on hashmap segment coverage
//
// Large transfers advertise only HASHMAP_MAX_LEN hashes in the first ADV;
// further slices arrive via RESOURCE_HMU when the peer signals hashmap exhausted
// (Python `ResourceAdvertisement.HASHMAP_MAX_LEN` / HMU).

import Testing
import Foundation
@testable import ReticulumKit

@Suite("Resource HMU")
struct ResourceHMUTests {

    private func setupEstablishedLink() async throws -> (
        Transport, Transport, MockTransportInterface, MockTransportInterface, Link
    ) {
        let transportA = Transport()
        let transportB = Transport()
        let mockA = MockTransportInterface(id: "hmu-a")
        let mockB = MockTransportInterface(id: "hmu-b")
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

        let routeEntry = RouteEntry(
            destinationHash: responderDest.hash,
            publicKey: responderIdentity.publicKeyBytes,
            nameHash: responderDest.nameHash,
            appData: nil,
            hops: 0,
            timestamp: Date(),
            interfaceId: "hmu-a"
        )
        await transportA.routingTable.addEntry(routeEntry)

        let link = try await transportA.establishLink(to: responderDest.hash, identity: initiatorIdentity)
        await mockB.feedPacket(await mockA.sentPackets[0])
        try await Task.sleep(for: .milliseconds(200))
        await mockA.feedPacket(await mockB.sentPackets[0])
        try await Task.sleep(for: .milliseconds(200))
        let sentByA = await mockA.sentPackets
        await mockB.feedPacket(sentByA[1])
        try await Task.sleep(for: .milliseconds(200))
        return (transportA, transportB, mockA, mockB, link)
    }

    @Test("large payload advertises capped hashmap requiring HMU segments")
    func largeHashmapAdvertisement() async throws {
        let (_, _, _, _, link) = try await setupEstablishedLink()
        // Enough parts to exceed HASHMAP_MAX_LEN (~74) so follow-on HMU is required.
        let plaintext = Data(repeating: 0xCD, count: 36_000)
        final class AdvBox: @unchecked Sendable {
            var adv: ResourceAdvertisement?
        }
        let box = AdvBox()
        let resource = try await Resource.outgoing(
            plaintext: plaintext,
            link: link,
            sendPacket: { packet in
                if packet.context == .resourceAdv,
                   let decrypted = try? await link.decrypt(packet.data),
                   let adv = try? ResourceAdvertisement.unpack(decrypted) {
                    box.adv = adv
                }
            }
        )

        #expect(await resource.hashmapSegmentCount > 1)
        #expect(await resource.advertisedHashmapEntryCount == ResourceConstants.hashmapMaxLength)

        try await resource.advertise()
        #expect(box.adv != nil)
        #expect(box.adv?.totalSegments == 1)
        #expect(box.adv?.segmentIndex == 1)
        #expect(box.adv?.isSplit == false)
        #expect(box.adv!.hashmap.count == ResourceConstants.hashmapMaxLength * ResourceConstants.mapHashLength)
    }

    @Test("transfer larger than one ADV hashmap slice completes via HMU")
    func largeResourceTransferUsesHMU() async throws {
        let (transportA, transportB, mockA, mockB, linkA) = try await setupEstablishedLink()
        let linkId = await linkA.linkId
        let linkB = await transportB.link(for: linkId)
        #expect(linkB != nil)

        final class Box: @unchecked Sendable {
            var received: Data?
            var sawHMU = false
        }
        let box = Box()
        await transportB.onIncomingResource { data, _ in
            box.received = data
        }

        let payload = Data(repeating: 0x5A, count: 36_000)
        var lastA = await mockA.sentPackets.count
        var lastB = await mockB.sentPackets.count
        var spins = 0
        final class Flag: @unchecked Sendable {
            var done = false
        }
        let flag = Flag()
        let sendTask = Task {
            defer { flag.done = true }
            try await transportA.sendResource(on: linkA, plaintext: payload, timeout: 60)
        }
        while !flag.done && spins < 800 {
            let sentA = await mockA.sentPackets
            if sentA.count > lastA {
                for packetData in sentA[lastA..<sentA.count] {
                    if let packet = try? Packet.unpack(packetData),
                       packet.context == .resourceHMU {
                        box.sawHMU = true
                    }
                    await mockB.feedPacket(packetData)
                }
                lastA = sentA.count
            }
            let sentB = await mockB.sentPackets
            if sentB.count > lastB {
                for packetData in sentB[lastB..<sentB.count] {
                    await mockA.feedPacket(packetData)
                }
                lastB = sentB.count
            }
            try await Task.sleep(for: .milliseconds(25))
            spins += 1
        }
        try await sendTask.value
        #expect(box.sawHMU, "initiator should send RESOURCE_HMU follow-on hashmap segments")
        #expect(box.received == payload)
    }
}
