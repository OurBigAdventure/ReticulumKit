// SPDX-License-Identifier: MIT
// ResourceMultiSegmentTests.swift — Large resource hashmap and size-split coverage

import Testing
import Foundation
@testable import ReticulumKit

@Suite("Resource multi-segment outbound")
struct ResourceMultiSegmentTests {

    private func setupEstablishedLink() async throws -> (
        Transport, Transport, MockTransportInterface, MockTransportInterface, Link
    ) {
        let transportA = Transport()
        let transportB = Transport()
        let mockA = MockTransportInterface(id: "res-a")
        let mockB = MockTransportInterface(id: "res-b")
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
            interfaceId: "res-a"
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

    @Test("large payload advertises capped hashmap and multiple hashmap segments")
    func largeHashmapAdvertisement() async throws {
        let (_, _, _, _, link) = try await setupEstablishedLink()
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

    @Test("payload over maxEfficientSize sets split flag and totalSegments")
    func sizeSplitAdvertisement() async throws {
        let (_, _, _, _, link) = try await setupEstablishedLink()
        let oversized = Data(repeating: 0xAB, count: ResourceConstants.maxEfficientSize + 512)
        final class AdvBox: @unchecked Sendable {
            var adv: ResourceAdvertisement?
        }
        let box = AdvBox()
        let resource = try await Resource.outgoing(
            plaintext: oversized,
            link: link,
            sendPacket: { packet in
                if packet.context == .resourceAdv,
                   let decrypted = try? await link.decrypt(packet.data),
                   let adv = try? ResourceAdvertisement.unpack(decrypted) {
                    box.adv = adv
                }
            }
        )

        try await resource.advertise()
        #expect(box.adv?.totalSegments == 2)
        #expect(box.adv?.isSplit == true)
        #expect((box.adv?.flags ?? 0) & 0x04 != 0)
    }

    @Test("link reassembles size-split resource segments by original hash")
    func linkSplitAssembly() async throws {
        let (_, _, _, _, link) = try await setupEstablishedLink()
        let originalHash = Data(repeating: 0x01, count: 32)
        let segment1 = Data(repeating: 0xAA, count: 128)
        let segment2 = Data(repeating: 0xBB, count: 64)
        await link.storeSplitSegment(
            originalHash: originalHash,
            segmentIndex: 1,
            data: segment1,
            totalSegments: 2
        )
        #expect(await link.isExpectingSplitSegment(originalHash: originalHash, segmentIndex: 2))
        let full = await link.completeSplitAssembly(
            originalHash: originalHash,
            segmentIndex: 2,
            finalSegment: segment2,
            totalSegments: 2
        )
        #expect(full == segment1 + segment2)
    }
}
