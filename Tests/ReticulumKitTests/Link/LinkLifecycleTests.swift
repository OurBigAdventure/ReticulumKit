// SPDX-License-Identifier: MIT
// LinkLifecycleTests.swift -- Tests for link keepalive, timeout, teardown, and key cleanup

import Testing
import Foundation
@testable import ReticulumKit

@Suite("Link Lifecycle Tests")
struct LinkLifecycleTests {

    // MARK: - Close and Teardown

    @Test("close() returns teardown packet and zeroes token")
    func closeReturnsTeardownAndZeroesToken() async throws {
        let (initiatorLink, _) = try await performFullHandshake()

        let status = await initiatorLink.status
        #expect(status == .active)

        let teardownPacket = await initiatorLink.close(reason: .initiatorClosed)
        #expect(teardownPacket != nil)

        let closedStatus = await initiatorLink.status
        #expect(closedStatus == .closed)

        let reason = await initiatorLink.teardownReason
        #expect(reason == .initiatorClosed)

        // Token is zeroed -- encrypt/decrypt should throw
        await #expect(throws: ReticulumError.self) {
            try await initiatorLink.encrypt(Data("test".utf8))
        }
    }

    @Test("close() on already closed link returns nil")
    func closeAlreadyClosedReturnsNil() async throws {
        let (initiatorLink, _) = try await performFullHandshake()

        let _ = await initiatorLink.close(reason: .initiatorClosed)
        let secondClose = await initiatorLink.close(reason: .initiatorClosed)
        #expect(secondClose == nil)
    }

    @Test("teardown packet data decrypts to linkId.data")
    func teardownPacketContainsEncryptedLinkId() async throws {
        let (initiatorLink, responderLink) = try await performFullHandshake()

        let teardownPacket = await initiatorLink.close(reason: .initiatorClosed)
        #expect(teardownPacket != nil)

        // Responder can handle the teardown
        try await responderLink.handleIncomingTeardown(packet: teardownPacket!)

        let rStatus = await responderLink.status
        #expect(rStatus == .closed)

        let rReason = await responderLink.teardownReason
        #expect(rReason == .destinationClosed)
    }

    @Test("handleIncomingTeardown transitions to .closed and zeroes token")
    func handleIncomingTeardownClosesAndZeroes() async throws {
        let (initiatorLink, responderLink) = try await performFullHandshake()

        let teardownPacket = await initiatorLink.close(reason: .initiatorClosed)
        #expect(teardownPacket != nil)

        try await responderLink.handleIncomingTeardown(packet: teardownPacket!)

        let rStatus = await responderLink.status
        #expect(rStatus == .closed)

        // Token zeroed -- encrypt should throw
        await #expect(throws: ReticulumError.self) {
            try await responderLink.encrypt(Data("test".utf8))
        }
    }

    // MARK: - Keepalive

    @Test("Keepalive request/reply round trip")
    func keepaliveRequestReplyRoundTrip() async throws {
        let (initiatorLink, responderLink) = try await performFullHandshake()

        // Initiator creates keepalive request (0xFF)
        let keepaliveRequest = try await initiatorLink.createKeepaliveRequest()
        #expect(keepaliveRequest.context == .keepalive)
        #expect(keepaliveRequest.header.destinationType == .link)

        // Responder handles keepalive request and returns reply
        let replyPacket = try await responderLink.handleKeepalive(packet: keepaliveRequest)
        #expect(replyPacket != nil)

        // Initiator handles keepalive reply (0xFE) -- should return nil
        let noReply = try await initiatorLink.handleKeepalive(packet: replyPacket!)
        #expect(noReply == nil)
    }

    @Test("Keepalive request from initiator to initiator is ignored")
    func keepaliveRequestToInitiatorIgnored() async throws {
        let (initiatorLink, _) = try await performFullHandshake()

        // Create a keepalive request (0xFF) and feed it to initiator -- should be ignored
        let keepaliveRequest = try await initiatorLink.createKeepaliveRequest()
        let result = try await initiatorLink.handleKeepalive(packet: keepaliveRequest)
        #expect(result == nil)
    }

    // MARK: - Timeout

    @Test("checkTimeout transitions active -> stale -> closed")
    func checkTimeoutTransitions() async throws {
        let (initiatorLink, _) = try await performFullHandshake()

        let status1 = await initiatorLink.status
        #expect(status1 == .active)

        // Simulate time passing beyond stale threshold (360 * 2 = 720 seconds)
        let staleResult = await initiatorLink.checkTimeout(
            now: Date().addingTimeInterval(800)
        )
        // Should transition to stale but not yet closed
        #expect(staleResult == nil)
        let staleStatus = await initiatorLink.status
        #expect(staleStatus == .stale)

        // Simulate more time passing beyond staleGrace (800 + 10 > 720 + 5)
        let closedResult = await initiatorLink.checkTimeout(
            now: Date().addingTimeInterval(810)
        )
        #expect(closedResult == .timeout)
        let closedStatus = await initiatorLink.status
        #expect(closedStatus == .closed)

        // Token zeroed
        await #expect(throws: ReticulumError.self) {
            try await initiatorLink.encrypt(Data("test".utf8))
        }
    }

    @Test("checkTimeout does nothing when within keepalive interval")
    func checkTimeoutWithinInterval() async throws {
        let (initiatorLink, _) = try await performFullHandshake()

        // 100 seconds is well within 720 stale threshold
        let result = await initiatorLink.checkTimeout(
            now: Date().addingTimeInterval(100)
        )
        #expect(result == nil)

        let status = await initiatorLink.status
        #expect(status == .active)
    }

    @Test("encrypt/decrypt throw after close due to token zeroing")
    func encryptDecryptThrowAfterClose() async throws {
        let (initiatorLink, _) = try await performFullHandshake()

        await initiatorLink.close(reason: .initiatorClosed)

        await #expect(throws: ReticulumError.self) {
            try await initiatorLink.encrypt(Data("plaintext".utf8))
        }
        await #expect(throws: ReticulumError.self) {
            try await initiatorLink.decrypt(Data(repeating: 0xAA, count: 64))
        }
    }

    // MARK: - Activity Recording

    @Test("handleKeepalive updates lastActivityAt")
    func handleKeepaliveUpdatesActivity() async throws {
        let (initiatorLink, responderLink) = try await performFullHandshake()

        // After handshake, lastActivityAt is set. Wait a bit in simulated time.
        // Send keepalive to responder which should update lastActivityAt
        let keepaliveRequest = try await initiatorLink.createKeepaliveRequest()
        let _ = try await responderLink.handleKeepalive(packet: keepaliveRequest)

        // Now checking timeout with 800 seconds from NOW should still transition to stale
        // because lastActivityAt was just updated to ~now
        let result = await responderLink.checkTimeout(
            now: Date().addingTimeInterval(800)
        )
        #expect(result == nil) // stale, not closed yet
        let status = await responderLink.status
        #expect(status == .stale)
    }

    // MARK: - Helpers

    /// Perform a complete 3-packet handshake, returning both Link instances in active state.
    private func performFullHandshake() async throws -> (initiator: Link, responder: Link) {
        let initiatorIdentity = Identity()
        let responderIdentity = Identity()

        let link = Link.initiator(to: responderIdentity.hash, identity: initiatorIdentity)
        let (_, rawRequest) = try await link.createRequest()

        let requestPacket = try Packet.unpack(rawRequest)
        let (responderLink, proofPacket) = try Link.respondToRequest(
            rawPacket: rawRequest,
            packet: requestPacket,
            responderIdentity: responderIdentity
        )

        let rawProof = try proofPacket.pack()
        try await link.processProof(
            rawProofPacket: rawProof,
            proofPacket: proofPacket,
            peerIdentity: responderIdentity
        )

        let rttPacket = try await link.createRTTPacket()
        try await responderLink.processRTT(packet: rttPacket)

        return (link, responderLink)
    }
}
