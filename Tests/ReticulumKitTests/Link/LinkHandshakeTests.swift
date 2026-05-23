// SPDX-License-Identifier: MIT
// LinkHandshakeTests.swift -- Tests for 3-packet ECDH link handshake

import Testing
import Foundation
@testable import ReticulumKit

@Suite("Link Handshake Tests")
struct LinkHandshakeTests {

    // MARK: - Full 3-packet handshake

    @Test("Full 3-packet handshake completes between initiator and responder")
    func fullHandshake() async throws {
        let initiatorIdentity = Identity()
        let responderIdentity = Identity()

        // Step 1: Initiator creates link and request packet
        let link = Link.initiator(to: responderIdentity.hash, identity: initiatorIdentity)
        let status1 = await link.status
        #expect(status1 == .pending)

        let (_, rawRequest) = try await link.createRequest()

        // Step 2: Responder receives request and creates proof
        let requestPacket = try Packet.unpack(rawRequest)
        let (responderLink, proofPacket) = try Link.respondToRequest(
            rawPacket: rawRequest,
            packet: requestPacket,
            responderIdentity: responderIdentity
        )

        // Responder holds the Token immediately after responding, so it goes
        // straight to .active; the initiator's RTT packet is optional for the
        // responder side (see Link.respondToRequest).
        let rStatus = await responderLink.status
        #expect(rStatus == .active)

        // Step 3: Initiator processes proof
        let rawProof = try proofPacket.pack()
        try await link.processProof(
            rawProofPacket: rawProof,
            proofPacket: proofPacket,
            peerIdentity: responderIdentity
        )

        let status2 = await link.status
        #expect(status2 == .handshake)

        // Step 4: Initiator creates RTT packet
        let rttPacket = try await link.createRTTPacket()

        // Step 5: Responder processes RTT
        try await responderLink.processRTT(packet: rttPacket)

        let rStatusFinal = await responderLink.status
        #expect(rStatusFinal == .active)
    }

    // MARK: - Bidirectional encryption

    @Test("Initiator encrypt -> responder decrypt works after handshake")
    func initiatorToResponderEncryption() async throws {
        let (initiatorLink, responderLink) = try await performFullHandshake()

        let plaintext = Data("Hello from initiator".utf8)
        let ciphertext = try await initiatorLink.encrypt(plaintext)
        let decrypted = try await responderLink.decrypt(ciphertext)

        #expect(decrypted == plaintext)
    }

    @Test("Responder encrypt -> initiator decrypt works after handshake")
    func responderToInitiatorEncryption() async throws {
        let (initiatorLink, responderLink) = try await performFullHandshake()

        let plaintext = Data("Hello from responder".utf8)
        let ciphertext = try await responderLink.encrypt(plaintext)
        let decrypted = try await initiatorLink.decrypt(ciphertext)

        #expect(decrypted == plaintext)
    }

    // MARK: - Forward secrecy

    @Test("Ephemeral private keys are nil after handshake on both sides")
    func forwardSecrecy() async throws {
        let (initiatorLink, responderLink) = try await performFullHandshake()

        let initiatorHasKey = await initiatorLink.hasEphemeralKey
        let responderHasKey = await responderLink.hasEphemeralKey

        #expect(initiatorHasKey == false)
        #expect(responderHasKey == false)
    }

    // MARK: - Unique ephemeral keypairs

    @Test("Two separate links produce different ephemeral public keys")
    func uniqueEphemeralKeys() async throws {
        let identity = Identity()
        let targetHash = Identity().hash

        let link1 = Link.initiator(to: targetHash, identity: identity)
        let link2 = Link.initiator(to: targetHash, identity: identity)

        let pub1 = await link1.ephemeralPublicKey
        let pub2 = await link2.ephemeralPublicKey

        #expect(pub1.rawRepresentation != pub2.rawRepresentation)
    }

    // MARK: - Link ID matching

    @Test("Link IDs match between initiator and responder for same request")
    func linkIdMatching() async throws {
        let initiatorIdentity = Identity()
        let responderIdentity = Identity()

        let link = Link.initiator(to: responderIdentity.hash, identity: initiatorIdentity)
        let (_, rawRequest) = try await link.createRequest()

        let requestPacket = try Packet.unpack(rawRequest)
        let (responderLink, _) = try Link.respondToRequest(
            rawPacket: rawRequest,
            packet: requestPacket,
            responderIdentity: responderIdentity
        )

        let initiatorLinkId = await link.linkId
        let responderLinkId = await responderLink.linkId

        #expect(initiatorLinkId == responderLinkId)
    }

    // MARK: - Helpers

    /// Perform a complete 3-packet handshake, returning both Link instances in active/handshake state.
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
