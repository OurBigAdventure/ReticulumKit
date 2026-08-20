// SPDX-License-Identifier: MIT
// LinkIdentifyTests.swift -- Tests for Link.identify / handle_identify backchannel

import Testing
import Foundation
import CryptoKit
@testable import ReticulumKit

@Suite("Link Identify Tests")
struct LinkIdentifyTests {

    @Test("identify requires an active link")
    func identifyRequiresActive() async throws {
        let initiatorIdentity = Identity()
        let link = Link.initiator(to: Identity().hash, identity: initiatorIdentity)

        await #expect(throws: ReticulumError.self) {
            try await link.identify(identity: initiatorIdentity)
        }
    }

    @Test("identify packet uses linkIdentify context and encrypts proof")
    func identifyPacketShape() async throws {
        let (initiatorLink, _, initiatorIdentity, _) = try await performFullHandshake()

        let packet = try await initiatorLink.identify(identity: initiatorIdentity)
        #expect(packet.context == .linkIdentify)
        #expect(packet.header.destinationType == .link)
        #expect(packet.header.packetType == .data)

        let linkId = await initiatorLink.linkId
        #expect(packet.destinationHash == linkId)

        // Ciphertext must be longer than the 96-byte plaintext proof.
        #expect(packet.data.count > 96)
    }

    @Test("responder verifies identify and recovers signing public key")
    func identifyRoundTripVerify() async throws {
        let (initiatorLink, responderLink, initiatorIdentity, _) = try await performFullHandshake()

        let packet = try await initiatorLink.identify(identity: initiatorIdentity)
        let pubKey = try await responderLink.verifiedIdentifyPublicKey(from: packet)

        #expect(pubKey == Data(initiatorIdentity.signingPublicKey.rawRepresentation))
    }

    @Test("handleIncomingIdentify attaches looked-up remote identity")
    func handleIncomingIdentifyAttachesIdentity() async throws {
        let (initiatorLink, responderLink, initiatorIdentity, _) = try await performFullHandshake()

        let packet = try await initiatorLink.identify(identity: initiatorIdentity)
        try await responderLink.handleIncomingIdentify(packet) { signingKey in
            guard signingKey == Data(initiatorIdentity.signingPublicKey.rawRepresentation) else {
                return nil
            }
            return initiatorIdentity
        }

        let remote = await responderLink.remoteIdentity
        #expect(remote?.hash == initiatorIdentity.hash)
        #expect(remote?.publicKeyBytes == initiatorIdentity.publicKeyBytes)
    }

    @Test("initiator does not accept identify packets")
    func initiatorIgnoresIdentify() async throws {
        let (initiatorLink, responderLink, initiatorIdentity, responderIdentity) =
            try await performFullHandshake()

        // Responder "identifies" toward initiator; initiator must ignore (Python: initiator side).
        let packet = try await responderLink.identify(identity: responderIdentity)
        let pubKey = try await initiatorLink.verifiedIdentifyPublicKey(from: packet)
        #expect(pubKey == nil)

        // Silence unused warning when only initiatorIdentity is needed for handshake setup.
        _ = initiatorIdentity
    }

    @Test("tampered identify signature fails verification")
    func tamperedIdentifyFails() async throws {
        let (initiatorLink, responderLink, initiatorIdentity, _) = try await performFullHandshake()

        let goodPacket = try await initiatorLink.identify(identity: initiatorIdentity)
        let plaintext = try await responderLink.decrypt(goodPacket.data)
        #expect(plaintext.count >= 96)

        // Flip a bit in the signature region and re-encrypt with the shared token.
        var tampered = plaintext
        tampered[40] ^= 0x01
        let badCiphertext = try await initiatorLink.encrypt(tampered)

        let badPacket = Packet(
            header: goodPacket.header,
            destinationHash: goodPacket.destinationHash,
            context: .linkIdentify,
            data: badCiphertext
        )

        let pubKey = try await responderLink.verifiedIdentifyPublicKey(from: badPacket)
        #expect(pubKey == nil)
    }

    // MARK: - Helpers

    /// Complete handshake returning both links and the identities used.
    private func performFullHandshake() async throws -> (
        initiator: Link,
        responder: Link,
        initiatorIdentity: Identity,
        responderIdentity: Identity
    ) {
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

        return (link, responderLink, initiatorIdentity, responderIdentity)
    }
}
