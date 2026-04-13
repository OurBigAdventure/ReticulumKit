// SPDX-License-Identifier: MIT
// AnnounceTests.swift — Tests for Announce creation and validation

import Testing
import Foundation
@testable import ReticulumKit

@Suite("Announce creation and validation")
struct AnnounceTests {

    // MARK: - Creation

    @Test("create produces packet with .announce type, .broadcast propagation, .single destination")
    func createProducesCorrectPacketType() throws {
        let identity = Identity()
        let destination = Destination(identity: identity, direction: .out, appName: "test", aspects: ["app"])
        let packet = try Announce.create(destination: destination)

        #expect(packet.header.packetType == .announce)
        #expect(packet.header.propagationType == .broadcast)
        #expect(packet.header.destinationType == .single)
        #expect(packet.header.headerType == .type1)
    }

    @Test("create payload is >= 148 bytes")
    func createPayloadMinimumSize() throws {
        let identity = Identity()
        let destination = Destination(identity: identity, direction: .out, appName: "test", aspects: ["app"])
        let packet = try Announce.create(destination: destination)

        #expect(packet.data.count >= 148)
    }

    @Test("create -> validate round-trip succeeds")
    func createValidateRoundTrip() throws {
        let identity = Identity()
        let destination = Destination(identity: identity, direction: .out, appName: "test", aspects: ["app"])
        let packet = try Announce.create(destination: destination)
        let result = try Announce.validate(packet: packet)

        #expect(result.destinationHash == destination.hash)
        #expect(result.publicKey == identity.publicKeyBytes)
        #expect(result.nameHash == destination.nameHash)
    }

    @Test("create -> validate round-trip with appData")
    func createValidateRoundTripWithAppData() throws {
        let identity = Identity()
        let destination = Destination(identity: identity, direction: .out, appName: "test", aspects: ["app"])
        let appData = Data("hello world".utf8)
        let packet = try Announce.create(destination: destination, appData: appData)
        let result = try Announce.validate(packet: packet)

        #expect(result.appData == appData)
        #expect(result.publicKey == identity.publicKeyBytes)
    }

    // MARK: - Validation

    @Test("validate rejects data < 148 bytes")
    func validateRejectsTooShort() throws {
        let identity = Identity()
        let destination = Destination(identity: identity, direction: .out, appName: "test", aspects: ["app"])
        let header = PacketHeader(
            headerType: .type1,
            propagationType: .broadcast,
            destinationType: .single,
            packetType: .announce
        )
        let shortData = Data(repeating: 0, count: 100)
        let packet = Packet(header: header, destinationHash: destination.hash, context: .none, data: shortData)

        #expect(throws: AnnounceError.tooShort) {
            try Announce.validate(packet: packet)
        }
    }

    @Test("validate rejects forged destination hash")
    func validateRejectsForgedDestHash() throws {
        let identity = Identity()
        let destination = Destination(identity: identity, direction: .out, appName: "test", aspects: ["app"])
        let packet = try Announce.create(destination: destination)

        // Create a packet with a different destination hash
        let forgedHash = try TruncatedHash(Data(repeating: 0xAA, count: 16))
        let forgedPacket = Packet(
            header: packet.header,
            destinationHash: forgedHash,
            context: packet.context,
            data: packet.data
        )

        #expect(throws: AnnounceError.destinationHashMismatch) {
            try Announce.validate(packet: forgedPacket)
        }
    }

    @Test("validate rejects invalid signature")
    func validateRejectsInvalidSignature() throws {
        let identity = Identity()
        let destination = Destination(identity: identity, direction: .out, appName: "test", aspects: ["app"])
        let packet = try Announce.create(destination: destination)

        // Corrupt signature bytes (bytes 84..<148 in payload)
        var corruptedData = packet.data
        corruptedData[84] ^= 0xFF
        corruptedData[85] ^= 0xFF

        let corruptedPacket = Packet(
            header: packet.header,
            destinationHash: packet.destinationHash,
            context: packet.context,
            data: corruptedData
        )

        #expect(throws: AnnounceError.signatureInvalid) {
            try Announce.validate(packet: corruptedPacket)
        }
    }

    @Test("validate extracts correct publicKey, nameHash, randomHash")
    func validateExtractsFields() throws {
        let identity = Identity()
        let destination = Destination(identity: identity, direction: .out, appName: "test", aspects: ["app"])
        let packet = try Announce.create(destination: destination)
        let result = try Announce.validate(packet: packet)

        #expect(result.publicKey.count == 64)
        #expect(result.nameHash.count == 10)
        #expect(result.randomHash.count == 10)
        #expect(result.signature.count == 64)
        #expect(result.publicKey == identity.publicKeyBytes)
        #expect(result.nameHash == destination.nameHash)
    }

    @Test("signed data does NOT contain signature (verify by checking signed data length)")
    func signedDataDoesNotContainSignature() throws {
        let identity = Identity()
        let destination = Destination(identity: identity, direction: .out, appName: "test", aspects: ["app"])
        let packet = try Announce.create(destination: destination)

        // The signed data is: destHash(16) + publicKey(64) + nameHash(10) + randomHash(10) = 100 bytes
        // Without appData, payload = publicKey(64) + nameHash(10) + randomHash(10) + signature(64) = 148 bytes
        // So payload is 148, but signed data is only 100 bytes (no signature in signed data)
        #expect(packet.data.count == 148)

        // Verify the round-trip works (if signature was in signed data, it would fail)
        let result = try Announce.validate(packet: packet)
        #expect(result.destinationHash == destination.hash)
    }
}
