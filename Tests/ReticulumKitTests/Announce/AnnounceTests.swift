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
        // No ratchet support yet — context_flag must be 0 so Python RNS peers
        // parse the payload as 148 bytes baseline (no 32-byte ratchet field).
        #expect(packet.header.contextFlag == false)
    }

    @Test("create payload is exactly 148 bytes (no appData, no ratchet)")
    func createPayloadMinimumSize() throws {
        let identity = Identity()
        let destination = Destination(identity: identity, direction: .out, appName: "test", aspects: ["app"])
        let packet = try Announce.create(destination: destination)

        // Python-RNS-compatible layout:
        //   publicKey(64) + nameHash(10) + randomHash(10) + signature(64) = 148 bytes
        #expect(packet.data.count == 148)
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
        #expect(result.ratchet == nil)
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

        // Create a packet with a different destination hash. The signature was
        // computed over the original dest hash, so swapping it must surface as
        // a signature mismatch (the destination-hash reconstruction check is
        // gated behind a successful signature check in validate()).
        let forgedHash = try TruncatedHash(Data(repeating: 0xAA, count: 16))
        let forgedPacket = Packet(
            header: packet.header,
            destinationHash: forgedHash,
            context: packet.context,
            data: packet.data
        )

        #expect(throws: AnnounceError.signatureInvalid) {
            try Announce.validate(packet: forgedPacket)
        }
    }

    @Test("validate rejects invalid signature")
    func validateRejectsInvalidSignature() throws {
        let identity = Identity()
        let destination = Destination(identity: identity, direction: .out, appName: "test", aspects: ["app"])
        let packet = try Announce.create(destination: destination)

        // Corrupt signature bytes (bytes 84..<148 in payload, no ratchet).
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
        // Python-RNS-compatible random hash: 5 random bytes + 5-byte big-endian
        // Unix timestamp = 10 bytes total. Fixed across all RNS versions.
        #expect(result.randomHash.count == 10)
        #expect(result.signature.count == 64)
        #expect(result.ratchet == nil)
        #expect(result.publicKey == identity.publicKeyBytes)
        #expect(result.nameHash == destination.nameHash)
    }

    @Test("randomHash trailing 5 bytes encode current Unix timestamp big-endian")
    func randomHashTrailingTimestamp() throws {
        let identity = Identity()
        let destination = Destination(identity: identity, direction: .out, appName: "test", aspects: ["app"])

        let beforeTs = UInt64(Date().timeIntervalSince1970)
        let packet = try Announce.create(destination: destination)
        let afterTs = UInt64(Date().timeIntervalSince1970)
        let result = try Announce.validate(packet: packet)

        // Bytes 5..10 are the timestamp, 5 bytes big-endian unsigned.
        let tsBytes = Array(result.randomHash[5..<10])
        let parsedTs =
            (UInt64(tsBytes[0]) << 32) |
            (UInt64(tsBytes[1]) << 24) |
            (UInt64(tsBytes[2]) << 16) |
            (UInt64(tsBytes[3]) << 8) |
             UInt64(tsBytes[4])

        #expect(parsedTs >= beforeTs)
        #expect(parsedTs <= afterTs)
    }

    @Test("signed data does NOT contain signature (verify by checking signed data length)")
    func signedDataDoesNotContainSignature() throws {
        let identity = Identity()
        let destination = Destination(identity: identity, direction: .out, appName: "test", aspects: ["app"])
        let packet = try Announce.create(destination: destination)

        // Python-RNS-compatible announce payload (no appData, no ratchet):
        //   publicKey(64) + nameHash(10) + randomHash(10) + signature(64) = 148 bytes
        // Signed data (NOT in payload, only used for signature):
        //   destHash(16) + publicKey(64) + nameHash(10) + randomHash(10) = 100 bytes
        #expect(packet.data.count == 148)

        // Verify the round-trip works (if signature was in signed data, it would fail)
        let result = try Announce.validate(packet: packet)
        #expect(result.destinationHash == destination.hash)
    }
}
