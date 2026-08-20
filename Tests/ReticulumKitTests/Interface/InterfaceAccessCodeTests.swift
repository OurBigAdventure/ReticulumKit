// SPDX-License-Identifier: MIT
// InterfaceAccessCodeTests.swift — IFAC wrap / unwrap

import Testing
import Foundation
@testable import ReticulumKit

@Suite("Interface Access Code")
struct InterfaceAccessCodeTests {

    @Test("wrap then unwrap restores the packed packet")
    func wrapUnwrapRoundTrip() throws {
        let ifac = try InterfaceAccessCode(networkName: "private-mesh", passphrase: "secret")
        let packet = Packet(
            header: PacketHeader(
                headerType: .type1,
                propagationType: .broadcast,
                destinationType: .single,
                packetType: .data
            ),
            destinationHash: try TruncatedHash(Data(repeating: 0x11, count: 16)),
            data: Data("hello-ifac".utf8)
        )
        let raw = try packet.pack()
        let seed = Data(ifac.identity.signingPrivateKey.rawRepresentation)
        let sig1 = try CryptoEngine.signRFC8032(raw, seed: seed)
        let sig2 = try CryptoEngine.signRFC8032(raw, seed: seed)
        #expect(sig1 == sig2)
        let wrapped = try ifac.wrap(raw)
        #expect(wrapped[wrapped.startIndex] & 0x80 == 0x80)
        #expect(wrapped.count == raw.count + ifac.tagSize)
        let unmasked = ifac.unmaskOnly(wrapped)
        #expect(unmasked == raw)
        let bytes = [UInt8](wrapped)
        let wireTag = Array(bytes[2..<(2 + ifac.tagSize)])
        let signedTag = Array(sig1.suffix(ifac.tagSize))
        #expect(wireTag == signedTag)
        let restored = ifac.unwrap(wrapped)
        #expect(restored == raw)
    }

    @Test("unwrap rejects a tampered tag")
    func unwrapRejectsTamper() throws {
        let ifac = try InterfaceAccessCode(passphrase: "secret")
        let raw = try Packet(
            header: PacketHeader(
                headerType: .type1,
                propagationType: .broadcast,
                destinationType: .single,
                packetType: .announce
            ),
            destinationHash: try TruncatedHash(Data(repeating: 0x22, count: 16)),
            data: Data([0x01])
        ).pack()
        var wrapped = try ifac.wrap(raw)
        wrapped[wrapped.startIndex + 3] ^= 0xFF
        #expect(ifac.unwrap(wrapped) == nil)
    }
}
