// SPDX-License-Identifier: MIT
// PathRequest.swift — Path request packet creation and path response detection
//
// Stateless namespace (enum with no cases) matching project convention (Announce pattern).
// Path requests are broadcast to a control destination derived from "path.request".
// Transport nodes recognize these and respond with the destination's announce.

import Foundation

/// Stateless namespace for path request creation and response detection.
public enum PathRequest: Sendable {

    /// Control destination hash for path requests.
    ///
    /// Derived as: truncatedHash(sha256("path.request"))
    /// This is the simplified client-side approach. For an iOS leaf node connecting
    /// via TCP to a transport node, path requests are broadcast to this control
    /// destination. The transport node recognizes them and responds.
    public static let controlDestinationHash: TruncatedHash = {
        let hash = CryptoEngine.truncatedHash(CryptoEngine.sha256(Data("path.request".utf8)))
        return try! TruncatedHash(hash)
    }()

    /// Create a path request packet for a target destination hash.
    ///
    /// The packet is addressed to the control destination with the target hash
    /// as payload. Transport nodes recognize the control destination and respond
    /// with the target's announce if they have it in their routing table.
    ///
    /// - Parameter targetHash: The destination hash to request a path for.
    /// - Returns: A `Packet` ready for transmission through all interfaces.
    public static func create(targetHash: TruncatedHash) throws -> Packet {
        let header = PacketHeader(
            headerType: .type1,
            propagationType: .broadcast,
            destinationType: .plain,
            packetType: .data
        )

        return Packet(
            header: header,
            destinationHash: controlDestinationHash,
            transportId: nil,
            context: .none,
            data: targetHash.data
        )
    }

    /// Check if a packet is a path response.
    ///
    /// Path responses are announce packets with `pathResponse` context.
    /// They contain the same payload as a normal announce but arrive in
    /// response to a path request rather than being spontaneously broadcast.
    ///
    /// - Parameter packet: The packet to check.
    /// - Returns: `true` if the packet is a path response announce.
    public static func isPathResponse(_ packet: Packet) -> Bool {
        packet.header.packetType == .announce && packet.context == .pathResponse
    }
}
