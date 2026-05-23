// SPDX-License-Identifier: MIT
// PathRequest.swift — Path request packet creation and path response detection
//
// Path requests are broadcast packets ADDRESSED TO THE TARGET DESTINATION.
// Per the Reticulum spec (and Python RNS Transport.request_path), the packet
// header destination is the destination we are asking for. Any node that has
// a routing entry for that destination — most commonly the destination itself
// — replies with an announce in `pathResponse` context.

import Foundation

/// Stateless namespace for path request creation and response detection.
public enum PathRequest: Sendable {

    /// Create a path request packet for a target destination hash.
    ///
    /// Wire layout: HT=type1, PROP=broadcast, DEST=plain, packetType=.data,
    /// header.destinationHash = `targetHash`, payload = a random tag the
    /// requester can use to correlate responses.
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

        // 10 random bytes as a request tag so responses can be correlated.
        // Matches Python RNS Transport.request_path which sends a random hash
        // as the request body.
        let requestTag = (try? CryptoEngine.randomBytes(count: 10)) ?? Data(count: 10)

        return Packet(
            header: header,
            destinationHash: targetHash,
            transportId: nil,
            context: .none,
            data: requestTag
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
