// SPDX-License-Identifier: MIT
// PathRequest.swift — Path request packet creation and path response detection
//
// Wire format matches Python RNS `Transport.request_path` for a non-transport
// client (`RNS/Transport.py`):
//   - Header destination is the PLAIN dest `rnstransport.path.request`
//     (not the hash being looked up).
//   - Payload is `targetHash(16) + requestTag(16)`.
// Transport nodes listen on that PLAIN dest and reply with an announce in
// `pathResponse` context. See Python `path_request_handler`.

import Foundation

/// Stateless namespace for path request creation and response detection.
public enum PathRequest: Sendable {

    /// Application name of the RNS transport control destination.
    public static let transportAppName = "rnstransport"

    /// PLAIN destination hash hubs listen on for path requests.
    public static let controlDestinationHash: TruncatedHash = Destination.plainHash(
        appName: transportAppName,
        aspects: ["path", "request"]
    )

    /// Truncated-hash length used for the lookup target and the request tag.
    public static let tagLength = ReticulumConstants.truncatedHashLength

    /// Create a path request packet for a target destination hash.
    ///
    /// - Parameter targetHash: The destination hash to request a path for.
    /// - Returns: A `Packet` ready for transmission.
    public static func create(targetHash: TruncatedHash) throws -> Packet {
        let header = PacketHeader(
            headerType: .type1,
            propagationType: .broadcast,
            destinationType: .plain,
            packetType: .data
        )

        // Python `Identity.get_random_hash()`: 16-byte truncated hash.
        let requestTag = (try? CryptoEngine.truncatedHash(CryptoEngine.randomBytes(count: 32)))
            ?? Data(count: tagLength)
        let payload = targetHash.data + requestTag

        return Packet(
            header: header,
            destinationHash: controlDestinationHash,
            transportId: nil,
            context: .none,
            data: payload
        )
    }

    /// The destination being looked up, if this packet is a Python-format path request.
    public static func targetHash(from packet: Packet) -> TruncatedHash? {
        guard packet.header.packetType == .data,
              packet.header.destinationType == .plain,
              packet.destinationHash == controlDestinationHash,
              packet.data.count >= tagLength
        else { return nil }
        return try? TruncatedHash(Data(packet.data.prefix(tagLength)))
    }

    /// Check if a packet is a path response.
    ///
    /// Path responses are announce packets with `pathResponse` context.
    public static func isPathResponse(_ packet: Packet) -> Bool {
        packet.header.packetType == .announce && packet.context == .pathResponse
    }
}
