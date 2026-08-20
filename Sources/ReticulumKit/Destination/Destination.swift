// SPDX-License-Identifier: MIT
// Destination.swift — Destination hash computation and addressing
//
// NOTE: DestinationType is defined in PacketTypes.swift (Plan 01-03, same module).
// When Plan 01-03 lands, add `type: DestinationType` property to this struct.
// Do NOT duplicate DestinationType here.

import Foundation
import CryptoKit

public enum DestinationDirection: Sendable {
    case `in`
    case out
}

public struct Destination: Sendable {
    public let identity: Identity
    public let direction: DestinationDirection
    public let appName: String
    public let aspects: [String]

    public init(
        identity: Identity,
        direction: DestinationDirection,
        appName: String,
        aspects: [String] = []
    ) {
        self.identity = identity
        self.direction = direction
        self.appName = appName
        self.aspects = aspects
    }

    /// "appName.aspect1.aspect2"
    public var expandedName: String {
        ([appName] + aspects).joined(separator: ".")
    }

    /// Name hash: SHA-256(expandedName.utf8) truncated to 10 bytes
    public var nameHash: Data {
        let full = CryptoEngine.sha256(Data(expandedName.utf8))
        return Data(full.prefix(ReticulumConstants.nameHashLength))  // 10 bytes
    }

    /// Destination hash: SHA-256(nameHash + identityHash) truncated to 16 bytes
    public var hash: TruncatedHash {
        let material = nameHash + identity.hash.data
        let full = CryptoEngine.truncatedHash(material)
        return try! TruncatedHash(full)
    }

    /// Hash of a PLAIN destination (no identity), matching Python `Destination.hash(None, app, *aspects)`.
    ///
    /// Used for control traffic such as `rnstransport.path.request`.
    public static func plainHash(appName: String, aspects: [String] = []) -> TruncatedHash {
        let expanded = ([appName] + aspects).joined(separator: ".")
        let nameHash = Data(CryptoEngine.sha256(Data(expanded.utf8)).prefix(ReticulumConstants.nameHashLength))
        return try! TruncatedHash(CryptoEngine.truncatedHash(nameHash))
    }
}
