// SPDX-License-Identifier: MIT
// RoutingTable.swift — Destination hash to route entry mapping
//
// Path selection matches Python RNS `Transport.inbound` announce handling
// (`RNS/Transport.py`): prefer a more recently *emitted* announce (unix time
// in random_hash[5..<10]), not hop count alone. A newer emission replaces an
// existing path even when hops are worse; an older emission is ignored unless
// the current path has expired (PATHFINDER_E = 1 week).

import Foundation

/// A route entry derived from a validated announce.
public struct RouteEntry: Sendable {
    /// The destination hash this route reaches
    public let destinationHash: TruncatedHash
    /// Combined public key: X25519(32) + Ed25519(32) = 64 bytes
    public let publicKey: Data
    /// Name hash: 10 bytes
    public let nameHash: Data
    /// Optional application data from the announce
    public let appData: Data?
    /// Number of hops to reach this destination
    public let hops: UInt8
    /// When this route was learned locally
    public let timestamp: Date
    /// Announce emission time (unix seconds) from random_hash[5..<10].
    public let emittedAt: UInt64
    /// When this path should be considered stale (PATHFINDER_E).
    public let expires: Date
    /// Identifier of the interface this announce arrived on
    public let interfaceId: String
    /// Recent announce random_blobs for loop detection (max 64).
    public let randomBlobs: [Data]

    public init(
        destinationHash: TruncatedHash,
        publicKey: Data,
        nameHash: Data,
        appData: Data?,
        hops: UInt8,
        timestamp: Date,
        interfaceId: String,
        emittedAt: UInt64 = 0,
        expires: Date = Date().addingTimeInterval(RoutingTable.defaultExpiry),
        randomBlobs: [Data] = []
    ) {
        self.destinationHash = destinationHash
        self.publicKey = publicKey
        self.nameHash = nameHash
        self.appData = appData
        self.hops = hops
        self.timestamp = timestamp
        self.emittedAt = emittedAt
        self.expires = expires
        self.interfaceId = interfaceId
        self.randomBlobs = randomBlobs
    }
}

/// Actor-isolated routing table for thread-safe access from multiple interfaces.
public actor RoutingTable {
    /// Route entries keyed by destination hash
    private var entries: [TruncatedHash: RouteEntry] = [:]

    /// Default entry expiry: 1 week (Python `PATHFINDER_E`).
    public static let defaultExpiry: TimeInterval = 604_800

    /// Python `MAX_RANDOM_BLOBS`.
    public static let maxRandomBlobs = 64

    public init() {}

    /// Add or update a route using Python announce recency rules.
    ///
    /// - Returns: `true` when the table changed.
    @discardableResult
    public func addEntry(_ entry: RouteEntry) -> Bool {
        if let existing = entries[entry.destinationHash] {
            guard shouldReplace(existing: existing, with: entry) else { return false }
            entries[entry.destinationHash] = merged(existing: existing, incoming: entry)
        } else {
            entries[entry.destinationHash] = entry
        }
        return true
    }

    /// Look up a route entry by destination hash.
    public func lookup(_ destinationHash: TruncatedHash) -> RouteEntry? {
        entries[destinationHash]
    }

    /// Interface that last delivered a usable announce for this destination.
    public func interfaceId(for destinationHash: TruncatedHash) -> String? {
        entries[destinationHash]?.interfaceId
    }

    /// Check if a path exists for the given destination hash.
    public func hasPath(for destinationHash: TruncatedHash) -> Bool {
        entries[destinationHash] != nil
    }

    /// Remove a route entry by destination hash.
    public func removeEntry(_ destinationHash: TruncatedHash) {
        entries.removeValue(forKey: destinationHash)
    }

    /// Return all route entries.
    public func allEntries() -> [RouteEntry] {
        Array(entries.values)
    }

    /// Remove entries whose `expires` timestamp is in the past.
    public func removeExpired(olderThan: TimeInterval = defaultExpiry) {
        let now = Date()
        entries = entries.filter { _, entry in
            entry.expires > now && now.timeIntervalSince(entry.timestamp) <= olderThan
        }
    }

    /// Number of entries in the routing table.
    public var count: Int {
        entries.count
    }

    /// Restore entries previously written by ``save(to:)``.
    public func load(from directory: URL?) {
        guard let directory else { return }
        let url = directory.appendingPathComponent("destination_table.json")
        guard let data = try? Data(contentsOf: url),
              let snapshot = try? JSONDecoder().decode([PersistedRoute].self, from: data)
        else { return }
        var restored: [TruncatedHash: RouteEntry] = [:]
        for row in snapshot {
            guard let hashData = Data(hexString: row.destinationHex),
                  let hash = try? TruncatedHash(hashData),
                  let publicKey = Data(hexString: row.publicKeyHex),
                  let nameHash = Data(hexString: row.nameHashHex)
            else { continue }
            restored[hash] = RouteEntry(
                destinationHash: hash,
                publicKey: publicKey,
                nameHash: nameHash,
                appData: row.appDataHex.flatMap { Data(hexString: $0) },
                hops: row.hops,
                timestamp: row.timestamp,
                interfaceId: row.interfaceId,
                emittedAt: row.emittedAt,
                expires: row.expires,
                randomBlobs: row.randomBlobHexes.compactMap { Data(hexString: $0) }
            )
        }
        entries = restored
    }

    /// Write the table to `destination_table.json` in `directory`.
    public func save(to directory: URL?) {
        guard let directory else { return }
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let snapshot = entries.values.map { entry in
            PersistedRoute(
                destinationHex: entry.destinationHash.hexString,
                publicKeyHex: entry.publicKey.hexString,
                nameHashHex: entry.nameHash.hexString,
                appDataHex: entry.appData?.hexString,
                hops: entry.hops,
                timestamp: entry.timestamp,
                emittedAt: entry.emittedAt,
                expires: entry.expires,
                interfaceId: entry.interfaceId,
                randomBlobHexes: entry.randomBlobs.map(\.hexString)
            )
        }
        let url = directory.appendingPathComponent("destination_table.json")
        guard let data = try? JSONEncoder().encode(snapshot) else { return }
        try? data.write(to: url, options: [.atomic])
    }

    // MARK: - Python path selection

    /// Mirrors `should_add` in Python `Transport.inbound` for announces.
    private func shouldReplace(existing: RouteEntry, with incoming: RouteEntry) -> Bool {
        let blob = incoming.randomBlobs.last ?? Data()
        let alreadyHeard = existing.randomBlobs.contains(blob) && !blob.isEmpty
        let pathTimebase = existing.randomBlobs.map(Self.timebase(of:)).max() ?? existing.emittedAt

        if incoming.hops <= existing.hops {
            if !alreadyHeard && incoming.emittedAt > pathTimebase {
                return true
            }
            if incoming.hops < existing.hops && incoming.emittedAt >= pathTimebase {
                return true
            }
            return false
        }

        if Date() >= existing.expires {
            return !alreadyHeard
        }
        if incoming.emittedAt > (existing.randomBlobs.map(Self.timebase(of:)).max() ?? existing.emittedAt) {
            return !alreadyHeard
        }
        return false
    }

    private func merged(existing: RouteEntry, incoming: RouteEntry) -> RouteEntry {
        var blobs = existing.randomBlobs
        for blob in incoming.randomBlobs where !blob.isEmpty && !blobs.contains(blob) {
            blobs.append(blob)
        }
        if blobs.count > Self.maxRandomBlobs {
            blobs = Array(blobs.suffix(Self.maxRandomBlobs))
        }
        return RouteEntry(
            destinationHash: incoming.destinationHash,
            publicKey: incoming.publicKey,
            nameHash: incoming.nameHash,
            appData: incoming.appData,
            hops: incoming.hops,
            timestamp: incoming.timestamp,
            interfaceId: incoming.interfaceId,
            emittedAt: incoming.emittedAt,
            expires: incoming.expires,
            randomBlobs: blobs
        )
    }

    private static func timebase(of blob: Data) -> UInt64 {
        guard blob.count >= 10 else { return 0 }
        return blob.subdata(in: 5..<10).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }
}

private struct PersistedRoute: Codable {
    var destinationHex: String
    var publicKeyHex: String
    var nameHashHex: String
    var appDataHex: String?
    var hops: UInt8
    var timestamp: Date
    var emittedAt: UInt64
    var expires: Date
    var interfaceId: String
    var randomBlobHexes: [String]
}

private extension Data {
    init?(hexString: String) {
        let hex = hexString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard hex.count.isMultiple(of: 2) else { return nil }
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        self = data
    }

    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
