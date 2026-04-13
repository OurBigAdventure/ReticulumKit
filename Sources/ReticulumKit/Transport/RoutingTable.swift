// SPDX-License-Identifier: MIT
// RoutingTable.swift — Destination hash to route entry mapping
//
// Stores announce-derived route entries keyed by destination hash.
// Updates only when a new entry has strictly fewer hops than the existing one.
// Entries expire after 1 week (604,800 seconds) matching Python Reticulum.

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
    /// When this route was learned
    public let timestamp: Date
    /// Identifier of the interface this announce arrived on
    public let interfaceId: String
}

/// Actor-isolated routing table for thread-safe access from multiple interfaces.
public actor RoutingTable {
    /// Route entries keyed by destination hash
    private var entries: [TruncatedHash: RouteEntry] = [:]

    /// Default entry expiry: 1 week (matches Python Reticulum)
    public static let defaultExpiry: TimeInterval = 604_800

    public init() {}

    /// Add or update a route entry.
    ///
    /// Only replaces an existing entry if the new entry has strictly fewer hops.
    /// If hops are equal or greater, the existing entry is kept.
    ///
    /// - Parameter entry: The route entry to add.
    public func addEntry(_ entry: RouteEntry) {
        if let existing = entries[entry.destinationHash] {
            // Only replace if new entry has strictly fewer hops
            guard entry.hops < existing.hops else { return }
        }
        entries[entry.destinationHash] = entry
    }

    /// Look up a route entry by destination hash.
    ///
    /// - Parameter destinationHash: The destination hash to look up.
    /// - Returns: The route entry if found, nil otherwise.
    public func lookup(_ destinationHash: TruncatedHash) -> RouteEntry? {
        entries[destinationHash]
    }

    /// Check if a path exists for the given destination hash.
    ///
    /// - Parameter destinationHash: The destination hash to check.
    /// - Returns: `true` if a route entry exists for this destination.
    public func hasPath(for destinationHash: TruncatedHash) -> Bool {
        entries[destinationHash] != nil
    }

    /// Remove a route entry by destination hash.
    ///
    /// - Parameter destinationHash: The destination hash to remove.
    public func removeEntry(_ destinationHash: TruncatedHash) {
        entries.removeValue(forKey: destinationHash)
    }

    /// Return all route entries.
    public func allEntries() -> [RouteEntry] {
        Array(entries.values)
    }

    /// Remove entries older than the specified time interval.
    ///
    /// - Parameter olderThan: Maximum age in seconds. Defaults to 1 week.
    public func removeExpired(olderThan: TimeInterval = defaultExpiry) {
        let now = Date()
        entries = entries.filter { _, entry in
            now.timeIntervalSince(entry.timestamp) <= olderThan
        }
    }

    /// Number of entries in the routing table.
    public var count: Int {
        entries.count
    }
}
