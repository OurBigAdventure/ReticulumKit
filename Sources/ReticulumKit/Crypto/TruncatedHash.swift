// SPDX-License-Identifier: MIT
// TruncatedHash.swift — 16-byte truncated SHA-256 hash value type

import Foundation

/// A 16-byte (128-bit) truncated SHA-256 hash used throughout Reticulum
/// for destination addresses and identity hashes.
///
/// This is a value type that enforces the exact length constraint at init time.
public struct TruncatedHash: Sendable, Hashable, Equatable {
    /// The raw 16-byte hash data.
    public let data: Data

    /// Creates a TruncatedHash from exactly 16 bytes of data.
    ///
    /// - Parameter data: Exactly 16 bytes of hash data.
    /// - Throws: `ReticulumError.invalidHashLength` if data is not 16 bytes.
    public init(_ data: Data) throws {
        guard data.count == ReticulumConstants.truncatedHashLength else {
            throw ReticulumError.invalidHashLength(data.count)
        }
        self.data = data
    }

    // MARK: - Hashable

    public func hash(into hasher: inout Hasher) {
        hasher.combine(data)
    }

    // MARK: - Equatable

    public static func == (lhs: TruncatedHash, rhs: TruncatedHash) -> Bool {
        lhs.data == rhs.data
    }

    // MARK: - Debug

    /// Hex string representation of the hash for debug/logging output.
    public var hexString: String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}
