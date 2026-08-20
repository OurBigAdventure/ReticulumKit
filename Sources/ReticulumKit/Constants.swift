// SPDX-License-Identifier: MIT
// Constants.swift — Reticulum protocol constants (single source of truth)

import Foundation

/// Core Reticulum network protocol constants.
/// Source: RNS/Reticulum.py, RNS/Packet.py
public enum ReticulumConstants: Sendable {
    /// Maximum Transmission Unit — maximum packet size on the wire (bytes)
    public static let MTU = 500

    /// Minimum header size: 2 (flags+hops) + 1 (context) + 16 (dest hash)
    public static let headerMinSize = 19

    /// Maximum header size: 2 (flags+hops) + 1 (context) + 32 (two addresses)
    public static let headerMaxSize = 35

    /// Minimum IFAC overhead
    public static let ifacMinSize = 1

    /// Default IFAC tag length in bytes (Python `Interface.DEFAULT_IFAC_SIZE` = 9).
    public static let ifacDefaultSize = 9

    /// HKDF salt for deriving an interface access-code identity (Python `Reticulum.IFAC_SALT`).
    public static let ifacSalt = Data([
        0xad, 0xf5, 0x4d, 0x88, 0x2c, 0x9a, 0x9b, 0x80,
        0x71, 0xeb, 0x49, 0x95, 0xd7, 0x02, 0xd4, 0xa3,
        0xe7, 0x33, 0x39, 0x1b, 0x2a, 0x0f, 0x53, 0xf4,
        0x16, 0xd9, 0xf9, 0x07, 0xe5, 0x5c, 0xff, 0xf8
    ])

    /// Maximum Data Unit — maximum payload in a single packet
    public static let MDU = MTU - headerMaxSize - ifacMinSize  // 464

    /// Truncated hash length in bytes (128 bits)
    public static let truncatedHashLength = 16

    /// Name hash length in bytes (80 bits)
    public static let nameHashLength = 10
}

/// Identity-related constants.
/// Source: RNS/Identity.py
public enum IdentityConstants: Sendable {
    /// Combined public key size: 32 (X25519) + 32 (Ed25519)
    public static let keySize = 64

    /// Ed25519 signature length in bytes
    public static let sigLength = 64
}

/// Token (encrypt/decrypt) constants.
/// Source: RNS/Cryptography/Token.py
public enum TokenConstants: Sendable {
    /// Overhead added by token encryption: 16 (IV) + 32 (HMAC)
    public static let overhead = 48
}
