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
