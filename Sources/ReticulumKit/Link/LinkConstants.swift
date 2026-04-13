// SPDX-License-Identifier: MIT
// LinkConstants.swift — Protocol constants for link establishment and path requests
//
// Stateless namespace (enum with no cases) matching project convention (Announce pattern).
// Values sourced from Python RNS/Link.py and RNS/Packet.py.

import Foundation

/// Protocol constants for link establishment, keepalives, and path requests.
public enum LinkConstants: Sendable {

    // MARK: - Key Sizes

    /// Combined ephemeral public key size: X25519(32) + Ed25519(32)
    public static let ecPubSize = 64

    /// Individual key size (X25519 or Ed25519)
    public static let keySize = 32

    /// Signalling bytes appended to link request data beyond ecPubSize
    public static let linkMTUSize = 3

    // MARK: - Link Establishment

    /// Timeout per hop for link establishment (seconds)
    public static let establishmentTimeoutPerHop: TimeInterval = 6.0

    // MARK: - Keepalive

    /// Maximum keepalive interval (seconds)
    public static let keepaliveMax: TimeInterval = 360.0

    /// Minimum keepalive interval (seconds)
    public static let keepaliveMin: TimeInterval = 5.0

    /// Default keepalive interval (seconds)
    public static let defaultKeepalive: TimeInterval = 360.0

    /// Grace period added to stale check (seconds)
    public static let staleGrace: TimeInterval = 5.0

    /// Factor multiplied with keepalive to determine stale threshold
    public static let staleFactor = 2

    /// Factor multiplied with keepalive for keepalive timeout
    public static let keepaliveTimeoutFactor = 4

    /// Factor multiplied with keepalive for traffic timeout
    public static let trafficTimeoutFactor = 6

    // MARK: - Path Requests

    /// Timeout waiting for a path response (seconds)
    public static let pathRequestTimeout: TimeInterval = 15.0

    /// Grace period for path request timing (seconds)
    public static let pathRequestGrace: TimeInterval = 0.4

    /// Minimum interval between path requests to the same destination (seconds)
    public static let pathRequestMinInterval: TimeInterval = 20.0
}
