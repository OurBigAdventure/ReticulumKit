// SPDX-License-Identifier: MIT
// AnnounceRateLimiter.swift — Bandwidth-based announce rate limiting
//
// Enforces Reticulum's 2% announce bandwidth cap (ANNOUNCE_CAP).
// After sending an announce, the node must wait until the transmission
// time divided by the cap percentage has elapsed before sending another.
//
// Formula: waitTime = (packetSize * 8 / bitrate) / 0.02

import Foundation

/// Rate limiter that enforces the Reticulum announce bandwidth cap.
///
/// The announce cap is 2% of interface bandwidth. After sending an announce,
/// the minimum wait time before the next announce is:
/// `(packetBits / bitrate) / announceCap`
public actor AnnounceRateLimiter {
    /// Interface bitrate in bits per second
    private let bitrate: Int

    /// Announce bandwidth cap: 2% (ANNOUNCE_CAP / 100)
    private let announceCap: Double = 0.02

    /// Earliest time the next announce may be sent
    private var allowedAt: Date = .distantPast

    /// Create a rate limiter for an interface with the given bitrate.
    ///
    /// - Parameter bitrate: Interface speed in bits per second (e.g., 10_000_000 for 10 Mbps).
    public init(bitrate: Int) {
        self.bitrate = bitrate
    }

    /// Whether an announce may be sent now.
    public func canSend() -> Bool {
        Date() >= allowedAt
    }

    /// Record that an announce was just sent, updating the rate limit window.
    ///
    /// - Parameter packetSize: Size of the announce packet in bytes.
    public func recordSend(packetSize: Int) {
        let wait = computeWaitTime(packetSize: packetSize)
        allowedAt = Date().addingTimeInterval(wait)
    }

    /// Compute the required wait time for a packet of the given size.
    ///
    /// - Parameter packetSize: Size of the announce packet in bytes.
    /// - Returns: Required wait time in seconds.
    public func waitTime(packetSize: Int) -> TimeInterval {
        computeWaitTime(packetSize: packetSize)
    }

    /// Internal computation: txTime / announceCap
    private func computeWaitTime(packetSize: Int) -> TimeInterval {
        let txTime = Double(packetSize * 8) / Double(bitrate)
        return txTime / announceCap
    }
}
