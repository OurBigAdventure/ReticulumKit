// SPDX-License-Identifier: MIT
// AnnounceRateLimiterTests.swift — Tests for announce rate limiting

import Testing
import Foundation
@testable import ReticulumKit

@Suite("Announce rate limiter")
struct AnnounceRateLimiterTests {

    @Test("canSend returns true initially")
    func canSendInitially() async {
        let limiter = AnnounceRateLimiter(bitrate: 10_000_000)
        let result = await limiter.canSend()
        #expect(result == true)
    }

    @Test("canSend returns false immediately after recordSend")
    func canSendFalseAfterRecord() async {
        let limiter = AnnounceRateLimiter(bitrate: 10_000_000)
        await limiter.recordSend(packetSize: 500)
        let result = await limiter.canSend()
        #expect(result == false)
    }

    @Test("waitTime for 500-byte packet at 10Mbps = 0.02 seconds")
    func waitTime10Mbps() async {
        let limiter = AnnounceRateLimiter(bitrate: 10_000_000)
        let wait = await limiter.waitTime(packetSize: 500)
        // (500 * 8) / 10_000_000 / 0.02 = 4000 / 10_000_000 / 0.02 = 0.0004 / 0.02 = 0.02
        #expect(abs(wait - 0.02) < 0.001)
    }

    @Test("waitTime for 500-byte packet at 1Mbps = 0.2 seconds")
    func waitTime1Mbps() async {
        let limiter = AnnounceRateLimiter(bitrate: 1_000_000)
        let wait = await limiter.waitTime(packetSize: 500)
        // (500 * 8) / 1_000_000 / 0.02 = 4000 / 1_000_000 / 0.02 = 0.004 / 0.02 = 0.2
        #expect(abs(wait - 0.2) < 0.001)
    }
}
