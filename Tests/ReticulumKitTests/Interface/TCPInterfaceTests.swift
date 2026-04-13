// SPDX-License-Identifier: MIT
// TCPInterfaceTests.swift — TCPInterface lifecycle and protocol contract tests

import Testing
import Foundation
@testable import ReticulumKit

@Suite("TCPInterface")
struct TCPInterfaceTests {

    // MARK: - Initialization

    @Test("interfaceId has correct format tcp-host:port")
    func interfaceIdFormat() async {
        let iface = TCPInterface(host: "example.com", port: 4242)
        #expect(iface.interfaceId == "tcp-example.com:4242")
    }

    @Test("is not online before start")
    func notOnlineBeforeStart() async {
        let iface = TCPInterface(host: "example.com", port: 4242)
        let online = await iface.isOnline
        #expect(online == false)
    }

    @Test("bitrate defaults to 10_000_000")
    func defaultBitrate() {
        let iface = TCPInterface(host: "example.com", port: 4242)
        #expect(iface.bitrate == 10_000_000)
    }

    @Test("custom bitrate is respected")
    func customBitrate() {
        let iface = TCPInterface(host: "example.com", port: 4242, bitrate: 1_000_000)
        #expect(iface.bitrate == 1_000_000)
    }

    // MARK: - Reconnect delay calculation

    @Test("reconnectDelay attempt 0 equals base delay 5.0")
    func reconnectDelayAttempt0() {
        let delay = TCPInterface.reconnectDelay(attempt: 0)
        #expect(delay == 5.0)
    }

    @Test("reconnectDelay attempt 1 equals 10.0")
    func reconnectDelayAttempt1() {
        let delay = TCPInterface.reconnectDelay(attempt: 1)
        #expect(delay == 10.0)
    }

    @Test("reconnectDelay attempt 2 equals 20.0")
    func reconnectDelayAttempt2() {
        let delay = TCPInterface.reconnectDelay(attempt: 2)
        #expect(delay == 20.0)
    }

    @Test("reconnectDelay attempt 5 is capped at 60.0")
    func reconnectDelayCapped() {
        // 5 * 2^5 = 160, capped at 60
        let delay = TCPInterface.reconnectDelay(attempt: 5)
        #expect(delay == 60.0)
    }

    // MARK: - Mock NetworkInterface (protocol contract validation)

    @Test("MockNetworkInterface send/receive round-trip validates protocol")
    func mockRoundTrip() async throws {
        let mock = MockNetworkInterface()
        try await mock.start()
        let online = await mock.isOnline
        #expect(online == true)

        let payload = Data([0x01, 0x02, 0x03])
        try await mock.send(payload)

        var received: Data?
        for await packet in mock.incomingPackets {
            received = packet
            break
        }
        #expect(received == payload)

        await mock.stop()
        let offlineNow = await mock.isOnline
        #expect(offlineNow == false)
    }

    @Test("MockNetworkInterface throws when sending while offline")
    func mockSendWhileOffline() async {
        let mock = MockNetworkInterface()
        do {
            try await mock.send(Data([0x01]))
            #expect(Bool(false), "Should have thrown")
        } catch {
            #expect(error is ReticulumError)
        }
    }
}

// MARK: - Mock Implementation

/// A mock NetworkInterface for testing the protocol contract without real networking.
private actor MockNetworkInterface: NetworkInterface {
    let interfaceId = "mock-test"
    nonisolated let bitrate = 1_000_000
    private var _isOnline = false
    var isOnline: Bool { _isOnline }

    private var continuation: AsyncStream<Data>.Continuation?
    nonisolated let incomingPackets: AsyncStream<Data>

    init() {
        let (stream, cont) = AsyncStream.makeStream(of: Data.self)
        self.incomingPackets = stream
        self.continuation = cont
    }

    func start() async throws {
        _isOnline = true
    }

    func stop() async {
        _isOnline = false
        continuation?.finish()
    }

    func send(_ data: Data) async throws {
        guard _isOnline else { throw ReticulumError.interfaceOffline }
        // Echo back for testing
        continuation?.yield(data)
    }
}
