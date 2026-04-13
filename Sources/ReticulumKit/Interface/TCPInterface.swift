// SPDX-License-Identifier: MIT
// TCPInterface.swift — TCP client interface using NWConnection

import Foundation
import Network
import Logging

/// TCP client interface for connecting to Reticulum transport nodes.
///
/// Uses Network.framework `NWConnection` for TCP transport with HDLC framing.
/// Automatically reconnects on connection failure with exponential backoff
/// (5s base, 2x multiplier, 60s cap — T-02-03 mitigation).
/// Handles iOS app lifecycle (background/foreground) transitions.
///
/// Logging policy (T-02-04): Only connection state transitions and packet sizes
/// are logged at info level. Raw packet bytes are never logged at default level.
public actor TCPInterface: NetworkInterface {

    // MARK: - Public properties (nonisolated for cross-actor access)

    /// Unique identifier in format "tcp-{host}:{port}"
    public nonisolated let interfaceId: String

    /// Nominal bitrate in bits/second (default 10 Mbps for TCP)
    public nonisolated let bitrate: Int

    /// Stream of incoming deframed packets
    public nonisolated let incomingPackets: AsyncStream<Data>

    /// Whether the connection is currently ready
    public var isOnline: Bool { _isOnline }

    // MARK: - Private state

    private let host: String
    private let port: UInt16
    private var connection: NWConnection?
    private var deframer = HDLCDeframer()
    private var _isOnline = false
    private var packetContinuation: AsyncStream<Data>.Continuation?
    private var reconnectAttempts = 0
    private var shouldReconnect = true
    private let logger = Logger(label: "ReticulumKit.TCPInterface")

    private static let maxReconnectDelay: TimeInterval = 60.0
    private static let baseReconnectDelay: TimeInterval = 5.0

    // MARK: - Init

    /// Create a TCP interface targeting the given host and port.
    ///
    /// - Parameters:
    ///   - host: Remote hostname or IP address
    ///   - port: Remote TCP port
    ///   - bitrate: Nominal bitrate in bits/second (default 10 Mbps)
    public init(host: String, port: UInt16, bitrate: Int = 10_000_000) {
        self.host = host
        self.port = port
        self.bitrate = bitrate
        self.interfaceId = "tcp-\(host):\(port)"

        let (stream, continuation) = AsyncStream.makeStream(of: Data.self)
        self.incomingPackets = stream
        self.packetContinuation = continuation
    }

    // MARK: - Lifecycle

    /// Connect to the remote transport node and begin receiving packets.
    public func start() async throws {
        shouldReconnect = true
        createAndStartConnection()
    }

    /// Disconnect and stop all activity. Does not auto-reconnect after stop.
    public func stop() async {
        shouldReconnect = false
        _isOnline = false
        connection?.cancel()
        connection = nil
        packetContinuation?.finish()
        packetContinuation = nil
        logger.info("Stopped interface \(self.interfaceId)")
    }

    /// Cancel connection on iOS background entry. Will reconnect on foreground.
    public func onBackground() async {
        _isOnline = false
        connection?.cancel()
        connection = nil
        logger.info("Background: cancelled connection for \(self.interfaceId)")
    }

    /// Reconnect after iOS foreground return.
    public func onForeground() async {
        if shouldReconnect && !_isOnline {
            logger.info("Foreground: reconnecting \(self.interfaceId)")
            createAndStartConnection()
        }
    }

    // MARK: - Send

    /// Send raw packet data over TCP with HDLC framing.
    ///
    /// - Parameter data: Raw packet bytes to frame and send
    /// - Throws: `ReticulumError.interfaceOffline` if not connected
    public func send(_ data: Data) async throws {
        guard _isOnline, let connection = connection else {
            throw ReticulumError.interfaceOffline
        }
        let framed = HDLC.frame(data)
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: framed, completion: .contentProcessed { error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
            })
        }
        // T-02-04: Log packet size only, never raw bytes
        logger.debug("Sent \(data.count) bytes on \(self.interfaceId)")
    }

    // MARK: - Reconnect delay (public static for testability)

    /// Calculate reconnect delay with exponential backoff.
    ///
    /// - Parameters:
    ///   - attempt: Zero-based attempt number
    ///   - base: Base delay in seconds (default 5.0)
    ///   - max: Maximum delay cap in seconds (default 60.0)
    /// - Returns: Delay in seconds: min(base * 2^attempt, max)
    public static func reconnectDelay(
        attempt: Int,
        base: TimeInterval = 5.0,
        max: TimeInterval = 60.0
    ) -> TimeInterval {
        return Swift.min(base * pow(2.0, Double(attempt)), max)
    }

    // MARK: - Private helpers

    /// Create a new NWConnection and start it on a background queue.
    private func createAndStartConnection() {
        let nwHost = NWEndpoint.Host(host)
        let nwPort = NWEndpoint.Port(rawValue: port)!
        let conn = NWConnection(host: nwHost, port: nwPort, using: .tcp)

        conn.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            switch state {
            case .ready:
                Task { await self.handleReady() }
            case .failed(let error):
                Task { await self.handleFailed(error) }
            case .waiting:
                Task { await self.handleWaiting() }
            case .cancelled:
                break
            default:
                break
            }
        }

        self.connection = conn
        conn.start(queue: DispatchQueue(label: "ReticulumKit.TCPInterface.\(interfaceId)"))
        logger.info("Connecting \(self.interfaceId)")
    }

    /// Handle connection ready state — begin read loop.
    private func handleReady() {
        _isOnline = true
        reconnectAttempts = 0
        deframer = HDLCDeframer()
        logger.info("Connected \(self.interfaceId)")
        startReadLoop()
    }

    /// Handle connection failure — schedule reconnect.
    private func handleFailed(_ error: NWError) {
        _isOnline = false
        connection?.cancel()
        connection = nil
        logger.warning("Connection failed for \(self.interfaceId): \(error.localizedDescription)")
        scheduleReconnect()
    }

    /// Handle waiting state (network unavailable).
    private func handleWaiting() {
        _isOnline = false
        logger.info("Waiting for network on \(self.interfaceId)")
    }

    /// Begin reading from the connection in a loop.
    private func startReadLoop() {
        guard let connection = connection else { return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: 16384) { [weak self] content, _, isComplete, error in
            guard let self = self else { return }
            Task { await self.handleReceive(content: content, isComplete: isComplete, error: error) }
        }
    }

    /// Process received TCP data through the HDLC deframer.
    private func handleReceive(content: Data?, isComplete: Bool, error: NWError?) {
        if let data = content, !data.isEmpty {
            let packets = deframer.feed(data)
            for packet in packets {
                // T-02-04: Log packet size only
                logger.debug("Received \(packet.count) bytes on \(self.interfaceId)")
                packetContinuation?.yield(packet)
            }
        }

        if isComplete || error != nil {
            // Connection closed or errored
            _isOnline = false
            if error != nil {
                logger.warning("Read error on \(self.interfaceId): \(error!.localizedDescription)")
            } else {
                logger.info("Connection closed on \(self.interfaceId)")
            }
            connection?.cancel()
            connection = nil
            scheduleReconnect()
            return
        }

        // Continue reading
        startReadLoop()
    }

    /// Schedule a reconnect attempt with exponential backoff (T-02-03).
    private func scheduleReconnect() {
        guard shouldReconnect else { return }
        let delay = Self.reconnectDelay(
            attempt: reconnectAttempts,
            base: Self.baseReconnectDelay,
            max: Self.maxReconnectDelay
        )
        reconnectAttempts += 1
        logger.info("Reconnecting \(self.interfaceId) in \(delay)s (attempt \(self.reconnectAttempts))")

        Task.detached { [weak self] in
            try? await Task.sleep(for: .seconds(delay))
            await self?.attemptReconnect()
        }
    }

    /// Attempt reconnection if still desired and offline.
    private func attemptReconnect() {
        guard shouldReconnect && !_isOnline else { return }
        createAndStartConnection()
    }
}
