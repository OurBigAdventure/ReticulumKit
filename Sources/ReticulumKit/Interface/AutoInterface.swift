// SPDX-License-Identifier: MIT
// AutoInterface.swift — UDP multicast interface for local WiFi peer discovery
//
// Stub for TDD RED phase — tests should fail against this.

import Foundation
import Network
import CryptoKit
import Logging

/// UDP multicast interface for local WiFi peer discovery using NWConnectionGroup.
///
/// AutoInterface enables two devices on the same WiFi network to discover each other
/// and exchange Reticulum packets via IPv6 UDP multicast. Unlike TCPInterface, this
/// interface sends raw UDP datagrams with NO HDLC framing.
///
/// Discovery uses a peering protocol: devices exchange SHA-256-based discovery tokens
/// to verify membership in the same group before accepting traffic.
public actor AutoInterface: NetworkInterface {

    // MARK: - Peer type

    /// A discovered peer on the local network.
    internal struct Peer: Sendable {
        let address: String
        var lastSeen: Date
        let discoveryToken: Data
    }

    // MARK: - Constants

    /// Maximum number of tracked peers (T-06-06 DoS mitigation).
    internal static let maxPeers = 128

    /// Peering timeout in seconds — peers not seen within this window are pruned.
    internal static let peeringTimeout: TimeInterval = 22.0

    /// Discovery port (matching Python Reticulum AutoInterface default).
    private let discoveryPort: UInt16 = 29716

    /// Data port (matching Python Reticulum AutoInterface default).
    private let dataPort: UInt16 = 42671

    // MARK: - Public properties (nonisolated for cross-actor access)

    /// Unique identifier for this interface.
    public nonisolated let interfaceId: String = "AutoInterface"

    /// Nominal bitrate in bits/second (10 Mbps WiFi estimate).
    public nonisolated let bitrate: Int = 10_000_000

    /// Stream of incoming raw packet data.
    public nonisolated let incomingPackets: AsyncStream<Data>

    /// Whether the interface is currently online (multicast group joined and ready).
    public var isOnline: Bool { _isOnline }

    /// Number of currently tracked peers.
    public var peerCount: Int { peers.count }

    // MARK: - Private state

    private let groupId: String
    private var _isOnline = false
    private var peers: [String: Peer] = [:]
    private var incomingContinuation: AsyncStream<Data>.Continuation?
    private var discoveryGroup: NWConnectionGroup?
    private var dataGroup: NWConnectionGroup?
    private var pruneTask: Task<Void, Never>?
    /// Link-local address used for discovery token emission (Python sender address).
    private var localDiscoveryAddress: String?
    private let logger = Logger(label: "ReticulumKit.AutoInterface")

    /// Resolve the primary link-local IPv6 address for discovery token computation.
    public static func resolveLinkLocalAddress() -> String? {
        LinkLocalAddress.primary()
    }

    // MARK: - Init

    /// Create an AutoInterface for the given group.
    ///
    /// - Parameter groupId: The multicast group identifier (default: "reticulum").
    public init(groupId: String = "reticulum") {
        self.groupId = groupId
        let (stream, continuation) = AsyncStream.makeStream(of: Data.self)
        self.incomingPackets = stream
        self.incomingContinuation = continuation
    }

    // MARK: - Static Helpers

    /// Derive an IPv6 multicast address from a group identifier.
    ///
    /// Computes SHA-256 of the group ID and constructs an ff12:0: prefixed IPv6
    /// multicast address from hash bytes, matching the Python Reticulum derivation.
    ///
    /// - Parameter groupId: The group identifier string (e.g., "reticulum").
    /// - Returns: An IPv6 multicast address string (e.g., "ff12:0:abcd:...").
    public static func deriveMulticastAddress(groupId: String) -> String {
        let hash = Array(SHA256.hash(data: Data(groupId.utf8)))
        // Python: addr_hash_bytes = addr_hash[2:14] (12 bytes at indices 2..13)
        // Format as byte-swapped pairs: bytes[3]bytes[2]:bytes[5]bytes[4]:...
        return String(
            format: "ff12:0:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            hash[3], hash[2], hash[5], hash[4], hash[7], hash[6],
            hash[9], hash[8], hash[11], hash[10], hash[13], hash[12]
        )
    }

    /// Compute a discovery token for peer verification.
    ///
    /// The token is SHA-256(groupId.utf8 + address.utf8) truncated to 16 bytes.
    /// Used to verify that a peer belongs to the same multicast group.
    ///
    /// - Parameters:
    ///   - groupId: The group identifier string.
    ///   - address: The peer's link-local address (without scope ID).
    /// - Returns: A 16-byte discovery token.
    public static func discoveryToken(groupId: String, address: String) -> Data {
        var input = Data(groupId.utf8)
        input.append(contentsOf: address.utf8)
        let hash = SHA256.hash(data: input)
        return Data(hash.prefix(16))
    }

    // MARK: - Peer Management

    /// Add or update a discovered peer.
    ///
    /// If the peer count would exceed `maxPeers`, the oldest peer is evicted first
    /// (T-06-06 DoS mitigation).
    ///
    /// - Parameters:
    ///   - address: The peer's address.
    ///   - token: The peer's validated discovery token.
    internal func addPeer(address: String, token: Data) {
        // If already tracked, just update lastSeen
        if peers[address] != nil {
            peers[address]?.lastSeen = Date()
            return
        }

        // Evict oldest if at capacity
        if peers.count >= Self.maxPeers {
            if let oldest = peers.min(by: { $0.value.lastSeen < $1.value.lastSeen }) {
                peers.removeValue(forKey: oldest.key)
            }
        }

        peers[address] = Peer(address: address, lastSeen: Date(), discoveryToken: token)
    }

    /// Add a peer with a specific lastSeen time (for testing peer eviction).
    internal func addPeerForTesting(address: String, token: Data, lastSeen: Date) {
        // Evict oldest if at capacity
        if peers.count >= Self.maxPeers {
            if let oldest = peers.min(by: { $0.value.lastSeen < $1.value.lastSeen }) {
                peers.removeValue(forKey: oldest.key)
            }
        }

        peers[address] = Peer(address: address, lastSeen: lastSeen, discoveryToken: token)
    }

    /// Remove peers that haven't been seen within the peering timeout (22 seconds).
    internal func prunePeers() {
        let cutoff = Date().addingTimeInterval(-Self.peeringTimeout)
        peers = peers.filter { $0.value.lastSeen > cutoff }
    }

    // MARK: - NetworkInterface Lifecycle

    /// Start the multicast interface: join discovery and data multicast groups.
    ///
    /// Creates NWConnectionGroup instances for both the discovery port (peer exchange)
    /// and data port (packet transfer). Sets up receive handlers and state monitoring.
    public func start() async throws {
        let multicastAddress = Self.deriveMulticastAddress(groupId: groupId)
        let queue = DispatchQueue(label: "reticulumkit.autointerface")

        // Discovery group — for peering protocol
        guard let discoveryMulticast = try? NWMulticastGroup(for: [
            .hostPort(
                host: NWEndpoint.Host(multicastAddress),
                port: NWEndpoint.Port(rawValue: discoveryPort)!
            )
        ]) else {
            throw ReticulumError.interfaceOffline
        }

        let dGroup = NWConnectionGroup(with: discoveryMulticast, using: .udp)

        // T-06-07: Reject oversized discovery messages (max 1024 bytes)
        dGroup.setReceiveHandler(maximumMessageSize: 1024, rejectOversizedMessages: true) {
            [weak self] (message: NWConnectionGroup.Message, content: Data?, isComplete: Bool) in
            guard let self, let content else { return }
            Task { await self.handleDiscoveryReceive(message: message, content: content) }
        }

        dGroup.stateUpdateHandler = { [weak self] (state: NWConnectionGroup.State) in
            guard let self else { return }
            Task { await self.handleStateUpdate(state) }
        }

        dGroup.start(queue: queue)
        self.discoveryGroup = dGroup

        // Data group — for raw Reticulum packets
        guard let dataMulticast = try? NWMulticastGroup(for: [
            .hostPort(
                host: NWEndpoint.Host(multicastAddress),
                port: NWEndpoint.Port(rawValue: dataPort)!
            )
        ]) else {
            throw ReticulumError.interfaceOffline
        }

        let dtGroup = NWConnectionGroup(with: dataMulticast, using: .udp)

        // T-06-07: Reject oversized data messages (max 2048 bytes)
        dtGroup.setReceiveHandler(maximumMessageSize: 2048, rejectOversizedMessages: true) {
            [weak self] (message: NWConnectionGroup.Message, content: Data?, isComplete: Bool) in
            guard let self, let content else { return }
            Task { await self.handleDataReceive(content: content) }
        }

        dtGroup.start(queue: queue)
        self.dataGroup = dtGroup

        // Start periodic peer pruning (every 10 seconds)
        pruneTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(10))
                guard let self, !Task.isCancelled else { return }
                await self.prunePeers()
            }
        }

        // Send initial discovery announcement
        await sendDiscoveryAnnouncement()
    }

    /// Send raw packet data via the data multicast group.
    ///
    /// CRITICAL: No HDLC framing — each UDP datagram is exactly one Reticulum packet.
    ///
    /// - Parameter data: Raw packet bytes to send.
    /// - Throws: `ReticulumError.interfaceOffline` if the data group is not ready.
    public func send(_ data: Data) async throws {
        guard _isOnline, let dataGroup else {
            throw ReticulumError.interfaceOffline
        }
        dataGroup.send(content: data) { [weak self] error in
            if let error {
                Task { [weak self] in
                    self?.logger.warning("Send failed: \(error.localizedDescription)")
                }
            }
        }
    }

    /// Stop the interface: cancel multicast groups, clear peers, finish stream.
    public func stop() async {
        _isOnline = false
        pruneTask?.cancel()
        pruneTask = nil
        discoveryGroup?.cancel()
        discoveryGroup = nil
        dataGroup?.cancel()
        dataGroup = nil
        peers.removeAll()
        incomingContinuation?.finish()
        incomingContinuation = nil
        logger.info("Stopped AutoInterface")
    }

    // MARK: - Private Handlers

    /// Handle state updates from the connection groups.
    private func handleStateUpdate(_ state: NWConnectionGroup.State) {
        switch state {
        case .ready:
            _isOnline = true
            if localDiscoveryAddress == nil {
                localDiscoveryAddress = Self.resolveLinkLocalAddress()
            }
            logger.info("AutoInterface ready")
            Task { await self.sendDiscoveryAnnouncement() }
        case .failed(let error):
            _isOnline = false
            logger.warning("AutoInterface failed: \(error.localizedDescription)")
        case .cancelled:
            _isOnline = false
        default:
            break
        }
    }

    /// Handle incoming discovery messages: validate token and register peer.
    ///
    /// T-06-05: Verify token = SHA-256(group_id + sender_address) before accepting peer.
    private func handleDiscoveryReceive(message: NWConnectionGroup.Message, content: Data) {
        guard content.count == 16 else {
            logger.debug("Discovery message wrong size: \(content.count)")
            return
        }

        // Extract sender address from the message's remote endpoint
        guard let remoteEndpoint = message.remoteEndpoint,
              case .hostPort(let host, _) = remoteEndpoint else {
            return
        }

        let senderAddress = "\(host)"
        let expectedToken = Self.discoveryToken(groupId: groupId, address: senderAddress)

        // T-06-05: Reject mismatched tokens
        guard content == expectedToken else {
            logger.debug("Discovery token mismatch from \(senderAddress)")
            return
        }

        let isNew = peers[senderAddress] == nil
        addPeer(address: senderAddress, token: content)

        // If new peer, send our own discovery token back
        if isNew {
            Task { await self.sendDiscoveryAnnouncement() }
        }
    }

    /// Handle incoming data messages: feed raw bytes to incoming packet stream.
    private func handleDataReceive(content: Data) {
        incomingContinuation?.yield(content)
    }

    /// Send our discovery token to the multicast group.
    private func sendDiscoveryAnnouncement() async {
        guard let discoveryGroup else { return }

        guard let address = localDiscoveryAddress ?? Self.resolveLinkLocalAddress() else {
            logger.debug("No link-local address for discovery token")
            return
        }
        localDiscoveryAddress = address
        let token = Self.discoveryToken(groupId: groupId, address: address)

        discoveryGroup.send(content: token) { error in
            if let error {
                _ = error
            }
        }
    }
}
