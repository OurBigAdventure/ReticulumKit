// SPDX-License-Identifier: MIT
// Transport.swift — Central coordinator for interfaces, packet routing, and announce management
//
// The Transport actor is the "central nervous system" of a ReticulumKit node.
// It reads packets from interfaces, validates announces, updates the routing table,
// and sends announces out through all connected interfaces.

import Foundation
import CryptoKit
import Logging

/// Central coordinator that wires network interfaces to announce handling and routing.
///
/// Transport reads packets from all registered interfaces, validates incoming announces,
/// inserts them into the routing table, and sends outgoing announces through all online
/// interfaces while respecting per-interface rate limits.
public actor Transport {

    // MARK: - Public Properties

    /// Routing table populated by validated incoming announces.
    public let routingTable = RoutingTable()

    // MARK: - Private State

    /// All registered network interfaces.
    private var interfaces: [any NetworkInterface] = []

    /// Per-interface rate limiters keyed by interfaceId.
    private var rateLimiters: [String: AnnounceRateLimiter] = [:]

    /// Tracks random hashes from accepted announces for replay protection (T-02-10).
    private var seenAnnounceHashes: Set<Data> = []

    /// Maximum number of tracked announce hashes before pruning.
    private static let maxSeenHashes = 16_384

    /// Number of entries to remove when pruning seen hashes.
    private static let pruneCount = 1_000

    /// Background task for periodic re-announce.
    private var reAnnounceTask: Task<Void, Never>?

    /// Background tasks listening to each interface's incoming packet stream.
    private var interfaceListenerTasks: [Task<Void, Never>] = []

    /// Destinations this node announces for.
    private var localDestinations: [Destination] = []

    /// Optional app data per destination hash.
    private var localAppData: [TruncatedHash: Data] = [:]

    /// Tracks last path request time per destination for rate limiting (T-03-02).
    private var pathRequestTimes: [TruncatedHash: Date] = [:]

    /// Active links keyed by link ID.
    private var activeLinks: [TruncatedHash: Link] = [:]

    /// Pending initiator links keyed by target destination hash.
    private var pendingLinks: [TruncatedHash: Link] = [:]

    /// Identities for local destinations, keyed by destination hash.
    private var localIdentities: [TruncatedHash: Identity] = [:]

    /// Callback for link data packets with contexts not handled internally (RTT, keepalive, close).
    private var linkDataCallback: (@Sendable (Packet, Link) async -> Void)?

    /// Callback for single-destination data packets (non-link addressed).
    private var packetDataCallback: (@Sendable (Packet) async -> Void)?

    /// Callbacks for validated incoming announces.
    private var announceCallbacks: [@Sendable (AnnounceResult) async -> Void] = []

    /// Logger for transport events.
    private let logger = Logger(label: "reticulumkit.transport")

    // MARK: - Initialization

    public init() {}

    // MARK: - Interface Management

    /// Register a network interface and start listening for incoming packets.
    ///
    /// Creates a per-interface rate limiter and spawns a background task that
    /// iterates the interface's incoming packet stream, dispatching each packet
    /// to `processIncomingPacket`.
    ///
    /// - Parameter interface: The network interface to add.
    public func addInterface(_ interface: any NetworkInterface) async {
        interfaces.append(interface)
        rateLimiters[interface.interfaceId] = AnnounceRateLimiter(bitrate: interface.bitrate)

        let task = Task { [weak self] in
            for await raw in interface.incomingPackets {
                guard let self else { return }
                await self.processIncomingPacket(raw, from: interface)
            }
        }
        interfaceListenerTasks.append(task)
    }

    // MARK: - Destination Registration

    /// Register a local destination for announcing.
    ///
    /// - Parameters:
    ///   - destination: The destination to register.
    ///   - identity: Optional identity for this destination (needed for link request handling).
    ///   - appData: Optional application data to include in announces.
    public func registerDestination(_ destination: Destination, identity: Identity? = nil, appData: Data? = nil) {
        localDestinations.append(destination)
        if let identity {
            localIdentities[destination.hash] = identity
        }
        if let appData {
            localAppData[destination.hash] = appData
        }
    }

    // MARK: - Data Callback Registration

    /// Register a callback for link data packets with contexts not handled internally
    /// (RTT, keepalive, close are handled internally; all other contexts go to this callback).
    public func onLinkData(_ callback: @escaping @Sendable (Packet, Link) async -> Void) {
        linkDataCallback = callback
    }

    /// Register a callback for non-link single-destination data packets.
    public func onPacketData(_ callback: @escaping @Sendable (Packet) async -> Void) {
        packetDataCallback = callback
    }

    /// Register a callback for validated incoming announces.
    public func onAnnounce(_ callback: @escaping @Sendable (AnnounceResult) async -> Void) {
        announceCallbacks.append(callback)
    }

    // MARK: - Interface Status

    /// Return the current status of all registered interfaces.
    ///
    /// Queries each interface's `isOnline` property and returns a list of
    /// (id, isOnline) tuples for UI display. Replaces the Phase 5 placeholder
    /// in AppService.refreshInterfaceStatus().
    ///
    /// - Returns: Array of interface ID and online status pairs.
    public func interfaceStatuses() async -> [(id: String, isOnline: Bool)] {
        var statuses: [(id: String, isOnline: Bool)] = []
        for iface in interfaces {
            let online = await iface.isOnline
            statuses.append((id: iface.interfaceId, isOnline: online))
        }
        return statuses
    }

    // MARK: - Packet Sending

    /// Send a packet through all online interfaces.
    ///
    /// - Parameter packet: The packet to send.
    /// - Throws: If packing fails.
    public func sendPacket(_ packet: Packet) async throws {
        let packedData = try packet.pack()
        for interface in interfaces {
            let isOnline = await interface.isOnline
            guard isOnline else { continue }
            do {
                try await interface.send(packedData)
            } catch {
                logger.warning("Failed to send packet on \(interface.interfaceId): \(error)")
            }
        }
    }

    // MARK: - Incoming Packet Processing

    /// Process a raw packet received from an interface.
    ///
    /// Unpacks the packet and dispatches based on packet type. Only announce
    /// packets are handled in Phase 2; other types are logged and skipped.
    /// Malformed packets are silently dropped (T-02-11).
    ///
    /// - Parameters:
    ///   - raw: Raw wire-format bytes.
    ///   - interface: The interface the packet arrived on.
    private func processIncomingPacket(_ raw: Data, from interface: any NetworkInterface) async {
        guard let packet = try? Packet.unpack(raw) else {
            logger.warning("Failed to unpack packet from \(interface.interfaceId)")
            return
        }

        switch packet.header.packetType {
        case .announce:
            // Handles both normal announces (context=.none) and pathResponse announces
            // (context=.pathResponse). Announce.validate() does not check context,
            // so path responses are validated identically and inserted into routing table.
            await handleAnnounce(packet, from: interface)
        case .linkRequest:
            await handleLinkRequest(raw, packet: packet, from: interface)
        case .proof:
            if packet.context == .lrProof {
                await handleLinkProof(raw, packet: packet, from: interface)
            } else {
                logger.debug("Non-link proof context \(packet.context), skipping")
            }
        case .data:
            if packet.header.destinationType == .link {
                await handleLinkData(packet, from: interface)
            } else {
                if let packetDataCallback {
                    await packetDataCallback(packet)
                } else {
                    logger.debug("Non-link data packet, skipping (Phase 4+)")
                }
            }
        }
    }

    // MARK: - Path Requests

    /// Send a path request for an unknown destination through all online interfaces.
    ///
    /// If the destination is already in the routing table, returns immediately.
    /// Rate limited to one request per destination per `LinkConstants.pathRequestMinInterval` (T-03-02).
    ///
    /// - Parameter destinationHash: The destination hash to request a path for.
    /// - Throws: If packet creation or packing fails.
    public func requestPath(to destinationHash: TruncatedHash) async throws {
        // Skip if destination already known
        if await routingTable.hasPath(for: destinationHash) {
            logger.debug("Path already known for \(destinationHash.hexString)")
            return
        }

        // Rate limit: refuse if last request was less than pathRequestMinInterval ago
        if let lastRequest = pathRequestTimes[destinationHash] {
            let elapsed = Date().timeIntervalSince(lastRequest)
            if elapsed < LinkConstants.pathRequestMinInterval {
                logger.debug("Path request rate limited for \(destinationHash.hexString)")
                return
            }
        }

        let packet = try PathRequest.create(targetHash: destinationHash)
        let packedData = try packet.pack()

        for interface in interfaces {
            let isOnline = await interface.isOnline
            guard isOnline else { continue }
            do {
                try await interface.send(packedData)
            } catch {
                logger.warning("Failed to send path request on \(interface.interfaceId): \(error)")
            }
        }

        pathRequestTimes[destinationHash] = Date()
    }

    /// Handle an incoming announce packet.
    ///
    /// Validates the announce (signature + destination hash reconstruction),
    /// checks for replay (duplicate random hash), then inserts into the routing table.
    /// Logs only the first 4 bytes of the destination hash (T-02-12).
    ///
    /// - Parameters:
    ///   - packet: The unpacked announce packet.
    ///   - interface: The interface it arrived on.
    private func handleAnnounce(_ packet: Packet, from interface: any NetworkInterface) async {
        // T-02-09: Validate signature and destination hash before any routing table insertion
        guard let result = try? Announce.validate(packet: packet) else {
            logger.warning("Invalid announce rejected from \(interface.interfaceId)")
            return
        }

        // T-02-10: Replay protection via random hash tracking
        guard !seenAnnounceHashes.contains(result.randomHash) else {
            logger.debug("Duplicate announce ignored from \(interface.interfaceId)")
            return
        }

        seenAnnounceHashes.insert(result.randomHash)

        // Cap seen hashes to prevent unbounded growth
        if seenAnnounceHashes.count > Self.maxSeenHashes {
            let toRemove = Array(seenAnnounceHashes.prefix(Self.pruneCount))
            for hash in toRemove {
                seenAnnounceHashes.remove(hash)
            }
        }

        let entry = RouteEntry(
            destinationHash: result.destinationHash,
            publicKey: result.publicKey,
            nameHash: result.nameHash,
            appData: result.appData,
            hops: packet.header.hops,
            timestamp: Date(),
            interfaceId: interface.interfaceId
        )

        await routingTable.addEntry(entry)

        // Notify announce callbacks
        for callback in announceCallbacks {
            await callback(result)
        }

        // T-02-12: Log only first 4 bytes of destination hash
        logger.info("Announce accepted: \(result.destinationHash.data.prefix(4).hexEncodedString)")
    }

    // MARK: - Link Management

    /// Establish a link to a remote destination.
    ///
    /// Creates an initiator Link, sends the link request through all online interfaces,
    /// and stores the link in pendingLinks keyed by the target destination hash.
    ///
    /// - Parameters:
    ///   - destinationHash: The destination hash to link to.
    ///   - identity: The local identity for the initiator side.
    /// - Returns: The created Link (in .pending status).
    public func establishLink(to destinationHash: TruncatedHash, identity: Identity) async throws -> Link {
        let link = Link.initiator(to: destinationHash, identity: identity)
        let (packet, _) = try await link.createRequest()
        let packedData = try packet.pack()

        pendingLinks[destinationHash] = link

        for interface in interfaces {
            let isOnline = await interface.isOnline
            guard isOnline else { continue }
            do {
                try await interface.send(packedData)
            } catch {
                logger.warning("Failed to send link request on \(interface.interfaceId): \(error)")
            }
        }

        return link
    }

    /// Close an active link, sending a teardown packet.
    ///
    /// - Parameters:
    ///   - linkId: The link ID to close.
    ///   - reason: The teardown reason.
    public func closeLink(_ linkId: TruncatedHash, reason: Link.TeardownReason) async throws {
        guard let link = activeLinks[linkId] else { return }

        let teardownPacket = await link.close(reason: reason)
        activeLinks.removeValue(forKey: linkId)

        if let teardownPacket {
            let packedData = try teardownPacket.pack()
            for interface in interfaces {
                let isOnline = await interface.isOnline
                guard isOnline else { continue }
                do {
                    try await interface.send(packedData)
                } catch {
                    logger.warning("Failed to send teardown on \(interface.interfaceId): \(error)")
                }
            }
        }
    }

    /// Look up an active link by link ID.
    ///
    /// - Parameter linkId: The link ID to look up.
    /// - Returns: The active Link if found, nil otherwise.
    public func link(for linkId: TruncatedHash) -> Link? {
        activeLinks[linkId]
    }

    // MARK: - Link Request Handling

    /// Handle an incoming link request: create responder link if destination is local.
    private func handleLinkRequest(_ raw: Data, packet: Packet, from interface: any NetworkInterface) async {
        // T-03-10: Only process link requests for registered local destinations
        guard let responderIdentity = localIdentities[packet.destinationHash] else {
            logger.debug("Link request for unregistered destination \(packet.destinationHash.data.prefix(4).hexEncodedString), dropping")
            return
        }

        do {
            let (responderLink, proofPacket) = try Link.respondToRequest(
                rawPacket: raw,
                packet: packet,
                responderIdentity: responderIdentity
            )

            let linkId = await responderLink.linkId
            activeLinks[linkId] = responderLink

            let packedProof = try proofPacket.pack()
            try await interface.send(packedProof)
            logger.info("Link request accepted, proof sent for \(linkId.data.prefix(4).hexEncodedString)")
        } catch {
            logger.warning("Failed to respond to link request: \(error)")
        }
    }

    /// Handle an incoming link proof: complete initiator handshake.
    private func handleLinkProof(_ raw: Data, packet: Packet, from interface: any NetworkInterface) async {
        // The proof packet's destinationHash is the linkId
        let proofLinkId = packet.destinationHash

        // Find the pending link whose linkId matches
        var matchedDestHash: TruncatedHash?
        var matchedLink: Link?
        for (destHash, link) in pendingLinks {
            let linkId = await link.linkId
            if linkId == proofLinkId {
                matchedDestHash = destHash
                matchedLink = link
                break
            }
        }

        guard let destHash = matchedDestHash, let link = matchedLink else {
            logger.debug("No pending link found for proof linkId \(proofLinkId.data.prefix(4).hexEncodedString)")
            return
        }

        // Look up peer identity from routing table
        guard let routeEntry = await routingTable.lookup(destHash) else {
            logger.warning("No route entry for destination \(destHash.data.prefix(4).hexEncodedString), cannot verify proof")
            return
        }

        // Reconstruct peer Identity from public key bytes (X25519:32 + Ed25519:32)
        // We need the Ed25519 signing public key for signature verification
        guard routeEntry.publicKey.count == 64 else {
            logger.warning("Invalid public key size in route entry")
            return
        }

        do {
            // Create a verification-only Identity from the route entry's public key bytes.
            // This Identity can verify signatures but cannot sign or decrypt.
            let peerIdentity = try Identity(publicKeyBytes: routeEntry.publicKey)

            try await link.processProof(
                rawProofPacket: raw,
                proofPacket: packet,
                peerIdentity: peerIdentity
            )

            // Create and send RTT packet
            let rttPacket = try await link.createRTTPacket()
            let packedRTT = try rttPacket.pack()

            // Move from pending to active
            let linkId = await link.linkId
            pendingLinks.removeValue(forKey: destHash)
            activeLinks[linkId] = link

            for iface in interfaces {
                let isOnline = await iface.isOnline
                guard isOnline else { continue }
                do {
                    try await iface.send(packedRTT)
                } catch {
                    logger.warning("Failed to send RTT on \(iface.interfaceId): \(error)")
                }
            }

            logger.info("Link established with \(linkId.data.prefix(4).hexEncodedString)")
        } catch {
            logger.warning("Failed to process link proof: \(error)")
        }
    }

    /// Handle link-addressed data packets (RTT, keepalive, teardown).
    private func handleLinkData(_ packet: Packet, from interface: any NetworkInterface) async {
        let linkId = packet.destinationHash

        guard let link = activeLinks[linkId] else {
            logger.debug("No active link for \(linkId.data.prefix(4).hexEncodedString)")
            return
        }

        do {
            switch packet.context {
            case .lrRTT:
                try await link.processRTT(packet: packet)
                logger.debug("RTT processed for link \(linkId.data.prefix(4).hexEncodedString)")

            case .keepalive:
                let reply = try await link.handleKeepalive(packet: packet)
                if let reply {
                    let packedReply = try reply.pack()
                    try await interface.send(packedReply)
                }

            case .linkClose:
                try await link.handleIncomingTeardown(packet: packet)
                activeLinks.removeValue(forKey: linkId)
                logger.info("Link \(linkId.data.prefix(4).hexEncodedString) closed by peer")

            default:
                if let linkDataCallback {
                    await linkDataCallback(packet, link)
                } else {
                    logger.debug("Unhandled link data context \(packet.context) for \(linkId.data.prefix(4).hexEncodedString)")
                }
            }
        } catch {
            logger.warning("Failed to handle link data: \(error)")
        }
    }

    // MARK: - Outgoing Announces

    /// Send an announce for a destination through all online interfaces.
    ///
    /// Creates a signed announce packet and sends it through each interface,
    /// respecting per-interface rate limits.
    ///
    /// - Parameters:
    ///   - destination: The destination to announce.
    ///   - appData: Optional app data (falls back to registered app data).
    /// - Throws: If announce creation or packing fails.
    public func sendAnnounce(for destination: Destination, appData: Data? = nil) async throws {
        let packet = try Announce.create(
            destination: destination,
            appData: appData ?? localAppData[destination.hash]
        )
        let packedData = try packet.pack()

        for interface in interfaces {
            let limiter = rateLimiters[interface.interfaceId]
            if let limiter, await !limiter.canSend() {
                logger.debug("Rate limited on \(interface.interfaceId)")
                continue
            }
            do {
                try await interface.send(packedData)
                await limiter?.recordSend(packetSize: packedData.count)
            } catch {
                logger.warning("Failed to send announce on \(interface.interfaceId): \(error)")
            }
        }
    }

    // MARK: - Periodic Re-Announce

    /// Start periodic re-announce of all registered destinations.
    ///
    /// - Parameter interval: Time between re-announces in seconds. Defaults to 1800 (30 minutes).
    public func startReAnnounce(interval: TimeInterval = 1800) async {
        reAnnounceTask?.cancel()
        reAnnounceTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(interval))
                guard let self, !Task.isCancelled else { return }
                for dest in await self.localDestinations {
                    try? await self.sendAnnounce(for: dest)
                }
            }
        }
    }

    /// Stop periodic re-announce.
    public func stopReAnnounce() {
        reAnnounceTask?.cancel()
        reAnnounceTask = nil
    }

    // MARK: - Lifecycle

    /// Shut down the transport: stop re-announce, cancel all listeners, stop all interfaces.
    public func shutdown() async {
        stopReAnnounce()

        for task in interfaceListenerTasks {
            task.cancel()
        }
        interfaceListenerTasks.removeAll()

        for interface in interfaces {
            await interface.stop()
        }
    }
}

// MARK: - Data Hex String Extension

extension Data {
    /// Hex string representation for logging (e.g., "a1b2c3d4").
    var hexEncodedString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
