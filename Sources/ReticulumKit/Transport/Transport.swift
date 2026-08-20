// SPDX-License-Identifier: MIT
// Transport.swift — Central coordinator for interfaces, packet routing, and announce management
//
// The Transport actor is the "central nervous system" of a ReticulumKit node.
// It reads packets from interfaces, validates announces, updates the routing table,
// and sends announces out through all connected interfaces.

import Foundation
import CryptoKit
import Logging
import MessagePack

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

    /// Background tasks listening to each interface's incoming packet stream, keyed by interfaceId.
    private var interfaceListenerTasks: [String: Task<Void, Never>] = [:]

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

    /// Callback for non-link proof packets (delivery proofs).
    private var proofCallback: (@Sendable (Packet) async -> Void)?

    /// Callbacks for validated incoming announces.
    private var announceCallbacks: [@Sendable (AnnounceResult) async -> Void] = []

    /// Pending link REQUEST continuations keyed by truncated request id.
    private var pendingLinkRequests: [Data: CheckedContinuation<Data, Error>] = [:]

    /// Optional handler for inbound link REQUEST payloads `(link, pathHash, payload) -> responseData`.
    private var linkRequestHandler: (@Sendable (Link, Data, Data) async -> Data?)?

    /// Incoming assembled resource payload (receiver side).
    private var incomingResourceCallback: (@Sendable (Data, Link) async -> Void)?

    /// Outgoing resource reached COMPLETE (initiator side).
    private var outgoingResourceCallback: (@Sendable (Resource, Link) async -> Void)?

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
        interfaceListenerTasks[interface.interfaceId] = task
    }

    /// Unregister a network interface by id.
    ///
    /// Cancels the interface's packet listener task and removes its rate limiter.
    /// The caller is responsible for stopping the interface before (or instead of)
    /// calling this method — `InterfaceManager.remove(interfaceId:)` already does so.
    ///
    /// - Parameter id: The `interfaceId` of the interface to remove.
    public func removeInterface(id: String) async {
        interfaceListenerTasks[id]?.cancel()
        interfaceListenerTasks.removeValue(forKey: id)
        rateLimiters.removeValue(forKey: id)
        interfaces.removeAll { $0.interfaceId == id }
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

    /// Register a callback for non-link proof packets (delivery proofs).
    public func onProof(_ callback: @escaping @Sendable (Packet) async -> Void) {
        proofCallback = callback
    }

    /// Register a callback for validated incoming announces.
    public func onAnnounce(_ callback: @escaping @Sendable (AnnounceResult) async -> Void) {
        announceCallbacks.append(callback)
    }

    /// Handle inbound link REQUEST packets (Python `Link.handle_request`) on hosted destinations.
    public func onLinkRequest(_ handler: @escaping @Sendable (Link, Data, Data) async -> Data?) {
        linkRequestHandler = handler
    }

    /// Called when an incoming resource has been assembled (plaintext payload).
    public func onIncomingResource(_ callback: @escaping @Sendable (Data, Link) async -> Void) {
        incomingResourceCallback = callback
    }

    /// Called when an outgoing resource transfer completes.
    public func onOutgoingResource(_ callback: @escaping @Sendable (Resource, Link) async -> Void) {
        outgoingResourceCallback = callback
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

        logger.info("rx: type=\(packet.header.packetType) ctx=\(packet.context) dstType=\(packet.header.destinationType) dst=\(packet.destinationHash.data.prefix(4).hexEncodedString) bytes=\(raw.count) iface=\(interface.interfaceId)")

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
            } else if packet.context == .resourcePRF {
                await handleResourceProof(packet)
            } else if let proofCallback {
                await proofCallback(packet)
            } else {
                logger.debug("Non-link proof context \(packet.context), no handler registered")
            }
        case .data:
            if packet.header.destinationType == .link {
                await handleLinkData(packet, from: interface)
            } else if packet.header.destinationType == .plain
                && localDestinations.contains(where: { $0.hash == packet.destinationHash }) {
                // A broadcast `.data .plain` packet addressed to one of our
                // local destinations — treat as a path request from a peer
                // looking us up. Reply with our announce in pathResponse ctx.
                await handleIncomingPathRequest(packet, from: interface)
            } else {
                if let packetDataCallback {
                    await packetDataCallback(packet)
                } else {
                    logger.debug("Non-link data packet, skipping (Phase 4+)")
                }
            }
        }
    }

    /// Respond to an incoming path request.
    ///
    /// Path requests are broadcast `.data .plain` packets whose header destination
    /// is the destination being looked up. If the looked-up hash is one of our
    /// local destinations, reply with our announce in `pathResponse` context so
    /// the requester learns where to find us. Without this, peers like Sideband /
    /// Columba spin forever when adding us by hash.
    private func handleIncomingPathRequest(_ packet: Packet, from interface: any NetworkInterface) async {
        let targetHash = packet.destinationHash
        let targetHex = targetHash.data.prefix(4).hexEncodedString

        guard let localDest = localDestinations.first(where: { $0.hash == targetHash }) else {
            // Should be impossible because the dispatch already checked, but be defensive.
            logger.debug("path request: dispatch matched but destination missing for \(targetHex)")
            return
        }

        do {
            let appData = localAppData[targetHash]
            let basePacket = try Announce.create(destination: localDest, appData: appData)
            // Re-emit with pathResponse context so recipients know this is a reply.
            let response = Packet(
                header: basePacket.header,
                destinationHash: basePacket.destinationHash,
                transportId: basePacket.transportId,
                context: .pathResponse,
                data: basePacket.data
            )
            let packedData = try response.pack()
            try await interface.send(packedData)
            logger.info("path request: replied for local \(targetHex) on \(interface.interfaceId) (\(packedData.count) bytes)")
        } catch {
            logger.warning("path request: failed to build response for \(targetHex): \(error)")
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
        let destHex = destinationHash.data.prefix(4).hexEncodedString
        // Skip if destination already known
        if await routingTable.hasPath(for: destinationHash) {
            logger.info("requestPath: path already known for \(destHex)")
            return
        }

        // Rate limit: refuse if last request was less than pathRequestMinInterval ago
        if let lastRequest = pathRequestTimes[destinationHash] {
            let elapsed = Date().timeIntervalSince(lastRequest)
            if elapsed < LinkConstants.pathRequestMinInterval {
                logger.warning("requestPath: rate-limited for \(destHex) (last request \(Int(elapsed))s ago)")
                return
            }
        }

        let packet = try PathRequest.create(targetHash: destinationHash)
        let packedData = try packet.pack()

        var sentOn = 0
        for interface in interfaces {
            let isOnline = await interface.isOnline
            guard isOnline else { continue }
            do {
                try await interface.send(packedData)
                sentOn += 1
            } catch {
                logger.warning("Failed to send path request on \(interface.interfaceId): \(error)")
            }
        }
        logger.info("requestPath: broadcast for \(destHex) on \(sentOn) interface(s)")

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
        let linkId = await link.linkId
        let destHex = destinationHash.data.prefix(4).hexEncodedString
        let linkHex = linkId.data.prefix(4).hexEncodedString

        let routeEntry = await routingTable.lookup(destinationHash)
        if routeEntry == nil {
            logger.warning("establishLink: no route for \(destHex) -- link request will be broadcast blindly")
        } else {
            logger.debug("establishLink: route known for \(destHex)")
        }

        pendingLinks[destinationHash] = link

        var sentOn = 0
        for interface in interfaces {
            let isOnline = await interface.isOnline
            guard isOnline else {
                logger.debug("establishLink: skipping offline interface \(interface.interfaceId)")
                continue
            }
            do {
                try await interface.send(packedData)
                sentOn += 1
                logger.info("establishLink: link=\(linkHex) -> \(destHex) request sent on \(interface.interfaceId) (\(packedData.count) bytes)")
            } catch {
                logger.warning("establishLink: failed to send link request on \(interface.interfaceId): \(error)")
            }
        }
        if sentOn == 0 {
            logger.warning("establishLink: link=\(linkHex) -> \(destHex) NO online interface; request not transmitted")
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
        let proofHex = proofLinkId.data.prefix(4).hexEncodedString
        logger.info("handleLinkProof: received proof for link=\(proofHex) on \(interface.interfaceId) (\(raw.count) bytes)")

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
            logger.warning("handleLinkProof: no pending link matches proof \(proofHex); pendingLinks count=\(pendingLinks.count)")
            return
        }

        // Look up peer identity from routing table. If we don't have an announce
        // yet for the responder, fall back to processing the proof's ECDH portion
        // alone — the link is then "tentatively" authenticated (confidential
        // tunnel via ECDH, but no peer-identity verification until an announce
        // catches up). This is the difference between "messages can flow now"
        // and "messages never flow because we missed the 30-min announce window".
        let routeEntryOpt = await routingTable.lookup(destHash)

        do {
            if let routeEntry = routeEntryOpt, routeEntry.publicKey.count == 64 {
                let peerIdentity = try Identity(publicKeyBytes: routeEntry.publicKey)
                try await link.processProof(
                    rawProofPacket: raw,
                    proofPacket: packet,
                    peerIdentity: peerIdentity
                )
            } else {
                logger.warning("handleLinkProof: no announce in routing table for \(destHash.data.prefix(4).hexEncodedString); accepting proof via ECDH only (peer identity NOT verified)")
                try await link.processProofWithoutSignatureCheck(
                    rawProofPacket: raw,
                    proofPacket: packet
                )
            }

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

            case .request:
                let plaintext = try await link.decrypt(packet.data)
                if let unpacked = LinkRequestCodec.unpackRequest(plaintext),
                   let handler = linkRequestHandler,
                   let responsePayload = await handler(link, unpacked.pathHash, unpacked.payload) {
                    let requestId = CryptoEngine.truncatedHash(plaintext)
                    let response = LinkRequestCodec.packResponse(requestId: requestId, payload: responsePayload)
                    if response.count <= LinkConstants.mdu {
                        let encrypted = try await link.encrypt(response)
                        let reply = Packet(
                            header: PacketHeader(
                                headerType: .type1,
                                propagationType: .broadcast,
                                destinationType: .link,
                                packetType: .data
                            ),
                            destinationHash: linkId,
                            context: .response,
                            data: encrypted
                        )
                        try await sendPacket(reply)
                    } else {
                        // Python Link.request: oversized packed response rides a Resource
                        // with is_response + request_id so the peer completes linkRequest.
                        let resource = try await Resource.outgoing(
                            plaintext: response,
                            link: link,
                            sendPacket: { [weak self] packet in
                                guard let self else { return }
                                try await self.sendPacket(packet)
                            },
                            autoCompress: false,
                            requestId: requestId,
                            isResponse: true
                        )
                        await link.registerOutgoingResource(resource)
                        try await resource.advertise()
                    }
                }

            case .response:
                let plaintext = try await link.decrypt(packet.data)
                if let unpacked = LinkRequestCodec.unpackResponse(plaintext),
                   let cont = pendingLinkRequests.removeValue(forKey: unpacked.requestId) {
                    cont.resume(returning: unpacked.payload)
                } else if linkDataCallback != nil {
                    await linkDataCallback?(packet, link)
                }

            case .resourceAdv:
                await handleResourceAdvertisement(packet, link: link)
            case .resourceReq:
                await handleResourceRequest(packet, link: link)
            case .resourceHMU:
                await handleResourceHashmapUpdate(packet, link: link)
            case .resource:
                for resource in await link.incomingResourceList() {
                    await resource.receivePart(packet.data)
                    if await resource.status == .complete, let data = await resource.assembledData {
                        if let requestId = await resource.responseRequestId,
                           let cont = pendingLinkRequests.removeValue(forKey: requestId) {
                            // Packed RESPONSE Resource: msgpack [request_id, payload].
                            // File responses may be raw bytes; fall back to whole body.
                            if let unpacked = LinkRequestCodec.unpackResponse(data) {
                                cont.resume(returning: unpacked.payload)
                            } else {
                                cont.resume(returning: data)
                            }
                        } else {
                            await incomingResourceCallback?(data, link)
                        }
                        await link.removeResource(hash: await resource.hash, outgoing: false)
                    }
                }
            case .resourceICL:
                if let plaintext = try? await link.decrypt(packet.data) {
                    let hash = Data(plaintext.prefix(ResourceConstants.identityHashLength))
                    if let resource = await link.incomingResource(hash: hash) {
                        await resource.cancel()
                        await link.removeResource(hash: hash, outgoing: false)
                    }
                }
            case .resourceRCL:
                if let plaintext = try? await link.decrypt(packet.data) {
                    let hash = Data(plaintext.prefix(ResourceConstants.identityHashLength))
                    if let resource = await link.outgoingResource(hash: hash) {
                        await resource.cancel(rejected: true)
                        await link.removeResource(hash: hash, outgoing: true)
                    }
                }

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

    // MARK: - Link.request

    /// Send a Python `Link.request` and await the RESPONSE payload bytes.
    ///
    /// Small replies arrive as CONTEXT RESPONSE packets. Oversized replies may
    /// arrive as a Resource with `is_response` + `request_id`; inbound completion
    /// resumes the same continuation.
    public func linkRequest(
        on link: Link,
        path: String,
        payload: Data?,
        timeout: TimeInterval = 120
    ) async throws -> Data {
        let plaintext = LinkRequestCodec.packRequest(path: path, payload: payload)
        let requestId = CryptoEngine.truncatedHash(plaintext)
        return try await withCheckedThrowingContinuation { continuation in
            pendingLinkRequests[requestId] = continuation
            Task {
                do {
                    let encrypted = try await link.encrypt(plaintext)
                    let linkId = await link.linkId
                    let packet = Packet(
                        header: PacketHeader(
                            headerType: .type1,
                            propagationType: .broadcast,
                            destinationType: .link,
                            packetType: .data
                        ),
                        destinationHash: linkId,
                        context: .request,
                        data: encrypted
                    )
                    try await sendPacket(packet)
                } catch {
                    if pendingLinkRequests.removeValue(forKey: requestId) != nil {
                        continuation.resume(throwing: error)
                    }
                }
            }
            Task {
                try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                if pendingLinkRequests.removeValue(forKey: requestId) != nil {
                    continuation.resume(throwing: ReticulumError.linkRequestTimeout)
                }
            }
        }
    }

    // MARK: - Resources

    /// Send `plaintext` as an RNS Resource on an active link and wait until the
    /// peer proves the transfer (Python `RNS.Resource`).
    public func sendResource(
        on link: Link,
        plaintext: Data,
        timeout: TimeInterval = 120,
        autoCompress: Bool = false
    ) async throws {
        let resource = try await Resource.outgoing(
            plaintext: plaintext,
            link: link,
            sendPacket: { [weak self] packet in
                guard let self else { return }
                try await self.sendPacket(packet)
            },
            autoCompress: autoCompress
        )
        await link.registerOutgoingResource(resource)
        try await resource.advertise()
        try await resource.waitUntilComplete(timeout: timeout)
        await link.removeResource(hash: await resource.hash, outgoing: true)
    }

    private func handleResourceAdvertisement(_ packet: Packet, link: Link) async {
        guard let plaintext = try? await link.decrypt(packet.data),
              let advertisement = try? ResourceAdvertisement.unpack(plaintext) else {
            logger.warning("Invalid resource advertisement")
            return
        }
        let resource = await Resource.incoming(advertisement: advertisement, link: link) { [weak self] packet in
            guard let self else { return }
            try await self.sendPacket(packet)
        }
        await link.registerIncomingResource(resource)
        logger.info("resource incoming hash=\(advertisement.hash.prefix(4).hexEncodedString) parts=\(advertisement.partCount)")
        await resource.requestNext()
    }

    private func handleResourceRequest(_ packet: Packet, link: Link) async {
        guard let plaintext = try? await link.decrypt(packet.data) else { return }
        let hashOffset: Int
        if plaintext.first == ResourceConstants.hashmapExhausted {
            hashOffset = 1 + ResourceConstants.mapHashLength
        } else {
            hashOffset = 1
        }
        guard plaintext.count >= hashOffset + ResourceConstants.identityHashLength else { return }
        let hash = Data(plaintext.dropFirst(hashOffset).prefix(ResourceConstants.identityHashLength))
        if let resource = await link.outgoingResource(hash: hash) {
            await resource.handleRequest(plaintext)
        }
    }

    private func handleResourceHashmapUpdate(_ packet: Packet, link: Link) async {
        guard let plaintext = try? await link.decrypt(packet.data),
              plaintext.count > ResourceConstants.identityHashLength else { return }
        let hash = Data(plaintext.prefix(ResourceConstants.identityHashLength))
        let rest = Data(plaintext.dropFirst(ResourceConstants.identityHashLength))
        guard let decoded = try? MessagePackDecoder().decode(HashmapUpdateWire.self, from: rest) else { return }
        if let resource = await link.incomingResource(hash: hash) {
            await resource.hashmapUpdate(segment: decoded.segment, hashmapBytes: decoded.hashmap)
        }
    }

    private func handleResourceProof(_ packet: Packet) async {
        guard let link = activeLinks[packet.destinationHash] else { return }
        let hash = Data(packet.data.prefix(ResourceConstants.identityHashLength))
        if let resource = await link.outgoingResource(hash: hash) {
            await resource.validateProof(packet.data)
            if await resource.status == .complete {
                await outgoingResourceCallback?(resource, link)
                await link.removeResource(hash: hash, outgoing: true)
            }
        }
    }

    private struct HashmapUpdateWire: Decodable {
        let segment: Int
        let hashmap: Data

        init(from decoder: Decoder) throws {
            var container = try decoder.unkeyedContainer()
            self.segment = try container.decode(Int.self)
            self.hashmap = try container.decode(Data.self)
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
        let destHex = destination.hash.data.prefix(4).hexEncodedString

        var sentOn: [String] = []
        var rateLimitedOn: [String] = []
        var offlineOn: [String] = []
        var failedOn: [String] = []

        for interface in interfaces {
            let limiter = rateLimiters[interface.interfaceId]
            if let limiter, await !limiter.canSend() {
                rateLimitedOn.append(interface.interfaceId)
                continue
            }
            let online = await interface.isOnline
            guard online else {
                offlineOn.append(interface.interfaceId)
                logger.warning("sendAnnounce: \(destHex) -- interface \(interface.interfaceId) is offline; announce NOT transmitted there")
                continue
            }
            do {
                try await interface.send(packedData)
                await limiter?.recordSend(packetSize: packedData.count)
                sentOn.append(interface.interfaceId)
            } catch {
                failedOn.append("\(interface.interfaceId)(\(error))")
                logger.warning("Failed to send announce on \(interface.interfaceId): \(error)")
            }
        }
        if sentOn.isEmpty {
            logger.warning("sendAnnounce: \(destHex) NOT TRANSMITTED -- offline=\(offlineOn) rateLimited=\(rateLimitedOn) failed=\(failedOn) (\(packedData.count) bytes)")
        } else {
            logger.info("sendAnnounce: \(destHex) sent on \(sentOn) (\(packedData.count) bytes)")
        }
    }

    // MARK: - Periodic Re-Announce

    /// Returns true if at least one registered interface currently reports `isOnline`.
    ///
    /// Used by `startReAnnounce` to defer the very first announce until a transport
    /// is actually capable of carrying bytes — without this, an announce issued
    /// before BLE finishes its scan/connect/detect handshake is silently dropped.
    public func hasAnyOnlineInterface() async -> Bool {
        for iface in interfaces {
            if await iface.isOnline { return true }
        }
        return false
    }

    /// Start periodic re-announce of all registered destinations.
    ///
    /// Behaviour:
    ///   1. Wait (up to `initialOnlineTimeout`) for at least one interface to come
    ///      online, polling every 1s. This avoids the BLE-not-yet-online race where
    ///      `sendAnnounce` would otherwise log "NOT TRANSMITTED" and lose the
    ///      first announce.
    ///   2. Send the first announce immediately on every local destination.
    ///   3. Loop: sleep `interval` seconds, send again.
    ///
    /// If no interface comes online within `initialOnlineTimeout`, the first
    /// announce is still attempted (so the warning surfaces in logs) and the
    /// periodic loop continues — a later online transition will be picked up
    /// by the next iteration.
    ///
    /// - Parameters:
    ///   - interval: Time between re-announces in seconds. Defaults to 1800 (30 minutes).
    ///   - initialOnlineTimeout: Max seconds to wait for an interface before the
    ///     first announce. Defaults to 60s.
    public func startReAnnounce(interval: TimeInterval = 1800, initialOnlineTimeout: TimeInterval = 60) async {
        reAnnounceTask?.cancel()
        reAnnounceTask = Task { [weak self] in
            guard let self else { return }

            // Phase 1: wait for at least one online interface, with a safety deadline.
            let deadline = Date().addingTimeInterval(initialOnlineTimeout)
            while !Task.isCancelled {
                if await self.hasAnyOnlineInterface() { break }
                if Date() >= deadline {
                    self.logger.warning("startReAnnounce: no interface came online within \(Int(initialOnlineTimeout))s; sending initial announce anyway (will log NOT TRANSMITTED)")
                    break
                }
                try? await Task.sleep(for: .seconds(1))
            }
            if Task.isCancelled { return }

            // Phase 2: initial announce on every local destination.
            for dest in await self.localDestinations {
                try? await self.sendAnnounce(for: dest)
            }

            // Phase 3: periodic re-announce.
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(interval))
                guard !Task.isCancelled else { return }
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

        for task in interfaceListenerTasks.values {
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
