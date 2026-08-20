// SPDX-License-Identifier: MIT
// Resource.swift — Chunked link payload transfer (Python `RNS.Resource`)
//
// Flow: initiator encrypts (random4 + plaintext) with the link Token, splits
// into SDU parts, advertises a hashmap, then sends requested parts. RESOURCE
// parts are not encrypted again at the packet layer. Receiver decrypts the
// assembled stream, strips the random prefix, and proves with
// SHA-256(plaintext + resource_hash).
//
// Deferred follow-ups: bz2 auto-compress (RK-12), multi-segment size splits (RK-14),
// response Resources (RK-16).

import Foundation
import CryptoKit
import Logging

/// Status of a resource transfer (Python `Resource` status constants).
public enum ResourceStatus: UInt8, Sendable {
    case none = 0x00
    case queued = 0x01
    case advertised = 0x02
    case transferring = 0x03
    case awaitingProof = 0x04
    case assembling = 0x05
    case complete = 0x06
    case failed = 0x07
    case corrupt = 0x08
    case rejected = 0x09
}

/// One RNS Resource transfer on a link.
public actor Resource {
    public private(set) var hash: Data
    public nonisolated let originalHash: Data
    public nonisolated let initiator: Bool
    public private(set) var status: ResourceStatus
    public private(set) var assembledData: Data?

    private let link: Link
    private let sendPacket: @Sendable (Packet) async throws -> Void
    private var randomHash: Data
    private var expectedProof: Data
    private var plaintext: Data
    private var compressed: Bool
    private var parts: [Data?]
    private var hashmap: [Data]
    private var mapHashes: [Data]
    private var window: Int
    private var consecutiveCompletedHeight: Int
    private var receivedCount: Int
    private var outstandingParts: Int
    private var sentPartCount: Int
    private var waitingForHMU: Bool
    private var segmentIndex: Int
    private var totalSegments: Int
    private let logger = Logger(label: "reticulumkit.resource")

    /// Number of hashmap slices required for `mapHashes` (Python HMU segments).
    var hashmapSegmentCount: Int {
        (mapHashes.count + ResourceConstants.hashmapMaxLength - 1) / ResourceConstants.hashmapMaxLength
    }

    /// Hashmap entries included in the first ADV packet.
    var advertisedHashmapEntryCount: Int {
        min(mapHashes.count, ResourceConstants.hashmapMaxLength)
    }

    // MARK: - Initiator

    /// Prepare an outgoing resource. Does not advertise until `advertise()`.
    ///
    /// Compression (`autoCompress`) is reserved for a follow-up; this core path
    /// always sends uncompressed plaintext. The resource hash is over plaintext.
    public static func outgoing(
        plaintext: Data,
        link: Link,
        sendPacket: @escaping @Sendable (Packet) async throws -> Void,
        autoCompress: Bool = false
    ) async throws -> Resource {
        let linkId = await link.linkId
        guard await link.status == .active else {
            throw ReticulumError.linkInvalidState("resource requires an active link")
        }
        // Single-segment only; size-split multi-segment is a follow-up.
        _ = autoCompress
        let segmentPlaintext = plaintext
        let compressed = false
        let streamBody = segmentPlaintext
        let prefix = try CryptoEngine.randomBytes(count: ResourceConstants.randomHashSize)
        let encrypted = try await link.encrypt(prefix + streamBody)
        let sdu = ResourceConstants.sdu
        let partCount = max(1, (encrypted.count + sdu - 1) / sdu)
        var randomHash = try CryptoEngine.randomBytes(count: ResourceConstants.randomHashSize)
        var hashmap: [Data] = []
        var chunks: [Data] = []
        var attempts = 0
        while true {
            attempts += 1
            hashmap = []
            chunks = []
            var guardList: [Data] = []
            var collided = false
            for i in 0..<partCount {
                let start = i * sdu
                let end = min(start + sdu, encrypted.count)
                let chunk = encrypted[start..<end]
                let mapHash = Data(CryptoEngine.sha256(chunk + randomHash).prefix(ResourceConstants.mapHashLength))
                if guardList.contains(mapHash) {
                    collided = true
                    break
                }
                guardList.append(mapHash)
                if guardList.count > ResourceConstants.windowMaxFast * 2 + ResourceConstants.hashmapMaxLength {
                    guardList.removeFirst()
                }
                hashmap.append(mapHash)
                chunks.append(Data(chunk))
            }
            if !collided { break }
            randomHash = try CryptoEngine.randomBytes(count: ResourceConstants.randomHashSize)
            guard attempts < 8 else {
                throw ReticulumError.resourceFailed("hashmap collision")
            }
        }
        let hash = CryptoEngine.sha256(segmentPlaintext + randomHash)
        let expectedProof = CryptoEngine.sha256(segmentPlaintext + hash)
        return Resource(
            hash: hash,
            originalHash: hash,
            initiator: true,
            status: .queued,
            link: link,
            sendPacket: sendPacket,
            randomHash: randomHash,
            expectedProof: expectedProof,
            plaintext: segmentPlaintext,
            compressed: compressed,
            parts: chunks.map { Optional($0) },
            hashmap: hashmap,
            mapHashes: hashmap,
            window: ResourceConstants.window,
            consecutiveCompletedHeight: -1,
            receivedCount: 0,
            outstandingParts: 0,
            sentPartCount: 0,
            waitingForHMU: false,
            segmentIndex: 1,
            totalSegments: 1,
            assembledData: nil,
            linkId: linkId
        )
    }

    // MARK: - Receiver

    /// Accept an advertisement and begin requesting parts.
    public static func incoming(
        advertisement: ResourceAdvertisement,
        link: Link,
        sendPacket: @escaping @Sendable (Packet) async throws -> Void
    ) async -> Resource {
        let partCount = max(1, advertisement.partCount)
        var hashmap = Array(repeating: Data(), count: partCount)
        let mapBytes = [UInt8](advertisement.hashmap)
        // Copy to an Array first: MessagePack `Data` may have a non-zero startIndex,
        // and `hashmap[0..<4]` would trap.
        let hashes = mapBytes.count / ResourceConstants.mapHashLength
        for i in 0..<hashes {
            let start = i * ResourceConstants.mapHashLength
            let end = start + ResourceConstants.mapHashLength
            if i < partCount {
                hashmap[i] = Data(mapBytes[start..<end])
            }
        }
        return Resource(
            hash: advertisement.hash,
            originalHash: advertisement.originalHash,
            initiator: false,
            status: .transferring,
            link: link,
            sendPacket: sendPacket,
            randomHash: advertisement.randomHash,
            expectedProof: Data(),
            plaintext: Data(),
            compressed: advertisement.isCompressed,
            parts: Array(repeating: nil, count: partCount),
            hashmap: hashmap,
            mapHashes: hashmap,
            window: ResourceConstants.window,
            consecutiveCompletedHeight: -1,
            receivedCount: 0,
            outstandingParts: 0,
            sentPartCount: 0,
            waitingForHMU: false,
            segmentIndex: advertisement.segmentIndex,
            totalSegments: advertisement.totalSegments,
            assembledData: nil,
            linkId: await link.linkId
        )
    }

    private let linkId: TruncatedHash

    private init(
        hash: Data,
        originalHash: Data,
        initiator: Bool,
        status: ResourceStatus,
        link: Link,
        sendPacket: @escaping @Sendable (Packet) async throws -> Void,
        randomHash: Data,
        expectedProof: Data,
        plaintext: Data,
        compressed: Bool,
        parts: [Data?],
        hashmap: [Data],
        mapHashes: [Data],
        window: Int,
        consecutiveCompletedHeight: Int,
        receivedCount: Int,
        outstandingParts: Int,
        sentPartCount: Int,
        waitingForHMU: Bool,
        segmentIndex: Int,
        totalSegments: Int,
        assembledData: Data?,
        linkId: TruncatedHash
    ) {
        self.hash = hash
        self.originalHash = originalHash
        self.initiator = initiator
        self.status = status
        self.link = link
        self.sendPacket = sendPacket
        self.randomHash = randomHash
        self.expectedProof = expectedProof
        self.plaintext = plaintext
        self.compressed = compressed
        self.parts = parts
        self.hashmap = hashmap
        self.mapHashes = mapHashes
        self.window = window
        self.consecutiveCompletedHeight = consecutiveCompletedHeight
        self.receivedCount = receivedCount
        self.outstandingParts = outstandingParts
        self.sentPartCount = sentPartCount
        self.waitingForHMU = waitingForHMU
        self.segmentIndex = segmentIndex
        self.totalSegments = totalSegments
        self.assembledData = assembledData
        self.linkId = linkId
    }

    /// Advertise this outgoing resource (Python `Resource.advertise`).
    ///
    /// The first ADV carries the first hashmap slice; further slices use RESOURCE_HMU
    /// when the peer signals hashmap exhausted.
    public func advertise() async throws {
        guard initiator else { return }
        var flags: UInt8 = 0x01 // encrypted
        if compressed { flags |= 0x02 }
        if totalSegments > 1 { flags |= 0x04 } // split
        let hashmapBytes = mapHashes.prefix(ResourceConstants.hashmapMaxLength).reduce(into: Data()) { $0.append($1) }
        let adv = ResourceAdvertisement(
            transferSize: parts.compactMap { $0 }.reduce(0) { $0 + $1.count },
            dataSize: plaintext.count,
            partCount: parts.count,
            hash: hash,
            randomHash: randomHash,
            originalHash: originalHash,
            segmentIndex: segmentIndex,
            totalSegments: totalSegments,
            requestId: nil,
            flags: flags,
            hashmap: hashmapBytes
        )
        let packed = try adv.pack()
        let encrypted = try await link.encrypt(packed)
        try await sendPacket(linkPacket(context: .resourceAdv, data: encrypted))
        status = .advertised
        logger.info(
            "resource advertised hash=\(hash.prefix(4).hexEncodedString) segment=\(segmentIndex)/\(totalSegments) parts=\(parts.count) hashmapSegs=\(hashmapSegmentCount)"
        )
    }

    /// Wait until the transfer completes or fails.
    public func waitUntilComplete(timeout: TimeInterval = 120) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while status != .complete {
            if status == .failed || status == .rejected || status == .corrupt {
                throw ReticulumError.resourceFailed("resource \(status)")
            }
            if Date() > deadline {
                throw ReticulumError.resourceFailed("resource timeout")
            }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
    }

    /// Handle a RESOURCE_REQ on the initiator.
    public func handleRequest(_ requestData: Data) async {
        guard initiator, requestData.count >= 1 + ResourceConstants.identityHashLength else { return }
        status = .transferring
        let wantsHMU = requestData[requestData.startIndex] == ResourceConstants.hashmapExhausted
        let pad = wantsHMU ? 1 + ResourceConstants.mapHashLength : 1
        guard requestData.count >= pad + ResourceConstants.identityHashLength else { return }
        let requested = requestData.dropFirst(pad + ResourceConstants.identityHashLength)
        var requestedHashes: [Data] = []
        var offset = 0
        while offset + ResourceConstants.mapHashLength <= requested.count {
            requestedHashes.append(Data(requested.dropFirst(offset).prefix(ResourceConstants.mapHashLength)))
            offset += ResourceConstants.mapHashLength
        }
        for (index, mapHash) in mapHashes.enumerated() {
            if requestedHashes.contains(mapHash), let chunk = parts[index] {
                do {
                    try await sendPacket(linkPacket(context: .resource, data: chunk))
                    sentPartCount += 1
                } catch {
                    logger.warning("resource part send failed: \(error)")
                    await fail()
                    return
                }
            }
        }
        if wantsHMU {
            await sendHashmapUpdate(requestData: requestData)
        }
        if sentPartCount >= parts.count {
            status = .awaitingProof
        }
    }

    private func sendHashmapUpdate(requestData: Data) async {
        let lastHash = Data(requestData[requestData.startIndex + 1..<requestData.startIndex + 1 + ResourceConstants.mapHashLength])
        guard let idx = mapHashes.firstIndex(of: lastHash) else { return }
        let nextSegment = (idx + 1) / ResourceConstants.hashmapMaxLength
        let start = nextSegment * ResourceConstants.hashmapMaxLength
        guard start < mapHashes.count else { return }
        let end = min(start + ResourceConstants.hashmapMaxLength, mapHashes.count)
        var hashmapBytes = Data()
        for i in start..<end { hashmapBytes.append(mapHashes[i]) }
        do {
            let payload = hashmapUpdatePayload(segment: nextSegment, hashmap: hashmapBytes)
            let body = hash + payload
            let encrypted = try await link.encrypt(body)
            try await sendPacket(linkPacket(context: .resourceHMU, data: encrypted))
        } catch {
            logger.warning("resource HMU send failed: \(error)")
        }
    }

    /// Request the next window of missing parts (receiver).
    public func requestNext() async {
        guard !initiator, status != .failed else { return }
        var requested = Data()
        var exhausted: UInt8 = ResourceConstants.hashmapNotExhausted
        outstandingParts = 0
        let searchStart = consecutiveCompletedHeight + 1
        var pn = searchStart
        while pn < parts.count && outstandingParts < window {
            if parts[pn] == nil {
                let mapHash = hashmap[pn]
                if mapHash.isEmpty {
                    exhausted = ResourceConstants.hashmapExhausted
                    break
                }
                requested.append(mapHash)
                outstandingParts += 1
            }
            pn += 1
        }
        var body = Data([exhausted])
        if exhausted == ResourceConstants.hashmapExhausted {
            let last = hashmap.last { !$0.isEmpty } ?? Data()
            body.append(last)
            waitingForHMU = true
        }
        body.append(hash)
        body.append(requested)
        do {
            let encrypted = try await link.encrypt(body)
            try await sendPacket(linkPacket(context: .resourceReq, data: encrypted))
        } catch {
            logger.warning("resource request failed: \(error)")
            await fail()
        }
    }

    /// Apply a hashmap update (receiver).
    public func hashmapUpdate(segment: Int, hashmapBytes: Data) async {
        let hashes = hashmapBytes.count / ResourceConstants.mapHashLength
        let mapBytes = [UInt8](hashmapBytes)
        let base = segment * ResourceConstants.hashmapMaxLength
        for i in 0..<hashes {
            let dest = base + i
            guard dest < hashmap.count else { break }
            let start = i * ResourceConstants.mapHashLength
            hashmap[dest] = Data(mapBytes[start..<start + ResourceConstants.mapHashLength])
        }
        waitingForHMU = false
        await requestNext()
    }

    /// Receive a RESOURCE part (already packet-layer plaintext / stream ciphertext).
    public func receivePart(_ partData: Data) async {
        guard !initiator, status != .failed else { return }
        let partHash = Data(CryptoEngine.sha256(partData + randomHash).prefix(ResourceConstants.mapHashLength))
        let start = max(0, consecutiveCompletedHeight)
        for i in start..<min(start + window + 1, parts.count) {
            if hashmap[i] == partHash, parts[i] == nil {
                parts[i] = partData
                receivedCount += 1
                outstandingParts = max(0, outstandingParts - 1)
                if i == consecutiveCompletedHeight + 1 {
                    consecutiveCompletedHeight = i
                    var cp = consecutiveCompletedHeight + 1
                    while cp < parts.count, parts[cp] != nil {
                        consecutiveCompletedHeight = cp
                        cp += 1
                    }
                }
                break
            }
        }
        if receivedCount == parts.count {
            await assemble()
        } else if outstandingParts == 0 {
            if window < ResourceConstants.windowMaxSlow { window += 1 }
            await requestNext()
        }
    }

    /// Validate a RESOURCE_PRF on the initiator.
    public func validateProof(_ proofData: Data) async {
        guard initiator else { return }
        let half = ResourceConstants.identityHashLength
        guard proofData.count == half * 2 else { return }
        let proofHash = proofData.prefix(half)
        let proof = proofData.suffix(half)
        if proofHash == hash && proof == expectedProof {
            status = .complete
            assembledData = plaintext
            logger.info("resource complete hash=\(hash.prefix(4).hexEncodedString)")
        }
    }

    /// Cancel this transfer.
    public func cancel(rejected: Bool = false) async {
        status = rejected ? .rejected : .failed
        let context: PacketContext = initiator ? .resourceICL : .resourceRCL
        if let encrypted = try? await link.encrypt(hash) {
            try? await sendPacket(linkPacket(context: context, data: encrypted))
        }
    }

    private func assemble() async {
        status = .assembling
        let stream = parts.compactMap { $0 }.reduce(into: Data()) { $0.append($1) }
        do {
            var decrypted = try await link.decrypt(stream)
            guard decrypted.count > ResourceConstants.randomHashSize else {
                throw ReticulumError.resourceFailed("short resource")
            }
            decrypted = Data(decrypted.dropFirst(ResourceConstants.randomHashSize))
            // bz2 inflate is a follow-up; compressed ADV is treated as corrupt here.
            if compressed {
                status = .corrupt
                return
            }
            let uncompressed = decrypted
            let calculated = CryptoEngine.sha256(uncompressed + randomHash)
            guard calculated == hash else {
                status = .corrupt
                return
            }
            let proof = CryptoEngine.sha256(uncompressed + hash)
            try await sendPacket(linkPacket(context: .resourcePRF, data: hash + proof, packetType: .proof))
            assembledData = uncompressed
            status = .complete
            logger.info("resource assembled hash=\(hash.prefix(4).hexEncodedString) bytes=\(uncompressed.count)")
        } catch {
            status = .corrupt
        }
    }

    private func hashmapUpdatePayload(segment: Int, hashmap: Data) -> Data {
        var payload = Data([0x92]) // fixarray 2
        if segment <= 0x7F {
            payload.append(UInt8(segment))
        } else {
            payload.append(0xCD)
            payload.append(UInt8((segment >> 8) & 0xFF))
            payload.append(UInt8(segment & 0xFF))
        }
        if hashmap.count <= 0xFF {
            payload.append(0xC4)
            payload.append(UInt8(hashmap.count))
        } else {
            payload.append(0xC5)
            payload.append(UInt8((hashmap.count >> 8) & 0xFF))
            payload.append(UInt8(hashmap.count & 0xFF))
        }
        payload.append(hashmap)
        return payload
    }

    private func fail() async {
        status = .failed
    }

    private func linkPacket(
        context: PacketContext,
        data: Data,
        packetType: PacketType = .data
    ) -> Packet {
        Packet(
            header: PacketHeader(
                headerType: .type1,
                propagationType: .broadcast,
                destinationType: .link,
                packetType: packetType
            ),
            destinationHash: linkId,
            context: context,
            data: data
        )
    }
}
