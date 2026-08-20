// SPDX-License-Identifier: MIT
// Link.swift -- Reticulum Link actor with 3-packet ECDH handshake
//
// The Link establishes an encrypted, forward-secret communication channel
// between two Reticulum nodes using a 3-packet handshake:
//   1. Link Request:  initiator -> responder (ephemeral X25519 pub + identity Ed25519 pub)
//   2. Link Proof:    responder -> initiator (Ed25519 signature + responder ephemeral X25519 pub)
//   3. RTT Packet:    initiator -> responder (Token-encrypted msgpack Double of round-trip time)
//
// SECURITY: Ephemeral private keys are set to nil immediately after ECDH completes (forward secrecy).
// SECURITY: HMAC verification via Token.decrypt() catches any modification to encrypted link traffic.

import Foundation
import CryptoKit
import MessagePack

public actor Link {

    // MARK: - Types

    public enum Status: UInt8, Sendable {
        case pending   = 0x00
        case handshake = 0x01
        case active    = 0x02
        case stale     = 0x03
        case closed    = 0x04
    }

    public enum TeardownReason: UInt8, Sendable {
        case timeout           = 0x01
        case initiatorClosed   = 0x02
        case destinationClosed = 0x03
    }

    public enum Side: Sendable {
        case initiator
        case responder
    }

    // MARK: - Properties

    public private(set) var linkId: TruncatedHash
    public private(set) var status: Status
    public let side: Side
    private var ephemeralPrivateKey: Curve25519.KeyAgreement.PrivateKey?
    public let ephemeralPublicKey: Curve25519.KeyAgreement.PublicKey
    private let identity: Identity
    private let targetDestinationHash: TruncatedHash?
    private var token: Token?
    private var rtt: TimeInterval = 0
    private var requestSentAt: Date?
    private var lastActivityAt: Date = Date()
    private var keepaliveInterval: TimeInterval = LinkConstants.defaultKeepalive
    public private(set) var teardownReason: TeardownReason?

    /// Outgoing resources keyed by 32-byte resource hash.
    private var outgoingResources: [Data: Resource] = [:]
    /// Incoming resources keyed by 32-byte resource hash.
    private var incomingResources: [Data: Resource] = [:]

    /// In-progress multi-segment resource receive (Python split Resource), keyed by original hash.
    private struct SplitResourceAssembly {
        var accumulated: Data
        var totalSegments: Int
        var nextExpectedSegment: Int
    }

    private var splitResourceAssemblies: [Data: SplitResourceAssembly] = [:]

    /// Test-accessible property: true if ephemeral private key is still held.
    public var hasEphemeralKey: Bool {
        ephemeralPrivateKey != nil
    }

    /// Wait for the link to become active (handshake complete).
    /// Polls status with short sleep intervals until active, closed, or timeout.
    /// - Parameter timeout: Maximum wait time in seconds (default 10).
    /// - Throws: If the link closes or times out before becoming active.
    public func waitForActive(timeout: TimeInterval = 10) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while status != .active {
            if status == .closed {
                throw ReticulumError.linkInvalidState("link closed while waiting for active")
            }
            if Date() > deadline {
                throw ReticulumError.linkInvalidState("timeout waiting for link to become active")
            }
            try await Task.sleep(nanoseconds: 50_000_000) // 50ms
        }
    }

    // MARK: - Private Init

    private init(
        linkId: TruncatedHash,
        status: Status,
        side: Side,
        ephemeralPrivateKey: Curve25519.KeyAgreement.PrivateKey?,
        ephemeralPublicKey: Curve25519.KeyAgreement.PublicKey,
        identity: Identity,
        targetDestinationHash: TruncatedHash?,
        token: Token?
    ) {
        self.linkId = linkId
        self.status = status
        self.side = side
        self.ephemeralPrivateKey = ephemeralPrivateKey
        self.ephemeralPublicKey = ephemeralPublicKey
        self.identity = identity
        self.targetDestinationHash = targetDestinationHash
        self.token = token
    }

    // MARK: - Initiator Factory

    /// Create a Link as initiator, targeting a destination hash.
    /// Generates a fresh ephemeral X25519 keypair for forward secrecy.
    public static func initiator(to destinationHash: TruncatedHash, identity: Identity) -> Link {
        let ephemeralKey = Curve25519.KeyAgreement.PrivateKey()
        // Use a placeholder linkId (will be computed in createRequest)
        let placeholder = try! TruncatedHash(Data(repeating: 0, count: 16))
        return Link(
            linkId: placeholder,
            status: .pending,
            side: .initiator,
            ephemeralPrivateKey: ephemeralKey,
            ephemeralPublicKey: ephemeralKey.publicKey,
            identity: identity,
            targetDestinationHash: destinationHash,
            token: nil
        )
    }

    // MARK: - Create Link Request (Initiator)

    /// Build a link request packet.
    /// Data = ephemeralX25519Pub(32) + identityEd25519Pub(32) = 64 bytes.
    /// Returns both the Packet and its raw packed bytes (needed for link ID computation).
    public func createRequest() throws -> (packet: Packet, rawBytes: Data) {
        guard status == .pending else {
            throw ReticulumError.linkInvalidState("createRequest requires .pending, got \(status)")
        }
        guard let destHash = targetDestinationHash else {
            throw ReticulumError.linkInvalidState("createRequest requires targetDestinationHash")
        }

        // Build request data: ephemeral X25519 pub (32) + identity Ed25519 pub (32)
        var requestData = Data()
        requestData.append(ephemeralPublicKey.rawRepresentation)
        requestData.append(identity.signingPublicKey.rawRepresentation)

        let header = PacketHeader(
            headerType: .type1,
            propagationType: .broadcast,
            destinationType: .single,
            packetType: .linkRequest
        )

        let packet = Packet(
            header: header,
            destinationHash: destHash,
            context: .none,
            data: requestData
        )

        let rawBytes = try packet.pack()

        // Compute link ID from hashable part
        let hashable = Packet.hashablePart(raw: rawBytes, headerType: .type1)
        let linkIdData = CryptoEngine.truncatedHash(hashable)
        self.linkId = try TruncatedHash(linkIdData)
        self.requestSentAt = Date()

        return (packet, rawBytes)
    }

    // MARK: - Responder Factory (Static)

    /// Create a Link as responder to an incoming link request.
    /// Parses the request, performs ECDH, derives Token, creates proof packet.
    public static func respondToRequest(
        rawPacket: Data,
        packet: Packet,
        responderIdentity: Identity
    ) throws -> (link: Link, proofPacket: Packet) {
        // Validate request data size
        guard packet.data.count >= LinkConstants.ecPubSize else {
            throw ReticulumError.linkRequestTooShort(packet.data.count)
        }

        // Extract initiator keys from request data
        let initiatorX25519PubBytes = Data(packet.data.prefix(32))
        let initiatorEd25519PubBytes = Data(packet.data[32..<64])

        let initiatorX25519Pub = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: initiatorX25519PubBytes
        )

        // Compute link ID from hashable part of raw packet
        let hashable = Packet.hashablePart(raw: rawPacket, headerType: packet.header.headerType)
        let linkIdData = CryptoEngine.truncatedHash(hashable)
        let linkId = try TruncatedHash(linkIdData)

        // Generate fresh ephemeral X25519 keypair for responder
        let responderEphemeral = Curve25519.KeyAgreement.PrivateKey()

        // Perform ECDH
        let sharedSecret = try CryptoEngine.keyAgreement(
            privateKey: responderEphemeral,
            publicKey: initiatorX25519Pub
        )

        // Derive Token via HKDF with linkId as salt
        let sharedSecretData = sharedSecret.withUnsafeBytes { Data($0) }
        let derivedKey = CryptoEngine.hkdf(
            length: 64,
            inputKeyMaterial: sharedSecretData,
            salt: linkId.data,
            context: nil
        )
        let token = try Token(key: derivedKey)

        // Sign proof: sign(linkId + ourX25519Pub + ourEd25519Pub + signallingBytes)
        // This matches Python RNS Link.prove() which signs responder's own keys + MTU signalling
        let signallingBytes = Link.signallingBytes()
        let signedData = linkId.data
            + responderEphemeral.publicKey.rawRepresentation
            + responderIdentity.signingPublicKey.rawRepresentation
            + signallingBytes
        let signature = try responderIdentity.sign(signedData)

        // Build proof data: signature(64) + responderEphemeralPub(32) + signallingBytes(3)
        var proofData = Data()
        proofData.append(signature)
        proofData.append(responderEphemeral.publicKey.rawRepresentation)
        proofData.append(signallingBytes)

        let proofHeader = PacketHeader(
            headerType: .type1,
            propagationType: .broadcast,
            destinationType: .link,
            packetType: .proof
        )

        let proofPacket = Packet(
            header: proofHeader,
            destinationHash: linkId,
            context: .lrProof,
            data: proofData
        )

        // Forward secrecy: discard ephemeral private key
        // Responder has the Token immediately — mark as active
        // (RTT from initiator is optional for responder side)
        let link = Link(
            linkId: linkId,
            status: .active,
            side: .responder,
            ephemeralPrivateKey: nil,  // Already discarded
            ephemeralPublicKey: responderEphemeral.publicKey,
            identity: responderIdentity,
            targetDestinationHash: nil,
            token: token
        )

        return (link, proofPacket)
    }

    // MARK: - Process Proof (Initiator)

    /// Process the link proof from the responder, skipping the Ed25519 signature
    /// verification step.
    ///
    /// **Use only when no announce is in the routing table for the destination.**
    /// Without the peer's announce we don't have their long-term Ed25519 signing
    /// key to verify the proof signature, so we can only do the ECDH portion of
    /// the handshake. The link tunnel still provides confidentiality (the Token
    /// is derived from a fresh ECDH each link), but loses peer-identity
    /// authentication — a MITM that intercepted the link request could impersonate
    /// the responder. A subsequent announce should re-establish full trust.
    public func processProofWithoutSignatureCheck(
        rawProofPacket: Data,
        proofPacket: Packet
    ) throws {
        guard status == .pending else {
            throw ReticulumError.linkInvalidState("processProofWithoutSignatureCheck requires .pending, got \(status)")
        }
        guard let ephPriv = ephemeralPrivateKey else {
            throw ReticulumError.linkInvalidState("processProofWithoutSignatureCheck: ephemeral private key missing")
        }
        guard proofPacket.data.count >= 96 else {
            throw ReticulumError.linkInvalidProof("proof data too short: \(proofPacket.data.count)")
        }

        // ECDH with responder ephemeral X25519
        let responderX25519PubBytes = Data(proofPacket.data[64..<96])
        let responderX25519Pub = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: responderX25519PubBytes
        )
        let sharedSecret = try CryptoEngine.keyAgreement(
            privateKey: ephPriv,
            publicKey: responderX25519Pub
        )
        let sharedSecretData = sharedSecret.withUnsafeBytes { Data($0) }
        let derivedKey = CryptoEngine.hkdf(
            length: 64,
            inputKeyMaterial: sharedSecretData,
            salt: linkId.data,
            context: nil
        )
        self.token = try Token(key: derivedKey)

        self.status = .handshake
        self.ephemeralPrivateKey = nil
        if let sentAt = requestSentAt {
            self.rtt = Date().timeIntervalSince(sentAt)
        }
    }

    /// Process the link proof from the responder.
    /// Performs ECDH with responder's ephemeral key, derives Token, verifies signature.
    public func processProof(
        rawProofPacket: Data,
        proofPacket: Packet,
        peerIdentity: Identity
    ) throws {
        guard status == .pending else {
            throw ReticulumError.linkInvalidState("processProof requires .pending, got \(status)")
        }
        guard let ephPriv = ephemeralPrivateKey else {
            throw ReticulumError.linkInvalidState("processProof: ephemeral private key missing")
        }
        guard proofPacket.data.count >= 96 else {
            throw ReticulumError.linkInvalidProof("proof data too short: \(proofPacket.data.count)")
        }

        // Extract signature and responder ephemeral public key
        let signature = Data(proofPacket.data.prefix(64))
        let responderX25519PubBytes = Data(proofPacket.data[64..<96])
        let responderX25519Pub = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: responderX25519PubBytes
        )

        // Perform ECDH
        let sharedSecret = try CryptoEngine.keyAgreement(
            privateKey: ephPriv,
            publicKey: responderX25519Pub
        )

        // Derive Token with HKDF (salt = linkId)
        let sharedSecretData = sharedSecret.withUnsafeBytes { Data($0) }
        let derivedKey = CryptoEngine.hkdf(
            length: 64,
            inputKeyMaterial: sharedSecretData,
            salt: linkId.data,
            context: nil
        )
        self.token = try Token(key: derivedKey)

        // Verify signature: Python RNS signs:
        //   link_id + responder_X25519_pub + responder_Ed25519_pub + signalling_bytes
        // The signalling bytes are the last bytes of proof data after the responder X25519 key.
        let signallingBytes = proofPacket.data.count > 96 ? Data(proofPacket.data[96...]) : Data()

        // Get responder's Ed25519 signing key from peerIdentity
        let responderSigningPubBytes = Data(peerIdentity.signingPublicKey.rawRepresentation)

        let signedData = linkId.data + responderX25519PubBytes + responderSigningPubBytes + signallingBytes

        guard peerIdentity.verify(signature: signature, for: signedData) else {
            throw ReticulumError.linkInvalidProof("signature verification failed")
        }

        // Transition to handshake
        self.status = .handshake

        // Forward secrecy: discard ephemeral private key
        self.ephemeralPrivateKey = nil

        // Compute RTT
        if let sentAt = requestSentAt {
            self.rtt = Date().timeIntervalSince(sentAt)
        }
    }

    // MARK: - Create RTT Packet (Initiator)

    /// Create the RTT measurement packet (3rd handshake packet).
    /// Encodes RTT as msgpack Double, encrypts with Token.
    public func createRTTPacket() throws -> Packet {
        guard status == .handshake else {
            throw ReticulumError.linkInvalidState("createRTTPacket requires .handshake, got \(status)")
        }
        guard let token = token else {
            throw ReticulumError.linkNoToken
        }

        // Encode RTT as msgpack
        let encoder = MessagePackEncoder()
        let msgpackData = try encoder.encode(rtt)

        // Encrypt with Token
        let encrypted = try token.encrypt(msgpackData)

        let header = PacketHeader(
            headerType: .type1,
            propagationType: .broadcast,
            destinationType: .link,
            packetType: .data
        )

        // Initiator transitions to active after sending RTT
        self.status = .active
        recordActivity()

        return Packet(
            header: header,
            destinationHash: linkId,
            context: .lrRTT,
            data: encrypted
        )
    }

    // MARK: - Process RTT (Responder)

    /// Process the RTT packet from the initiator.
    /// Decrypts with Token, decodes msgpack Double, transitions to .active.
    public func processRTT(packet: Packet) throws {
        // Accept RTT in both .handshake (normal) and .active (responder already activated)
        guard status == .handshake || status == .active else {
            throw ReticulumError.linkInvalidState("processRTT requires .handshake or .active, got \(status)")
        }
        guard let token = token else {
            throw ReticulumError.linkNoToken
        }

        // Decrypt
        let decrypted = try token.decrypt(packet.data)

        // Decode msgpack Double
        let decoder = MessagePackDecoder()
        let rttValue = try decoder.decode(Double.self, from: decrypted)
        self.rtt = rttValue

        // Transition to active
        self.status = .active
        recordActivity()
    }

    // MARK: - Data Encrypt/Decrypt

    /// Encrypt plaintext using the link's Token.
    public func encrypt(_ plaintext: Data) throws -> Data {
        guard status == .active else {
            throw ReticulumError.linkInvalidState("encrypt requires .active, got \(status)")
        }
        guard let token = token else {
            throw ReticulumError.linkNoToken
        }
        return try token.encrypt(plaintext)
    }

    /// Decrypt ciphertext using the link's Token.
    public func decrypt(_ ciphertext: Data) throws -> Data {
        guard status == .active else {
            throw ReticulumError.linkInvalidState("decrypt requires .active, got \(status)")
        }
        guard let token = token else {
            throw ReticulumError.linkNoToken
        }
        return try token.decrypt(ciphertext)
    }

    // MARK: - Lifecycle: Close and Teardown

    /// Close the link, producing a teardown packet for the peer.
    ///
    /// Sets status to `.closed`, records the teardown reason, and zeroes all key material.
    /// If the link is already closed, returns nil (no packet to send).
    ///
    /// - Parameter reason: Why the link is being closed.
    /// - Returns: A teardown packet to send to the peer, or nil if already closed.
    @discardableResult
    public func close(reason: TeardownReason) -> Packet? {
        guard status != .closed else { return nil }

        // Build teardown packet: encrypt linkId.data with Token
        var teardownPacket: Packet? = nil
        if let token = token {
            if let encryptedLinkId = try? token.encrypt(linkId.data) {
                let header = PacketHeader(
                    headerType: .type1,
                    propagationType: .broadcast,
                    destinationType: .link,
                    packetType: .data
                )
                teardownPacket = Packet(
                    header: header,
                    destinationHash: linkId,
                    context: .linkClose,
                    data: encryptedLinkId
                )
            }
        }

        // Transition to closed
        self.status = .closed
        self.teardownReason = reason

        // SECURITY: Zero all key material (T-03-13)
        self.token = nil
        self.ephemeralPrivateKey = nil

        return teardownPacket
    }

    /// Handle an incoming teardown packet from the peer.
    ///
    /// Decrypts the packet data and verifies it matches the link ID.
    /// Transitions to `.closed` and zeroes all key material.
    ///
    /// - Parameter packet: The incoming teardown packet (context = .linkClose).
    /// - Throws: If the link is already closed, token is nil, or verification fails.
    public func handleIncomingTeardown(packet: Packet) throws {
        guard status != .closed else {
            throw ReticulumError.linkInvalidState("handleIncomingTeardown: already closed")
        }
        guard let token = token else {
            throw ReticulumError.linkNoToken
        }

        // Decrypt and verify: decrypted data must equal linkId.data (T-03-11)
        let decrypted = try token.decrypt(packet.data)
        guard decrypted == linkId.data else {
            throw ReticulumError.linkInvalidState("teardown verification failed: decrypted data does not match linkId")
        }

        // Transition to closed
        self.status = .closed
        self.teardownReason = .destinationClosed

        // SECURITY: Zero all key material (T-03-13)
        self.token = nil
    }

    // MARK: - Lifecycle: Keepalive

    /// Create a keepalive request packet (byte 0xFF).
    ///
    /// Sent by the initiator to check if the responder is still alive.
    /// - Returns: A keepalive packet with encrypted 0xFF byte.
    public func createKeepaliveRequest() throws -> Packet {
        guard let token = token else {
            throw ReticulumError.linkNoToken
        }
        let encrypted = try token.encrypt(Data([0xFF]))
        let header = PacketHeader(
            headerType: .type1,
            propagationType: .broadcast,
            destinationType: .link,
            packetType: .data
        )
        return Packet(
            header: header,
            destinationHash: linkId,
            context: .keepalive,
            data: encrypted
        )
    }

    /// Create a keepalive reply packet (byte 0xFE).
    ///
    /// Sent by the responder in response to a keepalive request.
    /// - Returns: A keepalive packet with encrypted 0xFE byte.
    public func createKeepaliveReply() throws -> Packet {
        guard let token = token else {
            throw ReticulumError.linkNoToken
        }
        let encrypted = try token.encrypt(Data([0xFE]))
        let header = PacketHeader(
            headerType: .type1,
            propagationType: .broadcast,
            destinationType: .link,
            packetType: .data
        )
        return Packet(
            header: header,
            destinationHash: linkId,
            context: .keepalive,
            data: encrypted
        )
    }

    /// Handle an incoming keepalive packet.
    ///
    /// Decrypts the payload and checks the first byte:
    /// - 0xFF (request): If this side is responder, updates activity and returns a reply.
    /// - 0xFE (reply): Updates activity, returns nil (acknowledged).
    /// - 0xFF on initiator side: Ignored (should not happen), returns nil.
    ///
    /// - Parameter packet: The incoming keepalive packet (context = .keepalive).
    /// - Returns: A keepalive reply packet if this is a responder receiving a request, nil otherwise.
    public func handleKeepalive(packet: Packet) throws -> Packet? {
        guard let token = token else {
            throw ReticulumError.linkNoToken
        }

        let decrypted = try token.decrypt(packet.data)
        guard !decrypted.isEmpty else { return nil }

        let firstByte = decrypted[decrypted.startIndex]

        if firstByte == 0xFF && side == .responder {
            // Keepalive request received by responder -- reply
            recordActivity()
            return try createKeepaliveReply()
        } else if firstByte == 0xFE {
            // Keepalive reply received -- acknowledge
            recordActivity()
            return nil
        } else {
            // 0xFF on initiator side or unknown -- ignore
            return nil
        }
    }

    // MARK: - Signalling

    /// Generate MTU signalling bytes (3 bytes).
    /// Matches Python RNS Link.signalling_bytes(mtu, mode):
    ///   signalling_value = (mtu & MTU_BYTEMASK) + (((mode << 5) & MODE_BYTEMASK) << 16)
    ///   packed as big-endian uint32, last 3 bytes
    ///
    /// MODE_DEFAULT = 1 (AES_256_CBC). Mode is encoded in top 3 bits of first byte.
    public static func signallingBytes(mtu: UInt16 = 500, mode: UInt8 = 1) -> Data {
        let mtuMask: UInt32 = 0x1FFFFF    // MTU_BYTEMASK
        let modeMask: UInt32 = 0xE0        // MODE_BYTEMASK
        let signallingValue = (UInt32(mtu) & mtuMask) + (((UInt32(mode) << 5) & modeMask) << 16)
        // Pack as big-endian uint32, take last 3 bytes
        var be = signallingValue.bigEndian
        let fullBytes = withUnsafeBytes(of: &be) { Data($0) }
        return Data(fullBytes[1...3])  // skip first byte of uint32
    }

    // MARK: - Lifecycle: Timeout Detection

    /// Check if the link has timed out based on time since last activity.
    ///
    /// - If active and elapsed > staleFactor * keepalive: transitions to `.stale`, returns nil.
    /// - If stale and elapsed > staleFactor * keepalive + staleGrace: transitions to `.closed`,
    ///   zeroes keys, returns `.timeout`.
    /// - Otherwise: returns nil (link is healthy).
    ///
    /// - Parameter now: The current time (injectable for testing).
    /// - Returns: `.timeout` if the link was closed, nil otherwise.
    public func checkTimeout(now: Date = Date()) -> TeardownReason? {
        let staleTime = keepaliveInterval * Double(LinkConstants.staleFactor)
        let elapsed = now.timeIntervalSince(lastActivityAt)

        if status == .active && elapsed > staleTime {
            status = .stale
            return nil
        }

        if status == .stale && elapsed > staleTime + LinkConstants.staleGrace {
            status = .closed
            teardownReason = .timeout
            // SECURITY: Zero key material (T-03-13, T-03-14)
            token = nil
            return .timeout
        }

        return nil
    }

    // MARK: - Identify

    /// Create an identify packet containing this node's identity hash.
    ///
    /// Used by LXMF propagation clients to identify themselves to a propagation node
    /// after link establishment. The identity hash is encrypted with the link Token
    /// and sent as a link-addressed data packet with `.linkIdentify` context.
    ///
    /// - Parameter identity: The identity whose hash to send.
    /// - Returns: A packet ready to send via Transport.sendPacket.
    /// - Throws: If the link is not active or has no Token.
    public func identify(identity: Identity) throws -> Packet {
        guard status == .active else {
            throw ReticulumError.linkInvalidState("identify requires .active, got \(status)")
        }
        guard let token = token else {
            throw ReticulumError.linkNoToken
        }

        let encrypted = try token.encrypt(identity.hash.data)

        let header = PacketHeader(
            headerType: .type1,
            propagationType: .broadcast,
            destinationType: .link,
            packetType: .data
        )

        return Packet(
            header: header,
            destinationHash: linkId,
            context: .linkIdentify,
            data: encrypted
        )
    }

    // MARK: - Resources

    /// Register an outgoing resource on this link.
    public func registerOutgoingResource(_ resource: Resource) async {
        let hash = await resource.hash
        outgoingResources[hash] = resource
    }

    /// Register an incoming resource on this link.
    public func registerIncomingResource(_ resource: Resource) async {
        let hash = await resource.hash
        incomingResources[hash] = resource
    }

    /// Look up an outgoing resource by hash.
    public func outgoingResource(hash: Data) -> Resource? {
        outgoingResources[hash]
    }

    /// Look up an incoming resource by hash.
    public func incomingResource(hash: Data) -> Resource? {
        incomingResources[hash]
    }

    /// Incoming resources currently transferring.
    public func incomingResourceList() -> [Resource] {
        Array(incomingResources.values)
    }

    /// Remove a finished resource.
    public func removeResource(hash: Data, outgoing: Bool) {
        if outgoing {
            outgoingResources.removeValue(forKey: hash)
        } else {
            incomingResources.removeValue(forKey: hash)
        }
    }

    /// True when a size-split resource ADV is the next expected segment.
    func isExpectingSplitSegment(originalHash: Data, segmentIndex: Int) -> Bool {
        guard segmentIndex > 1, let state = splitResourceAssemblies[originalHash] else { return false }
        return state.nextExpectedSegment == segmentIndex
    }

    /// Store a completed split segment and advance the expected segment index.
    func storeSplitSegment(originalHash: Data, segmentIndex: Int, data: Data, totalSegments: Int) {
        if segmentIndex == 1 {
            splitResourceAssemblies[originalHash] = SplitResourceAssembly(
                accumulated: data,
                totalSegments: totalSegments,
                nextExpectedSegment: 2
            )
            return
        }
        guard let state = splitResourceAssemblies[originalHash],
              state.nextExpectedSegment == segmentIndex,
              segmentIndex < totalSegments else { return }
        state.accumulated.append(data)
        state.nextExpectedSegment = segmentIndex + 1
        splitResourceAssemblies[originalHash] = state
    }

    /// Append the final split segment and return the full assembled plaintext.
    func completeSplitAssembly(
        originalHash: Data,
        segmentIndex: Int,
        finalSegment: Data,
        totalSegments: Int
    ) -> Data? {
        guard segmentIndex == totalSegments else { return nil }
        if totalSegments == 1 { return finalSegment }
        guard let state = splitResourceAssemblies[originalHash],
              state.nextExpectedSegment == segmentIndex else { return nil }
        var full = state.accumulated
        full.append(finalSegment)
        splitResourceAssemblies.removeValue(forKey: originalHash)
        return full
    }

    // MARK: - Activity Tracking

    /// Record incoming activity, resetting the timeout clock.
    public func recordActivity() {
        lastActivityAt = Date()
    }
}
