// SPDX-License-Identifier: MIT
// Channel.swift — Link Channel envelopes (Python `RNS.Channel`)
//
// Wire envelope: `>HHH` (msgtype, sequence, length) + payload. Packets use
// `PacketContext.channel` and are Token-encrypted by the Link. Full windowed
// reliability (retries, RING) is not required for LXMF image Resources; this
// type lets us send/receive Channel frames without dropping them.

import Foundation

/// One Channel envelope (Python `Envelope.pack` / `unpack`).
public struct ChannelEnvelope: Sendable, Equatable {
    public var messageType: UInt16
    public var sequence: UInt16
    public var payload: Data

    public init(messageType: UInt16, sequence: UInt16, payload: Data) {
        self.messageType = messageType
        self.sequence = sequence
        self.payload = payload
    }

    /// Pack to `struct.pack(">HHH", msgtype, sequence, len) + data`.
    public func pack() -> Data {
        var data = Data(count: 6)
        data[0] = UInt8(messageType >> 8)
        data[1] = UInt8(messageType & 0xFF)
        data[2] = UInt8(sequence >> 8)
        data[3] = UInt8(sequence & 0xFF)
        let length = UInt16(truncatingIfNeeded: payload.count)
        data[4] = UInt8(length >> 8)
        data[5] = UInt8(length & 0xFF)
        return data + payload
    }

    /// Unpack a Channel envelope. Returns `nil` if shorter than 6 bytes.
    public static func unpack(_ raw: Data) -> ChannelEnvelope? {
        guard raw.count >= 6 else { return nil }
        let messageType = UInt16(raw[raw.startIndex]) << 8 | UInt16(raw[raw.startIndex + 1])
        let sequence = UInt16(raw[raw.startIndex + 2]) << 8 | UInt16(raw[raw.startIndex + 3])
        let length = Int(UInt16(raw[raw.startIndex + 4]) << 8 | UInt16(raw[raw.startIndex + 5]))
        let payloadStart = raw.startIndex + 6
        let payloadEnd = min(raw.endIndex, payloadStart + length)
        return ChannelEnvelope(
            messageType: messageType,
            sequence: sequence,
            payload: Data(raw[payloadStart..<payloadEnd])
        )
    }
}

/// Bidirectional Channel over an active Link (Python `RNS.Channel`).
public actor Channel {
    private let link: Link
    private let sendPacket: @Sendable (Packet) async throws -> Void
    private var nextSequence: UInt16 = 0
    private var handlers: [@Sendable (ChannelEnvelope) async -> Void] = []

    public init(link: Link, sendPacket: @escaping @Sendable (Packet) async throws -> Void) {
        self.link = link
        self.sendPacket = sendPacket
    }

    /// Register a callback for received envelopes.
    public func onMessage(_ handler: @escaping @Sendable (ChannelEnvelope) async -> Void) {
        handlers.append(handler)
    }

    /// Send a Channel message. Payload must fit in `LinkConstants.mdu` after the 6-byte header.
    public func send(messageType: UInt16, payload: Data) async throws {
        let envelope = ChannelEnvelope(messageType: messageType, sequence: nextSequence, payload: payload)
        nextSequence &+= 1
        let packed = envelope.pack()
        guard packed.count <= LinkConstants.mdu else {
            throw ReticulumError.channelMessageTooLarge(packed.count)
        }
        let encrypted = try await link.encrypt(packed)
        let linkId = await link.linkId
        let packet = Packet(
            header: PacketHeader(
                headerType: .type1,
                propagationType: .broadcast,
                destinationType: .link,
                packetType: .data
            ),
            destinationHash: linkId,
            context: .channel,
            data: encrypted
        )
        try await sendPacket(packet)
    }

    /// Handle a decrypted Channel payload.
    public func receive(_ plaintext: Data) async {
        guard let envelope = ChannelEnvelope.unpack(plaintext) else { return }
        for handler in handlers {
            await handler(envelope)
        }
    }
}
