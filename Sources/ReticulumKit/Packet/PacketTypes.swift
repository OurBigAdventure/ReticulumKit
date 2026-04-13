// SPDX-License-Identifier: MIT
// PacketTypes.swift — Reticulum packet type enums (canonical definitions)

import Foundation

/// Header type determines addressing format.
/// type1: single destination (16-byte address), type2: transport (two 16-byte addresses).
public enum HeaderType: UInt8, Sendable {
    case type1 = 0  // Single destination (16-byte address)
    case type2 = 1  // Transport (two 16-byte addresses)
}

/// Packet type determines the purpose of the packet.
public enum PacketType: UInt8, Sendable {
    case data        = 0x00
    case announce    = 0x01
    case linkRequest = 0x02
    case proof       = 0x03
}

/// Canonical definition of DestinationType for the entire ReticulumKit module.
/// Used by both PacketHeader (this file) and Destination (Destination.swift).
/// Do NOT duplicate this enum in Destination.swift or anywhere else.
public enum DestinationType: UInt8, Sendable {
    case single = 0x00
    case group  = 0x01
    case plain  = 0x02
    case link   = 0x03
}

/// Propagation type determines how the packet is forwarded.
public enum PropagationType: UInt8, Sendable {
    case broadcast = 0
    case transport = 1
}

/// Context byte values indicating the purpose/sub-type of the packet payload.
/// Source: RNS/Packet.py
public enum PacketContext: UInt8, Sendable {
    case none           = 0x00
    case resource       = 0x01
    case resourceAdv    = 0x02
    case resourceReq    = 0x03
    case resourceHMU    = 0x04
    case resourcePRF    = 0x05
    case resourceICL    = 0x06
    case resourceRCL    = 0x07
    case cacheRequest   = 0x08
    case request        = 0x09
    case response       = 0x0A
    case pathResponse   = 0x0B
    case command        = 0x0C
    case commandStatus  = 0x0D
    case channel        = 0x0E
    case keepalive      = 0xFA
    case linkIdentify   = 0xFB
    case linkClose      = 0xFC
    case linkProof      = 0xFD
    case lrRTT          = 0xFE
    case lrProof        = 0xFF
}
