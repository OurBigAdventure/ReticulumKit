// SPDX-License-Identifier: MIT
// ResourceAdvertisement.swift — msgpack ADV payload (Python `ResourceAdvertisement`)
//
// Wire dictionary keys: t d n h r o i l q f m. Flags byte:
// bit0 encrypted, bit1 compressed, bit2 split, bit3 is_request,
// bit4 is_response, bit5 has_metadata.

import Foundation
import MessagePack

/// Parsed or packed RNS resource advertisement.
public struct ResourceAdvertisement: Sendable {
    public var transferSize: Int
    public var dataSize: Int
    public var partCount: Int
    public var hash: Data
    public var randomHash: Data
    public var originalHash: Data
    public var segmentIndex: Int
    public var totalSegments: Int
    public var requestId: Data?
    public var flags: UInt8
    public var hashmap: Data

    public var isEncrypted: Bool { flags & 0x01 != 0 }
    public var isCompressed: Bool { (flags >> 1) & 0x01 != 0 }
    public var isSplit: Bool { (flags >> 2) & 0x01 != 0 }
    public var isRequest: Bool { (flags >> 3) & 0x01 != 0 }
    public var isResponse: Bool { (flags >> 4) & 0x01 != 0 }
    public var hasMetadata: Bool { (flags >> 5) & 0x01 != 0 }

    /// Pack to msgpack (Python `ResourceAdvertisement.pack`).
    ///
    /// Always emits all 11 keys including `q` as nil. Omitting `q` makes
    /// Python `dictionary["q"]` throw, and some peers tear down the link.
    public func pack() throws -> Data {
        var out = Data()
        out.append(0x8B) // fixmap 11
        func key(_ name: String) {
            let bytes = Array(name.utf8)
            out.append(0xA0 | UInt8(bytes.count))
            out.append(contentsOf: bytes)
        }
        func int(_ value: Int) {
            if value >= 0 && value <= 0x7F {
                out.append(UInt8(value))
            } else if value >= 0 && value <= 0xFF {
                out.append(contentsOf: [0xCC, UInt8(value)])
            } else if value >= 0 && value <= 0xFFFF {
                out.append(0xCD)
                out.append(UInt8((value >> 8) & 0xFF))
                out.append(UInt8(value & 0xFF))
            } else if value >= 0 && value <= 0xFFFF_FFFF {
                out.append(0xCE)
                out.append(UInt8((value >> 24) & 0xFF))
                out.append(UInt8((value >> 16) & 0xFF))
                out.append(UInt8((value >> 8) & 0xFF))
                out.append(UInt8(value & 0xFF))
            } else {
                var v = Int64(value).bigEndian
                out.append(0xD3)
                withUnsafeBytes(of: &v) { out.append(contentsOf: $0) }
            }
        }
        func bin(_ data: Data) {
            let n = data.count
            if n <= 0xFF {
                out.append(contentsOf: [0xC4, UInt8(n)])
            } else if n <= 0xFFFF {
                out.append(0xC5)
                out.append(UInt8((n >> 8) & 0xFF))
                out.append(UInt8(n & 0xFF))
            } else {
                out.append(0xC6)
                out.append(UInt8((n >> 24) & 0xFF))
                out.append(UInt8((n >> 16) & 0xFF))
                out.append(UInt8((n >> 8) & 0xFF))
                out.append(UInt8(n & 0xFF))
            }
            out.append(data)
        }
        key("t"); int(transferSize)
        key("d"); int(dataSize)
        key("n"); int(partCount)
        key("h"); bin(hash)
        key("r"); bin(randomHash)
        key("o"); bin(originalHash)
        key("i"); int(segmentIndex)
        key("l"); int(totalSegments)
        key("q")
        if let requestId {
            bin(requestId)
        } else {
            out.append(0xC0)
        }
        key("f"); int(Int(flags))
        key("m"); bin(hashmap)
        return out
    }

    /// Unpack an advertisement plaintext (already link-decrypted).
    public static func unpack(_ data: Data) throws -> ResourceAdvertisement {
        let wire = try MessagePackDecoder().decode(Wire.self, from: data)
        guard wire.n > 0, wire.n <= 16_384 else {
            throw ReticulumError.resourceFailed("Invalid part count")
        }
        guard wire.t <= ResourceConstants.maxEfficientSize * 3 else {
            throw ReticulumError.resourceFailed("Invalid transfer size")
        }
        return ResourceAdvertisement(
            transferSize: wire.t,
            dataSize: wire.d,
            partCount: wire.n,
            hash: wire.h,
            randomHash: wire.r,
            originalHash: wire.o,
            segmentIndex: wire.i,
            totalSegments: wire.l,
            requestId: wire.q,
            flags: UInt8(truncatingIfNeeded: wire.f),
            hashmap: wire.m
        )
    }

    private struct Wire: Codable {
        var t: Int
        var d: Int
        var n: Int
        var h: Data
        var r: Data
        var o: Data
        var i: Int
        var l: Int
        var q: Data?
        var f: Int
        var m: Data
    }
}
