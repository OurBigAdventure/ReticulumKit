// SPDX-License-Identifier: MIT
// LinkRequest.swift — Python `Link.request` / `Packet.REQUEST` codec
//
// Wire: msgpack `[timestamp(float64), path_hash(bin16), payload]`.
// Path hash is SHA-256(path UTF-8) truncated to 16 bytes.
// Packet request id is Python `Packet.getTruncatedHash()` of the REQUEST
// packet (not truncated_hash of the plaintext body). Response is
// msgpack `[request_id(bin16), response]`.

import Foundation
import CryptoKit

/// Helpers for Reticulum link REQUEST / RESPONSE packets (Python `Link.request`).
public enum LinkRequestCodec {
    /// Truncated SHA-256 of a request path string (Python `Identity.truncated_hash(path.encode())`).
    public static func pathHash(for path: String) -> Data {
        Data(SHA256.hash(data: Data(path.utf8)).prefix(ReticulumConstants.truncatedHashLength))
    }

    /// Pack a request body: `[timestamp, path_hash, payload_bytes_or_nil]`.
    ///
    /// `payload` is already msgpack-encoded (or empty for a msgpack nil).
    public static func packRequest(path: String, payload: Data?, timestamp: TimeInterval = Date().timeIntervalSince1970) -> Data {
        var out = Data()
        out.append(0x93) // fixarray 3
        out.append(msgpackFloat64(timestamp))
        out.append(msgpackBin(pathHash(for: path)))
        if let payload {
            out.append(payload)
        } else {
            out.append(0xC0)
        }
        return out
    }

    /// Unpack a request body into path hash and remaining payload bytes (verbatim msgpack of element 2).
    public static func unpackRequest(_ data: Data) -> (pathHash: Data, payload: Data)? {
        let bytes = Array(data)
        guard !bytes.isEmpty else { return nil }
        let tag = bytes[0]
        guard tag & 0xF0 == 0x90, Int(tag & 0x0F) >= 3 else { return nil }
        var pos = 1
        // skip timestamp
        guard let afterTs = skipMsgpackValue(bytes, offset: pos) else { return nil }
        pos = afterTs
        guard let (hash, afterHash) = readBin(bytes, offset: pos), hash.count == 16 else { return nil }
        pos = afterHash
        guard pos < bytes.count, let end = skipMsgpackValue(bytes, offset: pos) else { return nil }
        return (hash, Data(bytes[pos..<end]))
    }

    /// Pack a response: `[request_id, response_payload]`.
    ///
    /// `payload` must already be a msgpack value (bin/str/array/map).
    public static func packResponse(requestId: Data, payload: Data) -> Data {
        var out = Data()
        out.append(0x92)
        out.append(msgpackBin(requestId))
        out.append(payload)
        return out
    }

    /// Unpack `[request_id, response]` and return the response as raw remaining msgpack of element 1.
    public static func unpackResponse(_ data: Data) -> (requestId: Data, payload: Data)? {
        let bytes = Array(data)
        guard !bytes.isEmpty else { return nil }
        let tag = bytes[0]
        guard tag & 0xF0 == 0x90, Int(tag & 0x0F) >= 2 else { return nil }
        var pos = 1
        guard let (requestId, afterId) = readBin(bytes, offset: pos) else { return nil }
        pos = afterId
        guard pos < bytes.count, let end = skipMsgpackValue(bytes, offset: pos) else { return nil }
        return (requestId, Data(bytes[pos..<end]))
    }

    // MARK: - Minimal msgpack

    private static func msgpackFloat64(_ value: Double) -> Data {
        var bits = value.bitPattern.bigEndian
        var out = Data([0xCB])
        withUnsafeBytes(of: &bits) { out.append(contentsOf: $0) }
        return out
    }

    private static func msgpackBin(_ value: Data) -> Data {
        var out = Data()
        let n = value.count
        if n <= 0xFF {
            out.append(contentsOf: [0xC4, UInt8(n)])
        } else {
            out.append(0xC5)
            out.append(UInt8((n >> 8) & 0xFF))
            out.append(UInt8(n & 0xFF))
        }
        out.append(value)
        return out
    }

    private static func readBin(_ bytes: [UInt8], offset: Int) -> (Data, Int)? {
        guard offset < bytes.count else { return nil }
        let tag = bytes[offset]
        var pos = offset + 1
        let len: Int
        if tag & 0xE0 == 0xA0 {
            len = Int(tag & 0x1F)
        } else {
            switch tag {
            case 0xC4:
                guard pos < bytes.count else { return nil }
                len = Int(bytes[pos]); pos += 1
            case 0xC5:
                guard pos + 2 <= bytes.count else { return nil }
                len = Int(bytes[pos]) << 8 | Int(bytes[pos + 1]); pos += 2
            default:
                return nil
            }
        }
        guard pos + len <= bytes.count else { return nil }
        return (Data(bytes[pos..<pos + len]), pos + len)
    }

    private static func skipMsgpackValue(_ bytes: [UInt8], offset: Int) -> Int? {
        guard offset < bytes.count else { return nil }
        let tag = bytes[offset]
        let pos = offset + 1
        if tag & 0x80 == 0x00 { return pos }
        if tag & 0xE0 == 0xE0 { return pos }
        if tag & 0xE0 == 0xA0 { return advance(pos, by: Int(tag & 0x1F), max: bytes.count) }
        if tag & 0xF0 == 0x90 {
            return walk(bytes, offset: pos, count: Int(tag & 0x0F), per: 1)
        }
        if tag & 0xF0 == 0x80 {
            return walk(bytes, offset: pos, count: Int(tag & 0x0F), per: 2)
        }
        switch tag {
        case 0xC0, 0xC2, 0xC3: return pos
        case 0xC4:
            guard let n = readUInt(bytes, offset: pos, width: 1) else { return nil }
            return advance(pos + 1, by: n, max: bytes.count)
        case 0xC5:
            guard let n = readUInt(bytes, offset: pos, width: 2) else { return nil }
            return advance(pos + 2, by: n, max: bytes.count)
        case 0xC6:
            guard let n = readUInt(bytes, offset: pos, width: 4) else { return nil }
            return advance(pos + 4, by: n, max: bytes.count)
        case 0xCA: return advance(pos, by: 4, max: bytes.count)
        case 0xCB: return advance(pos, by: 8, max: bytes.count)
        case 0xCC: return advance(pos, by: 1, max: bytes.count)
        case 0xCD: return advance(pos, by: 2, max: bytes.count)
        case 0xCE: return advance(pos, by: 4, max: bytes.count)
        case 0xCF: return advance(pos, by: 8, max: bytes.count)
        case 0xD0: return advance(pos, by: 1, max: bytes.count)
        case 0xD1: return advance(pos, by: 2, max: bytes.count)
        case 0xD2: return advance(pos, by: 4, max: bytes.count)
        case 0xD3: return advance(pos, by: 8, max: bytes.count)
        case 0xD9:
            guard let n = readUInt(bytes, offset: pos, width: 1) else { return nil }
            return advance(pos + 1, by: n, max: bytes.count)
        case 0xDA:
            guard let n = readUInt(bytes, offset: pos, width: 2) else { return nil }
            return advance(pos + 2, by: n, max: bytes.count)
        case 0xDC:
            guard let n = readUInt(bytes, offset: pos, width: 2) else { return nil }
            return walk(bytes, offset: pos + 2, count: n, per: 1)
        case 0xDE:
            guard let n = readUInt(bytes, offset: pos, width: 2) else { return nil }
            return walk(bytes, offset: pos + 2, count: n, per: 2)
        default:
            return nil
        }
    }

    private static func walk(_ bytes: [UInt8], offset: Int, count: Int, per: Int) -> Int? {
        var pos = offset
        for _ in 0..<(count * per) {
            guard let next = skipMsgpackValue(bytes, offset: pos) else { return nil }
            pos = next
        }
        return pos
    }

    private static func readUInt(_ bytes: [UInt8], offset: Int, width: Int) -> Int? {
        guard offset + width <= bytes.count else { return nil }
        var v = 0
        for i in 0..<width { v = (v << 8) | Int(bytes[offset + i]) }
        return v
    }

    private static func advance(_ pos: Int, by len: Int, max: Int) -> Int? {
        let end = pos + len
        return end <= max ? end : nil
    }
}
