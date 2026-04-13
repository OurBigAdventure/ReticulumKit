// SPDX-License-Identifier: MIT
// HDLC.swift — HDLC frame/deframe and stream deframer

import Foundation

/// HDLC-like framing for Reticulum TCP transport.
///
/// Uses flag-byte delimited framing with byte-stuffing escape sequences.
/// Flag byte (0x7E) marks frame boundaries; escape byte (0x7D) followed by
/// the original byte XORed with 0x20 handles in-band occurrences.
public enum HDLC: Sendable {

    /// Frame boundary delimiter
    public static let FLAG: UInt8 = 0x7E
    /// Escape byte — next byte is XORed with ESC_MASK
    public static let ESC: UInt8 = 0x7D
    /// XOR mask applied to escaped bytes
    public static let ESC_MASK: UInt8 = 0x20

    /// Escape FLAG and ESC bytes in data using byte-stuffing.
    ///
    /// - FLAG (0x7E) becomes [0x7D, 0x5E]
    /// - ESC  (0x7D) becomes [0x7D, 0x5D]
    /// - All other bytes pass through unchanged.
    public static func escape(_ data: Data) -> Data {
        var result = Data(capacity: data.count)
        for byte in data {
            if byte == FLAG {
                result.append(ESC)
                result.append(FLAG ^ ESC_MASK)
            } else if byte == ESC {
                result.append(ESC)
                result.append(ESC ^ ESC_MASK)
            } else {
                result.append(byte)
            }
        }
        return result
    }

    /// Reverse byte-stuffing escape sequences.
    ///
    /// [0x7D, 0xNN] becomes (0xNN ^ ESC_MASK). Lone ESC at end of data
    /// is passed through as-is (malformed input tolerance).
    public static func unescape(_ data: Data) -> Data {
        var result = Data(capacity: data.count)
        var i = data.startIndex
        while i < data.endIndex {
            let byte = data[i]
            if byte == ESC {
                let next = data.index(after: i)
                if next < data.endIndex {
                    result.append(data[next] ^ ESC_MASK)
                    i = data.index(after: next)
                } else {
                    // Lone ESC at end — pass through (malformed tolerance)
                    result.append(byte)
                    i = data.index(after: i)
                }
            } else {
                result.append(byte)
                i = data.index(after: i)
            }
        }
        return result
    }

    /// Wrap data in HDLC frame: [FLAG] + escaped(data) + [FLAG]
    public static func frame(_ data: Data) -> Data {
        var result = Data(capacity: data.count + 10)
        result.append(FLAG)
        result.append(escape(data))
        result.append(FLAG)
        return result
    }
}

/// Streaming HDLC deframer that handles partial TCP reads.
///
/// Feed incoming TCP bytes via `feed(_:)`. Complete frames are extracted,
/// unescaped, and returned. Partial frames are buffered until the closing
/// flag arrives.
///
/// Not Sendable — must be used within a single actor's isolation domain.
/// Thread safety is provided by the owning actor (e.g., TCPInterface).
public final class HDLCDeframer {

    /// Internal buffer for accumulating bytes between FLAG delimiters
    private var buffer = Data()

    /// Whether we have seen a FLAG and are currently accumulating frame content
    private var inFrame = false

    /// Maximum buffer size before forced reset (T-02-02 mitigation)
    private static let bufferCap = 4096

    public init() {}

    /// Feed incoming TCP bytes. Returns zero or more complete deframed packets.
    ///
    /// Handles:
    /// - Split TCP reads (partial frames buffered until complete)
    /// - Multiple concatenated frames in a single read
    /// - Empty frames (consecutive FLAG bytes) — silently discarded
    /// - Oversized frames exceeding MTU — discarded (T-02-01)
    /// - Buffer overflow without frame completion — reset (T-02-02)
    public func feed(_ data: Data) -> [Data] {
        var packets: [Data] = []

        for byte in data {
            if byte == HDLC.FLAG {
                if inFrame && !buffer.isEmpty {
                    // End of frame — unescape and validate
                    let unescaped = HDLC.unescape(buffer)
                    // T-02-01: Discard frames exceeding MTU
                    if unescaped.count <= ReticulumConstants.MTU {
                        packets.append(unescaped)
                    }
                }
                // Start of next frame (or consecutive flag)
                buffer.removeAll(keepingCapacity: true)
                inFrame = true
            } else if inFrame {
                buffer.append(byte)
                // T-02-02: Cap buffer to prevent memory exhaustion
                if buffer.count > Self.bufferCap {
                    buffer.removeAll(keepingCapacity: true)
                    inFrame = false
                }
            }
            // Bytes before first FLAG are discarded (not in frame)
        }

        return packets
    }
}
