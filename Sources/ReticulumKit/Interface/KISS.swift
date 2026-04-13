// SPDX-License-Identifier: MIT
// KISS.swift — KISS frame/deframe and stream deframer for RNode BLE communication

import Foundation

/// KISS framing protocol for serial-over-BLE communication with RNode hardware.
///
/// Uses FEND-delimited framing with byte-stuffing escape sequences.
/// FEND (0xC0) marks frame boundaries; payload bytes matching FEND or FESC
/// are escaped using substitution (not XOR like HDLC).
///
/// Frame format: [FEND, command, ...escaped_payload..., FEND]
public enum KISS: Sendable {

    /// Frame end delimiter
    public static let FEND: UInt8 = 0xC0
    /// Frame escape byte
    public static let FESC: UInt8 = 0xDB
    /// Transposed FEND (FESC + TFEND = escaped 0xC0)
    public static let TFEND: UInt8 = 0xDC
    /// Transposed FESC (FESC + TFESC = escaped 0xDB)
    public static let TFESC: UInt8 = 0xDD

    /// Wrap data in a KISS frame: [FEND, command, ...escaped_payload..., FEND]
    ///
    /// Escaping rules (direct substitution, not XOR):
    /// - 0xC0 (FEND) in payload becomes [0xDB, 0xDC]
    /// - 0xDB (FESC) in payload becomes [0xDB, 0xDD]
    /// - All other bytes pass through unchanged.
    ///
    /// - Parameters:
    ///   - command: KISS command byte (e.g., CMD_DATA = 0x00)
    ///   - data: Payload bytes to frame
    /// - Returns: Complete KISS frame including delimiters
    public static func frame(command: UInt8, data: Data) -> Data {
        var result = Data(capacity: data.count + 10)
        result.append(FEND)
        result.append(command)
        for byte in data {
            if byte == FEND {
                result.append(FESC)
                result.append(TFEND)
            } else if byte == FESC {
                result.append(FESC)
                result.append(TFESC)
            } else {
                result.append(byte)
            }
        }
        result.append(FEND)
        return result
    }
}

/// Streaming KISS deframer that handles partial BLE reads.
///
/// Feed incoming BLE bytes via `feed(_:)`. Complete frames are extracted,
/// unescaped, and returned as (command, payload) tuples. Partial frames are
/// buffered until the closing FEND arrives.
///
/// Not Sendable -- must be used within a single actor's isolation domain.
/// Thread safety is provided by the owning actor (e.g., RNodeInterface).
public final class KISSDeframer {

    /// Internal buffer for accumulating bytes between FEND delimiters
    private var buffer = Data()

    /// Whether we have seen a FEND and are currently accumulating frame content
    private var inFrame = false

    /// Maximum buffer size before forced reset (T-08-02, T-08-04 mitigation)
    private static let bufferCap = 4096

    public init() {}

    /// Feed incoming BLE bytes. Returns zero or more complete deframed (command, payload) tuples.
    ///
    /// Handles:
    /// - Split BLE reads (partial frames buffered until complete)
    /// - Multiple concatenated frames in a single read
    /// - Empty frames (consecutive FEND bytes) -- silently discarded
    /// - Oversized frames exceeding bufferCap -- discarded (T-08-02, T-08-04)
    /// - Escaped bytes in payload (FESC sequences)
    public func feed(_ data: Data) -> [(command: UInt8, payload: Data)] {
        var frames: [(command: UInt8, payload: Data)] = []

        for byte in data {
            if byte == KISS.FEND {
                if inFrame && !buffer.isEmpty {
                    // End of frame -- extract command and unescape payload
                    let command = buffer[buffer.startIndex]
                    let rawPayload = buffer.dropFirst()
                    let payload = Self.unescape(Data(rawPayload))
                    frames.append((command: command, payload: payload))
                }
                // Start of next frame (or consecutive FEND)
                buffer.removeAll(keepingCapacity: true)
                inFrame = true
            } else if inFrame {
                buffer.append(byte)
                // T-08-02, T-08-04: Cap buffer to prevent memory exhaustion from BLE flood
                if buffer.count > Self.bufferCap {
                    buffer.removeAll(keepingCapacity: true)
                    inFrame = false
                }
            }
            // Bytes before first FEND are discarded (not in frame)
        }

        return frames
    }

    /// Unescape KISS byte-stuffing sequences in payload data.
    ///
    /// - FESC (0xDB) + TFEND (0xDC) -> 0xC0
    /// - FESC (0xDB) + TFESC (0xDD) -> 0xDB
    /// - Lone FESC at end or followed by unknown byte is passed through (malformed tolerance)
    private static func unescape(_ data: Data) -> Data {
        var result = Data(capacity: data.count)
        var i = data.startIndex
        while i < data.endIndex {
            let byte = data[i]
            if byte == KISS.FESC {
                let next = data.index(after: i)
                if next < data.endIndex {
                    switch data[next] {
                    case KISS.TFEND:
                        result.append(KISS.FEND)
                    case KISS.TFESC:
                        result.append(KISS.FESC)
                    default:
                        // Malformed -- pass through both bytes
                        result.append(byte)
                        result.append(data[next])
                    }
                    i = data.index(after: next)
                } else {
                    // Lone FESC at end -- pass through
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
}
