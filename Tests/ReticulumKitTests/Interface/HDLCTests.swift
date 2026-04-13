// SPDX-License-Identifier: MIT
// HDLCTests.swift — HDLC framing and deframing tests

import Testing
import Foundation
@testable import ReticulumKit

@Suite("HDLC Framing")
struct HDLCTests {

    // MARK: - Escape / Unescape

    @Test("escape produces correct bytes for FLAG and ESC in input")
    func escapeSpecialBytes() {
        let input = Data([0x00, 0x7E, 0x7D, 0xFF])
        let escaped = HDLC.escape(input)
        #expect(escaped == Data([0x00, 0x7D, 0x5E, 0x7D, 0x5D, 0xFF]))
    }

    @Test("unescape reverses escape exactly")
    func unescapeRoundTrip() {
        let input = Data([0x00, 0x7E, 0x7D, 0xFF])
        let escaped = HDLC.escape(input)
        let unescaped = HDLC.unescape(escaped)
        #expect(unescaped == input)
    }

    // MARK: - Frame

    @Test("frame wraps data with FLAG delimiters")
    func frameWrapsWithFlags() {
        let payload = Data([0x01, 0x02, 0x03])
        let framed = HDLC.frame(payload)
        #expect(framed.first == 0x7E)
        #expect(framed.last == 0x7E)
        // Inner bytes should be escaped payload
        let inner = framed.dropFirst().dropLast()
        #expect(HDLC.unescape(Data(inner)) == payload)
    }

    // MARK: - HDLCDeframer

    @Test("deframer with complete frame returns 1 deframed packet")
    func deframerCompleteFrame() {
        let deframer = HDLCDeframer()
        let payload = Data([0x01, 0x02, 0x03])
        let framed = HDLC.frame(payload)
        let packets = deframer.feed(framed)
        #expect(packets.count == 1)
        #expect(packets.first == payload)
    }

    @Test("deframer with split delivery returns packet on second call")
    func deframerSplitDelivery() {
        let deframer = HDLCDeframer()
        let payload = Data([0xAA, 0xBB, 0xCC])
        let framed = HDLC.frame(payload)
        let midpoint = framed.count / 2

        let first = deframer.feed(Data(framed[0..<midpoint]))
        #expect(first.isEmpty)

        let second = deframer.feed(Data(framed[midpoint...]))
        #expect(second.count == 1)
        #expect(second.first == payload)
    }

    @Test("deframer with two concatenated frames returns 2 packets")
    func deframerTwoConcatenatedFrames() {
        let deframer = HDLCDeframer()
        let payload1 = Data([0x01])
        let payload2 = Data([0x02])
        var combined = HDLC.frame(payload1)
        combined.append(HDLC.frame(payload2))
        let packets = deframer.feed(combined)
        #expect(packets.count == 2)
        #expect(packets[0] == payload1)
        #expect(packets[1] == payload2)
    }

    @Test("deframer skips empty frames (two consecutive flags)")
    func deframerSkipsEmptyFrames() {
        let deframer = HDLCDeframer()
        // Two consecutive flags with nothing between = empty frame
        let data = Data([0x7E, 0x7E])
        let packets = deframer.feed(data)
        #expect(packets.isEmpty)
    }

    @Test("round-trip with data containing 0x7E and 0x7D bytes")
    func roundTripSpecialBytes() {
        let deframer = HDLCDeframer()
        let payload = Data([0x7E, 0x7D, 0x00, 0x7E, 0xFF, 0x7D])
        let framed = HDLC.frame(payload)
        let packets = deframer.feed(framed)
        #expect(packets.count == 1)
        #expect(packets.first == payload)
    }

    @Test("round-trip with 500-byte MTU-sized packet")
    func roundTripMTUSize() {
        let deframer = HDLCDeframer()
        let payload = Data(repeating: 0xAB, count: 500)
        let framed = HDLC.frame(payload)
        let packets = deframer.feed(framed)
        #expect(packets.count == 1)
        #expect(packets.first == payload)
    }

    // MARK: - Threat mitigations (T-02-01, T-02-02)

    @Test("deframer discards oversized frames exceeding MTU")
    func deframerDiscardsOversizedFrames() {
        let deframer = HDLCDeframer()
        // 501 bytes exceeds MTU of 500
        let oversized = Data(repeating: 0xAA, count: 501)
        let framed = HDLC.frame(oversized)
        let packets = deframer.feed(framed)
        #expect(packets.isEmpty)
    }

    @Test("deframer resets buffer when exceeding cap without producing frame")
    func deframerBufferCapReset() {
        let deframer = HDLCDeframer()
        // Send > 4096 bytes of non-FLAG data preceded by a FLAG to start accumulation
        var data = Data([0x7E])
        data.append(Data(repeating: 0xAA, count: 4100))
        let packets = deframer.feed(data)
        #expect(packets.isEmpty)
        // Deframer should have reset — a new valid frame should still work
        let payload = Data([0x01, 0x02])
        let framed = HDLC.frame(payload)
        let recovered = deframer.feed(framed)
        #expect(recovered.count == 1)
        #expect(recovered.first == payload)
    }
}
