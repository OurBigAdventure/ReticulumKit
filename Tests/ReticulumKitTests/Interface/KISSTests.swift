// SPDX-License-Identifier: MIT
// KISSTests.swift — KISS framing and deframing tests

import Testing
import Foundation
@testable import ReticulumKit

@Suite("KISS Framing")
struct KISSTests {

    // MARK: - Frame

    @Test("frame with CMD_DATA and single byte produces correct KISS frame")
    func frameDataSingleByte() {
        let result = KISS.frame(command: 0x00, data: Data([0x42]))
        #expect(result == Data([0xC0, 0x00, 0x42, 0xC0]))
    }

    @Test("frame escapes FEND (0xC0) in payload to [0xDB, 0xDC]")
    func frameEscapesFEND() {
        let result = KISS.frame(command: 0x00, data: Data([0xC0]))
        #expect(result == Data([0xC0, 0x00, 0xDB, 0xDC, 0xC0]))
    }

    @Test("frame escapes FESC (0xDB) in payload to [0xDB, 0xDD]")
    func frameEscapesFESC() {
        let result = KISS.frame(command: 0x00, data: Data([0xDB]))
        #expect(result == Data([0xC0, 0x00, 0xDB, 0xDD, 0xC0]))
    }

    @Test("frame with empty data returns [FEND, command, FEND]")
    func frameEmptyData() {
        let result = KISS.frame(command: 0x08, data: Data())
        #expect(result == Data([0xC0, 0x08, 0xC0]))
    }

    @Test("frame escapes multiple special bytes in payload")
    func frameEscapesMultipleSpecialBytes() {
        let result = KISS.frame(command: 0x00, data: Data([0x01, 0xC0, 0x02, 0xDB, 0x03]))
        #expect(result == Data([0xC0, 0x00, 0x01, 0xDB, 0xDC, 0x02, 0xDB, 0xDD, 0x03, 0xC0]))
    }

    // MARK: - KISSDeframer

    @Test("deframer with complete frame returns [(command, data)]")
    func deframerCompleteFrame() {
        let deframer = KISSDeframer()
        let framed = KISS.frame(command: 0x00, data: Data([0x01, 0x02, 0x03]))
        let frames = deframer.feed(framed)
        #expect(frames.count == 1)
        #expect(frames[0].command == 0x00)
        #expect(frames[0].payload == Data([0x01, 0x02, 0x03]))
    }

    @Test("deframer with split data across two calls returns frame on second call")
    func deframerSplitDelivery() {
        let deframer = KISSDeframer()
        let framed = KISS.frame(command: 0x00, data: Data([0xAA, 0xBB, 0xCC]))
        let midpoint = framed.count / 2

        let first = deframer.feed(Data(framed[0..<midpoint]))
        #expect(first.isEmpty)

        let second = deframer.feed(Data(framed[midpoint...]))
        #expect(second.count == 1)
        #expect(second[0].payload == Data([0xAA, 0xBB, 0xCC]))
    }

    @Test("deframer with multiple concatenated frames returns all frames")
    func deframerMultipleConcatenated() {
        let deframer = KISSDeframer()
        let frame1 = KISS.frame(command: 0x00, data: Data([0x01]))
        let frame2 = KISS.frame(command: 0x08, data: Data([0x73]))
        var combined = frame1
        combined.append(frame2)
        let frames = deframer.feed(combined)
        #expect(frames.count == 2)
        #expect(frames[0].command == 0x00)
        #expect(frames[0].payload == Data([0x01]))
        #expect(frames[1].command == 0x08)
        #expect(frames[1].payload == Data([0x73]))
    }

    @Test("deframer discards frames exceeding bufferCap (4096 bytes)")
    func deframerDiscardsOversized() {
        let deframer = KISSDeframer()
        // Start a frame with FEND + command, then flood > 4096 bytes of non-FEND data
        var data = Data([0xC0, 0x00])
        data.append(Data(repeating: 0xAA, count: 4100))
        let frames = deframer.feed(data)
        #expect(frames.isEmpty)

        // Deframer should recover — a new valid frame should work
        let payload = Data([0x01, 0x02])
        let recovered = deframer.feed(KISS.frame(command: 0x00, data: payload))
        #expect(recovered.count == 1)
        #expect(recovered[0].payload == payload)
    }

    @Test("deframer handles escaped bytes in payload correctly")
    func deframerHandlesEscapedBytes() {
        let deframer = KISSDeframer()
        // Payload containing both special bytes
        let payload = Data([0xC0, 0xDB, 0xFF])
        let framed = KISS.frame(command: 0x00, data: payload)
        let frames = deframer.feed(framed)
        #expect(frames.count == 1)
        #expect(frames[0].payload == payload)
    }

    @Test("deframer skips empty frames (consecutive FENDs)")
    func deframerSkipsEmptyFrames() {
        let deframer = KISSDeframer()
        let data = Data([0xC0, 0xC0])
        let frames = deframer.feed(data)
        #expect(frames.isEmpty)
    }

    @Test("round-trip with MTU-sized packet")
    func roundTripMTUSize() {
        let deframer = KISSDeframer()
        let payload = Data(repeating: 0xAB, count: 500)
        let framed = KISS.frame(command: 0x00, data: payload)
        let frames = deframer.feed(framed)
        #expect(frames.count == 1)
        #expect(frames[0].command == 0x00)
        #expect(frames[0].payload == payload)
    }
}
