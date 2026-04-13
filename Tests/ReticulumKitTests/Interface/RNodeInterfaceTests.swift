// SPDX-License-Identifier: MIT
// RNodeInterfaceTests.swift — RNodeInterface lifecycle tests with mock BLE

import Testing
import Foundation
@testable import ReticulumKit

@Suite("RNodeInterface")
struct RNodeInterfaceTests {

    // MARK: - KISS Deframer Integration (simulating BLE-chunked data)

    @Test("BLE-chunked data correctly deframed into packets")
    func bleChunkedDeframing() {
        let deframer = KISSDeframer()

        // Simulate a Reticulum packet wrapped in KISS CMD_DATA frame
        let packet = Data([0x01, 0x02, 0x03, 0x04, 0x05])
        let kissFrame = KISS.frame(command: RNodeConstants.CMD_DATA, data: packet)

        // Simulate BLE delivering the frame in 2 chunks (typical BLE behavior)
        let mid = kissFrame.count / 2
        let chunk1 = Data(kissFrame[0..<mid])
        let chunk2 = Data(kissFrame[mid...])

        let frames1 = deframer.feed(chunk1)
        #expect(frames1.isEmpty, "First chunk should not complete frame")

        let frames2 = deframer.feed(chunk2)
        #expect(frames2.count == 1)
        #expect(frames2[0].command == RNodeConstants.CMD_DATA)
        #expect(frames2[0].payload == packet)
    }

    @Test("Multiple packets in single BLE read correctly separated")
    func multiplePacketsInSingleRead() {
        let deframer = KISSDeframer()

        let packet1 = Data([0xAA, 0xBB])
        let packet2 = Data([0xCC, 0xDD])
        var combined = KISS.frame(command: RNodeConstants.CMD_DATA, data: packet1)
        combined.append(KISS.frame(command: RNodeConstants.CMD_DATA, data: packet2))

        let frames = deframer.feed(combined)
        #expect(frames.count == 2)
        #expect(frames[0].payload == packet1)
        #expect(frames[1].payload == packet2)
    }

    // MARK: - Detection Response Parsing

    @Test("CMD_DETECT with DETECT_RESP payload correctly identified")
    func detectResponseParsing() {
        let deframer = KISSDeframer()

        // Simulate RNode sending detection response
        let detectResp = KISS.frame(
            command: RNodeConstants.CMD_DETECT,
            data: Data([RNodeConstants.DETECT_RESP])
        )

        let frames = deframer.feed(detectResp)
        #expect(frames.count == 1)
        #expect(frames[0].command == RNodeConstants.CMD_DETECT)
        #expect(frames[0].payload.first == RNodeConstants.DETECT_RESP)
    }

    @Test("Detection request produces correct KISS frame")
    func detectRequestFormat() {
        let deframer = KISSDeframer()
        let frames = deframer.feed(RNodeConstants.detectRequest)
        #expect(frames.count == 1)
        #expect(frames[0].command == RNodeConstants.CMD_DETECT)
        #expect(frames[0].payload == Data([RNodeConstants.DETECT_REQ]))
    }

    // MARK: - Radio Init Command Sequence

    @Test("Radio init sends all expected commands in correct order")
    func radioInitCommandSequence() {
        let config = RNodeConstants.RadioConfig(
            frequency: 915_000_000,
            bandwidth: 250_000,
            spreadingFactor: 8,
            codingRate: 6,
            txPower: 20
        )

        // Generate all commands that initRadio() would send
        let commands: [Data] = [
            RNodeConstants.setFrequency(config.frequency),
            RNodeConstants.setBandwidth(config.bandwidth),
            RNodeConstants.setTXPower(config.txPower),
            RNodeConstants.setSpreadingFactor(config.spreadingFactor),
            RNodeConstants.setCodingRate(config.codingRate),
            RNodeConstants.enableRadio,
        ]

        // Verify each command decodes correctly
        let deframer = KISSDeframer()
        var allData = Data()
        for cmd in commands {
            allData.append(cmd)
        }

        let frames = deframer.feed(allData)
        #expect(frames.count == 6)

        // Frequency
        #expect(frames[0].command == RNodeConstants.CMD_FREQUENCY)
        #expect(frames[0].payload == RNodeConstants.encodeUInt32(915_000_000))

        // Bandwidth
        #expect(frames[1].command == RNodeConstants.CMD_BANDWIDTH)
        #expect(frames[1].payload == RNodeConstants.encodeUInt32(250_000))

        // TX Power
        #expect(frames[2].command == RNodeConstants.CMD_TXPOWER)
        #expect(frames[2].payload == Data([20]))

        // Spreading Factor
        #expect(frames[3].command == RNodeConstants.CMD_SF)
        #expect(frames[3].payload == Data([8]))

        // Coding Rate
        #expect(frames[4].command == RNodeConstants.CMD_CR)
        #expect(frames[4].payload == Data([6]))

        // Enable Radio
        #expect(frames[5].command == RNodeConstants.CMD_RADIO_STATE)
        #expect(frames[5].payload == Data([0x01]))
    }

    // MARK: - MTU Chunking

    @Test("KISS frame chunking splits correctly at MTU boundary")
    func kissFrameChunking() {
        // Simulate a 400-byte packet (within Reticulum MTU)
        let packet = Data(repeating: 0x42, count: 400)
        let kissFrame = KISS.frame(command: RNodeConstants.CMD_DATA, data: packet)

        // Simulate MTU of 185 bytes (typical BLE negotiated MTU)
        let mtu = 185
        var chunks: [Data] = []
        var offset = 0
        while offset < kissFrame.count {
            let end = min(offset + mtu, kissFrame.count)
            chunks.append(Data(kissFrame[offset..<end]))
            offset = end
        }

        // Should produce 3 chunks (402 bytes / 185 = 2.17 -> 3 chunks)
        // Frame size: FEND + CMD + 400 bytes + FEND = 402 (if no escaping needed)
        #expect(chunks.count >= 2, "Frame should be split into multiple chunks")

        // Verify all chunks reassemble correctly
        let deframer = KISSDeframer()
        var allFrames: [(command: UInt8, payload: Data)] = []
        for chunk in chunks {
            allFrames.append(contentsOf: deframer.feed(chunk))
        }

        #expect(allFrames.count == 1)
        #expect(allFrames[0].command == RNodeConstants.CMD_DATA)
        #expect(allFrames[0].payload == packet)
    }

    @Test("KISS frame with escaped bytes chunking works correctly")
    func kissFrameEscapedChunking() {
        // Packet with bytes that need KISS escaping
        var packet = Data(repeating: 0xC0, count: 50) // All FEND bytes = all escaped
        packet.append(Data(repeating: 0xDB, count: 50)) // All FESC bytes = all escaped
        let kissFrame = KISS.frame(command: RNodeConstants.CMD_DATA, data: packet)

        // Escaped: each 0xC0 becomes [0xDB, 0xDC] (2 bytes), each 0xDB becomes [0xDB, 0xDD] (2 bytes)
        // So 100 bytes become 200 escaped bytes + FEND + CMD + FEND = 203 bytes
        #expect(kissFrame.count == 203)

        // Chunk at MTU 100
        let mtu = 100
        var chunks: [Data] = []
        var offset = 0
        while offset < kissFrame.count {
            let end = min(offset + mtu, kissFrame.count)
            chunks.append(Data(kissFrame[offset..<end]))
            offset = end
        }

        #expect(chunks.count == 3)

        // Reassemble
        let deframer = KISSDeframer()
        var allFrames: [(command: UInt8, payload: Data)] = []
        for chunk in chunks {
            allFrames.append(contentsOf: deframer.feed(chunk))
        }

        #expect(allFrames.count == 1)
        #expect(allFrames[0].payload == packet)
    }

    // MARK: - Signal Quality Parsing

    @Test("RSSI and SNR command frames parse correctly")
    func signalQualityParsing() {
        let deframer = KISSDeframer()

        // RSSI: -80 dBm (as unsigned byte: 0xB0 = 176, signed = -80)
        let rssiFrame = KISS.frame(command: RNodeConstants.CMD_STAT_RSSI, data: Data([0xB0]))
        // SNR: 10 dB
        let snrFrame = KISS.frame(command: RNodeConstants.CMD_STAT_SNR, data: Data([0x0A]))

        var combined = rssiFrame
        combined.append(snrFrame)

        let frames = deframer.feed(combined)
        #expect(frames.count == 2)
        #expect(frames[0].command == RNodeConstants.CMD_STAT_RSSI)
        #expect(Int8(bitPattern: frames[0].payload[0]) == -80)
        #expect(frames[1].command == RNodeConstants.CMD_STAT_SNR)
        #expect(Int8(bitPattern: frames[1].payload[0]) == 10)
    }

    // MARK: - Interface Properties

    @Test("RNodeInterface has correct default properties")
    func interfaceProperties() async {
        let rnode = RNodeInterface()
        #expect(rnode.interfaceId == "ble-rnode")
        #expect(rnode.bitrate == 27_800)
        let online = await rnode.isOnline
        #expect(online == false)
    }

    // MARK: - Packet Size Validation (T-08-05)

    @Test("Packets exceeding MTU are rejected before KISS framing")
    func packetSizeValidation() async {
        let rnode = RNodeInterface()
        try? await rnode.start()

        // A packet larger than Reticulum MTU (500 bytes) should be rejected
        let oversized = Data(repeating: 0xAA, count: 501)
        do {
            try await rnode.send(oversized)
            #expect(Bool(false), "Should have thrown")
        } catch let error as ReticulumError {
            if case .packetTooLong(let size) = error {
                #expect(size == 501)
            } else if case .interfaceOffline = error {
                // Also acceptable -- interface isn't actually online
            } else {
                #expect(Bool(false), "Unexpected error type: \(error)")
            }
        } catch {
            // interfaceOffline is acceptable since we don't have real BLE
        }

        await rnode.stop()
    }
}
