// SPDX-License-Identifier: MIT
// RNodeCommandTests.swift — RNode radio parameter encoding tests

import Testing
import Foundation
@testable import ReticulumKit

@Suite("RNode Command Encoding")
struct RNodeCommandTests {

    // MARK: - UInt32 Encoding

    @Test("encodeUInt32(868000000) returns correct 4 big-endian bytes")
    func encodeUInt32Frequency() {
        let data = RNodeConstants.encodeUInt32(868_000_000)
        // 868000000 = 0x33BCA100
        #expect(data == Data([0x33, 0xBC, 0xA1, 0x00]))
    }

    @Test("encodeUInt32(125000) returns correct big-endian bytes")
    func encodeUInt32Bandwidth() {
        let data = RNodeConstants.encodeUInt32(125_000)
        // 125000 = 0x0001E848
        #expect(data == Data([0x00, 0x01, 0xE8, 0x48]))
    }

    // MARK: - Radio Command Helpers

    @Test("setFrequency produces valid KISS frame")
    func setFrequency() {
        let frame = RNodeConstants.setFrequency(868_000_000)
        // [FEND, CMD_FREQUENCY(0x01), ...escaped freq bytes..., FEND]
        #expect(frame.first == 0xC0)
        #expect(frame.last == 0xC0)
        #expect(frame[1] == RNodeConstants.CMD_FREQUENCY)

        // Deframe and verify payload
        let deframer = KISSDeframer()
        let frames = deframer.feed(frame)
        #expect(frames.count == 1)
        #expect(frames[0].command == RNodeConstants.CMD_FREQUENCY)
        #expect(frames[0].payload == Data([0x33, 0xBC, 0xA1, 0x00]))
    }

    @Test("setSpreadingFactor(7) produces [FEND, CMD_SF, 0x07, FEND]")
    func setSpreadingFactor() {
        let frame = RNodeConstants.setSpreadingFactor(7)
        #expect(frame == Data([0xC0, 0x04, 0x07, 0xC0]))
    }

    @Test("setBandwidth(125000) produces correct KISS frame")
    func setBandwidth() {
        let frame = RNodeConstants.setBandwidth(125_000)
        let deframer = KISSDeframer()
        let frames = deframer.feed(frame)
        #expect(frames.count == 1)
        #expect(frames[0].command == RNodeConstants.CMD_BANDWIDTH)
        #expect(frames[0].payload == Data([0x00, 0x01, 0xE8, 0x48]))
    }

    @Test("setTXPower(17) produces [FEND, CMD_TXPOWER, 0x11, FEND]")
    func setTXPower() {
        let frame = RNodeConstants.setTXPower(17)
        #expect(frame == Data([0xC0, 0x03, 0x11, 0xC0]))
    }

    @Test("setCodingRate(5) produces [FEND, CMD_CR, 0x05, FEND]")
    func setCodingRate() {
        let frame = RNodeConstants.setCodingRate(5)
        #expect(frame == Data([0xC0, 0x05, 0x05, 0xC0]))
    }

    @Test("detectRequest produces [FEND, CMD_DETECT, DETECT_REQ, FEND]")
    func detectRequest() {
        let frame = RNodeConstants.detectRequest
        #expect(frame == Data([0xC0, 0x08, 0x73, 0xC0]))
    }

    @Test("enableRadio produces [FEND, CMD_RADIO_STATE, 0x01, FEND]")
    func enableRadio() {
        let frame = RNodeConstants.enableRadio
        #expect(frame == Data([0xC0, 0x06, 0x01, 0xC0]))
    }

    @Test("disableRadio produces [FEND, CMD_RADIO_STATE, 0x00, FEND]")
    func disableRadio() {
        let frame = RNodeConstants.disableRadio
        #expect(frame == Data([0xC0, 0x06, 0x00, 0xC0]))
    }

    // MARK: - RadioConfig defaults

    @Test("RadioConfig default values match LoRa 868MHz defaults")
    func radioConfigDefaults() {
        let config = RNodeConstants.RadioConfig()
        #expect(config.frequency == 868_000_000)
        #expect(config.bandwidth == 125_000)
        #expect(config.spreadingFactor == 7)
        #expect(config.codingRate == 5)
        #expect(config.txPower == 17)
    }
}
