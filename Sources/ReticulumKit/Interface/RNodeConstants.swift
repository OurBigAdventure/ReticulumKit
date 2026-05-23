// SPDX-License-Identifier: MIT
// RNodeConstants.swift — KISS command bytes, radio parameter ranges, NUS UUIDs

import Foundation

/// Constants for RNode BLE communication: Nordic UART Service UUIDs,
/// KISS command bytes, detection protocol, and radio parameter helpers.
///
/// All UUIDs are stored as String (not CBUUID) to avoid requiring CoreBluetooth
/// import in this file. Convert to CBUUID at the call site in RNodeInterface.
///
/// Source: Python Reticulum RNodeInterface.py, RNode firmware Bluetooth.h
public enum RNodeConstants: Sendable {

    // MARK: - Nordic UART Service UUIDs

    /// NUS service UUID (Nordic UART Service)
    public static let nusServiceUUID = "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
    /// NUS RX characteristic UUID (write to device)
    public static let nusRXCharUUID = "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"
    /// NUS TX characteristic UUID (notify from device)
    public static let nusTXCharUUID = "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"

    // MARK: - KISS Command Bytes

    /// Data frame (Reticulum packet payload)
    public static let CMD_DATA: UInt8 = 0x00
    /// Set frequency (4 bytes big-endian Hz)
    public static let CMD_FREQUENCY: UInt8 = 0x01
    /// Set bandwidth (4 bytes big-endian Hz)
    public static let CMD_BANDWIDTH: UInt8 = 0x02
    /// Set TX power (1 byte, 0-37 dBm)
    public static let CMD_TXPOWER: UInt8 = 0x03
    /// Set spreading factor (1 byte, 5-12)
    public static let CMD_SF: UInt8 = 0x04
    /// Set coding rate (1 byte, 5-8)
    public static let CMD_CR: UInt8 = 0x05
    /// Set radio state (0=off, 1=on)
    public static let CMD_RADIO_STATE: UInt8 = 0x06
    /// Radio lock state (RNode -> Host)
    public static let CMD_RADIO_LOCK: UInt8 = 0x07
    /// Device detection handshake
    public static let CMD_DETECT: UInt8 = 0x08
    /// Short-term airtime lock (2 bytes, pct * 100)
    public static let CMD_ST_ALOCK: UInt8 = 0x0B
    /// Long-term airtime lock (2 bytes, pct * 100)
    public static let CMD_LT_ALOCK: UInt8 = 0x0C
    /// Radio ready indicator (RNode -> Host)
    public static let CMD_READY: UInt8 = 0x0F
    /// BLE link state notification (RNode -> Host, 1 byte)
    public static let CMD_BLE: UInt8 = 0x1F
    /// RX packet count statistic (RNode -> Host)
    public static let CMD_STAT_RX: UInt8 = 0x21
    /// TX packet count statistic (RNode -> Host)
    public static let CMD_STAT_TX: UInt8 = 0x22
    /// RSSI statistic (RNode -> Host, signed)
    public static let CMD_STAT_RSSI: UInt8 = 0x23
    /// SNR statistic (RNode -> Host, signed)
    public static let CMD_STAT_SNR: UInt8 = 0x24
    /// Channel-time / airtime metrics (RNode -> Host)
    public static let CMD_STAT_CHTM: UInt8 = 0x25
    /// Physical-layer parameter snapshot (RNode -> Host)
    public static let CMD_STAT_PHYPRM: UInt8 = 0x26
    /// Battery state (RNode -> Host)
    public static let CMD_STAT_BAT: UInt8 = 0x27
    /// CSMA/queue state (RNode -> Host)
    public static let CMD_STAT_CSMA: UInt8 = 0x28
    /// Platform identifier (RNode -> Host)
    public static let CMD_PLATFORM: UInt8 = 0x48
    /// MCU identifier (RNode -> Host)
    public static let CMD_MCU: UInt8 = 0x49
    /// Firmware version (RNode -> Host, 2 bytes)
    public static let CMD_FW_VERSION: UInt8 = 0x50
    /// Reset device
    public static let CMD_RESET: UInt8 = 0x55

    // MARK: - Detection Protocol

    /// Detection request byte (sent to RNode)
    public static let DETECT_REQ: UInt8 = 0x73
    /// Detection response byte (received from RNode)
    public static let DETECT_RESP: UInt8 = 0x46

    // MARK: - BLE State Restoration

    /// CBCentralManager restoration identifier for background BLE
    public static let bleRestorationId = "reticulumkit.rnode"

    // MARK: - Encoding Helpers

    /// Encode a UInt32 value as 4 big-endian bytes.
    ///
    /// - Parameter value: The value to encode.
    /// - Returns: 4-byte big-endian representation.
    public static func encodeUInt32(_ value: UInt32) -> Data {
        Data([
            UInt8((value >> 24) & 0xFF),
            UInt8((value >> 16) & 0xFF),
            UInt8((value >> 8) & 0xFF),
            UInt8(value & 0xFF),
        ])
    }

    // MARK: - Radio Command Helpers

    /// KISS-framed detect request: [FEND, CMD_DETECT, DETECT_REQ, FEND]
    public static let detectRequest: Data = KISS.frame(command: CMD_DETECT, data: Data([DETECT_REQ]))

    /// KISS-framed radio enable: [FEND, CMD_RADIO_STATE, 0x01, FEND]
    public static let enableRadio: Data = KISS.frame(command: CMD_RADIO_STATE, data: Data([0x01]))

    /// KISS-framed radio disable: [FEND, CMD_RADIO_STATE, 0x00, FEND]
    public static let disableRadio: Data = KISS.frame(command: CMD_RADIO_STATE, data: Data([0x00]))

    /// KISS-framed set frequency command.
    ///
    /// - Parameter hz: Frequency in Hz (e.g., 868000000 for 868 MHz).
    /// - Returns: Complete KISS frame with big-endian encoded frequency.
    public static func setFrequency(_ hz: UInt32) -> Data {
        KISS.frame(command: CMD_FREQUENCY, data: encodeUInt32(hz))
    }

    /// KISS-framed set bandwidth command.
    ///
    /// - Parameter hz: Bandwidth in Hz (e.g., 125000 for 125 kHz).
    /// - Returns: Complete KISS frame with big-endian encoded bandwidth.
    public static func setBandwidth(_ hz: UInt32) -> Data {
        KISS.frame(command: CMD_BANDWIDTH, data: encodeUInt32(hz))
    }

    /// KISS-framed set TX power command.
    ///
    /// - Parameter dbm: Transmit power in dBm (0-37, device-dependent max).
    /// - Returns: Complete KISS frame with single-byte power value.
    public static func setTXPower(_ dbm: UInt8) -> Data {
        KISS.frame(command: CMD_TXPOWER, data: Data([dbm]))
    }

    /// KISS-framed set spreading factor command.
    ///
    /// - Parameter sf: Spreading factor (5-12).
    /// - Returns: Complete KISS frame with single-byte SF value.
    public static func setSpreadingFactor(_ sf: UInt8) -> Data {
        KISS.frame(command: CMD_SF, data: Data([sf]))
    }

    /// KISS-framed set coding rate command.
    ///
    /// - Parameter cr: Coding rate (5-8, representing 4/5 to 4/8).
    /// - Returns: Complete KISS frame with single-byte CR value.
    public static func setCodingRate(_ cr: UInt8) -> Data {
        KISS.frame(command: CMD_CR, data: Data([cr]))
    }

    // MARK: - Radio Configuration

    /// Default radio parameters for LoRa 868 MHz configuration.
    public struct RadioConfig: Sendable, Equatable {
        /// Frequency in Hz
        public var frequency: UInt32
        /// Bandwidth in Hz
        public var bandwidth: UInt32
        /// Spreading factor (5-12)
        public var spreadingFactor: UInt8
        /// Coding rate (5-8)
        public var codingRate: UInt8
        /// TX power in dBm (0-37)
        public var txPower: UInt8

        /// Default LoRa 868 MHz configuration matching Python Reticulum defaults.
        public init(
            frequency: UInt32 = 868_000_000,
            bandwidth: UInt32 = 125_000,
            spreadingFactor: UInt8 = 7,
            codingRate: UInt8 = 5,
            txPower: UInt8 = 17
        ) {
            self.frequency = frequency
            self.bandwidth = bandwidth
            self.spreadingFactor = spreadingFactor
            self.codingRate = codingRate
            self.txPower = txPower
        }
    }
}
