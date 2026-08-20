// SPDX-License-Identifier: MIT
// ResourceConstants.swift — Python `RNS.Resource` transfer constants
//
// Source: RNS/Resource.py. SDU is Packet.MDU (464). Advertisement hashmap
// fits `floor((Link.MDU - 134) / 4)` hashes in the first ADV packet.

import Foundation

/// Constants for RNS Resource transfers over a Link.
public enum ResourceConstants: Sendable {
    public static let window = 4
    public static let windowMin = 2
    public static let windowMaxSlow = 10
    public static let windowMaxFast = 75
    public static let mapHashLength = 4
    public static let randomHashSize = 4
    public static let sdu = ReticulumConstants.MDU
    public static let advertisementOverhead = 134
    public static let hashmapMaxLength =
        max(1, (LinkConstants.mdu - advertisementOverhead) / mapHashLength)
    public static let hashmapNotExhausted: UInt8 = 0x00
    public static let hashmapExhausted: UInt8 = 0xFF
    public static let maxEfficientSize = 1_048_575
    public static let identityHashLength = 32
}
