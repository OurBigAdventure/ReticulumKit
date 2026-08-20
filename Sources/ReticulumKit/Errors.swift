// SPDX-License-Identifier: MIT
// Errors.swift — ReticulumKit error types

import Foundation

/// All errors produced by ReticulumKit operations.
public enum ReticulumError: Error, Sendable {
    case invalidHashLength(Int)
    case invalidKeySize(Int)
    case invalidTokenKeySize(Int)
    case tokenTooShort
    case hmacVerificationFailed
    case encryptionFailed(status: Int32)
    case decryptionFailed(status: Int32)
    case randomGenerationFailed
    case packetTooShort
    case packetTooLong(Int)
    case invalidHeaderType
    case invalidPacketType
    case invalidDestinationType
    case invalidPropagationType
    case keychainStoreFailed(status: OSStatus)
    case missingTransportId
    case unexpectedTransportId
    case invalidPacketContext(UInt8)
    case interfaceOffline
    case linkInvalidState(String)
    case linkInvalidProof(String)
    case linkRequestTooShort(Int)
    case linkNoToken
    /// Timed out waiting for a link REQUEST response (Python `Link.request` timeout).
    case linkRequestTimeout
}
