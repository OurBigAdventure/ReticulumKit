// SPDX-License-Identifier: MIT
// InterfaceAccessCode.swift — Python-compatible IFAC wrap / unwrap
//
// Source: RNS/Transport.py `transmit` / `inbound` and RNS/Reticulum.py IFAC key
// derivation. Public TCP hubs typically have IFAC off; private LoRa / named
// networks set `network_name` and/or `passphrase`.

import Foundation

/// Per-interface access code (IFAC) used to authenticate and obfuscate frames.
///
/// Derives a 64-byte identity from the network name and passphrase, signs each
/// outbound packet, inserts a trailing-`tagSize` signature slice after the
/// 2-byte header, and XOR-masks the header and payload with HKDF(tag, ifac_key).
public struct InterfaceAccessCode: Sendable {
    /// IFAC tag length in bytes (Python `ifac_size`, default 9).
    public let tagSize: Int
    /// 64-byte HKDF key (X25519 priv + Ed25519 priv).
    public let ifacKey: Data
    /// Identity used to sign packets.
    public let identity: Identity

    /// Build an access code from a network name and/or passphrase.
    ///
    /// - Parameters:
    ///   - networkName: Optional `network_name` / `networkname`.
    ///   - passphrase: Optional `passphrase` / `pass_phrase`.
    ///   - tagSize: Tag length in bytes, 1...64. Default 9.
    public init(networkName: String? = nil, passphrase: String? = nil, tagSize: Int = ReticulumConstants.ifacDefaultSize) throws {
        precondition(tagSize >= ReticulumConstants.ifacMinSize && tagSize <= 64, "IFAC tag size must be 1...64 bytes")
        self.tagSize = tagSize
        var origin = Data()
        if let networkName, !networkName.isEmpty {
            origin.append(CryptoEngine.sha256(Data(networkName.utf8)))
        }
        if let passphrase, !passphrase.isEmpty {
            origin.append(CryptoEngine.sha256(Data(passphrase.utf8)))
        }
        guard !origin.isEmpty else {
            throw ReticulumError.ifacMisconfigured("IFAC requires a network name or passphrase")
        }
        let originHash = CryptoEngine.sha256(origin)
        self.ifacKey = CryptoEngine.hkdf(
            length: 64,
            inputKeyMaterial: originHash,
            salt: ReticulumConstants.ifacSalt,
            context: nil
        )
        self.identity = try Identity(privateKeyBytes: ifacKey)
    }

    /// Wrap a packed packet for an IFAC-enabled interface (Python `Transport.transmit`).
    public func wrap(_ raw: Data) throws -> Data {
        guard raw.count > 2 else { return raw }
        let rawBytes = [UInt8](raw)
        // CryptoKit signatures are hedged; Python IFAC re-signs with RFC 8032.
        let signature = try CryptoEngine.signRFC8032(
            raw,
            seed: Data(identity.signingPrivateKey.rawRepresentation)
        )
        let tag = [UInt8](signature.suffix(tagSize))
        let mask = [UInt8](CryptoEngine.hkdf(
            length: raw.count + tagSize,
            inputKeyMaterial: Data(tag),
            salt: ifacKey,
            context: nil
        ))
        var assembled = [UInt8]()
        assembled.reserveCapacity(raw.count + tagSize)
        assembled.append(rawBytes[0] | 0x80)
        assembled.append(rawBytes[1])
        assembled.append(contentsOf: tag)
        assembled.append(contentsOf: rawBytes.dropFirst(2))

        var masked = [UInt8](repeating: 0, count: assembled.count)
        for i in assembled.indices {
            if i == 0 {
                masked[i] = (assembled[i] ^ mask[i]) | 0x80
            } else if i == 1 || i > tagSize + 1 {
                masked[i] = assembled[i] ^ mask[i]
            } else {
                masked[i] = assembled[i]
            }
        }
        return Data(masked)
    }

    /// Unwrap an inbound IFAC frame. Returns `nil` when the tag does not verify
    /// (Python drops the packet).
    public func unwrap(_ wrapped: Data) -> Data? {
        guard let restored = unmaskOnly(wrapped) else { return nil }
        let bytes = [UInt8](wrapped)
        let tag = Array(bytes[2..<(2 + tagSize)])
        guard let expected = try? CryptoEngine.signRFC8032(
            restored,
            seed: Data(identity.signingPrivateKey.rawRepresentation)
        ) else { return nil }
        let expectedTag = [UInt8](expected.suffix(tagSize))
        guard expectedTag == tag else { return nil }
        return restored
    }

    /// Unmask without verifying the tag (tests).
    func unmaskOnly(_ wrapped: Data) -> Data? {
        guard wrapped.count > 2 + tagSize else { return nil }
        let bytes = [UInt8](wrapped)
        guard bytes[0] & 0x80 == 0x80 else { return nil }
        let mask = [UInt8](CryptoEngine.hkdf(
            length: wrapped.count,
            inputKeyMaterial: Data(bytes[2..<(2 + tagSize)]),
            salt: ifacKey,
            context: nil
        ))
        var unmasked = [UInt8](repeating: 0, count: bytes.count)
        for i in bytes.indices {
            if i <= 1 || i > tagSize + 1 {
                unmasked[i] = bytes[i] ^ mask[i]
            } else {
                unmasked[i] = bytes[i]
            }
        }
        var restored = [UInt8]()
        restored.append(unmasked[0] & 0x7F)
        restored.append(unmasked[1])
        restored.append(contentsOf: unmasked.dropFirst(2 + tagSize))
        return Data(restored)
    }
}
