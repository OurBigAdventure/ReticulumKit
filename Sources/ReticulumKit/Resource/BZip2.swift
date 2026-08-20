// SPDX-License-Identifier: MIT
// BZip2.swift — Thin wrapper around system libbz2 (Python `bz2` / RNS Resource auto-compress)
//
// RNS Resource hashes uncompressed plaintext and encrypts `random4 + (bz2 bytes if smaller)`.
// Compression.framework has no bzip2, so we link Darwin `libbz2`.

import Foundation
import CBZip2

/// bzip2 compress/decompress matching Python `bz2.compress` / `bz2.decompress` (level 9).
public enum BZip2 {
    /// Maximum uncompressed size accepted when inflating a Resource.
    /// Python `AUTO_COMPRESS_MAX_SIZE` is 64 MB; this kit caps lower for leaf clients.
    public static let maxDecompressedSize = 16 * 1024 * 1024

    /// Compress `data` with bzip2. Returns nil if compression fails or does not shrink the buffer.
    public static func compress(_ data: Data) -> Data? {
        guard !data.isEmpty else { return data }
        var destLen = UInt32(data.count + data.count / 100 + 600)
        var dest = Data(count: Int(destLen))
        let status: Int32 = data.withUnsafeBytes { src in
            dest.withUnsafeMutableBytes { dst in
                var len = destLen
                let rc = cbzip2_compress(
                    src.baseAddress,
                    UInt32(data.count),
                    dst.baseAddress,
                    &len
                )
                destLen = len
                return rc
            }
        }
        guard status == 0, destLen < data.count else { return nil }
        return dest.prefix(Int(destLen))
    }

    /// Decompress bzip2 bytes. Returns nil on failure or if the result would exceed `maxBytes`.
    public static func decompress(_ data: Data, maxBytes: Int = maxDecompressedSize) -> Data? {
        guard !data.isEmpty, maxBytes > 0 else { return nil }
        var destLen = UInt32(maxBytes)
        var dest = Data(count: maxBytes)
        let status: Int32 = data.withUnsafeBytes { src in
            dest.withUnsafeMutableBytes { dst in
                var len = destLen
                let rc = cbzip2_decompress(
                    src.baseAddress,
                    UInt32(data.count),
                    dst.baseAddress,
                    &len
                )
                destLen = len
                return rc
            }
        }
        guard status == 0 else { return nil }
        return dest.prefix(Int(destLen))
    }
}
