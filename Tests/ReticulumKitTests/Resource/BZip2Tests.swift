// SPDX-License-Identifier: MIT
// BZip2Tests.swift — bz2 interop with Python bz2.compress level 9

import Testing
import Foundation
@testable import ReticulumKit

@Suite("BZip2")
struct BZip2Tests {

    private func hexToData(_ hex: String) -> Data {
        var data = Data()
        var hex = hex
        while hex.count >= 2 {
            let byteString = String(hex.prefix(2))
            hex = String(hex.dropFirst(2))
            data.append(UInt8(byteString, radix: 16)!)
        }
        return data
    }

    @Test("compress shrinks repetitive plaintext and decompress round-trips")
    func roundTrip() {
        let plaintext = Data(repeating: 0x41, count: 4096)
        guard let compressed = BZip2.compress(plaintext) else {
            Issue.record("compress returned nil")
            return
        }
        #expect(compressed.count < plaintext.count)
        guard let restored = BZip2.decompress(compressed) else {
            Issue.record("decompress failed")
            return
        }
        #expect(restored == plaintext)
    }

    @Test("matches Python bz2 fixture bytes")
    func pythonFixture() throws {
        let url = Bundle.module.url(
            forResource: "reticulum_vectors",
            withExtension: "json",
            subdirectory: "Fixtures"
        )!
        let raw = try Data(contentsOf: url)
        let json = try JSONSerialization.jsonObject(with: raw) as! [String: Any]
        let bz2 = json["bz2"] as! [String: Any]
        let plaintext = hexToData(bz2["plaintext_hex"] as! String)
        let expectedCompressed = hexToData(bz2["compressed_hex"] as! String)
        guard let compressed = BZip2.compress(plaintext) else {
            Issue.record("compress failed")
            return
        }
        #expect(compressed == expectedCompressed)
        #expect(BZip2.decompress(compressed) == plaintext)
    }
}
