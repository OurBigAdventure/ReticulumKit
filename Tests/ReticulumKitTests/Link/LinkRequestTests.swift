// SPDX-License-Identifier: MIT
// LinkRequestTests.swift — Python Link.request codec interop

import Testing
import Foundation
import CryptoKit
@testable import ReticulumKit

@Suite("Link.request codec")
struct LinkRequestTests {

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

    @Test("pathHash matches SHA-256 truncated to 16 bytes")
    func pathHash() {
        let path = "/get"
        let expected = Data(SHA256.hash(data: Data(path.utf8))).prefix(16)
        #expect(LinkRequestCodec.pathHash(for: path) == Data(expected))
    }

    @Test("packRequest round-trips via unpackRequest")
    func packUnpackRoundTrip() {
        let payload = Data([0x92, 0xC0, 0xC0])
        let packed = LinkRequestCodec.packRequest(path: "/get", payload: payload, timestamp: 1_700_000_000)
        guard let unpacked = LinkRequestCodec.unpackRequest(packed) else {
            Issue.record("unpack failed")
            return
        }
        #expect(unpacked.pathHash == LinkRequestCodec.pathHash(for: "/get"))
        #expect(unpacked.payload == payload)
    }

    @Test("packResponse round-trips via unpackResponse")
    func responseRoundTrip() {
        let requestId = Data(repeating: 0xAB, count: 16)
        let response = Data([0x91, 0xC0])
        let packed = LinkRequestCodec.packResponse(requestId: requestId, payload: response)
        guard let unpacked = LinkRequestCodec.unpackResponse(packed) else {
            Issue.record("unpack response failed")
            return
        }
        #expect(unpacked.requestId == requestId)
        #expect(unpacked.payload == response)
    }

    @Test("binary payload helpers round-trip raw page bytes")
    func binaryPayloadRoundTrip() {
        let page = Data(">Hello\n".utf8)
        let packed = LinkRequestCodec.packBinaryPayload(page)
        #expect(LinkRequestCodec.unpackBinaryPayload(packed) == page)
    }

    @Test("string map packs NomadNet form fields")
    func stringMapRoundTrip() {
        let fields = ["field_user": "alice", "var_token": "xyz"]
        let packed = LinkRequestCodec.packStringMap(fields)
        #expect(LinkRequestCodec.unpackStringMap(packed) == fields)
    }

    @Test("matches Python-generated fixture bytes")
    func pythonFixture() throws {
        let url = Bundle.module.url(
            forResource: "reticulum_vectors",
            withExtension: "json",
            subdirectory: "Fixtures"
        )!
        let raw = try Data(contentsOf: url)
        let json = try JSONSerialization.jsonObject(with: raw) as! [String: Any]
        let link = json["link_request"] as! [String: Any]
        let expectedHex = link["packed_request_hex"] as! String
        let payload = hexToData(link["payload_hex"] as! String)
        let ts = link["timestamp"] as! Double
        let packed = LinkRequestCodec.packRequest(path: "/get", payload: payload, timestamp: ts)
        #expect(packed == hexToData(expectedHex))
    }
}
