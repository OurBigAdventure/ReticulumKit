import Testing
import Foundation
@testable import ReticulumKit

@Suite("TruncatedHash Tests")
struct TruncatedHashTests {

    @Test("Init with exactly 16 bytes succeeds")
    func initWith16Bytes() throws {
        let data = Data(repeating: 0xAB, count: 16)
        let hash = try TruncatedHash(data)
        #expect(hash.data == data)
    }

    @Test("Init with fewer than 16 bytes throws invalidHashLength")
    func initWithTooFewBytes() {
        let data = Data(repeating: 0x00, count: 10)
        #expect(throws: ReticulumError.self) {
            _ = try TruncatedHash(data)
        }
    }

    @Test("Init with more than 16 bytes throws invalidHashLength")
    func initWithTooManyBytes() {
        let data = Data(repeating: 0x00, count: 32)
        #expect(throws: ReticulumError.self) {
            _ = try TruncatedHash(data)
        }
    }

    @Test("Two TruncatedHash from same data are equal")
    func equality() throws {
        let data = Data(repeating: 0xCD, count: 16)
        let a = try TruncatedHash(data)
        let b = try TruncatedHash(data)
        #expect(a == b)
    }

    @Test("Two TruncatedHash from different data are not equal")
    func inequality() throws {
        let a = try TruncatedHash(Data(repeating: 0x01, count: 16))
        let b = try TruncatedHash(Data(repeating: 0x02, count: 16))
        #expect(a != b)
    }

    @Test("TruncatedHash is Hashable (can be used in Set)")
    func hashable() throws {
        let data = Data(repeating: 0xEF, count: 16)
        let hash = try TruncatedHash(data)
        var set: Set<TruncatedHash> = []
        set.insert(hash)
        #expect(set.contains(hash))
    }

    @Test("hexString produces correct hex representation")
    func hexString() throws {
        let data = Data([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                         0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F])
        let hash = try TruncatedHash(data)
        #expect(hash.hexString == "000102030405060708090a0b0c0d0e0f")
    }
}
