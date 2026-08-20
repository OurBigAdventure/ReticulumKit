// SPDX-License-Identifier: MIT
// AutoInterfaceTests.swift — AutoInterface multicast address derivation, discovery token, and peer management tests

import Testing
import Foundation
@testable import ReticulumKit

@Suite("AutoInterface")
struct AutoInterfaceTests {

    // MARK: - Multicast Address Derivation

    @Test("deriveMulticastAddress for 'reticulum' produces valid ff12:0: IPv6 address")
    func multicastAddressDefault() {
        let addr = AutoInterface.deriveMulticastAddress(groupId: "reticulum")
        #expect(addr.hasPrefix("ff12:0:"))
        // Must have exactly 8 colon-separated groups (ff12:0:XX:XX:XX:XX:XX:XX)
        let groups = addr.split(separator: ":")
        #expect(groups.count == 8)
    }

    @Test("deriveMulticastAddress with different groupId produces different address")
    func multicastAddressDifferentGroup() {
        let addr1 = AutoInterface.deriveMulticastAddress(groupId: "reticulum")
        let addr2 = AutoInterface.deriveMulticastAddress(groupId: "testnet")
        #expect(addr1 != addr2)
    }

    @Test("deriveMulticastAddress is deterministic")
    func multicastAddressDeterministic() {
        let addr1 = AutoInterface.deriveMulticastAddress(groupId: "reticulum")
        let addr2 = AutoInterface.deriveMulticastAddress(groupId: "reticulum")
        #expect(addr1 == addr2)
    }

    // MARK: - Discovery Token

    @Test("discoveryToken computes SHA-256 truncated to 16 bytes")
    func discoveryTokenLength() {
        let token = AutoInterface.discoveryToken(groupId: "reticulum", address: "fe80::1")
        #expect(token.count == 16)
    }

    @Test("discoveryToken is deterministic")
    func discoveryTokenDeterministic() {
        let t1 = AutoInterface.discoveryToken(groupId: "reticulum", address: "fe80::1")
        let t2 = AutoInterface.discoveryToken(groupId: "reticulum", address: "fe80::1")
        #expect(t1 == t2)
    }

    @Test("discoveryToken differs for different addresses")
    func discoveryTokenDifferentAddresses() {
        let t1 = AutoInterface.discoveryToken(groupId: "reticulum", address: "fe80::1")
        let t2 = AutoInterface.discoveryToken(groupId: "reticulum", address: "fe80::2")
        #expect(t1 != t2)
    }

    @Test("discoveryToken differs for different groupIds")
    func discoveryTokenDifferentGroups() {
        let t1 = AutoInterface.discoveryToken(groupId: "reticulum", address: "fe80::1")
        let t2 = AutoInterface.discoveryToken(groupId: "testnet", address: "fe80::1")
        #expect(t1 != t2)
    }

    @Test("discoveryToken matches Python SHA256(group_id + address)[:16]")
    func discoveryTokenPythonFixture() {
        // Python: hashlib.sha256(b"reticulum" + b"fe80::1").digest()[:16]
        let token = AutoInterface.discoveryToken(groupId: "reticulum", address: "fe80::1")
        #expect(token.hexEncodedString == "97b25576749ea936b0d8a8536ffaf442")
    }

    // MARK: - Link-local address resolution

    @Test("resolveLinkLocalAddress is nil or fe80 without zone suffix")
    func resolveLinkLocalAddressFormat() {
        if let addr = AutoInterface.resolveLinkLocalAddress() {
            #expect(addr.lowercased().hasPrefix("fe80:"))
            #expect(!addr.contains("%"))
        }
    }

    @Test("resolveLinkLocalAddress is stable across calls")
    func resolveLinkLocalAddressStable() {
        let a = AutoInterface.resolveLinkLocalAddress()
        let b = AutoInterface.resolveLinkLocalAddress()
        #expect(a == b)
    }

    // MARK: - Peer Tracking

    @Test("addPeer stores peer and increments count")
    func addPeerIncrementsCount() async {
        let iface = AutoInterface(groupId: "reticulum")
        let token = Data(repeating: 0xAA, count: 16)
        await iface.addPeer(address: "fe80::1", token: token)
        let count = await iface.peerCount
        #expect(count == 1)
    }

    @Test("prunePeers removes expired peers")
    func prunePeersRemovesExpired() async {
        let iface = AutoInterface(groupId: "reticulum")
        let token = Data(repeating: 0xAA, count: 16)
        // Add a peer with an already-expired timestamp via test helper
        await iface.addPeerForTesting(address: "fe80::1", token: token, lastSeen: Date().addingTimeInterval(-30))
        let countBefore = await iface.peerCount
        #expect(countBefore == 1)

        await iface.prunePeers()
        let countAfter = await iface.peerCount
        #expect(countAfter == 0)
    }

    @Test("prunePeers keeps fresh peers")
    func prunePeersKeepsFresh() async {
        let iface = AutoInterface(groupId: "reticulum")
        let token = Data(repeating: 0xAA, count: 16)
        await iface.addPeer(address: "fe80::1", token: token)

        await iface.prunePeers()
        let count = await iface.peerCount
        #expect(count == 1)
    }

    @Test("peers capped at 128, oldest evicted on overflow")
    func peerCapEnforced() async {
        let iface = AutoInterface(groupId: "reticulum")
        // Add 129 peers — the first one should be evicted
        for i in 0..<129 {
            let token = Data(repeating: UInt8(i % 256), count: 16)
            let time = Date().addingTimeInterval(Double(i))
            await iface.addPeerForTesting(address: "fe80::\(i)", token: token, lastSeen: time)
        }
        let count = await iface.peerCount
        #expect(count == 128)
    }

    // MARK: - Interface Properties

    @Test("interfaceId is 'AutoInterface'")
    func interfaceIdCorrect() {
        let iface = AutoInterface(groupId: "reticulum")
        #expect(iface.interfaceId == "AutoInterface")
    }

    @Test("bitrate is 10_000_000")
    func bitrateCorrect() {
        let iface = AutoInterface(groupId: "reticulum")
        #expect(iface.bitrate == 10_000_000)
    }

    @Test("not online before start")
    func notOnlineBeforeStart() async {
        let iface = AutoInterface(groupId: "reticulum")
        let online = await iface.isOnline
        #expect(online == false)
    }
}
