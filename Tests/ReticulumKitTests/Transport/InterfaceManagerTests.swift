// SPDX-License-Identifier: MIT
// InterfaceManagerTests.swift -- Tests for InterfaceManager multi-interface coordinator

import Testing
import Foundation
@testable import ReticulumKit

// MARK: - Mock Network Interface

/// A mock network interface for testing InterfaceManager behavior.
/// Controls isOnline state and tracks start/stop calls.
actor MockManagedInterface: NetworkInterface {
    nonisolated let interfaceId: String
    nonisolated let bitrate: Int = 115_200
    private var _isOnline: Bool
    private(set) var startCallCount = 0
    private(set) var stopCallCount = 0
    nonisolated let incomingPackets: AsyncStream<Data>
    private let continuation: AsyncStream<Data>.Continuation

    var isOnline: Bool { _isOnline }

    init(id: String, online: Bool = false) {
        self.interfaceId = id
        self._isOnline = online
        var cont: AsyncStream<Data>.Continuation!
        self.incomingPackets = AsyncStream { cont = $0 }
        self.continuation = cont
    }

    func setOnline(_ online: Bool) {
        _isOnline = online
    }

    func send(_ data: Data) async throws {}

    func start() async throws {
        startCallCount += 1
        _isOnline = true
    }

    func stop() async {
        stopCallCount += 1
        _isOnline = false
    }
}

// MARK: - Tests

@Suite("InterfaceManager")
struct InterfaceManagerTests {

    @Test("Empty manager returns empty interface lists")
    func emptyManager() async {
        let manager = InterfaceManager()
        let all = await manager.allInterfaces()
        let active = await manager.activeInterfaces()
        let statuses = await manager.interfaceStatuses()
        #expect(all.isEmpty)
        #expect(active.isEmpty)
        #expect(statuses.isEmpty)
    }

    @Test("Add registers interface and returns it in allInterfaces")
    func addInterface() async {
        let manager = InterfaceManager()
        let iface = MockManagedInterface(id: "tcp-test")
        await manager.add(iface, priority: .tcp)

        let all = await manager.allInterfaces()
        #expect(all.count == 1)
        #expect(all[0].interfaceId == "tcp-test")
    }

    @Test("Interfaces ordered by priority: tcp < autoWiFi < ble")
    func priorityOrdering() async {
        let manager = InterfaceManager()
        let ble = MockManagedInterface(id: "ble-rnode")
        let tcp = MockManagedInterface(id: "tcp-main")
        let wifi = MockManagedInterface(id: "auto-wifi")

        // Add in reverse order
        await manager.add(ble, priority: .ble)
        await manager.add(tcp, priority: .tcp)
        await manager.add(wifi, priority: .autoWiFi)

        let all = await manager.allInterfaces()
        #expect(all.count == 3)
        #expect(all[0].interfaceId == "tcp-main")
        #expect(all[1].interfaceId == "auto-wifi")
        #expect(all[2].interfaceId == "ble-rnode")
    }

    @Test("activeInterfaces returns only online interfaces")
    func activeInterfacesFiltering() async {
        let manager = InterfaceManager()
        let online = MockManagedInterface(id: "tcp-online", online: true)
        let offline = MockManagedInterface(id: "tcp-offline", online: false)

        await manager.add(online, priority: .tcp)
        await manager.add(offline, priority: .tcp)

        let active = await manager.activeInterfaces()
        #expect(active.count == 1)
        #expect(active[0].interfaceId == "tcp-online")
    }

    @Test("Remove stops interface and removes from list")
    func removeInterface() async {
        let manager = InterfaceManager()
        let iface = MockManagedInterface(id: "tcp-remove")
        await manager.add(iface, priority: .tcp)

        await manager.remove(interfaceId: "tcp-remove")

        let all = await manager.allInterfaces()
        #expect(all.isEmpty)
        let stopCount = await iface.stopCallCount
        #expect(stopCount == 1)
    }

    @Test("Remove non-existent interfaceId does nothing")
    func removeNonExistent() async {
        let manager = InterfaceManager()
        let iface = MockManagedInterface(id: "tcp-keep")
        await manager.add(iface, priority: .tcp)

        await manager.remove(interfaceId: "does-not-exist")

        let all = await manager.allInterfaces()
        #expect(all.count == 1)
    }

    @Test("startAll calls start on all interfaces")
    func startAll() async {
        let manager = InterfaceManager()
        let iface1 = MockManagedInterface(id: "tcp-1")
        let iface2 = MockManagedInterface(id: "auto-1")

        await manager.add(iface1, priority: .tcp)
        await manager.add(iface2, priority: .autoWiFi)

        await manager.startAll()

        let starts1 = await iface1.startCallCount
        let starts2 = await iface2.startCallCount
        #expect(starts1 == 1)
        #expect(starts2 == 1)
    }

    @Test("stopAll calls stop on all interfaces")
    func stopAll() async {
        let manager = InterfaceManager()
        let iface1 = MockManagedInterface(id: "tcp-1", online: true)
        let iface2 = MockManagedInterface(id: "auto-1", online: true)

        await manager.add(iface1, priority: .tcp)
        await manager.add(iface2, priority: .autoWiFi)

        await manager.stopAll()

        let stops1 = await iface1.stopCallCount
        let stops2 = await iface2.stopCallCount
        #expect(stops1 == 1)
        #expect(stops2 == 1)
    }

    @Test("interfaceStatuses returns accurate snapshot")
    func interfaceStatuses() async {
        let manager = InterfaceManager()
        let online = MockManagedInterface(id: "tcp-on", online: true)
        let offline = MockManagedInterface(id: "ble-off", online: false)

        await manager.add(online, priority: .tcp)
        await manager.add(offline, priority: .ble)

        let statuses = await manager.interfaceStatuses()
        #expect(statuses.count == 2)
        #expect(statuses[0].interfaceId == "tcp-on")
        #expect(statuses[0].isOnline == true)
        #expect(statuses[0].priority == .tcp)
        #expect(statuses[1].interfaceId == "ble-off")
        #expect(statuses[1].isOnline == false)
        #expect(statuses[1].priority == .ble)
    }
}
