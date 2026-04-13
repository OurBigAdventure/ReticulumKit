// SPDX-License-Identifier: MIT
// InterfaceManager.swift -- Multi-interface lifecycle coordinator with priority ordering
//
// InterfaceManager coordinates multiple simultaneous network interfaces (TCP, WiFi, BLE)
// with lifecycle management and priority-based ordering for UI display.
// Note: Reticulum flood-sends to ALL online interfaces; priority is for display ordering only.

import Foundation
import Logging

/// Coordinates multiple network interfaces with lifecycle management and priority ordering.
///
/// InterfaceManager registers, starts, stops, and removes interfaces. It maintains
/// a priority-sorted list for UI display and provides status snapshots.
/// Reticulum flood-sends to all online interfaces; the priority here is for display only.
public actor InterfaceManager {

    // MARK: - Types

    /// Priority level for interface ordering in UI and status display.
    /// Reticulum flood-sends to ALL online interfaces; priority is for display only.
    public enum InterfacePriority: Int, Comparable, Sendable {
        case tcp = 0        // Highest (reliable, fast)
        case autoWiFi = 1   // Medium (local network)
        case ble = 2        // Lowest (slow, LoRa radio)

        public static func < (lhs: Self, rhs: Self) -> Bool {
            lhs.rawValue < rhs.rawValue
        }
    }

    /// Status snapshot for a managed interface.
    public struct InterfaceStatus: Sendable {
        public let interfaceId: String
        public let isOnline: Bool
        public let priority: InterfacePriority
    }

    // MARK: - Private Types

    private struct ManagedInterface {
        let interface: any NetworkInterface
        let priority: InterfacePriority
    }

    // MARK: - State

    private var managed: [ManagedInterface] = []

    /// Logger for interface manager events.
    private let logger = Logger(label: "reticulumkit.interfacemanager")

    // MARK: - Init

    public init() {}

    // MARK: - Interface Registration

    /// Register an interface with a given priority.
    public func add(_ interface: any NetworkInterface, priority: InterfacePriority) {
        managed.append(ManagedInterface(interface: interface, priority: priority))
        managed.sort { $0.priority < $1.priority }
    }

    /// Remove an interface by its interfaceId. Stops the interface before removal.
    public func remove(interfaceId: String) async {
        if let index = managed.firstIndex(where: { $0.interface.interfaceId == interfaceId }) {
            await managed[index].interface.stop()
            managed.remove(at: index)
        }
    }

    // MARK: - Queries

    /// All registered interfaces ordered by priority.
    public func allInterfaces() -> [any NetworkInterface] {
        managed.map(\.interface)
    }

    /// Only online interfaces, ordered by priority.
    public func activeInterfaces() async -> [any NetworkInterface] {
        var result: [any NetworkInterface] = []
        for m in managed {
            if await m.interface.isOnline {
                result.append(m.interface)
            }
        }
        return result
    }

    // MARK: - Lifecycle

    /// Start all registered interfaces. Failures are logged but do not block other interfaces (T-08-10).
    public func startAll() async {
        for m in managed {
            do {
                try await m.interface.start()
            } catch {
                logger.warning("Failed to start interface \(m.interface.interfaceId): \(error)")
            }
        }
    }

    /// Stop all registered interfaces.
    public func stopAll() async {
        for m in managed {
            await m.interface.stop()
        }
    }

    // MARK: - Status

    /// Snapshot of all interface statuses for UI display.
    public func interfaceStatuses() async -> [InterfaceStatus] {
        var statuses: [InterfaceStatus] = []
        for m in managed {
            statuses.append(InterfaceStatus(
                interfaceId: m.interface.interfaceId,
                isOnline: await m.interface.isOnline,
                priority: m.priority
            ))
        }
        return statuses
    }
}
