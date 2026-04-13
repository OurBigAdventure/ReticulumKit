// SPDX-License-Identifier: MIT
// NetworkInterface.swift — Protocol contract for all network interfaces

import Foundation

/// Contract for all Reticulum network interfaces (TCP, UDP multicast, BLE).
///
/// Each conforming type is expected to be an actor providing serialized access
/// to its underlying transport connection. The protocol itself is
/// `AnyObject & Sendable` to allow storage in collections across actor boundaries.
public protocol NetworkInterface: AnyObject, Sendable {
    /// Unique identifier for this interface instance (e.g., "tcp-example.com:4242")
    var interfaceId: String { get }

    /// Whether the interface is currently connected and able to send/receive
    var isOnline: Bool { get async }

    /// Nominal bitrate of the interface in bits per second
    var bitrate: Int { get }

    /// Send raw packet data over this interface
    func send(_ data: Data) async throws

    /// Start the interface (connect, begin listening)
    func start() async throws

    /// Stop the interface (disconnect, clean up resources)
    func stop() async

    /// Stream of incoming raw packet data from the interface
    var incomingPackets: AsyncStream<Data> { get }
}
