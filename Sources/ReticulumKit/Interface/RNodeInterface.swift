// SPDX-License-Identifier: MIT
// RNodeInterface.swift — BLE interface actor for RNode LoRa radio connectivity
//
// Requires bluetooth-central UIBackgroundMode in the host app's Info.plist for
// background BLE operation (IFACE-04). Add to UIBackgroundModes array:
//   <string>bluetooth-central</string>
//
// T-08-06: Do not log raw packet bytes at default level (follows T-02-04 logging policy).

import Foundation
import CoreBluetooth
import Logging

// MARK: - BLE Write Protocol (for testability)

/// Protocol abstracting BLE write operations for mock testing.
///
/// Extracted from CoreBluetooth calls so RNodeInterface logic can be tested
/// without real CoreBluetooth hardware.
public protocol BLEWritable: Sendable {
    func writeData(_ data: Data, mtu: Int) async throws
    func startScan() async
    func stopScan() async
    func disconnect() async
}

// MARK: - RNodeBLEDelegate

/// CoreBluetooth delegate bridge for RNode BLE communication.
///
/// CRITICAL per CLAUDE.md: Do NOT use async/await in CoreBluetooth delegate callbacks.
/// This class uses pure synchronous delegate callbacks. The actor boundary is crossed
/// only via closure handlers (dataHandler, stateHandler, etc.) which are thread-safe.
///
/// Not Sendable -- owned by the CBCentralManager's dispatch queue.
/// @unchecked Sendable: All access is serialized on the BLE dispatch queue.
final class RNodeBLEDelegate: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate, @unchecked Sendable {

    // MARK: - Handler closures (set by RNodeInterface actor)

    /// Called when BLE data arrives on the TX characteristic
    var dataHandler: (@Sendable (Data) -> Void)?
    /// Called when CBCentralManager state changes
    var stateHandler: (@Sendable (CBManagerState) -> Void)?
    /// Called when connection state changes (true = connected, false = disconnected)
    var connectionHandler: (@Sendable (Bool) -> Void)?
    /// Called on errors
    var errorHandler: (@Sendable (Error) -> Void)?

    // MARK: - State

    private var centralManager: CBCentralManager?
    private var peripheral: CBPeripheral?
    private var rxCharacteristic: CBCharacteristic?
    private var txCharacteristic: CBCharacteristic?
    private var shouldReconnect = true
    private let bleQueue: DispatchQueue

    /// NUS service UUID for scanning
    private let nusServiceCBUUID = CBUUID(string: RNodeConstants.nusServiceUUID)
    private let nusRXCharCBUUID = CBUUID(string: RNodeConstants.nusRXCharUUID)
    private let nusTXCharCBUUID = CBUUID(string: RNodeConstants.nusTXCharUUID)

    // MARK: - Init

    init(queue: DispatchQueue) {
        self.bleQueue = queue
        super.init()
        // Create CBCentralManager with state restoration for background BLE (IFACE-04)
        self.centralManager = CBCentralManager(
            delegate: self,
            queue: queue,
            options: [CBCentralManagerOptionRestoreIdentifierKey: RNodeConstants.bleRestorationId]
        )
    }

    // MARK: - Public interface (called from actor via Task bridge)

    /// Start scanning for RNode devices advertising NUS service.
    /// Uses specific CBUUID -- required for background scan callbacks (IFACE-04).
    func startScanning() {
        centralManager?.scanForPeripherals(
            withServices: [nusServiceCBUUID],
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: false]
        )
    }

    /// Stop scanning for peripherals.
    func stopScanning() {
        centralManager?.stopScan()
    }

    /// Disconnect from the connected peripheral.
    func disconnectPeripheral() {
        shouldReconnect = false
        if let peripheral = peripheral {
            centralManager?.cancelPeripheralConnection(peripheral)
        }
        peripheral = nil
        rxCharacteristic = nil
        txCharacteristic = nil
    }

    /// Set whether auto-reconnect is enabled.
    func setShouldReconnect(_ value: Bool) {
        shouldReconnect = value
    }

    /// Write data to the RX characteristic (to the RNode device).
    ///
    /// Chunks data to fit within BLE MTU. Uses .withoutResponse for throughput.
    func writeToDevice(_ data: Data) {
        guard let peripheral = peripheral, let rxChar = rxCharacteristic else { return }

        let mtu = peripheral.maximumWriteValueLength(for: .withoutResponse)
        guard mtu > 0 else { return }

        var offset = 0
        while offset < data.count {
            let chunkEnd = min(offset + mtu, data.count)
            let chunk = data[offset..<chunkEnd]
            peripheral.writeValue(Data(chunk), for: rxChar, type: .withoutResponse)
            offset = chunkEnd
        }
    }

    /// Get the current BLE MTU for write-without-response.
    var currentMTU: Int {
        peripheral?.maximumWriteValueLength(for: .withoutResponse) ?? 20
    }

    // MARK: - CBCentralManagerDelegate

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        stateHandler?(central.state)
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        // Store and connect to discovered RNode
        self.peripheral = peripheral
        peripheral.delegate = self
        central.stopScan()
        central.connect(peripheral, options: nil)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        // Discover NUS service on connected peripheral
        peripheral.discoverServices([nusServiceCBUUID])
    }

    func centralManager(
        _ central: CBCentralManager,
        didFailToConnect peripheral: CBPeripheral,
        error: Error?
    ) {
        connectionHandler?(false)
    }

    func centralManager(
        _ central: CBCentralManager,
        didDisconnectPeripheral peripheral: CBPeripheral,
        error: Error?
    ) {
        rxCharacteristic = nil
        txCharacteristic = nil
        connectionHandler?(false)

        // Auto-reconnect if desired
        if shouldReconnect {
            bleQueue.asyncAfter(deadline: .now() + 2.0) { @Sendable [weak self] in
                self?.startScanning()
            }
        }
    }

    /// State preservation/restoration for background BLE (IFACE-04).
    /// iOS calls this when relaunching the app after system termination.
    func centralManager(
        _ central: CBCentralManager,
        willRestoreState dict: [String: Any]
    ) {
        if let peripherals = dict[CBCentralManagerRestoredStatePeripheralsKey] as? [CBPeripheral],
           let restoredPeripheral = peripherals.first {
            self.peripheral = restoredPeripheral
            restoredPeripheral.delegate = self
            // Re-discover services to restore characteristic references
            if restoredPeripheral.state == .connected {
                restoredPeripheral.discoverServices([nusServiceCBUUID])
            } else {
                central.connect(restoredPeripheral, options: nil)
            }
        }
    }

    // MARK: - CBPeripheralDelegate

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard let services = peripheral.services else { return }
        for service in services where service.uuid == nusServiceCBUUID {
            peripheral.discoverCharacteristics(
                [nusRXCharCBUUID, nusTXCharCBUUID],
                for: service
            )
        }
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didDiscoverCharacteristicsFor service: CBService,
        error: Error?
    ) {
        guard let characteristics = service.characteristics else { return }
        for char in characteristics {
            if char.uuid == nusRXCharCBUUID {
                rxCharacteristic = char
            } else if char.uuid == nusTXCharCBUUID {
                txCharacteristic = char
                // Subscribe to TX notifications for incoming data from RNode
                peripheral.setNotifyValue(true, for: char)
            }
        }

        // If both characteristics found, signal connected
        if rxCharacteristic != nil && txCharacteristic != nil {
            connectionHandler?(true)
        }
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didUpdateValueFor characteristic: CBCharacteristic,
        error: Error?
    ) {
        // CRITICAL: Synchronous callback -- no async/await here per CLAUDE.md
        guard characteristic.uuid == nusTXCharCBUUID,
              let data = characteristic.value else { return }
        dataHandler?(data)
    }
}

// MARK: - RNodeInterface Actor

/// BLE interface actor for connecting to RNode LoRa radio hardware.
///
/// Uses CoreBluetooth to communicate with RNode via Nordic UART Service (NUS).
/// Incoming BLE data is KISS-deframed; CMD_DATA payloads are yielded to
/// `incomingPackets` as Reticulum packets.
///
/// Detection sequence: After BLE connection, sends DETECT_REQ (0x73) and waits
/// for DETECT_RESP (0x46) before configuring radio parameters.
///
/// Background BLE: Configured with `bluetooth-central` mode and state
/// preservation/restoration identifier for iOS background operation (IFACE-04).
public actor RNodeInterface: NetworkInterface {

    // MARK: - Public properties (nonisolated for cross-actor access)

    /// Unique identifier for this interface
    public nonisolated let interfaceId: String = "ble-rnode"

    /// Nominal bitrate in bits/second (LoRa SF7/125kHz theoretical max)
    public nonisolated let bitrate: Int = 27_800

    /// Stream of incoming deframed Reticulum packets
    public nonisolated let incomingPackets: AsyncStream<Data>

    /// Whether the interface is currently online (connected, detected, radio enabled)
    public var isOnline: Bool { _isOnline }

    // MARK: - Private state

    private var _isOnline = false
    private var packetContinuation: AsyncStream<Data>.Continuation?
    private var deframer = KISSDeframer()
    private let bleDelegate: RNodeBLEDelegate
    private var radioConfig: RNodeConstants.RadioConfig
    private var isDetected = false
    private var shouldReconnect = false
    private let logger = Logger(label: "ReticulumKit.RNodeInterface")

    // MARK: - Init

    /// Create an RNodeInterface with optional radio configuration.
    ///
    /// - Parameter radioConfig: Radio parameters (defaults to LoRa 868MHz).
    public init(radioConfig: RNodeConstants.RadioConfig = .init()) {
        self.radioConfig = radioConfig

        let (stream, continuation) = AsyncStream.makeStream(of: Data.self)
        self.incomingPackets = stream
        self.packetContinuation = continuation

        let queue = DispatchQueue(label: "reticulumkit.ble")
        let delegate = RNodeBLEDelegate(queue: queue)
        self.bleDelegate = delegate

        // Bridge delegate callbacks to actor isolation.
        // The Task{} bridge here is intentional and safe -- it's at the boundary
        // layer, not inside CoreBluetooth callbacks themselves.

        delegate.dataHandler = { [weak self] data in
            guard let self else { return }
            Task { await self.handleBLEData(data) }
        }

        delegate.connectionHandler = { [weak self] connected in
            guard let self else { return }
            if connected {
                Task { await self.onConnected() }
            } else {
                Task { await self.onDisconnected() }
            }
        }

        delegate.stateHandler = { [weak self] state in
            guard let self else { return }
            Task { await self.handleBLEStateChange(state) }
        }
    }

    // MARK: - NetworkInterface Lifecycle

    /// Start scanning for RNode devices. Enables auto-reconnect.
    public func start() async throws {
        shouldReconnect = true
        bleDelegate.setShouldReconnect(true)
        bleDelegate.startScanning()
        logger.info("RNodeInterface scanning for RNode devices")
    }

    /// Stop the interface. Disconnects BLE and disables auto-reconnect.
    public func stop() async {
        shouldReconnect = false
        _isOnline = false
        isDetected = false
        bleDelegate.setShouldReconnect(false)
        bleDelegate.stopScanning()
        bleDelegate.disconnectPeripheral()
        packetContinuation?.finish()
        packetContinuation = nil
        logger.info("RNodeInterface stopped")
    }

    /// Send a Reticulum packet over LoRa radio via KISS framing.
    ///
    /// T-08-05: Reject packets exceeding Reticulum MTU before framing.
    /// Chunks KISS frame to fit within BLE MTU.
    ///
    /// - Parameter data: Raw Reticulum packet bytes.
    /// - Throws: `ReticulumError.interfaceOffline` if not connected and configured.
    ///           `ReticulumError.packetTooLong` if data exceeds Reticulum MTU.
    public func send(_ data: Data) async throws {
        guard _isOnline else {
            throw ReticulumError.interfaceOffline
        }

        // T-08-05: Bound frame size by Reticulum MTU
        guard data.count <= ReticulumConstants.MTU else {
            throw ReticulumError.packetTooLong(data.count)
        }

        let kissFrame = KISS.frame(command: RNodeConstants.CMD_DATA, data: data)
        bleDelegate.writeToDevice(kissFrame)

        // T-08-06: Log size only, never raw bytes
        logger.debug("Sent \(data.count) bytes on ble-rnode")
    }

    /// Update radio configuration. If online, re-sends parameters to RNode.
    ///
    /// - Parameter radioConfig: New radio parameters.
    public func configure(radioConfig: RNodeConstants.RadioConfig) async {
        self.radioConfig = radioConfig
        if _isOnline {
            await initRadio()
        }
    }

    // MARK: - Private: BLE Data Handling

    /// Process raw BLE bytes through the KISS deframer.
    private func handleBLEData(_ data: Data) {
        let frames = deframer.feed(data)
        for frame in frames {
            switch frame.command {
            case RNodeConstants.CMD_DATA:
                // Reticulum packet -- yield to incoming stream
                // T-08-06: Log size only
                logger.debug("Received \(frame.payload.count) bytes on ble-rnode")
                packetContinuation?.yield(frame.payload)

            case RNodeConstants.CMD_DETECT:
                if frame.payload.first == RNodeConstants.DETECT_RESP {
                    isDetected = true
                    logger.info("RNode detected (DETECT_RESP received)")
                }

            case RNodeConstants.CMD_STAT_RSSI:
                if let rssi = frame.payload.first {
                    let signedRSSI = Int8(bitPattern: rssi)
                    logger.info("RNode RSSI: \(signedRSSI) dBm")
                }

            case RNodeConstants.CMD_STAT_SNR:
                if let snr = frame.payload.first {
                    let signedSNR = Int8(bitPattern: snr)
                    logger.info("RNode SNR: \(signedSNR) dB")
                }

            case RNodeConstants.CMD_READY:
                logger.info("RNode radio ready")

            case RNodeConstants.CMD_PLATFORM:
                logger.info("RNode platform: \(frame.payload.map { String(format: "%02X", $0) }.joined())")

            case RNodeConstants.CMD_FW_VERSION:
                logger.info("RNode firmware version: \(frame.payload.map { String(format: "%02X", $0) }.joined())")

            default:
                logger.debug("RNode command 0x\(String(format: "%02X", frame.command)) with \(frame.payload.count) bytes")
            }
        }
    }

    /// Handle CBCentralManager state changes.
    private func handleBLEStateChange(_ state: CBManagerState) {
        switch state {
        case .poweredOn:
            if shouldReconnect {
                bleDelegate.startScanning()
            }
        case .poweredOff, .unauthorized, .unsupported:
            _isOnline = false
            isDetected = false
            logger.warning("BLE state: \(String(describing: state))")
        default:
            break
        }
    }

    // MARK: - Private: Connection Lifecycle

    /// Called when BLE connection is established and NUS characteristics discovered.
    /// Runs the detection sequence before radio initialization.
    private func onConnected() async {
        logger.info("RNode BLE connected, running detection sequence")
        isDetected = false
        deframer = KISSDeframer()

        // Send detection request
        bleDelegate.writeToDevice(RNodeConstants.detectRequest)

        // Wait up to 3 seconds for detection response
        let deadline = Date().addingTimeInterval(3.0)
        while !isDetected && Date() < deadline {
            try? await Task.sleep(for: .milliseconds(100))
        }

        if isDetected {
            await initRadio()
        } else {
            logger.error("RNode detection failed -- no DETECT_RESP within 3 seconds")
            bleDelegate.disconnectPeripheral()
        }
    }

    /// Configure radio parameters and enable radio.
    /// Called after successful detection handshake.
    private func initRadio() async {
        logger.info("Initializing RNode radio")

        // Send configuration commands in sequence
        bleDelegate.writeToDevice(RNodeConstants.setFrequency(radioConfig.frequency))
        bleDelegate.writeToDevice(RNodeConstants.setBandwidth(radioConfig.bandwidth))
        bleDelegate.writeToDevice(RNodeConstants.setTXPower(radioConfig.txPower))
        bleDelegate.writeToDevice(RNodeConstants.setSpreadingFactor(radioConfig.spreadingFactor))
        bleDelegate.writeToDevice(RNodeConstants.setCodingRate(radioConfig.codingRate))
        bleDelegate.writeToDevice(RNodeConstants.enableRadio)

        _isOnline = true
        logger.info("RNode radio online (freq=\(self.radioConfig.frequency) bw=\(self.radioConfig.bandwidth) sf=\(self.radioConfig.spreadingFactor) cr=\(self.radioConfig.codingRate) txp=\(self.radioConfig.txPower))")
    }

    /// Called when BLE connection is lost.
    private func onDisconnected() {
        _isOnline = false
        isDetected = false
        logger.info("RNode BLE disconnected")

        if shouldReconnect {
            logger.info("Will attempt reconnection in 2 seconds")
            // Reconnect scan is handled by the delegate's didDisconnect handler
        }
    }
}
