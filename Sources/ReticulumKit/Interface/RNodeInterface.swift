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
    /// Cached preferred write type for the RX characteristic, derived from
    /// `rxCharacteristic.properties` after discovery. The stock RNode firmware
    /// (markqvist/RNode_Firmware/BLESerial.cpp:153) exposes RX with
    /// `PROPERTY_WRITE` only, so iOS will refuse `.withoutResponse` writes and
    /// silently drop the data. We pick the write type at discovery time.
    private var rxWriteType: CBCharacteristicWriteType = .withResponse
    private var shouldReconnect = true
    private let bleQueue: DispatchQueue
    /// Current reconnect backoff in seconds. Doubles on each failed attempt
    /// up to a cap, resets on successful connection. See `scheduleReconnect()`.
    private var reconnectBackoffSeconds: Double = 2.0
    private static let maxReconnectBackoffSeconds: Double = 30.0
    /// Logger for delegate-side events (CBError codes etc.) so the actor and
    /// the delegate share a logging surface.
    private let logger = Logger(label: "ReticulumKit.RNodeBLEDelegate")

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
    /// Chunks data to fit within BLE MTU. Write type is chosen at discovery
    /// time based on the characteristic's declared `properties`: prefers
    /// `.withoutResponse` for throughput when supported, falls back to
    /// `.withResponse` (with the corresponding lower MTU) when only the
    /// `write` bit is set — which is the case on stock RNode firmware
    /// (BLESerial.cpp:153, `BLECharacteristic::PROPERTY_WRITE` only).
    /// Querying `maximumWriteValueLength(for:)` with the actually-used type
    /// is required: it returns different sizes per type (typically 185 for
    /// `.withoutResponse` and 512 for `.withResponse` after MTU exchange).
    func writeToDevice(_ data: Data) {
        guard let peripheral = peripheral, let rxChar = rxCharacteristic else { return }

        let mtu = peripheral.maximumWriteValueLength(for: rxWriteType)
        guard mtu > 0 else { return }

        var offset = 0
        while offset < data.count {
            let chunkEnd = min(offset + mtu, data.count)
            let chunk = data[offset..<chunkEnd]
            peripheral.writeValue(Data(chunk), for: rxChar, type: rxWriteType)
            offset = chunkEnd
        }
    }

    /// Get the current BLE MTU for the chosen write type.
    var currentMTU: Int {
        peripheral?.maximumWriteValueLength(for: rxWriteType) ?? 20
    }

    /// Whether a peripheral is currently connected (CB state == .connected).
    var isConnected: Bool {
        peripheral?.state == .connected
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
        logBLEError(error, context: "didFailToConnect")
        connectionHandler?(false)
        if shouldReconnect { scheduleReconnect() }
    }

    func centralManager(
        _ central: CBCentralManager,
        didDisconnectPeripheral peripheral: CBPeripheral,
        error: Error?
    ) {
        logBLEError(error, context: "didDisconnectPeripheral")
        rxCharacteristic = nil
        txCharacteristic = nil
        // Reset write-type to a safe default for the next discovery cycle.
        rxWriteType = .withResponse
        connectionHandler?(false)

        // Auto-reconnect if desired, with exponential backoff.
        if shouldReconnect { scheduleReconnect() }
    }

    /// Log a CBError (or any Error) from a CoreBluetooth delegate callback.
    /// Includes the CBError.Code raw value, domain, and localized description
    /// so we can finally see whether iOS reports `pairingNotAllowed`,
    /// `peerRemovedPairingInformation`, `connectionTimeout`, etc.
    private func logBLEError(_ error: Error?, context: String) {
        guard let error = error else { return }
        let nsError = error as NSError
        if let cbCode = CBError.Code(rawValue: nsError.code) {
            logger.error(
                "BLE \(context) error: CBError code \(nsError.code) (\(String(describing: cbCode))), domain=\(nsError.domain), description=\(error.localizedDescription)"
            )
        } else {
            logger.error(
                "BLE \(context) error: code \(nsError.code), domain=\(nsError.domain), description=\(error.localizedDescription)"
            )
        }
        errorHandler?(error)
    }

    /// Schedule a reconnect attempt with the current backoff, then double the
    /// backoff for the next failure (capped). `onConnected` resets the backoff
    /// to the initial value on a successful link establishment.
    private func scheduleReconnect() {
        let delay = reconnectBackoffSeconds
        // Pre-double for the next failure.
        reconnectBackoffSeconds = min(reconnectBackoffSeconds * 2.0, Self.maxReconnectBackoffSeconds)
        if delay >= Self.maxReconnectBackoffSeconds {
            logger.warning("RNode reconnect throttled — too many rapid failures, backing off \(delay)s")
        } else {
            logger.info("Will attempt reconnection in \(Int(delay)) seconds")
        }
        bleQueue.asyncAfter(deadline: .now() + delay) { @Sendable [weak self] in
            self?.startScanning()
        }
    }

    /// Reset reconnect backoff after a successful establishment of the link.
    /// Called by the actor on every fresh `onConnected`.
    func resetReconnectBackoff() {
        reconnectBackoffSeconds = 2.0
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
                // Choose write type from declared properties. Stock RNode
                // firmware exposes only `.write` (with response); other
                // forks may expose `.writeWithoutResponse` for throughput.
                if char.properties.contains(.writeWithoutResponse) {
                    rxWriteType = .withoutResponse
                } else {
                    rxWriteType = .withResponse
                }
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

    /// Called when a `.withResponse` write completes (or fails). On stock
    /// RNode firmware the very first write to RX triggers iOS pairing; the
    /// callback fires with `error == nil` once pairing succeeds and the
    /// data has been delivered, or with a CBATT error if the user denied
    /// pairing or the link dropped first. We surface the error to the
    /// actor so it can decide whether to retry / disconnect.
    func peripheral(
        _ peripheral: CBPeripheral,
        didWriteValueFor characteristic: CBCharacteristic,
        error: Error?
    ) {
        if let error = error {
            errorHandler?(error)
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
    /// How the detection wait was resumed. Used to produce accurate log
    /// messages — previously every resume path reported "no DETECT_RESP
    /// within 20 seconds" which is misleading when the link dropped early.
    private enum DetectionOutcome {
        case detected           // DETECT_RESP received
        case linkDropped        // peripheral disconnected before DETECT_RESP
        case timedOut           // 20s watchdog elapsed while still connected
        case staleCancelled     // cancelled by a fresh connect cycle
    }
    /// Detection wait, resumed by `handleBLEData` on DETECT_RESP, by
    /// `onDisconnected` when the link drops, by the timeout watchdog, or
    /// by a stale-continuation cancellation in a fresh connect cycle.
    private var detectContinuation: CheckedContinuation<DetectionOutcome, Never>?
    /// Timestamp of the most recent BLE connect, used by `onDisconnected` to
    /// distinguish "dropped almost immediately" (likely pairing rejection by
    /// firmware) from a longer-lived link. Drives the "hold the button"
    /// hint heuristic.
    private var lastConnectAt: Date?
    /// Detection timeout. Stock RNode firmware requires an MITM-paired link
    /// before TX writes are unblocked (BLESerial.cpp:78), and pairing
    /// requires user interaction with the iOS pairing dialog. The Python
    /// upstream uses 5s; we use 20s to give the user realistic time to tap
    /// "Pair" without the connection being torn down out from under them.
    private static let detectTimeoutSeconds: UInt64 = 20
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
                    // Wake the detection wait immediately rather than
                    // letting it run out the full timeout.
                    if let continuation = detectContinuation {
                        detectContinuation = nil
                        continuation.resume(returning: .detected)
                    }
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
    ///
    /// On stock RNode firmware the very first write to the RX characteristic
    /// (DETECT_REQ) triggers an iOS pairing prompt because the firmware
    /// declares `ESP_GATT_PERM_WRITE_ENC_MITM`. The user must confirm the
    /// pairing dialog before the firmware will accept the write or send any
    /// notifications back. We therefore wait up to 20s — well beyond
    /// realistic user reaction time — and rely on a CheckedContinuation
    /// resumed either by an incoming DETECT_RESP or by `onDisconnected`
    /// when the link drops. We do NOT manually call `disconnectPeripheral`
    /// on timeout — that would dismiss any pending pairing dialog and
    /// guarantee failure.
    private func onConnected() async {
        logger.info("RNode BLE connected, running detection sequence")
        isDetected = false
        deframer = KISSDeframer()
        lastConnectAt = Date()

        // A successful link establishment resets the reconnect backoff so the
        // next failure starts at the short delay again.
        bleDelegate.resetReconnectBackoff()

        // Cancel any stale detection wait from a previous connection cycle.
        if let stale = detectContinuation {
            detectContinuation = nil
            stale.resume(returning: .staleCancelled)
        }

        // Send detection request. On first connect this triggers iOS pairing.
        bleDelegate.writeToDevice(RNodeConstants.detectRequest)

        // Wait for DETECT_RESP, link drop, or timeout — whichever first.
        let outcome = await withCheckedContinuation { (continuation: CheckedContinuation<DetectionOutcome, Never>) in
            self.detectContinuation = continuation
            // Timeout watchdog. If the continuation is still pending when
            // the timeout fires, resume it with `.timedOut`.
            Task { [weak self] in
                try? await Task.sleep(nanoseconds: Self.detectTimeoutSeconds * 1_000_000_000)
                await self?.timeoutDetection()
            }
        }

        switch outcome {
        case .detected:
            await initRadio()
        case .linkDropped:
            // No-op for logging here — `onDisconnected` already logged the
            // disconnect (and the pairing-mode hint if appropriate).
            break
        case .timedOut:
            logger.error("RNode detection timed out after \(Self.detectTimeoutSeconds)s while connected (DETECT_RESP never arrived)")
            // Tear down the link only after a real watchdog timeout. The
            // disconnect-resume path is handled by `onDisconnected` directly.
            if bleDelegate.isConnected {
                bleDelegate.disconnectPeripheral()
            }
        case .staleCancelled:
            // Superseded by a fresh connect cycle — nothing to log.
            break
        }
    }

    /// Resume the detection wait with `.timedOut` if it is still pending.
    /// Called from the timeout watchdog Task. Idempotent.
    private func timeoutDetection() {
        guard let continuation = detectContinuation else { return }
        detectContinuation = nil
        continuation.resume(returning: .timedOut)
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
    ///
    /// In addition to resuming the detection wait, this is where we apply
    /// the "pairing-mode hint" heuristic: if the link dropped within ~3s of
    /// being established and we never received DETECT_RESP, the most likely
    /// explanation is that the stock RNode firmware rejected the BLE
    /// security request because `bt_allow_pairing == false`. The user must
    /// hold the user button on the RNode hardware for 5-10 seconds to enter
    /// pairing mode (RNode_Firmware.ino:1822, `bt_enable_pairing()` →
    /// `bt_state = BT_STATE_PAIRING`). Surfacing this as an actionable log
    /// line is the single most user-visible improvement we can make.
    private func onDisconnected() {
        _isOnline = false
        let wasWaitingForDetect = (detectContinuation != nil) && !isDetected
        let connectionAge: TimeInterval? = lastConnectAt.map { Date().timeIntervalSince($0) }
        isDetected = false
        logger.info("RNode BLE disconnected")

        // If a detection wait is in flight, resume it with `.linkDropped` so
        // `onConnected` can take the disconnect-aware path and produce the
        // accurate log message there (or none, since we log here).
        if let continuation = detectContinuation {
            detectContinuation = nil
            continuation.resume(returning: .linkDropped)
        }

        // Pairing-mode hint heuristic: link dropped before DETECT_RESP and
        // dropped quickly. The "<= 3s" threshold is chosen to catch the
        // observed "connect and disconnect on the same second" pattern from
        // the firmware-side security_request rejection without false-firing
        // on legitimate transient drops on a working link (which take longer).
        if wasWaitingForDetect, let age = connectionAge, age <= 3.0 {
            logger.error(
                "RNode link dropped before pairing completed (link held \(String(format: "%.1f", age))s, no DETECT_RESP). The device likely requires pairing mode — on the RNode hardware, hold the user button for 5-10 seconds to enable pairing, then retry."
            )
        } else if wasWaitingForDetect {
            logger.warning("RNode disconnected before completing detection (DETECT_RESP never arrived)")
        }

        lastConnectAt = nil

        // Reconnect scheduling is handled by the delegate's didDisconnect /
        // didFailToConnect handlers via `scheduleReconnect()` (with backoff).
    }
}
