# ReticulumKit

A pure-Swift implementation of the [Reticulum](https://reticulum.network) cryptographic networking stack, built for modern Apple platforms with Swift 6 strict concurrency.

[![Swift 6.1](https://img.shields.io/badge/Swift-6.1-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%2016%2B%20%7C%20macOS%2013%2B-blue.svg)](https://developer.apple.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![SwiftPM](https://img.shields.io/badge/SwiftPM-compatible-brightgreen.svg)](https://swift.org/package-manager)

ReticulumKit lets you build apps that speak Reticulum natively — no Python runtime, no bridging, no daemon. It is wire-compatible with the reference [Python Reticulum](https://github.com/markqvist/Reticulum) stack, so nodes built with ReticulumKit interoperate with [Sideband](https://github.com/markqvist/Sideband), [MeshChat](https://github.com/liamcottle/reticulum-meshchat), [NomadNet](https://github.com/markqvist/NomadNet), and any other RNS peer on the network.

> **Independent project.** ReticulumKit is an independent, clean-room Swift implementation of the Reticulum protocol. Reticulum and its reference Python implementation are created by [Mark Qvist](https://github.com/markqvist). ReticulumKit is not affiliated with or endorsed by the Reticulum project.
>
> **Built with AI assistance.** ReticulumKit is written and maintained by a Swift developer, with AI assistance used as part of the development workflow. The code is human-reviewed and backed by a test suite verified against the reference implementation.

> **Status: alpha (`v0.1.0`).** The public API may change before `1.0`. It is wire-tested against Python RNS, but treat it as pre-release and pin to an exact version.

## What is Reticulum?

Reticulum is a cryptography-based networking stack for building local and wide-area networks over any medium — LoRa radios, packet radio, WiFi, or TCP/IP. Every destination is identified by a cryptographic hash, every link is end-to-end encrypted with forward secrecy, and the network routes without any central authority, DNS, or assigned addresses. It's designed to keep working on high-latency, low-bandwidth, and unreliable links.

## Features

- **Identity & addressing** — Curve25519 keypairs (X25519 + Ed25519), destination/name hashing, and Keychain-backed key storage.
- **Cryptography** — `Token` AEAD (AES-128-CBC + HKDF + HMAC-SHA256), Ed25519 sign/verify, and truncated-hash addressing, all built on Apple's CryptoKit.
- **Packets** — Full packet header encode/decode matching the RNS wire format (MTU 500, MDU 464).
- **Announces** — Create, sign, and validate announces (with ratchet support), replay protection, and per-interface rate limiting.
- **Transport** — A central `actor` that wires interfaces to announce handling, maintains the routing table, services path requests, and manages links.
- **Links** — Forward-secret encrypted channels via a 3-packet ECDH handshake; ephemeral keys are discarded the moment the shared secret is derived.
- **Interfaces** — Pluggable transport via the `NetworkInterface` protocol:
  - `TCPInterface` — connect to a Reticulum TCP server.
  - `AutoInterface` — peer discovery over UDP multicast on the local network.
  - `RNodeInterface` — drive an [RNode](https://unsigned.io/rnode/) LoRa radio over Bluetooth LE (KISS/HDLC framing).

## Requirements

- Swift 6.1+
- iOS 16+ / macOS 13+
- Xcode 16+

## Installation

Add ReticulumKit to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/J-Krush/ReticulumKit.git", from: "0.1.0"),
],
targets: [
    .target(
        name: "YourApp",
        dependencies: [
            .product(name: "ReticulumKit", package: "ReticulumKit"),
        ]
    ),
]
```

Or in Xcode: **File → Add Package Dependencies…** and enter the repository URL.

## Quick start

Bring up a node, connect to a TCP interface, and announce a destination so other peers can discover you:

```swift
import ReticulumKit

// 1. Create (or load) an identity — your node's long-term keypair.
let identity = Identity()

// 2. Define a destination you want to be reachable at.
let destination = Destination(
    identity: identity,
    direction: .in,
    appName: "myapp",
    aspects: ["chat"]
)

// 3. Start the transport and attach an interface.
let transport = Transport()
let tcp = TCPInterface(host: "amsterdam.connect.reticulum.network", port: 4965)
await transport.addInterface(tcp)
try await tcp.start()

// 4. React to peers as they announce themselves.
await transport.onAnnounce { announce in
    print("Discovered destination: \(announce.destinationHash.hexString)")
}

// 5. Register and announce your destination to the network.
transport.registerDestination(destination, identity: identity)
try await transport.sendAnnounce(for: destination)

// Optionally keep re-announcing on a schedule.
await transport.startReAnnounce(interval: 1800)
```

Establish an end-to-end encrypted link to a destination you've discovered:

```swift
// `peerHash` comes from an announce you received.
let link = try await transport.establishLink(to: peerHash, identity: identity)

// After the handshake completes, the link carries forward-secret traffic.
let status = await link.status   // -> .active
```

## Architecture

ReticulumKit mirrors the layering of the reference RNS stack:

```
┌─────────────────────────────────────────────┐
│  Your app  /  LXMFKit (messaging layer)       │
├─────────────────────────────────────────────┤
│  Transport (actor)                            │
│   • routing table   • path requests           │
│   • announce validation + rate limiting       │
│   • link management                           │
├──────────────┬────────────────┬──────────────┤
│  Link        │  Announce      │  Destination  │
│  (ECDH, FS)  │  (sign/verify) │  Identity     │
├──────────────┴────────────────┴──────────────┤
│  Packet  /  PacketHeader  (RNS wire format)   │
├─────────────────────────────────────────────┤
│  NetworkInterface protocol                    │
│   TCPInterface · AutoInterface · RNodeInterface│
└─────────────────────────────────────────────┘
```

Concurrency is built on Swift actors: `Transport`, `Link`, and each interface are actors, so cross-task access is serialized without manual locking. The package compiles under Swift 6 strict concurrency checking.

## Interoperability

ReticulumKit is verified against the Python RNS wire format. Packet headers, identity/destination hashing, announce signing, and the link handshake all match the reference implementation byte-for-byte. Source references to the corresponding Python modules are cited in the code where wire formats are implemented.

If you find a case where ReticulumKit and Python RNS disagree on the wire, that's a bug — please [open an issue](https://github.com/J-Krush/ReticulumKit/issues) with a packet capture or fixture.

## Related projects

- **[LXMFKit](https://github.com/J-Krush/LXMFKit)** — the LXMF messaging layer built on top of ReticulumKit.
- **[Reticulum](https://github.com/markqvist/Reticulum)** — the reference Python implementation and protocol specification.

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request, and note the [Code of Conduct](CODE_OF_CONDUCT.md). Security issues should follow the process in [SECURITY.md](SECURITY.md) — please do not file them as public issues.

## License

ReticulumKit is released under the [MIT License](LICENSE). Reticulum and its reference Python implementation, created by [Mark Qvist](https://github.com/markqvist), are likewise MIT-licensed.
