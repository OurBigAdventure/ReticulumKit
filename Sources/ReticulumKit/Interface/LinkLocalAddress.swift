// SPDX-License-Identifier: MIT
// LinkLocalAddress.swift — Resolve link-local IPv6 for AutoInterface discovery tokens
//
// Python AutoInterface: token = SHA256(group_id + sender_link_local_address)[:16]

import Foundation
import Darwin

enum LinkLocalAddress {
    /// First non-loopback link-local IPv6 address (fe80::/10), without zone suffix.
    static func primary() -> String? {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return nil }
        defer { freeifaddrs(ifaddr) }

        var ptr: UnsafeMutablePointer<ifaddrs>? = first
        var candidates: [(name: String, address: String)] = []
        while let interface = ptr {
            defer { ptr = interface.pointee.ifa_next }
            guard let addr = interface.pointee.ifa_addr else { continue }
            guard addr.pointee.sa_family == sa_family_t(AF_INET6) else { continue }
            let name = String(cString: interface.pointee.ifa_name)
            if name == "lo0" { continue }

            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let result = getnameinfo(
                addr,
                socklen_t(addr.pointee.sa_len),
                &host,
                socklen_t(host.count),
                nil,
                0,
                NI_NUMERICHOST
            )
            guard result == 0 else { continue }
            let bytes = host.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }
            var numeric = String(decoding: bytes, as: UTF8.self)
            if let pct = numeric.firstIndex(of: "%") {
                numeric = String(numeric[..<pct])
            }
            guard numeric.lowercased().hasPrefix("fe80:") else { continue }
            candidates.append((name, numeric))
        }

        if let en = candidates.first(where: { $0.name.hasPrefix("en") }) {
            return en.address
        }
        return candidates.first?.address
    }
}
