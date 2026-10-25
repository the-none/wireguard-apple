// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import Network

public struct Endpoint {
    public let host: NWEndpoint.Host
    public let port: NWEndpoint.Port

    public init(host: NWEndpoint.Host, port: NWEndpoint.Port) {
        self.host = host
        self.port = port
    }
}

extension Endpoint: Equatable {
    public static func == (lhs: Endpoint, rhs: Endpoint) -> Bool {
        return lhs.host == rhs.host && lhs.port == rhs.port
    }
}

extension Endpoint: Hashable {
    public func hash(into hasher: inout Hasher) {
        hasher.combine(host)
        hasher.combine(port)
    }
}

extension Endpoint {
    public var stringRepresentation: String {
        switch host {
        case .name(let hostname, _):
            return port.rawValue == 0 ? hostname : "\(hostname):\(port)"
        case .ipv4(let address):
            return "\(address):\(port)"
        case .ipv6(let address):
            if port.rawValue == 0, ip4pEndpoint != nil {
                return "[\(address)]"
            }
            return "[\(address)]:\(port)"
        @unknown default:
            fatalError()
        }
    }

    public init?(from string: String) {
        // Separation of host and port is based on 'parse_endpoint' function in
        // https://git.zx2c4.com/wireguard-tools/tree/src/config.c
        guard !string.isEmpty else { return nil }
        let hostString: String
        let portString: String?
        if string.first! == "[" {
            // Look for IPv6-style endpoint, like [::1]:80
            let startOfHost = string.index(after: string.startIndex)
            guard let endOfHost = string.dropFirst().firstIndex(of: "]") else { return nil }
            let afterEndOfHost = string.index(after: endOfHost)
            hostString = String(string[startOfHost ..< endOfHost])
            if afterEndOfHost == string.endIndex {
                portString = nil
            } else {
                guard string[afterEndOfHost] == ":" else { return nil }
                portString = String(string[string.index(after: afterEndOfHost)...])
            }
        } else if IPv6Address(string) != nil {
            hostString = string
            portString = nil
        } else if let endOfHost = string.firstIndex(of: ":") {
            hostString = String(string[..<endOfHost])
            portString = String(string[string.index(after: endOfHost)...])
        } else {
            hostString = string
            portString = nil
        }
        guard !hostString.isEmpty, let endpointPort = NWEndpoint.Port(portString ?? "0") else { return nil }
        let invalidCharacterIndex = hostString.unicodeScalars.firstIndex { char in
            return !CharacterSet.urlHostAllowed.contains(char)
        }
        guard invalidCharacterIndex == nil else { return nil }
        host = NWEndpoint.Host(hostString)
        port = endpointPort
        // A hostname can supply its port through an IP4P DNS answer.
        if portString == nil, hasHostAsIPAddress(), ip4pEndpoint == nil {
            return nil
        }
    }

    public var shouldConvertIP4P: Bool {
        return ip4pEndpoint != nil
    }

    public func convertIP4P(ipv6Address: IPv6Address) -> (String, String) {
        let originIPv6 = ("[\(ipv6Address)]", "\(port)")
        let bytes = ipv6Address.rawValue
        // IP4P is 2001::/80 followed by a 16-bit port and a 32-bit IPv4 address.
        guard bytes[0] == 0x20, bytes[1] == 0x01,
              bytes[2..<10].allSatisfy({ $0 == 0 }) else {
            return originIPv6
        }

        let port = UInt16(bytes[10]) << 8 | UInt16(bytes[11])
        guard port != 0 else { return originIPv6 }
        let ipv4String = "\(bytes[12]).\(bytes[13]).\(bytes[14]).\(bytes[15])"
        return (ipv4String, "\(port)")
    }

    var ip4pEndpoint: Endpoint? {
        guard case .ipv6(let address) = host else { return nil }
        let (addressString, portString) = convertIP4P(ipv6Address: address)
        guard let ipv4 = IPv4Address(addressString),
              let port = NWEndpoint.Port(portString) else { return nil }
        return Endpoint(host: .ipv4(ipv4), port: port)
    }
}

extension Endpoint {
    public func hasHostAsIPAddress() -> Bool {
        switch host {
        case .name:
            return false
        case .ipv4:
            return true
        case .ipv6:
            return true
        @unknown default:
            fatalError()
        }
    }

    public func hostname() -> String? {
        switch host {
        case .name(let hostname, _):
            return hostname
        case .ipv4:
            return nil
        case .ipv6:
            return nil
        @unknown default:
            fatalError()
        }
    }
}
