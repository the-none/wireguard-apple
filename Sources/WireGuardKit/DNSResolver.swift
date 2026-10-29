// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Network
import Foundation

enum DNSResolver {}

extension DNSResolver {

    /// Concurrent queue used for DNS resolutions
    private static let resolverQueue = DispatchQueue(label: "DNSResolverQueue", qos: .default, attributes: .concurrent)

    /// 使用 DoH 解析端点（如果配置启用）
    /// - Parameters:
    ///   - endpoints: 待解析的端点列表
    ///   - dohConfig: DoH 配置（为 nil 或未启用时使用系统 DNS）
    ///   - logHandler: 可选的日志处理器
    /// - Returns: 解析结果列表
    static func resolveSyncWithDoH(
        endpoints: [Endpoint?],
        dohConfig: DoHConfiguration?,
        logHandler: ((String) -> Void)? = nil
    ) -> [Result<Endpoint, DNSResolutionError>?] {
        return resolveCandidatesWithDoH(endpoints: endpoints, dohConfig: dohConfig, logHandler: logHandler)
            .map { $0?.map { $0[0] } }
    }

    static func resolveCandidatesWithDoH(
        endpoints: [Endpoint?],
        dohConfig: DoHConfiguration?,
        logHandler: ((String) -> Void)? = nil
    ) -> [Result<[Endpoint], DNSResolutionError>?] {
        // 如果 DoH 未启用，使用传统解析
        guard let config = dohConfig, config.isEnabled else {
            logHandler?("DoH: disabled, using system DNS")
            return resolveCandidates(endpoints: endpoints)
        }

        let isAllEndpointsAlreadyResolved = endpoints.allSatisfy { maybeEndpoint -> Bool in
            return maybeEndpoint?.hasHostAsIPAddress() ?? true
        }

        if isAllEndpointsAlreadyResolved {
            logHandler?("DoH: all endpoints already resolved")
            return endpoints.map { endpoint in
                return endpoint.map { .success([$0]) }
            }
        }

        let resolver = DoHResolver(configuration: config, logHandler: logHandler)

        return endpoints.concurrentMap(queue: resolverQueue) { endpoint -> Result<[Endpoint], DNSResolutionError>? in
            guard let endpoint = endpoint else { return nil }

            if endpoint.hasHostAsIPAddress() {
                return .success([endpoint])
            }

            guard case .name(let hostname, _) = endpoint.host else {
                return .success([endpoint])
            }

            do {
                let (ipv4, ipv6) = try resolver.resolveAddressesSync(hostname: hostname)

                let candidates = preferredEndpoints(ipv4: ipv4.first, ipv6: ipv6, port: endpoint.port)
                if !candidates.isEmpty {
                    logHandler?("DNS: \(hostname) candidates=\(candidates.map { $0.stringRepresentation })")
                    return .success(candidates)
                } else {
                    // DoH 解析失败，检查是否启用降级
                    if config.fallbackEnabled {
                        logHandler?("DNS: \(hostname) has no usable DoH endpoint; falling back to system DNS")
                        return Result { try DNSResolver.resolveCandidates(endpoint: endpoint) }
                            .mapError { error -> DNSResolutionError in
                                // swiftlint:disable:next force_cast
                                return error as! DNSResolutionError
                            }
                    }
                    return .failure(DNSResolutionError(errorCode: EAI_NONAME, address: hostname))
                }
            } catch {
                logHandler?("DNS: DoH failed for \(hostname): \(error); system fallback=\(config.fallbackEnabled)")
                // DoH 解析失败，检查是否启用降级
                if config.fallbackEnabled {
                    return Result { try DNSResolver.resolveCandidates(endpoint: endpoint) }
                        .mapError { error -> DNSResolutionError in
                            // swiftlint:disable:next force_cast
                            return error as! DNSResolutionError
                        }
                }
                return .failure(DNSResolutionError(errorCode: EAI_FAIL, address: hostname))
            }
        }
    }

    static func resolveSync(endpoints: [Endpoint?]) -> [Result<Endpoint, DNSResolutionError>?] {
        return resolveCandidates(endpoints: endpoints).map { $0?.map { $0[0] } }
    }

    private static func resolveCandidates(endpoints: [Endpoint?]) -> [Result<[Endpoint], DNSResolutionError>?] {
        let isAllEndpointsAlreadyResolved = endpoints.allSatisfy { maybeEndpoint -> Bool in
            return maybeEndpoint?.hasHostAsIPAddress() ?? true
        }

        if isAllEndpointsAlreadyResolved {
            return endpoints.map { endpoint in
                return endpoint.map { .success([$0]) }
            }
        }

        return endpoints.concurrentMap(queue: resolverQueue) { endpoint -> Result<[Endpoint], DNSResolutionError>? in
            guard let endpoint = endpoint else { return nil }

            if endpoint.hasHostAsIPAddress() {
                return .success([endpoint])
            } else {
                return Result { try DNSResolver.resolveCandidates(endpoint: endpoint) }
                    .mapError { error -> DNSResolutionError in
                        // swiftlint:disable:next force_cast
                        return error as! DNSResolutionError
                    }
            }
        }
    }

    private static func resolveCandidates(endpoint: Endpoint) throws -> [Endpoint] {
        guard case .name(let name, _) = endpoint.host else {
            return [endpoint]
        }

        var hints = addrinfo()
        hints.ai_flags = AI_ALL // We set this to ALL so that we get v4 addresses even on DNS64 networks
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_DGRAM
        hints.ai_protocol = IPPROTO_UDP

        var resultPointer: UnsafeMutablePointer<addrinfo>?
        defer {
            resultPointer.flatMap { freeaddrinfo($0) }
        }

        let errorCode = getaddrinfo(name, "\(endpoint.port)", &hints, &resultPointer)
        if errorCode != 0 {
            throw DNSResolutionError(errorCode: errorCode, address: name)
        }

        var ipv4Address: IPv4Address?
        var ipv6Addresses = [IPv6Address]()

        var next: UnsafeMutablePointer<addrinfo>? = resultPointer
        let iterator = AnyIterator { () -> addrinfo? in
            let result = next?.pointee
            next = result?.ai_next
            return result
        }

        for addrInfo in iterator {
            if let maybeIpv4Address = IPv4Address(addrInfo: addrInfo) {
                if ipv4Address == nil {
                    ipv4Address = maybeIpv4Address
                }
            } else if let maybeIpv6Address = IPv6Address(addrInfo: addrInfo) {
                ipv6Addresses.append(maybeIpv6Address)
            }
        }

        let candidates = preferredEndpoints(ipv4: ipv4Address, ipv6: ipv6Addresses, port: endpoint.port,
                                            ordinaryIPv6: ipv6Addresses.last)
        guard !candidates.isEmpty else {
            throw DNSResolutionError(errorCode: endpoint.port.rawValue == 0 ? EAI_SERVICE : EAI_NONAME, address: name)
        }
        return candidates
    }

    static func preferredEndpoints(ipv4: IPv4Address?, ipv6: [IPv6Address], port: NWEndpoint.Port,
                                   ordinaryIPv6: IPv6Address? = nil) -> [Endpoint] {
        var seen = Set<Endpoint>()
        let ip4p = ipv6.map { Endpoint(host: .ipv6($0), port: port) }
            .filter { $0.ip4pEndpoint != nil && seen.insert($0).inserted }
        if !ip4p.isEmpty { return ip4p }
        return preferredEndpoint(ipv4: ipv4, ipv6: ordinaryIPv6 ?? ipv6.first, port: port).map { [$0] } ?? []
    }

    static func recoveryEndpoint(candidates: [Endpoint], current: Endpoint?) -> Endpoint? {
        // Stable ordering prevents DNS answer shuffling from starving a candidate.
        let ip4p = candidates.filter { $0.ip4pEndpoint != nil }
            .sorted { $0.stringRepresentation < $1.stringRepresentation }
        guard !ip4p.isEmpty else { return candidates.first }
        guard let index = ip4p.firstIndex(where: { $0 == current }) else { return ip4p.first }
        return ip4p[(index + 1) % ip4p.count]
    }

    static func preferredEndpoint(ipv4: IPv4Address?, ipv6: IPv6Address?, port: NWEndpoint.Port) -> Endpoint? {
        let ipv6Endpoint = ipv6.map { Endpoint(host: .ipv6($0), port: port) }
        if let endpoint = ipv6Endpoint, endpoint.ip4pEndpoint != nil {
            return endpoint
        }
        guard port.rawValue != 0 else { return nil }
        // Preserve the usual IPv4 preference for non-IP4P endpoints.
        if let ipv4 = ipv4 {
            return Endpoint(host: .ipv4(ipv4), port: port)
        }
        return ipv6Endpoint
    }
}

extension Endpoint {
    func withReresolvedIP() throws -> Endpoint {
        #if os(iOS)
        let hostname: String
        switch host {
        case .name(let name, _):
            hostname = name
        case .ipv4(let address):
            hostname = "\(address)"
        case .ipv6(let address):
            hostname = "\(address)"
        @unknown default:
            fatalError()
        }

        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_DGRAM
        hints.ai_protocol = IPPROTO_UDP
        hints.ai_flags = 0 // We set this to zero so that we actually resolve this using DNS64

        var result: UnsafeMutablePointer<addrinfo>?
        defer {
            result.flatMap { freeaddrinfo($0) }
        }

        let errorCode = getaddrinfo(hostname, "\(self.port)", &hints, &result)
        if errorCode != 0 {
            throw DNSResolutionError(errorCode: errorCode, address: hostname)
        }

        let addrInfo = result!.pointee
        if let ipv4Address = IPv4Address(addrInfo: addrInfo) {
            return Endpoint(host: .ipv4(ipv4Address), port: port)
        } else if let ipv6Address = IPv6Address(addrInfo: addrInfo) {
            return Endpoint(host: .ipv6(ipv6Address), port: port)
        } else {
            fatalError()
        }
        #elseif os(macOS)
        return self
        #else
        #error("Unimplemented")
        #endif
    }
}

/// An error type describing DNS resolution error
public struct DNSResolutionError: LocalizedError, Sendable {
    public let errorCode: Int32
    public let address: String

    init(errorCode: Int32, address: String) {
        self.errorCode = errorCode
        self.address = address
    }

    public var errorDescription: String? {
        return String(cString: gai_strerror(errorCode))
    }
}
