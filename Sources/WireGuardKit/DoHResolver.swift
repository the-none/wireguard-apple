// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation
import Network

/// DNS over HTTPS 解析器
public final class DoHResolver {

    /// DoH 解析错误
    public enum DoHError: Error, LocalizedError {
        case invalidConfiguration
        case noBootstrapIP
        case networkError(Error)
        case invalidResponse
        case noRecordsFound
        case timeout
        case bootstrapResolutionFailed

        public var errorDescription: String? {
            switch self {
            case .invalidConfiguration:
                return "Invalid DoH configuration"
            case .noBootstrapIP:
                return "No bootstrap IP available"
            case .networkError(let error):
                return "Network error: \(error.localizedDescription)"
            case .invalidResponse:
                return "Invalid DNS response"
            case .noRecordsFound:
                return "No DNS records found"
            case .timeout:
                return "DNS query timeout"
            case .bootstrapResolutionFailed:
                return "Failed to resolve DoH server address using bootstrap DNS"
            }
        }
    }

    /// DNS 记录类型
    private enum DNSRecordType: UInt16 {
        case a = 1      // IPv4
        case aaaa = 28  // IPv6
    }

    public typealias LogHandler = (String) -> Void

    // MARK: - Properties

    private let configuration: DoHConfiguration
    private let logHandler: LogHandler?

    /// 缓存已解析的 DoH 服务器 IP
    private var resolvedDoHServerIP: String?

    // MARK: - Initialization

    public init(configuration: DoHConfiguration, logHandler: LogHandler? = nil) {
        self.configuration = configuration
        self.logHandler = logHandler

        log("DoH: init with provider=\(configuration.provider), enabled=\(configuration.isEnabled)")
    }

    private func log(_ message: String) {
        logHandler?(message)
    }

    // MARK: - Public API

    /// 解析域名
    /// - Parameters:
    ///   - hostname: 要解析的域名
    ///   - preferIPv4: 是否优先返回 IPv4 地址
    /// - Returns: 解析结果 (IPv4 地址, IPv6 地址)
    public func resolve(hostname: String, preferIPv4: Bool = true) async throws -> (ipv4: IPv4Address?, ipv6: IPv6Address?) {
        log("DoH: resolving \(hostname)")

        guard let dohURL = configuration.effectiveURL else {
            log("DoH: error - no effective URL configured")
            throw DoHError.invalidConfiguration
        }

        guard let dohHost = dohURL.host else {
            log("DoH: error - cannot extract host from URL")
            throw DoHError.invalidConfiguration
        }

        log("DoH: using URL \(dohURL.absoluteString)")

        let bootstrapIPs = configuration.effectiveBootstrapIPs
        guard !bootstrapIPs.isEmpty else {
            log("DoH: error - no bootstrap IPs")
            throw DoHError.noBootstrapIP
        }

        log("DoH: bootstrap IPs = \(bootstrapIPs.joined(separator: ", "))")

        // 获取 DoH 服务器的实际 IP
        let dohServerIP: String
        do {
            dohServerIP = try await resolveDoHServerIP(dohURL: dohURL, bootstrapIPs: bootstrapIPs)
            log("DoH: server IP resolved to \(dohServerIP)")
        } catch {
            log("DoH: failed to resolve server IP - \(error.localizedDescription)")
            throw error
        }

        // 并发查询 A 和 AAAA 记录
        async let ipv4Task = queryDNS(hostname: hostname, type: .a, dohURL: dohURL, dohServerIP: dohServerIP, originalHost: dohHost)
        async let ipv6Task = queryDNS(hostname: hostname, type: .aaaa, dohURL: dohURL, dohServerIP: dohServerIP, originalHost: dohHost)

        let ipv4Addresses = (try? await ipv4Task) ?? []
        let ipv6Addresses = (try? await ipv6Task) ?? []

        let ipv4: IPv4Address? = ipv4Addresses.compactMap { IPv4Address($0) }.first
        let ipv6Candidates = ipv6Addresses.compactMap { IPv6Address($0) }
        let ipv6 = Self.preferredIPv6Address(ipv6Candidates)

        log("DoH: resolved \(hostname) -> IPv4=\(ipv4.map { "\($0)" } ?? "nil"), IPv6=\(ipv6.map { "\($0)" } ?? "nil")")

        if ipv4 == nil && ipv6 == nil {
            log("DoH: error - no records found for \(hostname)")
            throw DoHError.noRecordsFound
        }

        return (ipv4, ipv6)
    }

    static func preferredIPv6Address(_ addresses: [IPv6Address]) -> IPv6Address? {
        if let address = addresses.first(where: {
            Endpoint(host: .ipv6($0), port: 0).ip4pEndpoint != nil
        }) {
            return address
        }
        return addresses.first
    }

    /// 同步解析域名
    public func resolveSync(hostname: String, preferIPv4: Bool = true) throws -> (ipv4: IPv4Address?, ipv6: IPv6Address?) {
        let semaphore = DispatchSemaphore(value: 0)
        var result: (ipv4: IPv4Address?, ipv6: IPv6Address?)?
        var error: Error?

        Task {
            do {
                result = try await resolve(hostname: hostname, preferIPv4: preferIPv4)
            } catch let e {
                error = e
            }
            semaphore.signal()
        }

        let timeoutResult = semaphore.wait(timeout: .now() + configuration.timeout * 2)
        if timeoutResult == .timedOut {
            throw DoHError.timeout
        }

        if let error = error {
            throw error
        }

        guard let result = result else {
            throw DoHError.noRecordsFound
        }

        return result
    }

    // MARK: - DoH Server Resolution

    /// 解析 DoH 服务器的 IP 地址
    /// 使用 Bootstrap IP 作为 DNS 服务器解析 DoH 域名
    private func resolveDoHServerIP(dohURL: URL, bootstrapIPs: [String]) async throws -> String {
        // 如果已有缓存，直接返回
        if let cached = resolvedDoHServerIP {
            log("DoH: using cached server IP \(cached)")
            return cached
        }

        guard let dohHost = dohURL.host else {
            log("DoH: error - cannot extract host from URL")
            throw DoHError.invalidConfiguration
        }

        log("DoH: resolving server host \(dohHost)")

        // 检查 DoH host 是否已经是 IP 地址
        if IPv4Address(dohHost) != nil || IPv6Address(dohHost) != nil {
            log("DoH: server host is already an IP address")
            resolvedDoHServerIP = dohHost
            return dohHost
        }

        // 使用 Bootstrap IP 作为 DNS 服务器解析 DoH 域名
        guard let bootstrapIP = bootstrapIPs.first else {
            log("DoH: error - no bootstrap IP")
            throw DoHError.noBootstrapIP
        }

        log("DoH: resolving \(dohHost) via UDP DNS server \(bootstrapIP)")

        // 使用传统 DNS (UDP) 通过 Bootstrap IP 解析 DoH 服务器域名
        let resolvedIP = try await resolveHostnameViaUDP(hostname: dohHost, dnsServer: bootstrapIP)
        log("DoH: \(dohHost) resolved to \(resolvedIP)")
        resolvedDoHServerIP = resolvedIP
        return resolvedIP
    }

    /// 使用传统 DNS (UDP 53) 解析域名
    private func resolveHostnameViaUDP(hostname: String, dnsServer: String) async throws -> String {
        log("DoH: UDP DNS query for \(hostname) via \(dnsServer):53")

        return try await withCheckedThrowingContinuation { continuation in
            let queue = DispatchQueue(label: "DoHResolver.UDP")

            guard let serverAddress = IPv4Address(dnsServer) else {
                self.log("DoH: UDP DNS error - invalid server address \(dnsServer)")
                continuation.resume(throwing: DoHError.invalidConfiguration)
                return
            }

            let endpoint = NWEndpoint.hostPort(host: .ipv4(serverAddress), port: 53)
            let connection = NWConnection(to: endpoint, using: .udp)

            var didResume = false
            let resumeOnce: (Result<String, Error>) -> Void = { result in
                guard !didResume else { return }
                didResume = true
                connection.cancel()
                switch result {
                case .success(let ip):
                    self.log("DoH: UDP DNS success - \(hostname) -> \(ip)")
                    continuation.resume(returning: ip)
                case .failure(let error):
                    self.log("DoH: UDP DNS failed - \(error.localizedDescription)")
                    continuation.resume(throwing: error)
                }
            }

            // 设置超时
            queue.asyncAfter(deadline: .now() + self.configuration.timeout) {
                self.log("DoH: UDP DNS timeout after \(self.configuration.timeout)s")
                resumeOnce(.failure(DoHError.timeout))
            }

            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    self.log("DoH: UDP connection ready, sending query")
                    // 发送 DNS 查询
                    let query = self.buildDNSQuery(hostname: hostname, type: .a)
                    connection.send(content: query, completion: .contentProcessed { error in
                        if let error = error {
                            self.log("DoH: UDP send error - \(error.localizedDescription)")
                            resumeOnce(.failure(DoHError.networkError(error)))
                        }
                    })

                    // 接收响应
                    connection.receive(minimumIncompleteLength: 1, maximumLength: 512) { data, _, _, error in
                        if let error = error {
                            self.log("DoH: UDP receive error - \(error.localizedDescription)")
                            resumeOnce(.failure(DoHError.networkError(error)))
                            return
                        }

                        guard let data = data else {
                            self.log("DoH: UDP receive error - no data")
                            resumeOnce(.failure(DoHError.invalidResponse))
                            return
                        }

                        self.log("DoH: UDP received \(data.count) bytes")
                        let addresses = self.parseDNSResponse(data: data, type: .a)
                        self.log("DoH: UDP parsed addresses: \(addresses)")
                        if let firstIP = addresses.first {
                            resumeOnce(.success(firstIP))
                        } else {
                            self.log("DoH: UDP DNS error - no A records in response")
                            resumeOnce(.failure(DoHError.bootstrapResolutionFailed))
                        }
                    }

                case .failed(let error):
                    self.log("DoH: UDP connection failed - \(error.localizedDescription)")
                    resumeOnce(.failure(DoHError.networkError(error)))

                case .cancelled:
                    break

                case .waiting(let error):
                    self.log("DoH: UDP connection waiting - \(error.localizedDescription)")

                default:
                    break
                }
            }

            connection.start(queue: queue)
        }
    }

    // MARK: - HTTPS DoH Query

    /// 执行 DoH DNS 查询 (使用 Network.framework 支持自定义 SNI)
    private func queryDNS(hostname: String, type: DNSRecordType, dohURL: URL, dohServerIP: String, originalHost: String) async throws -> [String] {
        let typeStr = type == .a ? "A" : "AAAA"
        log("DoH: HTTPS query \(typeStr) for \(hostname)")

        // 构建 DNS 查询包
        let queryData = buildDNSQuery(hostname: hostname, type: type)

        // 获取端口和路径
        let port = dohURL.port ?? 443
        let path = dohURL.path.isEmpty ? "/dns-query" : dohURL.path

        log("DoH: HTTPS connecting to \(dohServerIP):\(port) (SNI: \(originalHost), path: \(path))")

        return try await withCheckedThrowingContinuation { continuation in
            let queue = DispatchQueue(label: "DoHResolver.HTTPS")

            // 创建 TLS 参数，设置 SNI 为原始域名
            let tlsOptions = NWProtocolTLS.Options()
            sec_protocol_options_set_tls_server_name(tlsOptions.securityProtocolOptions, originalHost)

            let tcpOptions = NWProtocolTCP.Options()
            let params = NWParameters(tls: tlsOptions, tcp: tcpOptions)

            // 连接到 IP 地址
            let endpoint: NWEndpoint
            if let ipv4 = IPv4Address(dohServerIP) {
                endpoint = NWEndpoint.hostPort(host: .ipv4(ipv4), port: NWEndpoint.Port(integerLiteral: UInt16(port)))
            } else if let ipv6 = IPv6Address(dohServerIP) {
                endpoint = NWEndpoint.hostPort(host: .ipv6(ipv6), port: NWEndpoint.Port(integerLiteral: UInt16(port)))
            } else {
                self.log("DoH: HTTPS error - invalid server IP \(dohServerIP)")
                continuation.resume(throwing: DoHError.invalidConfiguration)
                return
            }

            let connection = NWConnection(to: endpoint, using: params)

            var didResume = false
            let resumeOnce: (Result<[String], Error>) -> Void = { result in
                guard !didResume else { return }
                didResume = true
                connection.cancel()
                switch result {
                case .success(let addresses):
                    continuation.resume(returning: addresses)
                case .failure(let error):
                    continuation.resume(throwing: error)
                }
            }

            // 设置超时
            queue.asyncAfter(deadline: .now() + self.configuration.timeout) {
                self.log("DoH: HTTPS timeout after \(self.configuration.timeout)s")
                resumeOnce(.failure(DoHError.timeout))
            }

            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    self.log("DoH: HTTPS TLS connection ready")

                    // 构建 HTTP 请求
                    var httpRequest = "POST \(path) HTTP/1.1\r\n"
                    httpRequest += "Host: \(originalHost)\r\n"
                    httpRequest += "Content-Type: application/dns-message\r\n"
                    httpRequest += "Accept: application/dns-message\r\n"
                    httpRequest += "Content-Length: \(queryData.count)\r\n"
                    httpRequest += "Connection: close\r\n"
                    httpRequest += "\r\n"

                    var requestData = httpRequest.data(using: .utf8)!
                    requestData.append(queryData)

                    // 发送请求
                    connection.send(content: requestData, completion: .contentProcessed { error in
                        if let error = error {
                            self.log("DoH: HTTPS send error - \(error.localizedDescription)")
                            resumeOnce(.failure(DoHError.networkError(error)))
                        }
                    })

                    // 接收响应
                    self.receiveHTTPResponse(connection: connection, type: type) { result in
                        resumeOnce(result)
                    }

                case .failed(let error):
                    self.log("DoH: HTTPS connection failed - \(error.localizedDescription)")
                    resumeOnce(.failure(DoHError.networkError(error)))

                case .waiting(let error):
                    self.log("DoH: HTTPS connection waiting - \(error.localizedDescription)")

                default:
                    break
                }
            }

            connection.start(queue: queue)
        }
    }

    /// 接收 HTTP 响应
    private func receiveHTTPResponse(connection: NWConnection, type: DNSRecordType, completion: @escaping (Result<[String], Error>) -> Void) {
        var receivedData = Data()

        func receiveMore() {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
                if let error = error {
                    self.log("DoH: HTTPS receive error - \(error.localizedDescription)")
                    completion(.failure(DoHError.networkError(error)))
                    return
                }

                if let data = data {
                    receivedData.append(data)
                }

                if isComplete {
                    // 解析 HTTP 响应
                    self.log("DoH: HTTPS received \(receivedData.count) bytes total")
                    self.parseHTTPResponse(data: receivedData, type: type, completion: completion)
                } else {
                    receiveMore()
                }
            }
        }

        receiveMore()
    }

    /// 解析 HTTP 响应
    private func parseHTTPResponse(data: Data, type: DNSRecordType, completion: @escaping (Result<[String], Error>) -> Void) {
        // 查找 HTTP body (空行分隔)
        guard let headerEndRange = data.range(of: Data("\r\n\r\n".utf8)) else {
            log("DoH: HTTPS error - cannot find header end")
            completion(.failure(DoHError.invalidResponse))
            return
        }

        let headerData = data[..<headerEndRange.lowerBound]
        let bodyData = data[headerEndRange.upperBound...]

        // 解析状态行
        guard let headerString = String(data: headerData, encoding: .utf8) else {
            log("DoH: HTTPS error - cannot parse header")
            completion(.failure(DoHError.invalidResponse))
            return
        }

        let lines = headerString.components(separatedBy: "\r\n")
        guard let statusLine = lines.first,
              statusLine.contains("200") else {
            log("DoH: HTTPS error - unexpected status: \(lines.first ?? "unknown")")
            completion(.failure(DoHError.invalidResponse))
            return
        }

        log("DoH: HTTPS response status=200, body size=\(bodyData.count) bytes")

        let addresses = parseDNSResponse(data: Data(bodyData), type: type)
        let typeStr = type == .a ? "A" : "AAAA"
        log("DoH: HTTPS \(typeStr) records: \(addresses)")
        completion(.success(addresses))
    }

    // MARK: - DNS Message Handling

    /// 构建 DNS 查询包 (RFC 1035 格式)
    private func buildDNSQuery(hostname: String, type: DNSRecordType) -> Data {
        var query = Data()

        // Transaction ID (随机)
        let transactionID = UInt16.random(in: 0...UInt16.max)
        query.append(contentsOf: withUnsafeBytes(of: transactionID.bigEndian) { Array($0) })

        // Flags: 标准查询, 递归查询
        let flags: UInt16 = 0x0100
        query.append(contentsOf: withUnsafeBytes(of: flags.bigEndian) { Array($0) })

        // QDCOUNT: 1 个问题
        let qdcount: UInt16 = 1
        query.append(contentsOf: withUnsafeBytes(of: qdcount.bigEndian) { Array($0) })

        // ANCOUNT, NSCOUNT, ARCOUNT: 都为 0
        query.append(contentsOf: [0, 0, 0, 0, 0, 0])

        // 问题部分: 域名
        let labels = hostname.split(separator: ".")
        for label in labels {
            query.append(UInt8(label.count))
            query.append(contentsOf: label.utf8)
        }
        query.append(0) // 域名结束

        // QTYPE
        query.append(contentsOf: withUnsafeBytes(of: type.rawValue.bigEndian) { Array($0) })

        // QCLASS: IN (Internet)
        let qclass: UInt16 = 1
        query.append(contentsOf: withUnsafeBytes(of: qclass.bigEndian) { Array($0) })

        return query
    }

    /// 解析 DNS 响应
    private func parseDNSResponse(data: Data, type: DNSRecordType) -> [String] {
        guard data.count >= 12 else { return [] }

        var addresses = [String]()
        var offset = 0

        // 跳过 header (12 字节)
        offset = 12

        // 读取 QDCOUNT
        let qdcount = UInt16(data[4]) << 8 | UInt16(data[5])

        // 跳过问题部分
        for _ in 0..<qdcount {
            offset = skipName(data: data, offset: offset)
            offset += 4 // QTYPE + QCLASS
        }

        // 读取 ANCOUNT
        let ancount = UInt16(data[6]) << 8 | UInt16(data[7])

        // 解析答案部分
        for _ in 0..<ancount {
            guard offset < data.count else { break }

            // 跳过名称
            offset = skipName(data: data, offset: offset)

            guard offset + 10 <= data.count else { break }

            // 读取类型
            let rtype = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
            offset += 2

            // 跳过类
            offset += 2

            // 跳过 TTL
            offset += 4

            // 读取数据长度
            let rdlength = Int(UInt16(data[offset]) << 8 | UInt16(data[offset + 1]))
            offset += 2

            guard offset + rdlength <= data.count else { break }

            // 解析地址
            if rtype == type.rawValue {
                if type == .a && rdlength == 4 {
                    let ip = "\(data[offset]).\(data[offset + 1]).\(data[offset + 2]).\(data[offset + 3])"
                    addresses.append(ip)
                } else if type == .aaaa && rdlength == 16 {
                    var parts = [String]()
                    for i in stride(from: 0, to: 16, by: 2) {
                        let value = UInt16(data[offset + i]) << 8 | UInt16(data[offset + i + 1])
                        parts.append(String(format: "%x", value))
                    }
                    addresses.append(parts.joined(separator: ":"))
                }
            }

            offset += rdlength
        }

        return addresses
    }

    /// 跳过 DNS 名称字段
    private func skipName(data: Data, offset: Int) -> Int {
        var currentOffset = offset

        while currentOffset < data.count {
            let length = Int(data[currentOffset])

            if length == 0 {
                // 名称结束
                return currentOffset + 1
            } else if (length & 0xC0) == 0xC0 {
                // 压缩指针
                return currentOffset + 2
            } else {
                // 普通标签
                currentOffset += 1 + length
            }
        }

        return currentOffset
    }
}
