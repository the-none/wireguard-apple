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
            }
        }
    }

    /// DNS 记录类型
    private enum DNSRecordType: UInt16 {
        case a = 1      // IPv4
        case aaaa = 28  // IPv6
    }

    private let configuration: DoHConfiguration
    private let session: URLSession

    public init(configuration: DoHConfiguration) {
        self.configuration = configuration

        // 创建自定义 URLSession 配置
        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.timeoutIntervalForRequest = configuration.timeout
        sessionConfig.timeoutIntervalForResource = configuration.timeout * 2
        sessionConfig.requestCachePolicy = .reloadIgnoringLocalCacheData

        self.session = URLSession(configuration: sessionConfig)
    }

    deinit {
        session.invalidateAndCancel()
    }

    /// 解析域名
    /// - Parameters:
    ///   - hostname: 要解析的域名
    ///   - preferIPv4: 是否优先返回 IPv4 地址
    /// - Returns: 解析结果 (IPv4 地址, IPv6 地址)
    public func resolve(hostname: String, preferIPv4: Bool = true) async throws -> (ipv4: IPv4Address?, ipv6: IPv6Address?) {
        guard let dohURL = configuration.effectiveURL else {
            throw DoHError.invalidConfiguration
        }

        let bootstrapIPs = configuration.effectiveBootstrapIPs
        guard !bootstrapIPs.isEmpty else {
            throw DoHError.noBootstrapIP
        }

        // 并发查询 A 和 AAAA 记录
        async let ipv4Task = queryDNS(hostname: hostname, type: .a, dohURL: dohURL, bootstrapIPs: bootstrapIPs)
        async let ipv6Task = queryDNS(hostname: hostname, type: .aaaa, dohURL: dohURL, bootstrapIPs: bootstrapIPs)

        let ipv4Addresses = (try? await ipv4Task) ?? []
        let ipv6Addresses = (try? await ipv6Task) ?? []

        let ipv4: IPv4Address? = ipv4Addresses.compactMap { IPv4Address($0) }.first
        let ipv6: IPv6Address? = ipv6Addresses.compactMap { IPv6Address($0) }.first

        if ipv4 == nil && ipv6 == nil {
            throw DoHError.noRecordsFound
        }

        return (ipv4, ipv6)
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

    /// 执行 DNS 查询
    private func queryDNS(hostname: String, type: DNSRecordType, dohURL: URL, bootstrapIPs: [String]) async throws -> [String] {
        // 构建 DNS 查询包
        let queryData = buildDNSQuery(hostname: hostname, type: type)

        // 使用 Bootstrap IP 替换域名解析
        guard let bootstrapIP = bootstrapIPs.first else {
            throw DoHError.noBootstrapIP
        }

        // 构建使用 Bootstrap IP 的 URL
        var components = URLComponents(url: dohURL, resolvingAgainstBaseURL: false)
        let originalHost = components?.host ?? ""
        components?.host = bootstrapIP

        guard let requestURL = components?.url else {
            throw DoHError.invalidConfiguration
        }

        var request = URLRequest(url: requestURL)
        request.httpMethod = "POST"
        request.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        request.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        request.setValue(originalHost, forHTTPHeaderField: "Host")
        request.httpBody = queryData

        do {
            let (data, response) = try await session.data(for: request)

            guard let httpResponse = response as? HTTPURLResponse,
                  httpResponse.statusCode == 200 else {
                throw DoHError.invalidResponse
            }

            return parseDNSResponse(data: data, type: type)
        } catch let error as DoHError {
            throw error
        } catch {
            throw DoHError.networkError(error)
        }
    }

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
