// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

/// DNS over HTTPS 服务商枚举
public enum DoHProvider: String, CaseIterable, Codable, Sendable {
    case cloudflare
    case google
    case quad9
    case aliDNS
    case dnsPod
    case custom

    /// DoH 服务器 URL
    public var defaultURL: URL? {
        switch self {
        case .cloudflare:
            return URL(string: "https://cloudflare-dns.com/dns-query")
        case .google:
            return URL(string: "https://dns.google/dns-query")
        case .quad9:
            return URL(string: "https://dns.quad9.net/dns-query")
        case .aliDNS:
            return URL(string: "https://dns.alidns.com/dns-query")
        case .dnsPod:
            return URL(string: "https://doh.pub/dns-query")
        case .custom:
            return nil
        }
    }

    /// 引导 IP 地址（用于避免 DNS 循环解析）
    public var bootstrapIPs: [String] {
        switch self {
        case .cloudflare:
            return ["1.1.1.1", "1.0.0.1"]
        case .google:
            return ["8.8.8.8", "8.8.4.4"]
        case .quad9:
            return ["9.9.9.9", "149.112.112.112"]
        case .aliDNS:
            return ["223.5.5.5", "223.6.6.6"]
        case .dnsPod:
            return ["119.29.29.29", "119.28.28.28"]
        case .custom:
            return []
        }
    }

    /// 显示名称
    public var displayName: String {
        switch self {
        case .cloudflare:
            return "Cloudflare"
        case .google:
            return "Google"
        case .quad9:
            return "Quad9"
        case .aliDNS:
            return "阿里 DNS"
        case .dnsPod:
            return "DNSPod"
        case .custom:
            return "自定义"
        }
    }

    /// 从字符串初始化
    public init?(from string: String) {
        let lowercased = string.lowercased()
        switch lowercased {
        case "cloudflare":
            self = .cloudflare
        case "google":
            self = .google
        case "quad9":
            self = .quad9
        case "alidns", "ali", "aliyun":
            self = .aliDNS
        case "dnspod", "tencent":
            self = .dnsPod
        case "custom":
            self = .custom
        default:
            return nil
        }
    }
}

/// DNS over HTTPS 配置
public struct DoHConfiguration: Codable, Equatable, Sendable {
    /// 是否启用 DoH
    public var isEnabled: Bool

    /// DoH 服务商
    public var provider: DoHProvider

    /// 自定义 DoH URL（仅当 provider 为 .custom 时使用）
    public var customURL: URL?

    /// 自定义引导 IP 地址（仅当 provider 为 .custom 时使用）
    public var customBootstrapIPs: [String]

    /// 是否在 DoH 失败时降级到系统 DNS
    public var fallbackEnabled: Bool

    /// 请求超时时间（秒）
    public var timeout: TimeInterval

    /// 默认配置
    public static let `default` = DoHConfiguration(
        isEnabled: false,
        provider: .cloudflare,
        customURL: nil,
        customBootstrapIPs: [],
        fallbackEnabled: true,
        timeout: 5.0
    )

    public init(
        isEnabled: Bool = false,
        provider: DoHProvider = .cloudflare,
        customURL: URL? = nil,
        customBootstrapIPs: [String] = [],
        fallbackEnabled: Bool = true,
        timeout: TimeInterval = 5.0
    ) {
        self.isEnabled = isEnabled
        self.provider = provider
        self.customURL = customURL
        self.customBootstrapIPs = customBootstrapIPs
        self.fallbackEnabled = fallbackEnabled
        self.timeout = timeout
    }

    /// 获取有效的 DoH URL
    public var effectiveURL: URL? {
        if provider == .custom {
            return customURL
        }
        return provider.defaultURL
    }

    /// 获取有效的引导 IP 列表
    /// 如果用户设置了自定义 Bootstrap IP，则优先使用；否则使用服务商默认值
    public var effectiveBootstrapIPs: [String] {
        if !customBootstrapIPs.isEmpty {
            return customBootstrapIPs
        }
        return provider.bootstrapIPs
    }
}
