// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

/// DoH 设置管理器 - 独立于隧道配置的全局设置
public class DoHSettingsManager {

    public static let shared = DoHSettingsManager()

    private let defaults: UserDefaults

    private struct Keys {
        static let isEnabled = "DoH.isEnabled"
        static let provider = "DoH.provider"
        static let customURL = "DoH.customURL"
        static let customBootstrapIPs = "DoH.customBootstrapIPs"
        static let fallbackEnabled = "DoH.fallbackEnabled"
        static let timeout = "DoH.timeout"
    }

    private init() {
        // 使用 App Group 的 UserDefaults 以便 Network Extension 也能访问
        if let appGroupDefaults = UserDefaults(suiteName: FileManager.appGroupId) {
            self.defaults = appGroupDefaults
        } else {
            self.defaults = UserDefaults.standard
        }
    }

    /// 获取当前 DoH 配置
    public var configuration: DoHConfiguration {
        get {
            var config = DoHConfiguration()
            config.isEnabled = defaults.bool(forKey: Keys.isEnabled)

            if let providerString = defaults.string(forKey: Keys.provider),
               let provider = DoHProvider(rawValue: providerString) {
                config.provider = provider
            }

            if let urlString = defaults.string(forKey: Keys.customURL),
               let url = URL(string: urlString) {
                config.customURL = url
            }

            if let bootstrapIPs = defaults.stringArray(forKey: Keys.customBootstrapIPs) {
                config.customBootstrapIPs = bootstrapIPs
            }

            // fallbackEnabled 默认为 true
            if defaults.object(forKey: Keys.fallbackEnabled) != nil {
                config.fallbackEnabled = defaults.bool(forKey: Keys.fallbackEnabled)
            } else {
                config.fallbackEnabled = true
            }

            // timeout 默认为 5.0
            let timeout = defaults.double(forKey: Keys.timeout)
            config.timeout = timeout > 0 ? timeout : 5.0

            return config
        }
        set {
            defaults.set(newValue.isEnabled, forKey: Keys.isEnabled)
            defaults.set(newValue.provider.rawValue, forKey: Keys.provider)

            if let customURL = newValue.customURL {
                defaults.set(customURL.absoluteString, forKey: Keys.customURL)
            } else {
                defaults.removeObject(forKey: Keys.customURL)
            }

            if !newValue.customBootstrapIPs.isEmpty {
                defaults.set(newValue.customBootstrapIPs, forKey: Keys.customBootstrapIPs)
            } else {
                defaults.removeObject(forKey: Keys.customBootstrapIPs)
            }

            defaults.set(newValue.fallbackEnabled, forKey: Keys.fallbackEnabled)
            defaults.set(newValue.timeout, forKey: Keys.timeout)

            defaults.synchronize()
        }
    }

    /// 是否启用 DoH
    public var isEnabled: Bool {
        get { configuration.isEnabled }
        set {
            var config = configuration
            config.isEnabled = newValue
            configuration = config
        }
    }

    /// DoH 服务商
    public var provider: DoHProvider {
        get { configuration.provider }
        set {
            var config = configuration
            config.provider = newValue
            configuration = config
        }
    }

    /// 重置为默认设置
    public func reset() {
        configuration = DoHConfiguration.default
    }
}
