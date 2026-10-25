// SPDX-License-Identifier: MIT

import Foundation

struct PeerRuntimeState {
    let publicKey: String
    let endpoint: Endpoint?
    let rxBytes: UInt64
    let txBytes: UInt64
    let lastHandshake: TimeInterval

    static func parse(_ configuration: String) -> [String: PeerRuntimeState] {
        var peers = [String: PeerRuntimeState]()
        var attributes = [String: String]()

        func appendPeer() {
            guard let key = attributes["public_key"],
                  let rx = attributes["rx_bytes"].flatMap(UInt64.init),
                  let tx = attributes["tx_bytes"].flatMap(UInt64.init),
                  let seconds = attributes["last_handshake_time_sec"].flatMap(UInt64.init),
                  let nanos = attributes["last_handshake_time_nsec"].flatMap(UInt64.init) else { return }
            peers[key] = PeerRuntimeState(
                publicKey: key,
                endpoint: attributes["endpoint"].flatMap(Endpoint.init(from:)),
                rxBytes: rx, txBytes: tx,
                lastHandshake: Double(seconds) + Double(nanos) / 1_000_000_000
            )
        }

        for line in configuration.split(separator: "\n") {
            let parts = line.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { continue }
            let key = String(parts[0])
            if key == "public_key" {
                appendPeer()
                attributes.removeAll(keepingCapacity: true)
            }
            switch key {
            case "public_key", "endpoint", "rx_bytes", "tx_bytes", "last_handshake_time_sec", "last_handshake_time_nsec":
                attributes[key] = String(parts[1])
            default:
                break
            }
        }
        appendPeer()
        return peers
    }

    func receivedTraffic(since previous: PeerRuntimeState) -> Bool {
        return rxBytes > previous.rxBytes || lastHandshake > previous.lastHandshake
    }

    func endpointUpdate(to endpoint: Endpoint) -> String? {
        guard self.endpoint != endpoint else { return nil }
        return "public_key=\(publicKey)\nupdate_only=true\nendpoint=\(endpoint.stringRepresentation)\n"
    }
}

/// Per-peer evidence of unanswered traffic; an old handshake alone is not a failure.
struct EndpointRecovery {
    static let normalPollInterval: TimeInterval = 60
    static let responseTimeout: TimeInterval = 30
    static let handshakeGrace: TimeInterval = 180
    static let retryInterval: TimeInterval = 15
    static let slowRetryInterval: TimeInterval = 60
    static let fastRecoveryDuration: TimeInterval = 180

    private(set) var pollInterval: TimeInterval = normalPollInterval
    private var previous: PeerRuntimeState?
    private var awaitingResponseSince: TimeInterval?
    private var failureSince: TimeInterval?
    private var lastResolutionAttempt: TimeInterval?

    mutating func didReceiveResponse(_ current: PeerRuntimeState) {
        previous = current
        awaitingResponseSince = nil
        failureSince = nil
        lastResolutionAttempt = nil
        pollInterval = Self.normalPollInterval
    }

    mutating func shouldResolve(_ current: PeerRuntimeState, at time: TimeInterval,
                                wallTime: TimeInterval, persistentKeepAlive: UInt16) -> Bool {
        if let previous = previous,
           current.rxBytes < previous.rxBytes || current.txBytes < previous.txBytes || current.lastHandshake < previous.lastHandshake {
            self = EndpointRecovery()
        }

        if let previous = previous {
            if current.receivedTraffic(since: previous) {
                didReceiveResponse(current)
            } else if current.txBytes > previous.txBytes || persistentKeepAlive > 0 {
                awaitingResponseSince = awaitingResponseSince ?? time
            }
        } else if (current.lastHandshake == 0 && current.txBytes > 0) || persistentKeepAlive > 0 {
            awaitingResponseSince = time
        }
        previous = current

        // Handshakes and keepalives contribute to tx_bytes too. Allow normal
        // rekeying to complete before treating an otherwise silent peer as lost.
        guard let waitingSince = awaitingResponseSince,
              current.lastHandshake == 0 || wallTime - current.lastHandshake >= Self.handshakeGrace else {
            pollInterval = Self.normalPollInterval
            return false
        }

        // Sample suspected loss sooner, without resolving until the response
        // window expires. Otherwise a normal poll would delay confirmation.
        guard time - waitingSince >= Self.responseTimeout else {
            pollInterval = Self.retryInterval
            return false
        }

        let failureStart = failureSince ?? time
        failureSince = failureStart
        pollInterval = time - failureStart >= Self.fastRecoveryDuration ? Self.slowRetryInterval : Self.retryInterval
        guard lastResolutionAttempt.map({ time - $0 >= pollInterval }) ?? true else { return false }
        lastResolutionAttempt = time
        return true
    }
}
