import Network
import XCTest
@testable import WireGuardKit

final class IP4PTests: XCTestCase {
    func testCompressedAndExpandedAddressesDecodeIdentically() throws {
        for address in ["2001::ca6c:cb00:7109", "2001:0:0:0:0:ca6c:cb00:7109"] {
            let endpoint = try XCTUnwrap(Endpoint(from: "[\(address)]:0"))
            XCTAssertEqual(endpoint.ip4pEndpoint?.stringRepresentation, "203.0.113.9:51820")
        }
    }

    func testZeroAddressSegmentsAndPortBoundaries() throws {
        for (address, expected) in [
            ("2001::1:0:1", "0.0.0.1:1"),
            ("2001::ffff:cb00:0", "203.0.0.0:65535")
        ] {
            let endpoint = try XCTUnwrap(Endpoint(from: "[\(address)]:0"))
            XCTAssertEqual(endpoint.ip4pEndpoint?.stringRepresentation, expected)
        }
    }

    func testNonIP4PAndZeroEncodedPortAreNotConverted() throws {
        for address in ["2001:db8:1:2::", "2001:0:0:0:1:ca6c:cb00:7109", "2002::ca6c:cb00:7109", "2001::cb00:7109"] {
            let endpoint = try XCTUnwrap(Endpoint(from: "[\(address)]:0"))
            XCTAssertNil(endpoint.ip4pEndpoint, address)
        }
    }

    func testEncodedPortTakesPriorityOverExplicitPort() throws {
        let endpoint = try XCTUnwrap(Endpoint(from: "[2001::ca6c:cb00:7109]:1234"))
        XCTAssertEqual(endpoint.ip4pEndpoint?.stringRepresentation, "203.0.113.9:51820")
    }

    func testIP4PAndHostnamesCanOmitPort() throws {
        for address in ["2001::ca6c:cb00:7109", "[2001::ca6c:cb00:7109]"] {
            let endpoint = try XCTUnwrap(Endpoint(from: address))
            XCTAssertEqual(endpoint.ip4pEndpoint?.stringRepresentation, "203.0.113.9:51820")
            XCTAssertEqual(Endpoint(from: endpoint.stringRepresentation), endpoint)
        }
        let endpoint = try XCTUnwrap(Endpoint(from: "vpn.example.com"))
        XCTAssertEqual(endpoint.stringRepresentation, "vpn.example.com")
        XCTAssertEqual(Endpoint(from: "vpn.example.com:0"), endpoint)
    }

    func testOrdinaryIPAddressesStillRequirePort() {
        for address in ["192.0.2.1", "2001:db8::1", "[2001:db8::1]", "vpn.example.com:", "[2001::ca6c:cb00:7109]:"] {
            XCTAssertNil(Endpoint(from: address), address)
        }
    }

    func testIP4PTakesPriorityOverARecord() throws {
        let ipv4 = try XCTUnwrap(IPv4Address("192.0.2.1"))
        let ipv6 = try XCTUnwrap(IPv6Address("2001::ca6c:cb00:7109"))
        let selected = DNSResolver.preferredEndpoint(ipv4: ipv4, ipv6: ipv6, port: 0)
        XCTAssertEqual(selected?.ip4pEndpoint?.stringRepresentation, "203.0.113.9:51820")
    }

    func testNonIP4PPreservesIPv4Preference() throws {
        let ipv4 = try XCTUnwrap(IPv4Address("192.0.2.1"))
        for address in ["2001:db8::1", "2001::cb00:7109"] {
            let ipv6 = try XCTUnwrap(IPv6Address(address))
            let selected = DNSResolver.preferredEndpoint(ipv4: ipv4, ipv6: ipv6, port: 1234)
            XCTAssertEqual(selected?.stringRepresentation, "192.0.2.1:1234")
        }
    }

    func testIP4PTakesPriorityEvenWithExplicitPort() throws {
        let ipv4 = try XCTUnwrap(IPv4Address("192.0.2.1"))
        let ipv6 = try XCTUnwrap(IPv6Address("2001::ca6c:cb00:7109"))
        let selected = DNSResolver.preferredEndpoint(ipv4: ipv4, ipv6: ipv6, port: 1234)
        XCTAssertEqual(selected?.ip4pEndpoint?.stringRepresentation, "203.0.113.9:51820")
    }

    func testHostnameWithoutPortRequiresIP4PAnswer() throws {
        let ipv4 = try XCTUnwrap(IPv4Address("192.0.2.1"))
        let ipv6 = try XCTUnwrap(IPv6Address("2001:db8::1"))
        XCTAssertNil(DNSResolver.preferredEndpoint(ipv4: ipv4, ipv6: ipv6, port: 0))
    }

    func testIPv6OnlyAndEmptyAnswers() throws {
        let ipv6 = try XCTUnwrap(IPv6Address("2001:db8::1"))
        XCTAssertEqual(DNSResolver.preferredEndpoint(ipv4: nil, ipv6: ipv6, port: 1234)?.host, .ipv6(ipv6))
        XCTAssertNil(DNSResolver.preferredEndpoint(ipv4: nil, ipv6: nil, port: 0))
    }

    func testDoHFindsIP4PAfterOrdinaryAAAARecords() throws {
        let ordinary = try XCTUnwrap(IPv6Address("2001:db8::1"))
        let invalid = try XCTUnwrap(IPv6Address("2001::cb00:7109"))
        let ip4p = try XCTUnwrap(IPv6Address("2001::ca6c:cb00:7109"))
        let answers = [ordinary, invalid, ip4p]
        XCTAssertEqual(DoHResolver.preferredIPv6Address(answers), ip4p)
        XCTAssertEqual(DoHResolver.preferredIPv6Address([ordinary, invalid]), ordinary)
    }

    func testAllIP4PCandidatesSurviveMixedDNSAnswersWithoutDuplicates() throws {
        let ordinary = try XCTUnwrap(IPv6Address("2001:db8::1"))
        let first = try XCTUnwrap(IPv6Address("2001::ca6c:c000:201"))
        let second = try XCTUnwrap(IPv6Address("2001::ca6d:cb00:7109"))
        let candidates = DNSResolver.preferredEndpoints(
            ipv4: IPv4Address("192.0.2.99"), ipv6: [ordinary, first, first, second], port: 1234)
        XCTAssertEqual(candidates.map { $0.ip4pEndpoint?.stringRepresentation },
                       ["192.0.2.1:51820", "203.0.113.9:51821"])
    }

    func testCandidateSelectionPreservesOrdinaryDNSBehavior() throws {
        let first = try XCTUnwrap(IPv6Address("2001:db8::1"))
        let last = try XCTUnwrap(IPv6Address("2001:db8::2"))
        XCTAssertEqual(DNSResolver.preferredEndpoints(ipv4: IPv4Address("192.0.2.1"), ipv6: [first, last], port: 1234)
            .map { $0.stringRepresentation }, ["192.0.2.1:1234"])
        XCTAssertEqual(DNSResolver.preferredEndpoints(ipv4: nil, ipv6: [first, last], port: 1234).first?.host, .ipv6(first))
        XCTAssertEqual(DNSResolver.preferredEndpoints(ipv4: nil, ipv6: [first, last], port: 1234, ordinaryIPv6: last)
            .first?.host, .ipv6(last))
        XCTAssertTrue(DNSResolver.preferredEndpoints(ipv4: IPv4Address("192.0.2.1"), ipv6: [first], port: 0).isEmpty)
    }

    func testRecoveryTriesSecondIP4PRegardlessOfDNSAnswerOrder() throws {
        let first = try XCTUnwrap(Endpoint(from: "[2001::ca6c:c000:201]"))
        let second = try XCTUnwrap(Endpoint(from: "[2001::ca6d:cb00:7109]"))
        for candidates in [[first, second], [second, first]] {
            XCTAssertEqual(DNSResolver.recoveryEndpoint(candidates: candidates, current: first), second)
            XCTAssertEqual(DNSResolver.recoveryEndpoint(candidates: candidates, current: second), first)
        }
    }

    func testThreeIP4PCandidatesAreNotStarvedByAnswerReordering() throws {
        let first = try XCTUnwrap(Endpoint(from: "[2001::ca6c:c000:201]"))
        let second = try XCTUnwrap(Endpoint(from: "[2001::ca6d:c000:201]"))
        let third = try XCTUnwrap(Endpoint(from: "[2001::ca6e:c000:201]"))
        XCTAssertEqual(DNSResolver.recoveryEndpoint(candidates: [third, second, first], current: first), second)
        XCTAssertEqual(DNSResolver.recoveryEndpoint(candidates: [second, first, third], current: second), third)
        XCTAssertEqual(DNSResolver.recoveryEndpoint(candidates: [third, first, second], current: third), first)
    }

    func testRecoveryUsesFreshCandidatesWhenOldAddressDisappears() throws {
        let old = try XCTUnwrap(Endpoint(from: "[2001::ca6c:c000:201]"))
        let new = try XCTUnwrap(Endpoint(from: "[2001::ca6d:cb00:7109]"))
        XCTAssertEqual(DNSResolver.recoveryEndpoint(candidates: [new], current: old), new)
        XCTAssertEqual(DNSResolver.recoveryEndpoint(candidates: [new], current: new), new)
        XCTAssertNil(DNSResolver.recoveryEndpoint(candidates: [], current: old))
    }

    func testRecoveryDoesNotChooseOrdinaryAddressWhenIP4PExists() throws {
        let ordinary = try XCTUnwrap(Endpoint(from: "192.0.2.99:1234"))
        let ip4p = try XCTUnwrap(Endpoint(from: "[2001::ca6c:c000:201]"))
        XCTAssertEqual(DNSResolver.recoveryEndpoint(candidates: [ordinary, ip4p], current: ip4p), ip4p)
        XCTAssertEqual(DNSResolver.recoveryEndpoint(candidates: [ordinary], current: ip4p), ordinary)
    }

    func testLiteralAndAbsentEndpointsKeepCandidateArrayAligned() throws {
        let literal = try XCTUnwrap(Endpoint(from: "[2001::ca6c:c000:201]"))
        let results = DNSResolver.resolveCandidatesWithDoH(endpoints: [nil, literal], dohConfig: .default)
        XCTAssertEqual(results.count, 2)
        XCTAssertNil(results[0])
        XCTAssertEqual(try results[1]?.get(), [literal])
    }

    #if os(macOS)
    func testPathReconfigurationKeepsSelectedCandidateAndRemainingChoices() throws {
        let first = try XCTUnwrap(Endpoint(from: "[2001::ca6c:c000:201]"))
        let second = try XCTUnwrap(Endpoint(from: "[2001::ca6d:cb00:7109]"))
        let generator = makeGenerator(endpoint: first)
        generator.endpointCandidates = [[first, second]]
        generator.resolvedEndpoints[0] = second
        for _ in 0..<10 {
            let (config, _) = generator.endpointUapiConfiguration()
            XCTAssertTrue(config.contains("endpoint=203.0.113.9:51821\n"))
            XCTAssertEqual(generator.endpointCandidates[0], [first, second])
            XCTAssertEqual(generator.resolvedEndpoints[0], second)
        }
    }

    func testBothUapiPathsUseDecodedEndpoint() throws {
        let endpoint = try XCTUnwrap(Endpoint(from: "[2001::ca6c:cb00:7109]:0"))
        let generator = makeGenerator(endpoint: endpoint)
        for (config, results) in [generator.uapiConfiguration(), generator.endpointUapiConfiguration()] {
            XCTAssertTrue(config.contains("endpoint=203.0.113.9:51820\n"))
            XCTAssertFalse(config.contains("2001:"))
            let result = try XCTUnwrap(results.first.flatMap { $0 })
            let (source, resolved) = try result.get()
            XCTAssertEqual(source.stringRepresentation, "203.0.113.9:51820")
            XCTAssertEqual(resolved, source)
        }
    }

    func testNonIP4PIPv6DoesNotCrashConfigurationGeneration() throws {
        let endpoint = try XCTUnwrap(Endpoint(from: "[2001:db8:1:2::]:0"))
        let generator = makeGenerator(endpoint: endpoint)
        for (config, results) in [generator.uapiConfiguration(), generator.endpointUapiConfiguration()] {
            XCTAssertTrue(config.contains("endpoint=\(endpoint.stringRepresentation)\n"))
            let result = try XCTUnwrap(results.first.flatMap { $0 })
            XCTAssertEqual(try result.get().1, endpoint)
        }
    }

    private func makeGenerator(endpoint: Endpoint) -> PacketTunnelSettingsGenerator {
        let privateKey = PrivateKey()
        var peer = PeerConfiguration(publicKey: privateKey.publicKey)
        peer.endpoint = endpoint
        let configuration = TunnelConfiguration(name: nil, interface: InterfaceConfiguration(privateKey: privateKey), peers: [peer])
        return PacketTunnelSettingsGenerator(tunnelConfiguration: configuration, resolvedEndpoints: [endpoint])
    }
    #endif
}
