import XCTest
@testable import WireGuardKit

final class EndpointRecoveryTests: XCTestCase {
    func testRuntimeParserKeepsPeersSeparateAndIncludesFractionalHandshake() throws {
        let peers = PeerRuntimeState.parse("""
        private_key=ignored
        listen_port=51820
        public_key=first
        endpoint=192.0.2.1:51820
        last_handshake_time_sec=1000
        last_handshake_time_nsec=500000000
        tx_bytes=148
        rx_bytes=92
        allowed_ip=0.0.0.0/0
        public_key=second
        endpoint=[2001:db8::1]:1234
        last_handshake_time_sec=0
        last_handshake_time_nsec=0
        tx_bytes=0
        rx_bytes=0
        """)
        XCTAssertEqual(peers.count, 2)
        let first = try XCTUnwrap(peers["first"])
        XCTAssertEqual(first.lastHandshake, 1000.5)
        XCTAssertEqual(first.txBytes, 148)
        XCTAssertEqual(first.rxBytes, 92)
        XCTAssertEqual(first.endpoint?.stringRepresentation, "192.0.2.1:51820")
        XCTAssertEqual(peers["second"]?.lastHandshake, 0)
        XCTAssertEqual(peers["second"]?.endpoint?.stringRepresentation, "[2001:db8::1]:1234")
    }

    func testIncompleteRuntimeIsNotTreatedAsAnUnresponsivePeer() {
        XCTAssertTrue(PeerRuntimeState.parse("public_key=first\nrx_bytes=0\ntx_bytes=invalid\n").isEmpty)
    }

    func testIdlePeerWithOldHandshakeDoesNotResolve() {
        var recovery = EndpointRecovery()
        for time in [0.0, 30, 180, 3600] {
            XCTAssertFalse(observe(&recovery, status(handshake: 1), time))
        }
    }

    func testIdlePeerThatHasNeverHandshakenDoesNotResolve() {
        var recovery = EndpointRecovery()
        XCTAssertFalse(observe(&recovery, status(), 0))
        XCTAssertFalse(observe(&recovery, status(), 3600))
    }

    func testInitialUnansweredHandshakeResolvesAfterThirtySeconds() {
        var recovery = EndpointRecovery()
        XCTAssertFalse(observe(&recovery, status(tx: 148), 0))
        XCTAssertFalse(observe(&recovery, status(tx: 296), 29))
        XCTAssertTrue(observe(&recovery, status(tx: 444), 30))
    }

    func testFrequentObservationsDoNotPostponeRecoveryWindow() {
        var recovery = EndpointRecovery()
        for time in stride(from: 0, to: 30, by: 5) {
            XCTAssertFalse(observe(&recovery, status(tx: UInt64(time + 1) * 148), Double(time)))
        }
        XCTAssertTrue(observe(&recovery, status(tx: 10000), 30))
        // The same backend retains its retry cooldown across further observations.
        XCTAssertFalse(observe(&recovery, status(tx: 10148), 35))
        XCTAssertTrue(observe(&recovery, status(tx: 10296), 45))
    }

    func testNewCandidateGetsFullResponseWindow() {
        var recovery = EndpointRecovery()
        XCTAssertFalse(observe(&recovery, status(tx: 148), 0))
        XCTAssertTrue(observe(&recovery, status(tx: 296), 30))
        recovery.didUpdateEndpoint(at: 35)
        XCTAssertFalse(observe(&recovery, status(tx: 444), 45))
        XCTAssertFalse(observe(&recovery, status(tx: 592), 60))
        XCTAssertFalse(observe(&recovery, status(tx: 592), 64))
        XCTAssertTrue(observe(&recovery, status(tx: 740), 65))
    }

    func testSuccessfulCandidateStopsRotation() {
        var recovery = EndpointRecovery()
        XCTAssertFalse(observe(&recovery, status(tx: 148), 0))
        XCTAssertTrue(observe(&recovery, status(tx: 296), 30))
        recovery.didUpdateEndpoint(at: 35)
        XCTAssertFalse(observe(&recovery, status(rx: 92, tx: 444, handshake: 1040), 45))
        XCTAssertEqual(recovery.pollInterval, EndpointRecovery.normalPollInterval)
        XCTAssertFalse(observe(&recovery, status(rx: 92, tx: 444, handshake: 1040), 3600))
    }

    func testUnansweredTrafficStartsTimeoutWhenSendingBegins() {
        var recovery = EndpointRecovery()
        XCTAssertFalse(observe(&recovery, status(handshake: 1), 0))
        XCTAssertFalse(observe(&recovery, status(tx: 100, handshake: 1), 300))
        XCTAssertFalse(observe(&recovery, status(tx: 200, handshake: 1), 329))
        XCTAssertTrue(observe(&recovery, status(tx: 200, handshake: 1), 330))
    }

    func testRecentHandshakeGetsRekeyGraceEvenWithUnansweredKeepalives() {
        var recovery = EndpointRecovery()
        XCTAssertFalse(observe(&recovery, status(handshake: 1000), 0, keepalive: 25))
        XCTAssertFalse(observe(&recovery, status(tx: 32, handshake: 1000), 30, keepalive: 25))
        XCTAssertFalse(observe(&recovery, status(tx: 64, handshake: 1000), 179, keepalive: 25))
        XCTAssertTrue(observe(&recovery, status(tx: 96, handshake: 1000), 180, keepalive: 25))
    }

    func testKeepaliveWithoutSuccessfulSendsStillDetectsInitialFailure() {
        var recovery = EndpointRecovery()
        XCTAssertFalse(observe(&recovery, status(), 0, keepalive: 25))
        XCTAssertTrue(observe(&recovery, status(), 30, keepalive: 25))
    }

    func testIncomingTrafficCancelsPendingFailure() {
        var recovery = EndpointRecovery()
        XCTAssertFalse(observe(&recovery, status(tx: 148), 0))
        XCTAssertFalse(observe(&recovery, status(rx: 92, tx: 296), 30))
        XCTAssertFalse(observe(&recovery, status(rx: 92, tx: 296), 3600))
    }

    func testHandshakeProgressCancelsPendingFailure() {
        var recovery = EndpointRecovery()
        XCTAssertFalse(observe(&recovery, status(tx: 148), 0))
        XCTAssertFalse(observe(&recovery, status(tx: 296, handshake: 1030), 30))
        XCTAssertFalse(observe(&recovery, status(tx: 296, handshake: 1030), 3600))
    }

    func testIncomingTrafficKeepsPeerHealthyEvenWithOldHandshake() {
        var recovery = EndpointRecovery()
        XCTAssertFalse(observe(&recovery, status(handshake: 1), 0, keepalive: 25))
        for time in stride(from: 5, through: 300, by: 5) {
            XCTAssertFalse(observe(&recovery, status(rx: UInt64(time), tx: UInt64(time), handshake: 1),
                                   Double(time), keepalive: 25))
        }
    }

    func testPersistentFailureRetriesEveryFifteenSeconds() {
        var recovery = EndpointRecovery()
        XCTAssertFalse(observe(&recovery, status(tx: 148), 0))
        XCTAssertTrue(observe(&recovery, status(tx: 296), 30))
        XCTAssertFalse(observe(&recovery, status(tx: 444), 44))
        XCTAssertTrue(observe(&recovery, status(tx: 444), 45))
    }

    func testPollingSpeedsUpOnSuspicionBeforeResolvingAndSlowsAfterResponse() {
        var recovery = EndpointRecovery()
        XCTAssertEqual(recovery.pollInterval, 60)
        XCTAssertFalse(observe(&recovery, status(tx: 148), 0))
        XCTAssertEqual(recovery.pollInterval, 15)
        XCTAssertTrue(observe(&recovery, status(tx: 296), 30))
        XCTAssertEqual(recovery.pollInterval, 15)
        XCTAssertFalse(observe(&recovery, status(rx: 92, tx: 296), 45))
        XCTAssertEqual(recovery.pollInterval, 60)
    }

    func testHandshakeGraceKeepsNormalPolling() {
        var recovery = EndpointRecovery()
        XCTAssertFalse(observe(&recovery, status(handshake: 1000), 0, keepalive: 25))
        XCTAssertFalse(observe(&recovery, status(tx: 32, handshake: 1000), 30, keepalive: 25))
        XCTAssertEqual(recovery.pollInterval, 60)
        XCTAssertTrue(observe(&recovery, status(tx: 64, handshake: 1000), 180, keepalive: 25))
        XCTAssertEqual(recovery.pollInterval, 15)
    }

    func testUnansweredTrafficAfterNormalPollIsConfirmedOnFastPolls() {
        var recovery = EndpointRecovery()
        XCTAssertFalse(observe(&recovery, status(handshake: 1), 0))
        XCTAssertEqual(recovery.pollInterval, 60)

        XCTAssertFalse(observe(&recovery, status(tx: 148, handshake: 1), 60))
        XCTAssertEqual(recovery.pollInterval, 15)
        XCTAssertFalse(observe(&recovery, status(tx: 296, handshake: 1), 75))
        XCTAssertTrue(observe(&recovery, status(tx: 444, handshake: 1), 90))
    }

    func testResponseDuringFastObservationAvoidsDNSAndRestoresNormalPolling() {
        var recovery = EndpointRecovery()
        XCTAssertFalse(observe(&recovery, status(handshake: 1), 0))
        XCTAssertFalse(observe(&recovery, status(tx: 148, handshake: 1), 60))
        XCTAssertEqual(recovery.pollInterval, 15)
        XCTAssertFalse(observe(&recovery, status(rx: 92, tx: 148, handshake: 1), 75))
        XCTAssertEqual(recovery.pollInterval, 60)
        XCTAssertFalse(observe(&recovery, status(rx: 92, tx: 148, handshake: 1), 135))
    }

    func testContinuousFailureBacksOffAfterThreeMinutesOfFastRecovery() {
        var recovery = EndpointRecovery()
        XCTAssertFalse(observe(&recovery, status(tx: 148), 0))
        for time in stride(from: 30, through: 195, by: 15) {
            XCTAssertTrue(observe(&recovery, status(tx: 296), Double(time)))
            XCTAssertEqual(recovery.pollInterval, 15)
        }
        XCTAssertFalse(observe(&recovery, status(tx: 296), 209))
        XCTAssertEqual(recovery.pollInterval, 15)
        XCTAssertFalse(observe(&recovery, status(tx: 296), 210))
        XCTAssertEqual(recovery.pollInterval, 60)
        XCTAssertFalse(observe(&recovery, status(tx: 296), 254))
        XCTAssertTrue(observe(&recovery, status(tx: 296), 255))
        XCTAssertFalse(observe(&recovery, status(tx: 296), 314))
        XCTAssertTrue(observe(&recovery, status(tx: 296), 315))
    }

    func testReceivedTrafficResetsBackoffForNextFailure() {
        var recovery = EndpointRecovery()
        XCTAssertFalse(observe(&recovery, status(tx: 148), 0))
        XCTAssertTrue(observe(&recovery, status(tx: 296), 30))
        XCTAssertTrue(observe(&recovery, status(tx: 296), 210))
        XCTAssertEqual(recovery.pollInterval, 60)
        XCTAssertFalse(observe(&recovery, status(rx: 92, tx: 296), 270))
        XCTAssertEqual(recovery.pollInterval, 60)
        XCTAssertFalse(observe(&recovery, status(rx: 92, tx: 444), 300))
        XCTAssertTrue(observe(&recovery, status(rx: 92, tx: 592), 330))
        XCTAssertEqual(recovery.pollInterval, 15)
        XCTAssertTrue(observe(&recovery, status(rx: 92, tx: 592), 345))
    }

    func testResponseDuringResolutionRestoresPollingAndKeepsNewBaseline() {
        var recovery = EndpointRecovery()
        XCTAssertFalse(observe(&recovery, status(tx: 148), 0))
        XCTAssertTrue(observe(&recovery, status(tx: 296), 30))
        recovery.didReceiveResponse(status(rx: 92, tx: 296))
        XCTAssertEqual(recovery.pollInterval, 60)
        XCTAssertFalse(observe(&recovery, status(rx: 92, tx: 296), 1000))
        XCTAssertFalse(observe(&recovery, status(rx: 92, tx: 296), 1030))
    }

    func testCounterResetClearsSlowPolling() {
        var recovery = EndpointRecovery()
        XCTAssertFalse(observe(&recovery, status(tx: 148), 0))
        XCTAssertTrue(observe(&recovery, status(tx: 296), 30))
        XCTAssertTrue(observe(&recovery, status(tx: 296), 210))
        XCTAssertEqual(recovery.pollInterval, 60)
        XCTAssertFalse(observe(&recovery, status(tx: 148), 270))
        XCTAssertEqual(recovery.pollInterval, 15)
        XCTAssertTrue(observe(&recovery, status(tx: 296), 300))
        XCTAssertEqual(recovery.pollInterval, 15)
    }

    func testPeerInBackoffDoesNotSlowAnotherPeersRecovery() {
        var first = EndpointRecovery()
        var second = EndpointRecovery()
        XCTAssertFalse(observe(&first, status(tx: 148), 0))
        XCTAssertTrue(observe(&first, status(tx: 296), 30))
        XCTAssertTrue(observe(&first, status(tx: 296), 210))
        XCTAssertEqual(first.pollInterval, 60)
        XCTAssertFalse(observe(&second, status(tx: 148), 210))
        XCTAssertEqual(second.pollInterval, 15)
        XCTAssertTrue(observe(&second, status(tx: 296), 240))
        XCTAssertEqual(second.pollInterval, 15)
    }

    func testCounterResetStartsNewObservationWindow() {
        var recovery = EndpointRecovery()
        XCTAssertFalse(observe(&recovery, status(tx: 148), 0))
        XCTAssertTrue(observe(&recovery, status(tx: 296), 30))
        XCTAssertFalse(observe(&recovery, status(tx: 148), 60))
        XCTAssertTrue(observe(&recovery, status(tx: 296), 90))
    }

    func testPeersDoNotShareFailureOrCooldownState() {
        var first = EndpointRecovery()
        var second = EndpointRecovery()
        XCTAssertFalse(observe(&first, status(tx: 148), 0))
        XCTAssertFalse(observe(&second, status(), 0))
        XCTAssertTrue(observe(&first, status(tx: 296), 30))
        XCTAssertFalse(observe(&second, status(), 30))
        XCTAssertFalse(observe(&second, status(tx: 148), 35))
        XCTAssertTrue(observe(&second, status(tx: 296), 65))
    }

    func testOnlyPortChangeProducesEndpointUpdate() throws {
        let current = status()
        let endpoint = try XCTUnwrap(Endpoint(from: "192.0.2.1:1234"))
        XCTAssertEqual(current.endpointUpdate(to: endpoint),
                       "public_key=peer\nupdate_only=true\nendpoint=192.0.2.1:1234\n")
    }

    func testIPAndPortChangeProducesEndpointUpdate() throws {
        let current = status()
        let endpoint = try XCTUnwrap(Endpoint(from: "203.0.113.9:1234"))
        XCTAssertEqual(current.endpointUpdate(to: endpoint),
                       "public_key=peer\nupdate_only=true\nendpoint=203.0.113.9:1234\n")
    }

    func testIP4PPortChangeOverridesOriginalPortInUpdate() throws {
        let encoded = try XCTUnwrap(Endpoint(from: "[2001::ca6d:c000:201]:51820"))
        let endpoint = try XCTUnwrap(encoded.ip4pEndpoint)
        XCTAssertEqual(status().endpointUpdate(to: endpoint),
                       "public_key=peer\nupdate_only=true\nendpoint=192.0.2.1:51821\n")
    }

    func testUnchangedEndpointDoesNotProduceUpdate() throws {
        let current = status()
        XCTAssertNil(current.endpointUpdate(to: try XCTUnwrap(current.endpoint)))
    }

    func testResolutionResultCanBeRejectedAfterRecovery() {
        let before = status(tx: 148)
        XCTAssertTrue(status(rx: 92, tx: 148).receivedTraffic(since: before))
        XCTAssertTrue(status(tx: 148, handshake: 1000).receivedTraffic(since: before))
        XCTAssertFalse(status(tx: 296).receivedTraffic(since: before))
    }

    private func status(rx: UInt64 = 0, tx: UInt64 = 0, handshake: TimeInterval = 0) -> PeerRuntimeState {
        return PeerRuntimeState(publicKey: "peer", endpoint: Endpoint(from: "192.0.2.1:51820"),
                                rxBytes: rx, txBytes: tx, lastHandshake: handshake)
    }

    private func observe(_ recovery: inout EndpointRecovery, _ status: PeerRuntimeState,
                         _ time: TimeInterval, keepalive: UInt16 = 0) -> Bool {
        return recovery.shouldResolve(status, at: time, wallTime: 1000 + time, persistentKeepAlive: keepalive)
    }
}
