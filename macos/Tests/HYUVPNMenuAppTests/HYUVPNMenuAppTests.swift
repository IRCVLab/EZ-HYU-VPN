
import Foundation
import Testing
@testable import HYUVPNMenuCore


private func sampleDocument() -> [String: Any] { [
    "schema_version": 1,
    "state": "connected",
    "automatic_reconnect_enabled": true,
    "connected_at": "2026-08-04T12:00:00Z",
    "session_expires_at": "2026-08-04T12:59:30Z",
    "last_successful_hip_at": "2026-08-04T11:59:00Z",
    "tunnel_interface": "utun7",
    "next_retry_at": NSNull(),
    "error_code": NSNull(),
    "last_transition_at": "2026-08-04T12:00:01Z",
    "backend_build_version": "2026.08.04+menubar",
] }

private func json(_ object: [String: Any]) throws -> Data { try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]) }
private func fixedDate(_ string: String) -> Date { let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime]; return f.date(from: string)! }

@Suite struct MenuStatusProtocolTests {
    @Test func strictDecoderAcceptsOnlyPythonStatusSchemaV1AndRejectsUnsafeInputs() throws {
        let status = try VPNStatusDecoder.decode(try json(sampleDocument()))
        #expect(status.state == .connected)
        #expect(status.automaticReconnectEnabled)
        #expect(status.tunnelInterface == "utun7")
        #expect(status.backendBuildVersion == "2026.08.04+menubar")
        var boolSchema = sampleDocument(); boolSchema["schema_version"] = true
        var boolAsInt = sampleDocument(); boolAsInt["automatic_reconnect_enabled"] = 1
        var unknown = sampleDocument(); unknown["updated_at"] = "2026-08-04T12:00:00Z"
        var secret = sampleDocument(); secret["password"] = "CANARY"
        var missing = sampleDocument(); missing.removeValue(forKey: "state")
        var badState = sampleDocument(); badState["state"] = "reconnecting"
        var badInterface = sampleDocument(); badInterface["tunnel_interface"] = "en0"
        var badError = sampleDocument(); badError["error_code"] = "portal password leaked"
        var badBuild = sampleDocument(); badBuild["backend_build_version"] = "bad version!"
        var badTime = sampleDocument(); badTime["last_transition_at"] = "2026-08-04T12:00:00"
        for object in [boolSchema, boolAsInt, unknown, secret, missing, badState, badInterface, badError, badBuild, badTime] {
            #expect(throws: StatusProtocolError.self) { try VPNStatusDecoder.decode(try json(object)) }
        }
        #expect(throws: StatusProtocolError.self) { try VPNStatusDecoder.decode(Data(repeating: 0x78, count: VPNStatusDecoder.maxBytes + 1)) }
        #expect(throws: StatusProtocolError.self) { try VPNStatusDecoder.decode(Data("{not-json".utf8)) }
    }

    @Test func fileReaderRejectsSymlinksNonRegularAndOversizedSameDescriptor() throws {
        let temp = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: temp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temp) }
        let statusURL = temp.appendingPathComponent("status.json")
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: temp.path)
        try json(sampleDocument()).write(to: statusURL)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: statusURL.path)
        #expect(try VPNStatusFileReader().read(from: statusURL).state == .connected)
        try Data(repeating: 0x20, count: VPNStatusDecoder.maxBytes + 1).write(to: statusURL)
        #expect(throws: StatusProtocolError.self) { try VPNStatusFileReader().read(from: statusURL) }
        let target = temp.appendingPathComponent("target.json")
        try json(sampleDocument()).write(to: target)
        let link = temp.appendingPathComponent("link.json")
        try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: target.path)
        #expect(throws: StatusProtocolError.self) { try VPNStatusFileReader().read(from: link) }
        #expect(throws: StatusProtocolError.self) { try VPNStatusFileReader().read(from: temp) }
    }
}

@Suite struct PresentationAndMenuTests {
    @Test func presentationMapsEveryStateToSafeTextSymbolsAndDurations() throws {
        let now = fixedDate("2026-08-04T12:30:00Z")
        let connected = try VPNStatusDecoder.decode(try json(sampleDocument()))
        let view = MenuPresenter.present(connected, now: now)
        #expect(view.symbolName == "shield.lefthalf.filled")
        #expect(view.statusItemTitle == "29m")
        #expect(view.primaryText.contains("Connected"))
        #expect(view.detailText.contains("utun7"))
        #expect(view.connectedDurationText == "30m connected")
        #expect(view.countdownText == "29m remaining")
        var absentExpiry = sampleDocument(); absentExpiry["session_expires_at"] = NSNull()
        let unknown = MenuPresenter.present(try VPNStatusDecoder.decode(try json(absentExpiry)), now: now)
        #expect(unknown.countdownText == "Unknown")
        #expect(unknown.statusItemTitle == "")
        let expected: [(VPNConnectionState, String, String)] = [(.disabled, "shield.slash", ""), (.waitingForNetwork, "exclamationmark.shield", ""), (.connecting, "arrow.triangle.2.circlepath", ""), (.connected, "shield.lefthalf.filled", "29m"), (.disconnecting, "shield.slash", ""), (.backoff, "clock.arrow.circlepath", ""), (.error, "exclamationmark.shield", "")]
        for (state, symbol, title) in expected {
            var doc = sampleDocument(); doc["state"] = state.rawValue
            if state != .connected { doc["session_expires_at"] = NSNull(); doc["connected_at"] = NSNull() }
            let projected = MenuPresenter.present(try VPNStatusDecoder.decode(try json(doc)), now: now)
            #expect(projected.symbolName == symbol)
            #expect(projected.statusItemTitle == title)
        }
    }
}

@Suite struct ControlNotificationAndWatcherTests {
    @Test func controlClientUsesFixedExecutableAndArgvWithoutShell() throws {
        let client = VPNControlClient(executablePath: "/Library/Application Support/HYU VPN/bin/hyu-vpn-control")
        #expect(client.request(for: .connect).executablePath == "/Library/Application Support/HYU VPN/bin/hyu-vpn-control")
        #expect(client.request(for: .connect).arguments == ["connect"])
        #expect(client.request(for: .disconnect).arguments == ["disconnect"])
        #expect(client.request(for: .reconnect).arguments == ["reconnect"])
        #expect(client.request(for: .setAutomaticReconnect(false)).arguments == ["automatic-off"])
        #expect(client.request(for: .setAutomaticReconnect(true)).arguments == ["automatic-on"])
        #expect(!client.request(for: .connect).usesShell)
    }
    @Test func notificationPlannerIsOffByDefaultStableAndSchedulesOnlyFutureKnownThresholds() throws {
        let now = fixedDate("2026-08-04T12:00:00Z")
        let connected = try VPNStatusDecoder.decode(try json(sampleDocument()))
        #expect(NotificationPreference.defaultValue == false)
        #expect(NotificationPlanner.plan(for: connected, now: now, enabled: false).requests.isEmpty)
        let plan = NotificationPlanner.plan(for: connected, now: now, enabled: true)
        #expect(plan.cancelIdentifiers == NotificationPlanner.stableIdentifiers)
        #expect(plan.requests.map(\.identifier) == ["hyu.vpn.session-expiry.10m", "hyu.vpn.session-expiry.1m"])
        #expect(plan.requests.map(\.timeInterval) == [2970, 3510])
        let nearEnd = fixedDate("2026-08-04T12:58:45Z")
        #expect(NotificationPlanner.plan(for: connected, now: nearEnd, enabled: true).requests.isEmpty)
        var noExpiry = sampleDocument(); noExpiry["session_expires_at"] = NSNull()
        #expect(NotificationPlanner.plan(for: try VPNStatusDecoder.decode(try json(noExpiry)), now: now, enabled: true).requests.isEmpty)
    }
    @Test func watcherConfigurationUsesFileEventsAndCoarseTimersWithoutReadingLogs() {
        let config = StatusWatcherConfiguration.default(statusPath: URL(fileURLWithPath: "/tmp/status.json"))
        #expect(config.statusPath.path == "/tmp/status.json")
        #expect(config.usesFileSystemEvents)
        #expect(config.pollInterval >= 15)
        #expect(config.timerLeeway >= 5)
        #expect(config.allowedReadPurpose == .sanitizedStatusOnly)
    }
}


@Suite struct MenuSafetyRegressionTests {
    @Test func decoderRejectsDuplicateTopLevelKeysBeforeDictionaryCollapse() throws {
        let base = String(data: try json(sampleDocument()), encoding: .utf8)!
        let duplicatePlain = base.replacingOccurrences(of: "\"state\":\"connected\"", with: "\"state\":\"connected\",\"state\":\"disabled\"")
        #expect(throws: StatusProtocolError.self) { try VPNStatusDecoder.decode(Data(duplicatePlain.utf8)) }
        let duplicateEscaped = base.replacingOccurrences(of: "\"schema_version\":1", with: "\"schema_version\":1,\"schema\\u005fversion\":1")
        #expect(throws: StatusProtocolError.self) { try VPNStatusDecoder.decode(Data(duplicateEscaped.utf8)) }
    }

    @Test func watcherDoesNotResurrectLastConnectedStateAfterUnavailableStatus() throws {
        let sink = TestStatusSink()
        let reader = TestStatusReader([.success(try VPNStatusDecoder.decode(try json(sampleDocument()))), .failure(StatusProtocolError.invalid("malformed")), .failure(StatusProtocolError.invalid("missing"))])
        let watcher = StatusWatcher(configuration: .default(statusPath: URL(fileURLWithPath: "/tmp/status.json")), reader: reader, sink: sink, now: { fixedDate("2026-08-04T12:30:00Z") })
        try watcher.initialRead()
        try watcher.handleFileEvent()
        try watcher.handleCountdownTick()
        #expect(sink.presentations.map(\.primaryText) == ["Connected", "Status unavailable", "Status unavailable"])
        #expect(sink.presentations.last?.statusItemTitle == "")
    }

    @Test func notificationErrorDiagnosticIsStableAndSanitized() {
        let diagnostic = NotificationFailureDiagnostic.normalizedCode(for: StatusProtocolError.invalid("password=CANARY"))
        #expect(diagnostic == "NOTIFICATION_SCHEDULE_FAILED")
        #expect(!diagnostic.contains("CANARY"))
    }

    @Test func runnerExposesOnlyMinimalFixedEnvironment() {
        let env = SystemControlProcessRunner.fixedEnvironment()
        #expect(env.contains("PATH=/usr/bin:/bin:/usr/sbin:/sbin"))
        #expect(env.contains("LC_ALL=C"))
        #expect(!env.contains { $0.hasPrefix("HOME=") || $0.hasPrefix("USER=") || $0.contains("CANARY") })
    }

    @Test func statusChangeNotificationFailureNormalizesDiagnosticAndDisables() throws {
        let store = TestPreferenceStore(); store.enabled = true
        let client = TestAsyncNotificationClient(scheduleFails: true)
        let coordinator = AsyncNotificationCoordinator(store: store, client: client)
        let done = DispatchSemaphore(value: 0)
        let box = TestCompletionBox()
        coordinator.statusDidChange(try VPNStatusDecoder.decode(try json(sampleDocument())), now: fixedDate("2026-08-04T12:00:00Z")) { result in box.record(result); done.signal() }
        #expect(done.wait(timeout: .now() + 2) == .success)
        #expect(box.diagnostic == "NOTIFICATION_SCHEDULE_FAILED")
        #expect(store.enabled == false)
    }
    @Test func internalSpawnSetupFailureDoesNotSpawnAndClosesFDs() throws {
        let pipeFactory = TestCountingPipeFactory(failOnCall: 0)
        let setup = TestFailingSpawnSetup()
        let runner = SystemControlProcessRunner(pipeFactory: pipeFactory, spawnSetup: setup)
        let result = try runner.run(ProcessLaunchRequest(executablePath: "/bin/true", arguments: [], usesShell: false), timeout: 1, maxOutputBytes: 128)
        #expect(result == .failure(.launchFailed))
        #expect(pipeFactory.openDescriptors.isEmpty)
        #expect(setup.spawnCalls == 0)
    }

}

final class TestStatusSink: StatusUpdateSink { var presentations: [MenuPresentation] = []; func apply(_ presentation: MenuPresentation) { presentations.append(presentation) } }
final class TestStatusReader: StatusReading { var results: [Result<VPNStatus, Error>]; init(_ results: [Result<VPNStatus, Error>]) { self.results = results }; func readStatus() throws -> VPNStatus { try results.removeFirst().get() } }

final class TestPreferenceStore: NotificationPreferenceStoring, @unchecked Sendable { var enabled: Bool?; func read() -> Bool { enabled ?? false }; func write(_ value: Bool) { enabled = value } }
final class TestAsyncNotificationClient: AsyncNotificationClient, @unchecked Sendable {
    let scheduleFails: Bool; init(scheduleFails: Bool) { self.scheduleFails = scheduleFails }
    func requestAuthorization(completion: @escaping @Sendable (Result<Bool, Error>) -> Void) { completion(.success(true)) }
    func cancel(_ identifiers: [String]) {}
    func schedule(_ requests: [PlannedNotification], completion: @escaping @Sendable (Result<Void, Error>) -> Void) { scheduleFails ? completion(.failure(StatusProtocolError.invalid("password=CANARY"))) : completion(.success(())) }
}
final class TestCompletionBox: @unchecked Sendable { private let lock = NSLock(); private var _diagnostic = ""; func record(_ result: Result<Void, Error>) { if case .failure(let error) = result { lock.lock(); _diagnostic = String(describing: error); lock.unlock() } }; var diagnostic: String { lock.lock(); defer { lock.unlock() }; return _diagnostic } }

final class TestFailingSpawnSetup: SpawnSetupManaging, @unchecked Sendable {
    private(set) var spawnCalls = 0
    func setup(actions: inout posix_spawn_file_actions_t?, attrs: inout posix_spawnattr_t?, stdoutPipe: [Int32], stderrPipe: [Int32]) -> Int32 { EINVAL }
    func spawn(pid: inout pid_t, path: String, actions: inout posix_spawn_file_actions_t?, attrs: inout posix_spawnattr_t?, argv: inout [UnsafeMutablePointer<CChar>?], env: inout [UnsafeMutablePointer<CChar>?]) -> Int32 { spawnCalls += 1; return 0 }
}
final class TestCountingPipeFactory: PipeCreating, @unchecked Sendable {
    let failOnCall: Int; private(set) var calls = 0; private(set) var openDescriptors: Set<Int32> = []
    init(failOnCall: Int) { self.failOnCall = failOnCall }
    func makePipe(_ fds: inout [Int32]) -> Int32 { calls += 1; if calls == failOnCall { errno = EMFILE; return -1 }; let result = pipe(&fds); if result == 0 { openDescriptors.insert(fds[0]); openDescriptors.insert(fds[1]) }; return result }
    func close(_ fd: Int32) { openDescriptors.remove(fd); Darwin.close(fd) }
}
