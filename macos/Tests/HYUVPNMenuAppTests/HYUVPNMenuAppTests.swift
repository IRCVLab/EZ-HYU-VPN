
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
        var maxWidthInterface = sampleDocument(); maxWidthInterface["tunnel_interface"] = "utun12345678"
        #expect(try VPNStatusDecoder.decode(try json(maxWidthInterface)).tunnelInterface == "utun12345678")
        var overWidthInterface = sampleDocument(); overWidthInterface["tunnel_interface"] = "utun123456789"
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
        for object in [boolSchema, boolAsInt, unknown, secret, missing, badState, badInterface, overWidthInterface, badError, badBuild, badTime] {
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
    private func status(state: VPNConnectionState) throws -> VPNStatus {
        var document = sampleDocument()
        document["state"] = state.rawValue
        if state != .connected {
            document["connected_at"] = NSNull()
            document["session_expires_at"] = NSNull()
            document["tunnel_interface"] = NSNull()
        }
        if state != .error { document["error_code"] = NSNull() }
        return try VPNStatusDecoder.decode(try json(document))
    }

    @Test func presentationMapsEveryStateToApprovedMenuBarCopyAndSymbols() throws {
        let expected: [(VPNConnectionState, String, String)] = [
            (.connected, "checkmark.shield.fill", "Connected"),
            (.connecting, "arrow.triangle.2.circlepath", "Connecting…"),
            (.disconnecting, "shield.slash", "Disconnecting…"),
            (.disabled, "shield.slash", "Disconnected"),
            (.waitingForNetwork, "wifi.exclamationmark", "Waiting for Network"),
            (.backoff, "clock.arrow.circlepath", "Reconnecting…"),
            (.error, "exclamationmark.shield.fill", "Needs Attention"),
        ]
        for (state, symbol, title) in expected {
            let view = MenuPresenter.present(try status(state: state))
            #expect(view.statusItemTitle.isEmpty)
            #expect(view.symbolName == symbol)
            #expect(view.primaryText == title)
        }
    }

    @Test func dynamicMenuModelUsesOnePrimaryActionAndNoExpiryActions() throws {
        let connected = MenuModel.make(status: try status(state: .connected), diagnostics: "", launchAtLogin: .enabled)
        #expect(connected[.primaryConnection]?.title == "Reconnect")
        #expect(connected[.primaryConnection]?.command == .reconnect)
        #expect(connected[.disconnect]?.isEnabled == true)
        #expect(connected[.launchAtLogin]?.isChecked == true)
        #expect(MenuAction.allCases == [.currentState, .primaryConnection, .disconnect, .resetCredentials, .launchAtLogin, .diagnostics, .quit])
    }

    @Test func primaryActionIsDisabledForTransientStates() throws {
        let expected: [(VPNConnectionState, String)] = [
            (.connecting, "Connecting…"),
            (.disconnecting, "Disconnecting…"),
            (.waitingForNetwork, "Waiting for Network"),
        ]
        for (state, title) in expected {
            let menu = MenuModel.make(status: try status(state: state), diagnostics: "", launchAtLogin: .disabled)
            #expect(menu[.primaryConnection]?.title == title)
            #expect(menu[.primaryConnection]?.isEnabled == false)
            #expect(menu[.primaryConnection]?.command == nil)
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

    @Test func runnerExposesOnlyMinimalFixedEnvironment() {
        let env = SystemControlProcessRunner.fixedEnvironment()
        #expect(env.contains("PATH=/usr/bin:/bin:/usr/sbin:/sbin"))
        #expect(env.contains("LC_ALL=C"))
        #expect(!env.contains { $0.hasPrefix("HOME=") || $0.hasPrefix("USER=") || $0.contains("CANARY") })
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
