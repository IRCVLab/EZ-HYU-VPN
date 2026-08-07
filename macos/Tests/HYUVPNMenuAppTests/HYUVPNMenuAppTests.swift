
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

@Suite struct TOTPDisplayTests {
    private let rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

    @Test func generatesSixDigitRFCValuesAndCountdownBoundaries() throws {
        let first = try TOTPDisplayGenerator.snapshot(seed: rfcSecret, at: Date(timeIntervalSince1970: 0))
        #expect(first == TOTPDisplaySnapshot(code: "755224", secondsRemaining: 30))

        let boundary = try TOTPDisplayGenerator.snapshot(seed: rfcSecret, at: Date(timeIntervalSince1970: 59))
        #expect(boundary == TOTPDisplaySnapshot(code: "287082", secondsRemaining: 1))
        #expect(boundary.code.count == 6)
        #expect(boundary.code.allSatisfy { $0.isNumber })
    }

    @Test func rejectsMalformedBase32WithoutExposingInput() {
        #expect(throws: TOTPDisplayError.self) {
            try TOTPDisplayGenerator.snapshot(seed: "NOT-A-VALID-SEED!", at: Date(timeIntervalSince1970: 0))
        }
        #expect(throws: TOTPDisplayError.self) {
            try TOTPDisplayGenerator.snapshot(seed: "", at: Date(timeIntervalSince1970: 0))
        }
    }
}

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
        let connected = MenuModel.make(status: try status(state: .connected), launchAtLogin: .enabled)
        #expect(connected[.primaryConnection]?.title == "Reconnect")
        #expect(connected[.primaryConnection]?.command == .reconnect)
        #expect(connected[.disconnect]?.isEnabled == true)
        #expect(connected[.launchAtLogin]?.isChecked == true)
        #expect(MenuAction.allCases == [.currentState, .primaryConnection, .disconnect, .resetCredentials, .launchAtLogin, .quit])
    }

    @Test func primaryActionConnectsOnlyFromDisabledAndReconnectsFromError() throws {
        let disabled = MenuModel.make(status: try status(state: .disabled), launchAtLogin: .disabled)
        #expect(disabled[.primaryConnection]?.title == "Connect")
        #expect(disabled[.primaryConnection]?.isEnabled == true)
        #expect(disabled[.primaryConnection]?.command == .connect)

        let error = MenuModel.make(status: try status(state: .error), launchAtLogin: .disabled)
        #expect(error[.primaryConnection]?.title == "Reconnect")
        #expect(error[.primaryConnection]?.isEnabled == true)
        #expect(error[.primaryConnection]?.command == .reconnect)
    }

    @Test func primaryActionIsDisabledForTransientStates() throws {
        let expected: [(VPNConnectionState, String)] = [
            (.connecting, "Connecting…"),
            (.disconnecting, "Disconnecting…"),
            (.waitingForNetwork, "Waiting for Network"),
        ]
        for (state, title) in expected {
            let menu = MenuModel.make(status: try status(state: state), launchAtLogin: .disabled)
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

    @Test func secureControlClientDecodesStrictCLIJsonAndFallsBackForMalformedOutput() throws {
        let metadata = UnitTestExecutableMetadata(ownerUID: 0, mode: 0o755, symlink: false, executable: true, parentModes: ["/Library": 0o755, "/Library/Application Support": 0o755, "/Library/Application Support/HYU VPN": 0o755, "/Library/Application Support/HYU VPN/bin": 0o755])
        let runner = UnitTestProcessRunner(results: [
            .success(exitCode: 1, stdout: #"{"schema_version":1,"ok":false,"error_code":"CONTROL_UNAVAILABLE"}"#, stderr: "", stdoutOverflowed: false),
            .success(exitCode: 1, stdout: #"{"schema_version":1,"ok":false,"error_code":"REPAIR_REQUIRED"}"#, stderr: "", stdoutOverflowed: false),
            .success(exitCode: 1, stdout: #"{"schema_version":1,"ok":false,"error_code":"BROKEN"}"#, stderr: "", stdoutOverflowed: false),
            .success(exitCode: 1, stdout: #"{"schema_version":1,"ok":false,"error_code":"CONTROL_UNAVAILABLE","error_code":"REPAIR_REQUIRED"}"#, stderr: "", stdoutOverflowed: false),
            .success(exitCode: 1, stdout: #"{"schema_version":1,"ok":false,"error_code":"CONTROL_UNAVAILABLE"}"#, stderr: "", stdoutOverflowed: true),
            .success(exitCode: 1, stdout: "not-json", stderr: "", stdoutOverflowed: false)
        ])
        let client = SecureVPNControlClient(metadata: metadata, runner: runner)
        #expect(try client.run(.connect).errorCode == "CONTROL_UNAVAILABLE")
        #expect(try client.run(.disconnect).errorCode == "REPAIR_REQUIRED")
        #expect(try client.run(.reconnect).errorCode == "CONTROL_EXIT_1")
        #expect(try client.run(.connect).errorCode == "CONTROL_EXIT_1")
        #expect(try client.run(.disconnect).errorCode == "CONTROL_EXIT_1")
        #expect(try client.run(.reconnect).errorCode == "CONTROL_EXIT_1")
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

@Suite struct ControlTowerCoreTests {
    private func input(
        username: String = "shchoi00",
        password: String = "correct horse",
        passwordConfirmation: String = "correct horse",
        totpSeed: String = "",
        totpSeedConfirmation: String = ""
    ) -> CredentialResetInput {
        CredentialResetInput(username: username, password: password, passwordConfirmation: passwordConfirmation, totpSeed: totpSeed, totpSeedConfirmation: totpSeedConfirmation)
    }

    @Test func credentialValidationNormalizesValidSeedAndRetainsBlankSeed() throws {
        let good = input(totpSeed: "jbsw y3dp-ehpk3pxp", totpSeedConfirmation: "JBSWY3DPEHPK3PXP")
        let validated = try CredentialValidator.validate(good)
        #expect(validated.username == "shchoi00")
        #expect(validated.password == "correct horse")
        #expect(validated.normalizedTOTPSeed == "JBSWY3DPEHPK3PXP")
        #expect(try CredentialValidator.validate(input(totpSeed: "", totpSeedConfirmation: "")).normalizedTOTPSeed == nil)
    }

    @Test func credentialValidationRejectsPasswordAndUsernameBoundsWithoutSecrets() {
        let canaryUser = "canaryUser42"
        let canaryPassword = "canaryPassword42"
        let cases: [(CredentialValidationError, CredentialResetInput)] = [
            (.usernameRequired, input(username: "")),
            (.usernameTooLong, input(username: String(repeating: "u", count: 129))),
            (.usernameContainsControlCharacter, input(username: "bad\u{7f}")),
            (.passwordRequired, input(password: "", passwordConfirmation: "")),
            (.passwordTooLong, input(password: String(repeating: "é", count: 513), passwordConfirmation: String(repeating: "é", count: 513))),
            (.passwordContainsDisallowedCharacter, input(password: "one\n", passwordConfirmation: "one\n")),
            (.passwordContainsDisallowedCharacter, input(password: "one\r", passwordConfirmation: "one\r")),
            (.passwordContainsDisallowedCharacter, input(password: "one\u{0}", passwordConfirmation: "one\u{0}")),
            (.passwordMismatch, input(username: canaryUser, password: canaryPassword, passwordConfirmation: "different")),
        ]
        for (expected, value) in cases {
            #expect(throws: expected) { try CredentialValidator.validate(value) }
            let description = expected.description
            #expect(!description.contains(canaryUser))
            #expect(!description.contains(canaryPassword))
        }
    }

    @Test func credentialValidationRejectsTotpErrorsAndRedactsSubmittedValues() {
        let canarySeed = "JBSWY3DPEHPK3PXP"
        let cases: [(CredentialValidationError, CredentialResetInput)] = [
            (.totpSeedRequired, input(totpSeed: canarySeed, totpSeedConfirmation: "")),
            (.totpSeedRequired, input(totpSeed: "", totpSeedConfirmation: canarySeed)),
            (.totpSeedMismatch, input(totpSeed: canarySeed, totpSeedConfirmation: "JBSWY3DPEHPK3PXQ")),
            (.totpSeedInvalidAlphabetOrPadding, input(totpSeed: "JBSWY3DPEHPK3PX!", totpSeedConfirmation: "JBSWY3DPEHPK3PX!")),
            (.totpSeedInvalidAlphabetOrPadding, input(totpSeed: "JBSWY3DP=EHPK3PXP", totpSeedConfirmation: "JBSWY3DP=EHPK3PXP")),
            (.totpSeedTooShort, input(totpSeed: "JBSWY3DPEHPK3PX", totpSeedConfirmation: "JBSWY3DPEHPK3PX")),
            (.totpSeedTooLong, input(totpSeed: String(repeating: "A", count: 257), totpSeedConfirmation: String(repeating: "A", count: 257))),
            (.totpSeedLooksLikeOneTimeCode, input(totpSeed: "123456", totpSeedConfirmation: "123456")),
        ]
        for (expected, value) in cases {
            #expect(throws: expected) { try CredentialValidator.validate(value) }
            #expect(!expected.description.contains(canarySeed))
            #expect(!expected.code.contains(canarySeed))
        }
    }

    @Test func credentialValidationAcceptsOnlyStrictRFC4648Base32PaddingShapes() throws {
        let validSeeds = [
            String(repeating: "A", count: 16),
            String(repeating: "A", count: 18),
            String(repeating: "A", count: 20),
            String(repeating: "A", count: 21),
            String(repeating: "A", count: 23),
            String(repeating: "A", count: 10) + "======",
            String(repeating: "A", count: 12) + "====",
            String(repeating: "A", count: 13) + "===",
            String(repeating: "A", count: 15) + "=",
        ]
        for seed in validSeeds {
            #expect(try CredentialValidator.validate(input(totpSeed: seed, totpSeedConfirmation: seed)).normalizedTOTPSeed == seed)
        }

        let invalidSeeds = [
            String(repeating: "A", count: 17),
            String(repeating: "A", count: 19),
            String(repeating: "A", count: 22),
            String(repeating: "A", count: 14) + "==",
            String(repeating: "A", count: 11) + "=====",
            String(repeating: "A", count: 16) + "===",
        ]
        for seed in invalidSeeds {
            #expect(throws: CredentialValidationError.totpSeedInvalidAlphabetOrPadding) {
                try CredentialValidator.validate(input(totpSeed: seed, totpSeedConfirmation: seed))
            }
        }
    }

    @Test func credentialTransactionRollsBackWritesRedactsErrorsAndDoesNotReconnectOnFailure() throws {
        let store = RecordingCredentialStore(initial: [.username: "old-user", .password: "old-pass", .totpSeed: "OLDTOTPSEEDVALUE1"], failOnWriteCall: 3)
        let resetter = RecordingTOTPResetter()
        var reconnects = 0
        let transaction = CredentialTransaction(store: store, totpResetter: resetter) { reconnects += 1 }
        let result = transaction.apply(ValidatedCredentials(username: "canary-user", password: "canary-pass", normalizedTOTPSeed: "JBSWY3DPEHPK3PXP"))
        #expect(result == .failure(code: .writeFailed))
        #expect(store.values[.username] == "old-user")
        #expect(store.values[.password] == "old-pass")
        #expect(store.values[.totpSeed] == "OLDTOTPSEEDVALUE1")
        #expect(store.events.suffix(2) == ["write:password:old-pass", "write:username:old-user"])
        #expect(resetter.resetCount == 0)
        #expect(reconnects == 0)
        #expect(!result.description.contains("canary-user"))
        #expect(!result.description.contains("canary-pass"))
        #expect(!result.description.contains("JBSWY3DPEHPK3PXP"))
    }

    @Test func credentialTransactionRemovesOriginallyAbsentKeysDuringRollback() {
        let store = RecordingCredentialStore(initial: [:], failOnWriteCall: 2)
        let result = CredentialTransaction(store: store, totpResetter: RecordingTOTPResetter()).apply(ValidatedCredentials(username: "new-user", password: "new-pass", normalizedTOTPSeed: nil))
        #expect(result == .failure(code: .writeFailed))
        #expect(store.values[.username] == nil)
        #expect(store.events.contains("remove:username"))
    }

    @Test func credentialTransactionResetsTotpOnlyAfterNewSeedCommitAndReconnectsAfterFullSuccess() {
        let resetter = RecordingTOTPResetter()
        var reconnects = 0
        let transaction = CredentialTransaction(store: RecordingCredentialStore(initial: [.username: "old", .password: "old"]), totpResetter: resetter) { reconnects += 1 }
        let result = transaction.apply(ValidatedCredentials(username: "new-user", password: "new-pass", normalizedTOTPSeed: "JBSWY3DPEHPK3PXP"))
        #expect(result == .success)
        #expect(resetter.resetCount == 1)
        #expect(reconnects == 1)

        let retainResetter = RecordingTOTPResetter()
        let retainResult = CredentialTransaction(store: RecordingCredentialStore(initial: [:]), totpResetter: retainResetter).apply(ValidatedCredentials(username: "new-user", password: "new-pass", normalizedTOTPSeed: nil))
        #expect(retainResult == .success)
        #expect(retainResetter.resetCount == 0)
    }

    @Test func credentialTransactionReportsReadAndTOTPResetFailuresWithStableCodesAndNoReconnect() {
        let readStore = RecordingCredentialStore(initial: [:], failReadKey: .password)
        var readReconnects = 0
        let readResult = CredentialTransaction(store: readStore, totpResetter: RecordingTOTPResetter()) { readReconnects += 1 }.apply(ValidatedCredentials(username: "canary-user", password: "canary-pass", normalizedTOTPSeed: nil))
        #expect(readResult == .failure(code: .readFailed))
        #expect(readResult.description == "READ_FAILED")
        #expect(readReconnects == 0)
        #expect(!readResult.description.contains("canary"))

        let resetter = RecordingTOTPResetter(fail: true)
        let resetStore = RecordingCredentialStore(initial: [.username: "old-user", .password: "old-pass", .totpSeed: "OLDTOTPSEEDVALUE1"])
        var resetReconnects = 0
        let resetResult = CredentialTransaction(store: resetStore, totpResetter: resetter) { resetReconnects += 1 }.apply(ValidatedCredentials(username: "new-user", password: "new-pass", normalizedTOTPSeed: "JBSWY3DPEHPK3PXP"))
        #expect(resetResult == .failure(code: .totpResetFailed))
        #expect(resetResult.description == "TOTP_RESET_FAILED")
        #expect(resetStore.values[.username] == "old-user")
        #expect(resetStore.values[.password] == "old-pass")
        #expect(resetStore.values[.totpSeed] == "OLDTOTPSEEDVALUE1")
        #expect(resetReconnects == 0)
    }

    @Test func credentialTransactionContinuesBestEffortRollbackAfterRemoveFailure() {
        let store = RecordingCredentialStore(initial: [:], failRemoveKeys: [.totpSeed])
        let resetter = RecordingTOTPResetter(fail: true)
        var reconnects = 0
        let result = CredentialTransaction(store: store, totpResetter: resetter) { reconnects += 1 }.apply(ValidatedCredentials(username: "new-user", password: "new-pass", normalizedTOTPSeed: "JBSWY3DPEHPK3PXP"))
        #expect(result == .failure(code: .rollbackFailed))
        #expect(result.description == "ROLLBACK_FAILED")
        #expect(store.events.contains("remove:totpSeed"))
        #expect(store.events.contains("remove:password"))
        #expect(store.events.contains("remove:username"))
        #expect(store.values[.username] == nil)
        #expect(store.values[.password] == nil)
        #expect(store.values[.totpSeed] == "JBSWY3DPEHPK3PXP")
        #expect(reconnects == 0)
    }


    @Test func credentialResetLifecycleOrdersDisconnectTransactionAndSingleReconnect() {
        var coordinator = AppLifecycleCoordinator()
        #expect(coordinator.handle(.credentialResetRequested) == .init(terminationDirective: .none, effects: [.runControl(command: .disconnect, operation: .credentialSave, timeout: 3)]))
        #expect(coordinator.handle(.credentialResetRequested).effects.isEmpty)
        #expect(coordinator.handle(.primaryConnectRequested).effects.isEmpty)
        #expect(coordinator.handle(.controlCompleted(operation: .credentialSave, result: ControlResult(status: .ok, errorCode: nil))) == .init(terminationDirective: .none, effects: [.runCredentialTransaction]))
        #expect(coordinator.handle(.credentialTransactionCompleted(.success)) == .init(terminationDirective: .none, effects: [.runControl(command: .connect, operation: .credentialSave, timeout: 3)]))
        #expect(coordinator.handle(.controlCompleted(operation: .credentialSave, result: ControlResult(status: .ok, errorCode: nil))).effects.isEmpty)
        #expect(coordinator.handle(.primaryConnectRequested).effects == [.runControl(command: .connect, operation: .connect, timeout: 3)])
    }

    @Test func credentialResetLifecycleSuppressesWritesReconnectAndTerminatesSafely() {
        var disconnectFailure = AppLifecycleCoordinator()
        _ = disconnectFailure.handle(.credentialResetRequested)
        #expect(disconnectFailure.handle(.controlCompleted(operation: .credentialSave, result: ControlResult(status: .failed, errorCode: "CONTROL_UNAVAILABLE"))) == .init(terminationDirective: .none, effects: [.showCredentialResetError("CONTROL_UNAVAILABLE")]))

        var transactionFailure = AppLifecycleCoordinator()
        _ = transactionFailure.handle(.credentialResetRequested)
        _ = transactionFailure.handle(.controlCompleted(operation: .credentialSave, result: ControlResult(status: .ok, errorCode: nil)))
        #expect(transactionFailure.handle(.credentialTransactionCompleted(.failure(code: .rollbackFailed))) == .init(terminationDirective: .none, effects: [.showCredentialResetError("ROLLBACK_FAILED")]))

        var terminateBeforeWrites = AppLifecycleCoordinator()
        _ = terminateBeforeWrites.handle(.credentialResetRequested)
        #expect(terminateBeforeWrites.handle(.terminateRequested) == .init(terminationDirective: .terminateLater, effects: [.dismissCredentialReset]))
        #expect(terminateBeforeWrites.handle(.controlCompleted(operation: .credentialSave, result: ControlResult(status: .ok, errorCode: nil))) == .init(terminationDirective: .none, effects: [.replyToTermination(true)]))

        var terminateDisconnectFailure = AppLifecycleCoordinator()
        _ = terminateDisconnectFailure.handle(.credentialResetRequested)
        _ = terminateDisconnectFailure.handle(.terminateRequested)
        #expect(terminateDisconnectFailure.handle(.controlCompleted(operation: .credentialSave, result: ControlResult(status: .timeout, errorCode: "CONTROL_TIMEOUT"))) == .init(terminationDirective: .none, effects: [.replyToTermination(false), .showTerminationFailureAlert("CONTROL_TIMEOUT")]))

        var terminateDuringTransaction = AppLifecycleCoordinator()
        _ = terminateDuringTransaction.handle(.credentialResetRequested)
        _ = terminateDuringTransaction.handle(.controlCompleted(operation: .credentialSave, result: ControlResult(status: .ok, errorCode: nil)))
        #expect(terminateDuringTransaction.handle(.terminateRequested) == .init(terminationDirective: .terminateLater, effects: [.dismissCredentialReset]))
        #expect(terminateDuringTransaction.handle(.credentialTransactionCompleted(.success)) == .init(terminationDirective: .none, effects: [.replyToTermination(true)]))
        #expect(terminateDuringTransaction.handle(.terminateRequested) == .init(terminationDirective: .terminateNow, effects: []))
    }

    @Test func startupPolicyRetriesOnlyFirstTwentyNineTransientOutcomesAndStopsAtThirtyAttempts() {
        var policy = StartupConnectPolicy()
        for _ in 0..<29 { #expect(policy.next(after: .controlUnavailable) == .retry(after: 1)) }
        #expect(policy.next(after: .controlUnavailable) == .stop)
        var launchPolicy = StartupConnectPolicy()
        #expect(launchPolicy.next(after: .launchFailure) == .retry(after: 1))
        var codePolicy = StartupConnectPolicy()
        #expect(codePolicy.next(after: .failure(code: "CONTROL_UNAVAILABLE")) == .retry(after: 1))
        var successPolicy = StartupConnectPolicy()
        #expect(successPolicy.next(after: .success) == .stop)
        var failurePolicy = StartupConnectPolicy()
        #expect(failurePolicy.next(after: .failure(code: "AUTH_FAILED")) == .stop)
    }

    @Test func operationGateRejectsOverlappingOperationsUntilFinish() {
        var gate = OperationGate()
        let first = gate.begin(.disconnect)
        let overlappingQuit = gate.begin(.quit)
        let duplicateDisconnect = gate.begin(.disconnect)
        gate.finish(.quit)
        let stillBlocked = gate.begin(.connect)
        gate.finish(.disconnect)
        let afterFinish = gate.begin(.quit)
        #expect(first)
        #expect(!overlappingQuit)
        #expect(!duplicateDisconnect)
        #expect(!stillBlocked)
        #expect(afterFinish)
    }

    @Test func loginItemStateIsFrameworkFreeEquatableModel() {
        #expect(LoginItemState.enabled != .disabled)
        #expect(LoginItemState.approvalRequired == .approvalRequired)
        #expect(LoginItemState.unavailable(code: "SM_UNAVAILABLE") == .unavailable(code: "SM_UNAVAILABLE"))
    }

    @Test func lifecycleCoordinatorHandlesStartupRetryAndRetryBound() {
        var coordinator = AppLifecycleCoordinator()
        #expect(coordinator.handle(.appLaunched) == .init(terminationDirective: .none, effects: [.runControl(command: .connect, operation: .connect, timeout: 3)]))
        #expect(coordinator.handle(.controlCompleted(operation: .connect, result: ControlResult(status: .failed, errorCode: "CONTROL_UNAVAILABLE"))) == .init(terminationDirective: .none, effects: [.scheduleStartupRetry(after: 1)]))
        #expect(coordinator.handle(.startupRetryTimerFired) == .init(terminationDirective: .none, effects: [.runControl(command: .connect, operation: .connect, timeout: 3)]))

        var bounded = AppLifecycleCoordinator()
        _ = bounded.handle(.appLaunched)
        for _ in 0..<29 {
            let transition = bounded.handle(.controlCompleted(operation: .connect, result: ControlResult(status: .failed, errorCode: "CONTROL_UNAVAILABLE")))
            #expect(transition.effects == [.scheduleStartupRetry(after: 1)])
            #expect(bounded.handle(.startupRetryTimerFired).effects == [.runControl(command: .connect, operation: .connect, timeout: 3)])
        }
        #expect(bounded.handle(.controlCompleted(operation: .connect, result: ControlResult(status: .failed, errorCode: "CONTROL_UNAVAILABLE"))).effects.isEmpty)
    }

    @Test func lifecycleCoordinatorDisconnectPauseAbsorbsCancelledRetryAndPendingDisconnect() {
        var coordinator = AppLifecycleCoordinator()
        _ = coordinator.handle(.appLaunched)
        #expect(coordinator.handle(.disconnectRequested) == .init(terminationDirective: .none, effects: []))
        #expect(coordinator.handle(.controlCompleted(operation: .connect, result: ControlResult(status: .ok, errorCode: nil))) == .init(terminationDirective: .none, effects: [.runControl(command: .disconnect, operation: .disconnect, timeout: 3)]))

        var retry = AppLifecycleCoordinator()
        _ = retry.handle(.appLaunched)
        _ = retry.handle(.controlCompleted(operation: .connect, result: ControlResult(status: .failed, errorCode: "CONTROL_UNAVAILABLE")))
        #expect(retry.handle(.disconnectRequested) == .init(terminationDirective: .none, effects: [.cancelStartupRetry, .runControl(command: .disconnect, operation: .disconnect, timeout: 3)]))
        #expect(retry.handle(.startupRetryTimerFired).effects.isEmpty)

        var terminateAbsorbsPending = AppLifecycleCoordinator()
        _ = terminateAbsorbsPending.handle(.appLaunched)
        _ = terminateAbsorbsPending.handle(.disconnectRequested)
        #expect(terminateAbsorbsPending.handle(.terminateRequested).terminationDirective == .terminateLater)
        #expect(terminateAbsorbsPending.handle(.controlCompleted(operation: .connect, result: ControlResult(status: .ok, errorCode: nil))) == .init(terminationDirective: .none, effects: [.runControl(command: .disconnect, operation: .quit, timeout: 15)]))
    }

    @Test func lifecycleCoordinatorHandlesTerminateIdleInFlightDuplicateAndReplyOrdering() {
        var idle = AppLifecycleCoordinator()
        _ = idle.handle(.appLaunched)
        _ = idle.handle(.controlCompleted(operation: .connect, result: ControlResult(status: .ok, errorCode: nil)))
        #expect(idle.handle(.terminateRequested) == .init(terminationDirective: .terminateLater, effects: [.runControl(command: .disconnect, operation: .quit, timeout: 15)]))
        #expect(idle.handle(.controlCompleted(operation: .quit, result: ControlResult(status: .ok, errorCode: nil))) == .init(terminationDirective: .none, effects: [.replyToTermination(true)]))
        #expect(idle.handle(.terminateRequested) == .init(terminationDirective: .terminateNow, effects: []))
        #expect(idle.handle(.startupRetryTimerFired).effects.isEmpty)
        #expect(idle.handle(.disconnectRequested).effects.isEmpty)

        var inFlightConnect = AppLifecycleCoordinator()
        _ = inFlightConnect.handle(.appLaunched)
        #expect(inFlightConnect.handle(.terminateRequested) == .init(terminationDirective: .terminateLater, effects: []))
        #expect(inFlightConnect.handle(.terminateRequested) == .init(terminationDirective: .terminateLater, effects: []))
        #expect(inFlightConnect.handle(.controlCompleted(operation: .connect, result: ControlResult(status: .ok, errorCode: nil))) == .init(terminationDirective: .none, effects: [.runControl(command: .disconnect, operation: .quit, timeout: 15)]))

        var existingDisconnect = AppLifecycleCoordinator()
        _ = existingDisconnect.handle(.appLaunched)
        _ = existingDisconnect.handle(.controlCompleted(operation: .connect, result: ControlResult(status: .ok, errorCode: nil)))
        _ = existingDisconnect.handle(.disconnectRequested)
        #expect(existingDisconnect.handle(.terminateRequested) == .init(terminationDirective: .terminateLater, effects: []))
        #expect(existingDisconnect.handle(.controlCompleted(operation: .disconnect, result: ControlResult(status: .timeout, errorCode: "CONTROL_TIMEOUT"))) == .init(terminationDirective: .none, effects: [.replyToTermination(false), .showTerminationFailureAlert("CONTROL_TIMEOUT")]))
    }
}

final class RecordingCredentialStore: CredentialStore {
    enum StoreFailure: Error { case injected }
    var values: [CredentialKey: String?]
    var events: [String] = []
    private let failOnWriteCall: Int?
    private let failReadKey: CredentialKey?
    private let failRemoveKeys: Set<CredentialKey>
    private var writeCalls = 0
    init(initial: [CredentialKey: String], failOnWriteCall: Int? = nil, failReadKey: CredentialKey? = nil, failRemoveKeys: Set<CredentialKey> = []) {
        self.values = initial.mapValues { Optional($0) }
        self.failOnWriteCall = failOnWriteCall
        self.failReadKey = failReadKey
        self.failRemoveKeys = failRemoveKeys
    }
    func read(_ key: CredentialKey) throws -> String? {
        events.append("read:\(key.rawValue)")
        if key == failReadKey { throw StoreFailure.injected }
        return values[key] ?? nil
    }
    func write(_ value: String, for key: CredentialKey) throws {
        writeCalls += 1
        events.append("write:\(key.rawValue):\(value)")
        if writeCalls == failOnWriteCall { throw StoreFailure.injected }
        values[key] = value
    }
    func remove(_ key: CredentialKey) throws {
        events.append("remove:\(key.rawValue)")
        if failRemoveKeys.contains(key) { throw StoreFailure.injected }
        values.removeValue(forKey: key)
    }
}

final class RecordingTOTPResetter: TOTPStateResetting {
    enum ResetFailure: Error { case injected }
    private let fail: Bool
    private(set) var resetCount = 0
    init(fail: Bool = false) { self.fail = fail }
    func resetTOTPState() throws {
        resetCount += 1
        if fail { throw ResetFailure.injected }
    }
}

struct UnitTestExecutableMetadata: ExecutableMetadataProviding {
    var ownerUID: uid_t
    var mode: mode_t
    var symlink: Bool
    var executable: Bool
    var parentModes: [String: mode_t]

    func metadata(for path: String) throws -> FileMetadata {
        FileMetadata(ownerUID: path == SecureVPNControlClient.defaultExecutablePath ? ownerUID : uid_t(0), mode: parentModes[path] ?? mode, isSymlink: symlink, isRegularFile: true, isExecutable: executable)
    }
}

final class UnitTestProcessRunner: ControlProcessRunning {
    var results: [ControlProcessOutcome]

    init(results: [ControlProcessOutcome]) {
        self.results = results
    }

    func run(_ request: ProcessLaunchRequest, timeout: TimeInterval, maxOutputBytes: Int) throws -> ControlProcessOutcome {
        results.removeFirst()
    }
}
