import Foundation
import Darwin
import HYUVPNMenuCore

struct HarnessFailure: Error, CustomStringConvertible { let description: String }
func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws { if !condition() { throw HarnessFailure(description: message) } }
func expectThrows(_ message: String, _ body: () throws -> Void) throws { do { try body(); throw HarnessFailure(description: "expected throw: \(message)") } catch is HarnessFailure { throw HarnessFailure(description: "expected throw: \(message)") } catch {} }

@main struct Harness {
    static func main() {
        do {
            if ProcessInfo.processInfo.environment["HYU_MENU_HARNESS_FORCE_FAILURE"] == "1" { throw HarnessFailure(description: "forced failure") }
            let tests: [(String, () throws -> Void)] = [
                ("strict-status-all-states-and-corrupt", strictStatusAllStates),
                ("status-file-security", statusFileSecurity),
                ("presentation-symbols-and-title-rule", presentationSymbolsAndTitleRule),
                ("dynamic-menu-actions-and-checks", dynamicMenuActionsAndChecks),
                ("watcher-initial-event-and-tick", watcherInitialEventAndTick),
                ("control-security-timeout-and-normalized-errors", controlSecurityTimeoutAndErrors),
                ("notification-preference-injected-cancel-reschedule", notificationPreferenceInjectedReschedule),
                ("bundle-assembler-produces-lsuielement-app", bundleAssembler),
                ("canonical-production-status-path", canonicalProductionStatusPath),
                ("schema-float-integers-rejected", schemaFloatIntegersRejected),
                ("connected-duration-only-connected", connectedDurationOnlyConnected),
                ("system-runner-drains-large-output-and-timeouts", systemRunnerDrainsLargeOutputAndTimeouts),
                ("async-notifications-grant-denial-status-change", asyncNotificationsGrantDenialStatusChange),
                ("real-dispatch-watcher-atomic-replace-and-tick", realDispatchWatcherAtomicReplaceAndTick),
                ("unavailable-status-cancels-notifications", unavailableStatusCancelsNotifications),
                ("notification-schedule-failure-completes-once", notificationScheduleFailureCompletesOnce),
                ("json-decoder-int-token-proof", jsonDecoderIntTokenProof),
                ("process-group-timeout-kills-descendant-and-discards-output", processGroupTimeoutKillsDescendantAndDiscardsOutput),
                ("near-expiry-thresholds-are-not-retroactive", nearExpiryThresholdsAreNotRetroactive),
                ("duplicate-json-keys-rejected-before-collapse", duplicateJSONKeysRejectedBeforeCollapse),
                ("unavailable-status-clears-stale-countdown", unavailableStatusClearsStaleCountdown),
                ("direct-child-success-with-open-descendant-pipe-fails", directChildSuccessWithOpenDescendantPipeFails),
                ("term-ignoring-descendant-is-killed", termIgnoringDescendantIsKilled),
                ("synthetic-echild-is-never-success", syntheticECHILDIsNeverSuccess),
                ("second-pipe-failure-closes-first-pipe", secondPipeFailureClosesFirstPipe),
                ("notification-failure-normalized-diagnostic", notificationFailureNormalizedDiagnostic),
                ("control-runner-uses-fixed-minimal-environment", controlRunnerUsesFixedMinimalEnvironment),
                ("sentinel-parent-fd-is-not-inherited", sentinelParentFDIsNotInherited),
                ("term-ignoring-descendant-closes-fds-still-killed", termIgnoringDescendantClosesFDsStillKilled),
                ("cleanup-reap-is-bounded", cleanupReapIsBounded),
                ("status-change-notification-failure-completes-normalized", statusChangeNotificationFailureCompletesNormalized),
                ("menu-core-has-no-direct-foundation-process-run-surface", menuCoreHasNoDirectFoundationProcessRunSurface),
                ("spawn-setup-seam-is-not-public-production-api", spawnSetupSeamIsNotPublicProductionAPI)
            ]
            for (name, test) in tests { print("RUN \(name)"); try test(); print("PASS \(name)") }
            print("HARNESS PASS \(tests.count) tests")
        } catch { FileHandle.standardError.write(Data("HARNESS FAIL: \(error)\n".utf8)); exit(1) }
    }

    static func packageRoot() -> URL {
        let current = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        if FileManager.default.fileExists(atPath: current.appendingPathComponent("Package.swift").path) { return current }
        return current.appendingPathComponent("macos")
    }

    static func statusData(state: VPNConnectionState = .connected, expiry: String? = "2026-08-04T12:59:30Z", connectedAt: String? = "2026-08-04T12:00:00Z", automatic: Bool = true, error: String? = nil, tunnel: String = "utun7") -> Data {
        let fields: [String] = [
            "\"schema_version\":1",
            "\"state\":\"\(state.rawValue)\"",
            "\"automatic_reconnect_enabled\":\(automatic ? "true" : "false")",
            "\"connected_at\":\(connectedAt.map { "\"\($0)\"" } ?? "null")",
            "\"session_expires_at\":\(expiry.map { "\"\($0)\"" } ?? "null")",
            "\"last_successful_hip_at\":\"2026-08-04T11:59:00Z\"",
            "\"tunnel_interface\":\"\(tunnel)\"",
            "\"next_retry_at\":null",
            "\"error_code\":\(error.map { "\"\($0)\"" } ?? "null")",
            "\"last_transition_at\":\"2026-08-04T12:00:01Z\"",
            "\"backend_build_version\":\"2026.08.04+menubar\""
        ]
        return Data(("{" + fields.joined(separator: ",") + "}\n").utf8)
    }
    static func date(_ string: String) -> Date { ISO8601DateFormatter().date(from: string)! }

    static func strictStatusAllStates() throws {
        for state in VPNConnectionState.allCases { let decoded = try VPNStatusDecoder.decode(statusData(state: state)); try expect(decoded.state == state, "state \(state.rawValue)") }
        let maxWidth = try VPNStatusDecoder.decode(statusData(tunnel: "utun12345678"))
        try expect(maxWidth.tunnelInterface == "utun12345678", "shared maximum-width utun accepted")
        try expectThrows("over-width utun") { _ = try VPNStatusDecoder.decode(statusData(tunnel: "utun123456789")) }
        for bad in [Data("{not-json".utf8), Data(repeating: 0x78, count: VPNStatusDecoder.maxBytes + 1), Data("{\"schema_version\":true}".utf8), Data("{\"schema_version\":1,\"password\":\"CANARY\"}".utf8)] { try expectThrows("bad status") { _ = try VPNStatusDecoder.decode(bad) } }
    }

    static func statusFileSecurity() throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("hyu-menu-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        let file = root.appendingPathComponent("status.json")
        try statusData().write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        let secureStatus = try VPNStatusFileReader().read(from: file)
        try expect(secureStatus.state == .connected, "secure status accepted")
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)
        try expectThrows("bad file mode") { _ = try VPNStatusFileReader().read(from: file) }
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: root.path)
        try expectThrows("bad parent mode") { _ = try VPNStatusFileReader().read(from: file) }
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        let link = root.appendingPathComponent("link.json")
        try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: file.path)
        try expectThrows("symlink") { _ = try VPNStatusFileReader().read(from: link) }
        var fake = FakeMetadata(ownerUID: getuid(), fileMode: 0o600, parentMode: 0o700, isSymlink: false, isRegular: true)
        fake.ownerUID = getuid() + 1
        try expectThrows("owner mismatch") { try StatusFileSecurity.validate(statusPath: file, metadata: fake) }
    }

    static func presentationSymbolsAndTitleRule() throws {
        let now = date("2026-08-04T12:30:00Z")
        let symbols: [(VPNConnectionState, String)] = [(.connected, "shield.lefthalf.filled"), (.connecting, "arrow.triangle.2.circlepath"), (.backoff, "clock.arrow.circlepath"), (.disabled, "shield.slash"), (.disconnecting, "shield.slash"), (.error, "exclamationmark.shield"), (.waitingForNetwork, "exclamationmark.shield")]
        for (state, symbol) in symbols {
            let status = try VPNStatusDecoder.decode(statusData(state: state, expiry: state == .connected ? "2026-08-04T12:59:30Z" : nil, connectedAt: state == .connected ? "2026-08-04T12:00:00Z" : nil))
            let view = MenuPresenter.present(status, now: now)
            try expect(view.symbolName == symbol, "symbol \(state.rawValue)")
            try expect(view.statusItemTitle == (state == .connected ? "29m" : ""), "title only connected")
        }
        let missingExpiry = try VPNStatusDecoder.decode(statusData(expiry: nil))
        try expect(MenuPresenter.present(missingExpiry, now: now).countdownText == "Unknown", "unknown expiry")
    }

    static func dynamicMenuActionsAndChecks() throws {
        let connected = try VPNStatusDecoder.decode(statusData(automatic: true))
        let menu = MenuModel.make(status: connected, notificationsEnabled: true, diagnostics: "state=connected interface=utun7", now: date("2026-08-04T12:30:00Z"))
        try expect(menu[.currentState]?.title.contains("Connected") == true, "current state")
        try expect(menu[.expiry]?.title.contains("2026-08-04 12:59:30 UTC") == true, "absolute expiry")
        try expect(menu[.connect]?.isEnabled == false && menu[.disconnect]?.isEnabled == true && menu[.reconnect]?.isEnabled == true, "connected action enablement")
        try expect(menu[.automaticReconnect]?.isChecked == true, "auto checked")
        try expect(menu[.expiryNotifications]?.isChecked == true, "notifications checked")
        try expect(menu[.diagnostics]?.title.contains("password") == false, "diagnostics sanitized")
        try expect(menu[.quit]?.command == nil, "quit has no vpn command")
        let error = try VPNStatusDecoder.decode(statusData(state: .error, expiry: nil, connectedAt: nil, automatic: false, error: "NETWORK_SCRIPT_POSTCONDITION_FAILED"))
        let errorMenu = MenuModel.make(status: error, notificationsEnabled: false, diagnostics: "")
        try expect(errorMenu[.disconnect]?.isEnabled == true, "error repair action enabled")
        try expect(errorMenu[.disconnect]?.title == "Repair and Disable", "error repair action title")
    }

    static func watcherInitialEventAndTick() throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("hyu-watch-\(UUID().uuidString)")
        let statusURL = root.appendingPathComponent("status.json")
        let config = StatusWatcherConfiguration.production(home: URL(fileURLWithPath: NSHomeDirectory()))
        try expect(config.statusPath.path.hasSuffix("Library/Application Support/hyu-openconnect/status.json"), "production path")
        let events = RecordingStatusSink()
        let reader = SequenceStatusReader([.success(try VPNStatusDecoder.decode(statusData())), .failure(StatusProtocolError.invalid("malformed status document")), .success(try VPNStatusDecoder.decode(statusData(expiry: "2026-08-04T13:00:30Z")))])
        let watcher = StatusWatcher(configuration: .default(statusPath: statusURL), reader: reader, sink: events, now: { date("2026-08-04T12:30:00Z") })
        try watcher.initialRead(); try watcher.handleFileEvent(); try watcher.handleCountdownTick()
        try expect(events.presentations.count == 3, "initial event tick")
        try expect(events.presentations[1].primaryText == "Status unavailable", "corrupt safe error")
        try expect(events.presentations[1].detailText.contains("password") == false, "no raw secret")
        try expect(watcher.configuration.usesDirectoryFileEvents && watcher.configuration.pollInterval >= 15 && watcher.configuration.timerLeeway >= 5, "directory events coarse timer")
    }

    static func controlSecurityTimeoutAndErrors() throws {
        let metadata = FakeExecutableMetadata(ownerUID: 0, mode: 0o755, symlink: false, executable: true, parentModes: ["/Library": 0o755, "/Library/Application Support": 0o755, "/Library/Application Support/HYU VPN": 0o755, "/Library/Application Support/HYU VPN/bin": 0o755])
        let runner = FakeProcessRunner(results: [.success(exitCode: 0, stdout: "ok\n", stderr: ""), .failure(.timeout), .success(exitCode: 7, stdout: "password=CANARY", stderr: "raw error")])
        let client = SecureVPNControlClient(metadata: metadata, runner: runner)
        let okResult = try client.run(.connect)
        try expect(okResult.status == .ok, "ok")
        let timeoutResult = try client.run(.disconnect)
        try expect(timeoutResult.status == .timeout, "timeout normalized")
        let exitResult = try client.run(.reconnect)
        try expect(exitResult.errorCode == "CONTROL_EXIT_7", "exit normalized")
        try expect(runner.requests.allSatisfy { !$0.usesShell && $0.executablePath == SecureVPNControlClient.defaultExecutablePath }, "fixed no shell")
        var bad = metadata; bad.symlink = true
        try expectThrows("symlink executable") { _ = try SecureVPNControlClient(metadata: bad, runner: runner).run(.connect) }
    }

    static func notificationPreferenceInjectedReschedule() throws {
        let store = InMemoryPreferenceStore()
        let center = RecordingNotificationClient(granted: true)
        let coordinator = NotificationCoordinator(store: store, client: center)
        let status = try VPNStatusDecoder.decode(statusData())
        try expect(coordinator.isEnabled == false, "off default")
        try coordinator.setEnabled(true, status: status, now: date("2026-08-04T12:00:00Z"))
        try expect(center.authorizationRequests == 1, "requested auth")
        try expect(center.cancelled == NotificationPlanner.stableIdentifiers, "cancel before schedule")
        try expect(center.scheduled.map(\.identifier) == NotificationPlanner.stableIdentifiers, "scheduled stable")
        try coordinator.statusDidChange(try VPNStatusDecoder.decode(statusData(expiry: "2026-08-04T12:20:00Z")), now: date("2026-08-04T12:00:00Z"))
        try expect(center.cancelBatches.count == 2, "reschedule cancels")
        try coordinator.setEnabled(false, status: status, now: date("2026-08-04T12:00:00Z"))
        try expect(center.cancelBatches.count == 3 && store.enabled == false, "disable cancels")
    }

    static func bundleAssembler() throws {
        let root = packageRoot()
        let executable = root.appendingPathComponent(".build/release/HYUVPNMenuApp")
        try expect(FileManager.default.isExecutableFile(atPath: executable.path), "release executable exists")
        let destination = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("hyu-bundle-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: destination) }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = [root.appendingPathComponent("Scripts/assemble-menu-app.sh").path, executable.path, destination.path]
        try process.run(); process.waitUntilExit()
        try expect(process.terminationStatus == 0, "assembler exit")
        let app = destination.appendingPathComponent("HYU VPN.app")
        let plist = app.appendingPathComponent("Contents/Info.plist")
        let binary = app.appendingPathComponent("Contents/MacOS/HYUVPNMenuApp")
        try expect(FileManager.default.isExecutableFile(atPath: binary.path), "bundle executable")
        let info = NSDictionary(contentsOf: plist) as? [String: Any]
        try expect(info?["CFBundleExecutable"] as? String == "HYUVPNMenuApp", "plist executable")
        try expect(info?["CFBundleName"] as? String == "HYU VPN", "plist name")
        try expect(info?["LSUIElement"] as? Bool == true, "lsui")
    }

    static func canonicalProductionStatusPath() throws {
        let config = StatusWatcherConfiguration.production(home: URL(fileURLWithPath: "/Users/alice"))
        try expect(config.statusPath.path == "/Users/alice/Library/Application Support/hyu-openconnect/status.json", "canonical committed supervisor path")
    }

    static func schemaFloatIntegersRejected() throws {
        try expectThrows("schema 1.0 rejected") { _ = try VPNStatusDecoder.decode(Data(String(decoding: statusData(), as: UTF8.self).replacingOccurrences(of: "\"schema_version\":1", with: "\"schema_version\":1.0").utf8)) }
        try expectThrows("schema 1e0 rejected") { _ = try VPNStatusDecoder.decode(Data(String(decoding: statusData(), as: UTF8.self).replacingOccurrences(of: "\"schema_version\":1", with: "\"schema_version\":1e0").utf8)) }
    }

    static func connectedDurationOnlyConnected() throws {
        let now = date("2026-08-04T12:30:00Z")
        for state in VPNConnectionState.allCases where state != .connected {
            let view = MenuPresenter.present(try VPNStatusDecoder.decode(statusData(state: state, expiry: nil, connectedAt: "2026-08-04T12:00:00Z")), now: now)
            try expect(view.connectedDurationText == "", "no connected duration for \(state.rawValue)")
        }
    }

    static func systemRunnerDrainsLargeOutputAndTimeouts() throws {
        let runner = SystemControlProcessRunner()
        let py = "/usr/bin/python3"
        if !FileManager.default.isExecutableFile(atPath: py) { return }
        let big = "import sys; sys.stdout.write('password=CANARY\\n' + 'A'*200000); sys.stderr.write('cookie=CANARY\\n' + 'B'*200000)"
        let large = try runner.run(ProcessLaunchRequest(executablePath: py, arguments: ["-c", big], usesShell: false), timeout: 5, maxOutputBytes: 256)
        guard case .success(let exitCode, let stdout, let stderr) = large else { throw HarnessFailure(description: "large output timed out") }
        try expect(exitCode == 0, "large output child exits")
        try expect(stdout.utf8.count <= 256 && stderr.utf8.count <= 256, "bounded output")
        try expect(!stdout.lowercased().contains("password") && !stderr.lowercased().contains("cookie"), "secret output sanitized")
        let sleepy = try runner.run(ProcessLaunchRequest(executablePath: "/bin/sleep", arguments: ["5"], usesShell: false), timeout: 0.2, maxOutputBytes: 128)
        try expect(sleepy == .failure(.timeout), "timeout killed/reaped")
    }

    static func asyncNotificationsGrantDenialStatusChange() throws {
        let grantedStore = InMemoryPreferenceStore()
        let grantedClient = AsyncRecordingNotificationClient(results: [.success(true)])
        let granted = AsyncNotificationCoordinator(store: grantedStore, client: grantedClient)
        let status = try VPNStatusDecoder.decode(statusData())
        let semaphore = DispatchSemaphore(value: 0)
        granted.setEnabled(true, status: status, now: date("2026-08-04T12:00:00Z")) { result in
            if case .success = result {} else { fatalError("unexpected notification failure") }
            semaphore.signal()
        }
        try expect(semaphore.wait(timeout: .now() + 2) == .success, "async grant completed")
        try expect(grantedStore.enabled == true, "persist only after grant")
        try expect(grantedClient.scheduled.map(\.identifier) == NotificationPlanner.stableIdentifiers, "scheduled after grant")
        granted.statusDidChange(try VPNStatusDecoder.decode(statusData(state: .disabled, expiry: nil, connectedAt: nil)), now: date("2026-08-04T12:00:00Z"))
        try expect(grantedClient.cancelBatches.last == NotificationPlanner.stableIdentifiers && grantedClient.scheduled.isEmpty, "disconnect cancels")
        let deniedStore = InMemoryPreferenceStore()
        let deniedClient = AsyncRecordingNotificationClient(results: [.success(false)])
        let denied = AsyncNotificationCoordinator(store: deniedStore, client: deniedClient)
        let deniedSem = DispatchSemaphore(value: 0)
        denied.setEnabled(true, status: status, now: date("2026-08-04T12:00:00Z")) { _ in deniedSem.signal() }
        try expect(deniedSem.wait(timeout: .now() + 2) == .success, "async denial completed")
        try expect(deniedStore.enabled == false && deniedClient.scheduled.isEmpty, "denial not persisted")
    }

    static func realDispatchWatcherAtomicReplaceAndTick() throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("hyu-real-watch-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        let statusURL = root.appendingPathComponent("status.json")
        try atomicWrite(statusData(expiry: "2026-08-04T13:00:00Z"), to: statusURL)
        let sink = SemaphoreStatusSink(expected: 3)
        let config = StatusWatcherConfiguration(statusPath: statusURL, usesFileSystemEvents: true, usesDirectoryFileEvents: true, pollInterval: 0.4, timerLeeway: 0.1, allowedReadPurpose: .sanitizedStatusOnly)
        let watcher = StatusWatcher(configuration: config, reader: FileStatusReader(url: statusURL), sink: sink, now: { date("2026-08-04T12:30:00Z") })
        try watcher.start(queue: DispatchQueue(label: "hyu.real.watch"))
        try atomicWrite(statusData(expiry: "2026-08-04T13:01:00Z"), to: statusURL)
        try expect(sink.wait(seconds: 3), "initial atomic replace tick observed")
        watcher.stop()
        try expect(sink.presentations.contains { $0.statusItemTitle == "31m" }, "atomic replace updated countdown")
    }

    static func atomicWrite(_ data: Data, to url: URL) throws {
        let tmp = url.deletingLastPathComponent().appendingPathComponent(".status.\(UUID().uuidString).tmp")
        try data.write(to: tmp)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tmp.path)
        _ = try FileManager.default.replaceItemAt(url, withItemAt: tmp, backupItemName: nil, options: [])
    }


    static func unavailableStatusCancelsNotifications() throws {
        let store = InMemoryPreferenceStore(); store.enabled = true
        let client = AsyncRecordingNotificationClient(results: [])
        let coordinator = AsyncNotificationCoordinator(store: store, client: client)
        coordinator.statusUnavailable()
        try expect(client.cancelBatches.last == NotificationPlanner.stableIdentifiers, "unavailable cancels stable notifications")
    }

    static func notificationScheduleFailureCompletesOnce() throws {
        let store = InMemoryPreferenceStore()
        let client = AsyncRecordingNotificationClient(results: [.success(true)], scheduleResults: [.failure])
        let coordinator = AsyncNotificationCoordinator(store: store, client: client)
        let done = DispatchSemaphore(value: 0)
        let completionBox = CompletionBox()
        coordinator.setEnabled(true, status: try VPNStatusDecoder.decode(statusData()), now: date("2026-08-04T12:00:00Z")) { result in
            completionBox.record(result)
            done.signal()
        }
        try expect(done.wait(timeout: .now() + 2) == .success, "schedule failure returned")
        let count = completionBox.count; let sawFailure = completionBox.failed
        try expect(count == 1 && sawFailure, "completion exactly once failure")
        try expect(store.enabled == false, "not persisted after schedule failure")
        try expect(client.cancelBatches.last == NotificationPlanner.stableIdentifiers, "partial schedule cancelled")
    }

    static func jsonDecoderIntTokenProof() throws {
        struct Probe: Decodable { let schema_version: Int }
        let decoder = JSONDecoder()
        _ = try decoder.decode(Probe.self, from: Data(#"{"schema_versio\u006e":1}"#.utf8))
        _ = try decoder.decode(Probe.self, from: Data(#"{"schema_versio\u006e":1.0}"#.utf8))
        _ = try decoder.decode(Probe.self, from: Data(#"{"schema_versio\u006e":1e0}"#.utf8))
        _ = try VPNStatusDecoder.decode(Data(String(decoding: statusData(), as: UTF8.self).replacingOccurrences(of: "\"schema_version\"", with: "\"schema_versio\\u006e\"").utf8))
        try expectThrows("escaped float rejected") { _ = try VPNStatusDecoder.decode(Data(String(decoding: statusData(), as: UTF8.self).replacingOccurrences(of: "\"schema_version\":1", with: "\"schema_versio\\u006e\":1.0").utf8)) }
    }

    static func processGroupTimeoutKillsDescendantAndDiscardsOutput() throws {
        let py = "/usr/bin/python3"; if !FileManager.default.isExecutableFile(atPath: py) { return }
        let pidFile = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("hyu-child-\(UUID().uuidString).pid")
        let script = "import subprocess,sys,time,os; c=subprocess.Popen(['/bin/sleep','20']); open('\(pidFile.path)','w').write(str(c.pid)); sys.stdout.write('pass'); sys.stdout.flush(); sys.stdout.write('word=CANARY\\n'+'A'*200000); sys.stderr.write('cook'); sys.stderr.flush(); sys.stderr.write('ie=CANARY\\n'+'B'*200000); time.sleep(20)"
        let runner = SystemControlProcessRunner()
        let result = try runner.run(ProcessLaunchRequest(executablePath: py, arguments: ["-c", script], usesShell: false), timeout: 0.5, maxOutputBytes: 256)
        try expect(result == .failure(.timeout), "process group timeout")
        let childPID = Int32((try? String(contentsOf: pidFile).trimmingCharacters(in: .whitespacesAndNewlines)).flatMap(Int.init) ?? -1)
        if childPID > 0 { Thread.sleep(forTimeInterval: 0.3); try expect(kill(childPID, 0) == -1 && errno == ESRCH, "descendant killed/reaped") }
        let output = try runner.run(ProcessLaunchRequest(executablePath: py, arguments: ["-c", "import sys; sys.stdout.write('password=CANARY'); sys.stderr.write('cookie=CANARY')"], usesShell: false), timeout: 5, maxOutputBytes: 256)
        guard case .success(_, let stdout, let stderr) = output else { throw HarnessFailure(description: "output child failed") }
        try expect(stdout.isEmpty && stderr.isEmpty, "stdout stderr discarded")
    }

    static func duplicateJSONKeysRejectedBeforeCollapse() throws {
        let base = String(decoding: statusData(), as: UTF8.self)
        let duplicatePlain = base.replacingOccurrences(of: "\"state\":\"connected\"", with: "\"state\":\"connected\",\"state\":\"disabled\"")
        try expectThrows("duplicate plain key") { _ = try VPNStatusDecoder.decode(Data(duplicatePlain.utf8)) }
        let duplicateEscaped = base.replacingOccurrences(of: "\"schema_version\":1", with: "\"schema_version\":1,\"schema\\u005fversion\":1")
        try expectThrows("duplicate escaped key") { _ = try VPNStatusDecoder.decode(Data(duplicateEscaped.utf8)) }
        let duplicateUnknown = base.replacingOccurrences(of: "\"backend_build_version\":\"2026.08.04+menubar\"", with: "\"backend_build_version\":\"2026.08.04+menubar\",\"extra\":1,\"extra\":2")
        try expectThrows("duplicate unknown key") { _ = try VPNStatusDecoder.decode(Data(duplicateUnknown.utf8)) }
    }

    static func unavailableStatusClearsStaleCountdown() throws {
        let events = RecordingStatusSink()
        let reader = SequenceStatusReader([.success(try VPNStatusDecoder.decode(statusData())), .failure(StatusProtocolError.invalid("malformed status document")), .failure(StatusProtocolError.invalid("still missing"))])
        let watcher = StatusWatcher(configuration: .default(statusPath: URL(fileURLWithPath: "/tmp/status.json")), reader: reader, sink: events, now: { date("2026-08-04T12:30:00Z") })
        try watcher.initialRead()
        try watcher.handleFileEvent()
        try watcher.handleCountdownTick()
        try expect(events.presentations.count == 3, "initial error tick")
        try expect(events.presentations[1].primaryText == "Status unavailable", "event unavailable")
        try expect(events.presentations[2].primaryText == "Status unavailable", "tick stays unavailable")
        try expect(events.presentations[2].statusItemTitle.isEmpty, "no stale countdown title")
    }

    static func directChildSuccessWithOpenDescendantPipeFails() throws {
        let py = "/usr/bin/python3"; if !FileManager.default.isExecutableFile(atPath: py) { return }
        let pidFile = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("hyu-orphan-\(UUID().uuidString).pid")
        let script = #"""
import os,sys,time
pid=os.fork()
if pid:
    open('\#(pidFile.path)','w').write(str(pid))
    sys.exit(0)
time.sleep(20)
"""#
        let runner = SystemControlProcessRunner()
        let result = try runner.run(ProcessLaunchRequest(executablePath: py, arguments: ["-c", script], usesShell: false), timeout: 3, maxOutputBytes: 128)
        let childPID = Int32((try? String(contentsOf: pidFile).trimmingCharacters(in: .whitespacesAndNewlines)).flatMap(Int.init) ?? -1)
        if childPID > 0, result != .failure(.timeout) { kill(childPID, SIGKILL) }
        try expect(result == .failure(.timeout), "open descendant pipe cannot be success")
        if childPID > 0 { Thread.sleep(forTimeInterval: 0.3); try expect(kill(childPID, 0) == -1 && errno == ESRCH, "orphan descendant killed") }
    }

    static func termIgnoringDescendantIsKilled() throws {
        let py = "/usr/bin/python3"; if !FileManager.default.isExecutableFile(atPath: py) { return }
        let pidFile = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("hyu-ignore-\(UUID().uuidString).pid")
        let script = #"""
import os,signal,sys,time
pid=os.fork()
if pid:
    open('\#(pidFile.path)','w').write(str(pid))
    sys.exit(0)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
time.sleep(20)
"""#
        let runner = SystemControlProcessRunner()
        let result = try runner.run(ProcessLaunchRequest(executablePath: py, arguments: ["-c", script], usesShell: false), timeout: 3, maxOutputBytes: 128)
        try expect(result == .failure(.timeout), "TERM-ignoring descendant escalated")
        let childPID = Int32((try? String(contentsOf: pidFile).trimmingCharacters(in: .whitespacesAndNewlines)).flatMap(Int.init) ?? -1)
        if childPID > 0 { Thread.sleep(forTimeInterval: 0.3); try expect(kill(childPID, 0) == -1 && errno == ESRCH, "SIGKILL removed descendant") }
    }

    static func syntheticECHILDIsNeverSuccess() throws {
        let runner = SystemControlProcessRunner(waiter: SyntheticECHILDWaiter())
        let result = try runner.run(ProcessLaunchRequest(executablePath: "/bin/true", arguments: [], usesShell: false), timeout: 1, maxOutputBytes: 128)
        try expect(result == .failure(.launchFailed), "ECHILD normalized failure")
    }

    static func secondPipeFailureClosesFirstPipe() throws {
        let pipeFactory = CountingPipeFactory(failOnCall: 2)
        let runner = SystemControlProcessRunner(pipeFactory: pipeFactory)
        let result = try runner.run(ProcessLaunchRequest(executablePath: "/bin/true", arguments: [], usesShell: false), timeout: 1, maxOutputBytes: 128)
        try expect(result == .failure(.launchFailed), "second pipe failure is launch failure")
        try expect(pipeFactory.openDescriptors.isEmpty, "first pipe descriptors closed on partial failure")
    }

    static func notificationFailureNormalizedDiagnostic() throws {
        let diagnostic = NotificationFailureDiagnostic.normalizedCode(for: StatusProtocolError.invalid("password=CANARY schedule failed"))
        try expect(diagnostic == "NOTIFICATION_SCHEDULE_FAILED", "normalized schedule diagnostic")
        try expect(!diagnostic.contains("CANARY") && !diagnostic.lowercased().contains("password"), "no secret diagnostic")
    }

    static func controlRunnerUsesFixedMinimalEnvironment() throws {
        let env = SystemControlProcessRunner.fixedEnvironment()
        try expect(env.contains("PATH=/usr/bin:/bin:/usr/sbin:/sbin"), "minimal path")
        try expect(env.contains("LC_ALL=C"), "stable locale")
        try expect(!env.contains { $0.contains("CANARY") || $0.hasPrefix("HOME=") || $0.hasPrefix("USER=") || $0.hasPrefix("SSH_AUTH_SOCK=") }, "no inherited or secret env")
    }

    static func sentinelParentFDIsNotInherited() throws {
        let py = "/usr/bin/python3"; if !FileManager.default.isExecutableFile(atPath: py) { return }
        let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("hyu-fd-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let sentinel = root.appendingPathComponent("sentinel")
        let marker = root.appendingPathComponent("leaked")
        let fd = open(sentinel.path, O_CREAT | O_RDWR, 0o600)
        try expect(fd >= 0, "sentinel fd opened")
        defer { Darwin.close(fd) }
        let script = """
import os,sys
fd=int(sys.argv[1])
marker=sys.argv[2]
try:
    os.fstat(fd)
    open(marker, 'w').write('leaked')
except OSError:
    pass
"""
        let runner = SystemControlProcessRunner()
        let result = try runner.run(ProcessLaunchRequest(executablePath: py, arguments: ["-c", script, "\(fd)", marker.path], usesShell: false), timeout: 3, maxOutputBytes: 128)
        guard case .success(let code, _, _) = result, code == 0 else { throw HarnessFailure(description: "fd sentinel child failed") }
        try expect(!FileManager.default.fileExists(atPath: marker.path), "unrelated parent fd was not inherited")
    }

    static func termIgnoringDescendantClosesFDsStillKilled() throws {
        let py = "/usr/bin/python3"; if !FileManager.default.isExecutableFile(atPath: py) { return }
        let pidFile = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("hyu-closefds-\(UUID().uuidString).pid")
        let script = #"""
import os,signal,sys,time
pid=os.fork()
if pid:
    open('\#(pidFile.path)','w').write(str(pid))
    sys.exit(0)
os.close(1)
os.close(2)
signal.signal(signal.SIGTERM, signal.SIG_IGN)
time.sleep(20)
"""#
        let runner = SystemControlProcessRunner()
        let result = try runner.run(ProcessLaunchRequest(executablePath: py, arguments: ["-c", script], usesShell: false), timeout: 3, maxOutputBytes: 128)
        let childPID = Int32((try? String(contentsOf: pidFile).trimmingCharacters(in: .whitespacesAndNewlines)).flatMap(Int.init) ?? -1)
        if childPID > 0, result != .failure(.timeout) { kill(childPID, SIGKILL) }
        try expect(result == .failure(.timeout), "closed-fd TERM-ignoring descendant cannot be success")
        if childPID > 0 { Thread.sleep(forTimeInterval: 0.3); try expect(kill(childPID, 0) == -1 && errno == ESRCH, "closed-fd descendant killed") }
    }

    static func cleanupReapIsBounded() throws {
        let waiter = BlockingOptionsZeroWaiter()
        let runner = SystemControlProcessRunner(waiter: waiter)
        let start = Date()
        let result = try runner.run(ProcessLaunchRequest(executablePath: "/bin/sleep", arguments: ["20"], usesShell: false), timeout: 0.05, maxOutputBytes: 128)
        let elapsed = Date().timeIntervalSince(start)
        try expect(result == .failure(.timeout), "timeout returned")
        try expect(elapsed < 1.5, "cleanup reap bounded")
        try expect(waiter.blockingWaitCalls == 0, "no unbounded waitpid options 0")
    }

    static func statusChangeNotificationFailureCompletesNormalized() throws {
        let store = InMemoryPreferenceStore(); store.enabled = true
        let client = AsyncRecordingNotificationClient(results: [], scheduleResults: [.failure])
        let coordinator = AsyncNotificationCoordinator(store: store, client: client)
        let done = DispatchSemaphore(value: 0)
        let completionBox = CompletionBox()
        coordinator.statusDidChange(try VPNStatusDecoder.decode(statusData()), now: date("2026-08-04T12:00:00Z")) { result in completionBox.record(result); done.signal() }
        try expect(done.wait(timeout: .now() + 2) == .success, "status change failure completed")
        try expect(completionBox.count == 1 && completionBox.failed, "status change completion once failure")
        try expect(completionBox.diagnostic == "NOTIFICATION_SCHEDULE_FAILED", "status change normalized diagnostic")
        try expect(store.enabled == false, "status change failure disables notifications")
        try expect(client.cancelBatches.last == NotificationPlanner.stableIdentifiers, "status change failure cancels notifications")
    }

    static func menuCoreHasNoDirectFoundationProcessRunSurface() throws {
        let root = packageRoot().deletingLastPathComponent()
        let source = try String(contentsOf: root.appendingPathComponent("macos/Sources/HYUVPNMenuCore/MenuCore.swift"))
        try expect(!source.contains("Process()"), "MenuCore must not create Foundation.Process")
        try expect(!source.contains("process.run()"), "MenuCore must not expose direct Process.run bypass")
    }

    static func spawnSetupSeamIsNotPublicProductionAPI() throws {
        let root = packageRoot().deletingLastPathComponent()
        let source = try String(contentsOf: root.appendingPathComponent("macos/Sources/HYUVPNMenuCore/MenuCore.swift"))
        try expect(!source.contains("public protocol SpawnSetupManaging"), "spawn setup seam is not public")
        try expect(!source.contains("public final class SystemSpawnSetupManager"), "spawn setup manager is not public")
        try expect(!source.contains("public init(pipeFactory: PipeCreating = SystemPipeFactory(), waiter: ChildProcessWaiting = SystemChildProcessWaiter(), spawnSetup:"), "public runner init cannot accept spawn setup")
        try expect(source.contains("public convenience init(pipeFactory: PipeCreating = SystemPipeFactory(), waiter: ChildProcessWaiting = SystemChildProcessWaiter())"), "public runner init uses fixed system setup")
        try expect(source.contains("defer { if actionsInitialized { posix_spawn_file_actions_destroy(&actions) } }"), "actions cleanup registered independently")
        try expect(source.contains("defer { if attrsInitialized { posix_spawnattr_destroy(&attrs) } }"), "attrs cleanup registered independently")
    }

    static func nearExpiryThresholdsAreNotRetroactive() throws {
        let status = try VPNStatusDecoder.decode(statusData(expiry: "2026-08-04T12:59:30Z"))
        let plan = NotificationPlanner.plan(for: status, now: date("2026-08-04T12:58:45Z"), enabled: true)
        try expect(plan.requests.isEmpty, "no immediate warning after threshold passed")
    }

}

struct FakeMetadata: FileMetadataProviding {
    var ownerUID: uid_t; var fileMode: mode_t; var parentMode: mode_t; var isSymlink: Bool; var isRegular: Bool
    func metadata(for path: String) throws -> FileMetadata { FileMetadata(ownerUID: ownerUID, mode: path.hasSuffix("status.json") ? fileMode : parentMode, isSymlink: isSymlink, isRegularFile: isRegular, isExecutable: true) }
}
final class RecordingStatusSink: StatusUpdateSink { var presentations: [MenuPresentation] = []; func apply(_ presentation: MenuPresentation) { presentations.append(presentation) } }
final class SequenceStatusReader: StatusReading { var results: [Result<VPNStatus, Error>]; init(_ results: [Result<VPNStatus, Error>]) { self.results = results }; func readStatus() throws -> VPNStatus { try results.removeFirst().get() } }
struct FakeExecutableMetadata: ExecutableMetadataProviding { var ownerUID: uid_t; var mode: mode_t; var symlink: Bool; var executable: Bool; var parentModes: [String: mode_t]; func metadata(for path: String) throws -> FileMetadata { FileMetadata(ownerUID: path == SecureVPNControlClient.defaultExecutablePath ? ownerUID : uid_t(0), mode: parentModes[path] ?? mode, isSymlink: symlink, isRegularFile: true, isExecutable: executable) } }
final class FakeProcessRunner: ControlProcessRunning { var results: [ControlProcessOutcome]; var requests: [ProcessLaunchRequest] = []; init(results: [ControlProcessOutcome]) { self.results = results }; func run(_ request: ProcessLaunchRequest, timeout: TimeInterval, maxOutputBytes: Int) throws -> ControlProcessOutcome { requests.append(request); return results.removeFirst() } }
final class InMemoryPreferenceStore: NotificationPreferenceStoring, @unchecked Sendable { var enabled: Bool?; func read() -> Bool { enabled ?? false }; func write(_ value: Bool) { enabled = value } }
final class RecordingNotificationClient: NotificationClient { let granted: Bool; var authorizationRequests = 0; var cancelBatches: [[String]] = []; var scheduled: [PlannedNotification] = []; init(granted: Bool) { self.granted = granted }; func requestAuthorization() -> Bool { authorizationRequests += 1; return granted }; func cancel(_ identifiers: [String]) { cancelBatches.append(identifiers) }; func schedule(_ requests: [PlannedNotification]) { scheduled = requests }; var cancelled: [String] { cancelBatches.last ?? [] } }


final class SemaphoreStatusSink: StatusUpdateSink {
    private let lock = NSLock(); private let semaphore: DispatchSemaphore; private let expected: Int; private(set) var presentations: [MenuPresentation] = []
    init(expected: Int) { self.expected = expected; self.semaphore = DispatchSemaphore(value: 0) }
    func apply(_ presentation: MenuPresentation) { lock.lock(); presentations.append(presentation); let shouldSignal = presentations.count >= expected; lock.unlock(); if shouldSignal { semaphore.signal() } }
    func wait(seconds: TimeInterval) -> Bool { semaphore.wait(timeout: .now() + seconds) == .success }
}

enum AsyncNotificationResult { case success(Bool), failure }
final class AsyncRecordingNotificationClient: AsyncNotificationClient, @unchecked Sendable {
    var results: [AsyncNotificationResult]; var scheduleResults: [AsyncNotificationResult]; var cancelBatches: [[String]] = []; var scheduled: [PlannedNotification] = []
    init(results: [AsyncNotificationResult], scheduleResults: [AsyncNotificationResult] = []) { self.results = results; self.scheduleResults = scheduleResults }
    func requestAuthorization(completion: @escaping @Sendable (Result<Bool, Error>) -> Void) { let result = results.removeFirst(); DispatchQueue.global().async { switch result { case .success(let value): completion(.success(value)); case .failure: completion(.failure(StatusProtocolError.invalid("denied"))) } } }
    func cancel(_ identifiers: [String]) { cancelBatches.append(identifiers); scheduled = [] }
    func schedule(_ requests: [PlannedNotification], completion: @escaping @Sendable (Result<Void, Error>) -> Void) { scheduled = requests; let result = scheduleResults.isEmpty ? .success(true) : scheduleResults.removeFirst(); DispatchQueue.global().async { switch result { case .success: completion(.success(())); case .failure: completion(.failure(StatusProtocolError.invalid("schedule failed"))) } } }
}

final class CompletionBox: @unchecked Sendable {
    private let lock = NSLock(); private var _count = 0; private var _failed = false; private var _diagnostic = ""
    func record(_ result: Result<Void, Error>) { lock.lock(); _count += 1; if case .failure(let error) = result { _failed = true; _diagnostic = String(describing: error) }; lock.unlock() }
    var count: Int { lock.lock(); defer { lock.unlock() }; return _count }
    var failed: Bool { lock.lock(); defer { lock.unlock() }; return _failed }
    var diagnostic: String { lock.lock(); defer { lock.unlock() }; return _diagnostic }
}


final class SyntheticECHILDWaiter: ChildProcessWaiting, @unchecked Sendable {
    private var reaped = false
    func wait(pid: pid_t, status: inout Int32, options: Int32) -> pid_t {
        if !reaped { var realStatus: Int32 = 0; _ = Darwin.waitpid(pid, &realStatus, 0); reaped = true }
        errno = ECHILD
        return -1
    }
}

final class CountingPipeFactory: PipeCreating, @unchecked Sendable {
    let failOnCall: Int
    private(set) var calls = 0
    private(set) var openDescriptors: Set<Int32> = []
    init(failOnCall: Int) { self.failOnCall = failOnCall }
    func makePipe(_ fds: inout [Int32]) -> Int32 {
        calls += 1
        if calls == failOnCall { errno = EMFILE; return -1 }
        let result = pipe(&fds)
        if result == 0 { openDescriptors.insert(fds[0]); openDescriptors.insert(fds[1]) }
        return result
    }
    func close(_ fd: Int32) { openDescriptors.remove(fd); Darwin.close(fd) }
}


final class BlockingOptionsZeroWaiter: ChildProcessWaiting, @unchecked Sendable {
    private let lock = NSLock()
    private var _blockingWaitCalls = 0
    var blockingWaitCalls: Int { lock.lock(); defer { lock.unlock() }; return _blockingWaitCalls }
    func wait(pid: pid_t, status: inout Int32, options: Int32) -> pid_t {
        if options == 0 { lock.lock(); _blockingWaitCalls += 1; lock.unlock(); Thread.sleep(forTimeInterval: 2.0) }
        return Darwin.waitpid(pid, &status, options)
    }
}
