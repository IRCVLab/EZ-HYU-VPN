import AppKit
import Foundation
import Darwin
import HYUVPNMenuCore
import HYUVPNMenuAppSupport

struct HarnessFailure: Error, CustomStringConvertible { let description: String }
final class LockedResetState: @unchecked Sendable { let lock = NSLock(); var completed = false; var error: Error? }
func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws { if !condition() { throw HarnessFailure(description: message) } }
func expectThrows(_ message: String, _ body: () throws -> Void) throws { do { try body(); throw HarnessFailure(description: "expected throw: \(message)") } catch is HarnessFailure { throw HarnessFailure(description: "expected throw: \(message)") } catch {} }
func requireIndex(of needle: String, in haystack: String, message: String) throws -> String.Index {
    guard let index = haystack.range(of: needle)?.lowerBound else { throw HarnessFailure(description: message) }
    return index
}

@main struct Harness {
    static func main() {
        do {
            if ProcessInfo.processInfo.environment["HYU_MENU_HARNESS_FORCE_FAILURE"] == "1" { throw HarnessFailure(description: "forced failure") }
            let tests: [(String, () throws -> Void)] = [
                ("strict-status-all-states-and-corrupt", strictStatusAllStates),
                ("rust-status-fractional-seconds", rustStatusFractionalSeconds),
                ("status-file-security", statusFileSecurity),
                ("presentation-symbols-and-title-rule", presentationSymbolsAndTitleRule),
                ("dynamic-menu-actions-and-checks", dynamicMenuActionsAndChecks),
                ("primary-action-disabled-transient-states", primaryActionDisabledTransientStates),
                ("login-item-state-projections-and-actions", loginItemStateProjectionsAndActions),
                ("login-item-error-normalization", loginItemErrorNormalization),
                ("login-item-runtime-truth-after-operation-failure", loginItemRuntimeTruthAfterOperationFailure),
                ("login-item-first-launch-policy", loginItemFirstLaunchPolicy),
                ("live-menu-includes-native-login-item-control", liveMenuIncludesNativeLoginItemControl),
                                ("bootstrap-splits-appkit-and-argument-gate", bootstrapSplitsAppKitAndArgumentGate),
                ("control-tower-menu-copy-and-icon-contract", controlTowerMenuCopyAndIconContract),
                ("lifecycle-coordinator-runtime", lifecycleCoordinatorRuntime),
                ("safe-quit-without-diagnostics-contract", safeQuitWithoutDiagnosticsContract),
                ("watcher-initial-event-and-tick", watcherInitialEventAndTick),
                ("bundle-assembler-produces-lsuielement-app", bundleAssembler),
                ("canonical-production-status-path", canonicalProductionStatusPath),
                ("schema-float-integers-rejected", schemaFloatIntegersRejected),
                                ("real-dispatch-watcher-atomic-replace-and-tick", realDispatchWatcherAtomicReplaceAndTick),
                ("json-decoder-int-token-proof", jsonDecoderIntTokenProof),
                                ("duplicate-json-keys-rejected-before-collapse", duplicateJSONKeysRejectedBeforeCollapse),
                ("unavailable-status-clears-stale-countdown", unavailableStatusClearsStaleCountdown),
                                                                                                                                                ("menu-core-has-no-direct-foundation-process-run-surface", menuCoreHasNoDirectFoundationProcessRunSurface),
                                ("control-tower-credential-validation", controlTowerCredentialValidation),
                ("control-tower-transaction-policy-gate", controlTowerTransactionPolicyGate),
                ("native-credential-reset-source-contract", nativeCredentialResetSourceContract),
                ("encrypted-credential-and-totp-source-contract", encryptedCredentialAndTOTPSourceContract),
                ("totp-resetter-runtime-secure-delete-and-missing-state", totpResetterRuntimeSecureDeleteAndMissingState),
                ("totp-resetter-runtime-unsafe-metadata-fails-closed", totpResetterRuntimeUnsafeMetadataFailsClosed),
                ("totp-resetter-runtime-flock-coordination", totpResetterRuntimeFlockCoordination),
                ("encrypted-credential-store-runtime", encryptedCredentialStoreRuntime),
                ("menu-totp-provider-and-clipboard-policy-runtime", menuTOTPProviderAndClipboardPolicyRuntime),
                ("rust-ipc-client-runtime-fixtures-and-request-ids", rustIPCClientRuntimeFixturesAndRequestIDs),
                ("passive-otp-preview-polling-preserves-snapshot-countdown-copy", passiveOTPPreviewPollingPreservesSnapshotCountdownCopy),
                ("service-refresh-coordinator-drops-stale-forced-results", serviceRefreshCoordinatorDropsStaleForcedResults),
                ("native-credential-reader-closed-command-surface", nativeCredentialReaderClosedCommandSurface),
                ("credential-reset-controller-runtime-behavior", credentialResetControllerRuntimeBehavior),
                ("credential-reset-lifecycle-runtime", credentialResetLifecycleRuntime),
                ("update-feed-and-checker-runtime", updateFeedAndCheckerRuntime),
                ("update-menu-source-contract", updateMenuSourceContract)
            ]
            for (name, test) in tests { print("RUN \(name)"); try test(); print("PASS \(name)") }
            print("HARNESS PASS \(tests.count) tests")
        } catch { FileHandle.standardError.write(Data("HARNESS FAIL: \(error)\n".utf8)); exit(1) }
    }


    typealias FakeLoginItemStatus = LoginItemPlatformStatus

    enum FakeLoginItemEvent: Equatable { case register, unregister, openSettings }

    final class FakeLoginItemProbe {
        var events: [FakeLoginItemEvent] = []
        var status: LoginItemPlatformStatus?
    }

    struct FakeLoginItemPlatform: LoginItemPlatforming {
        var currentStatus: LoginItemPlatformStatus
        var registerError: String? = nil
        var unregisterError: String? = nil
        var probe = FakeLoginItemProbe()

        mutating func status() -> LoginItemPlatformStatus { probe.status ?? currentStatus }

        mutating func register() throws {
            probe.events.append(.register)
            if let registerError { throw LoginItemControllerError.unavailable(code: registerError) }
            currentStatus = .enabled
        }

        mutating func unregister() throws {
            probe.events.append(.unregister)
            if let unregisterError { throw LoginItemControllerError.unavailable(code: unregisterError) }
            currentStatus = .notRegistered
        }

        mutating func openSystemSettingsLoginItems() { probe.events.append(.openSettings) }
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

    static func rustStatusFractionalSeconds() throws {
        let productionTimestamp = "2026-08-13T05:20:45.063847Z"
        var raw = String(decoding: statusData(state: .disabled, expiry: nil, connectedAt: nil, automatic: false), as: UTF8.self)
        raw = raw.replacingOccurrences(of: "2026-08-04T12:00:01Z", with: productionTimestamp)
        let decoded = try VPNStatusDecoder.decode(Data(raw.utf8))
        try expect(decoded.state == .disabled, "Rust status with fractional seconds is accepted")
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
            let status = try VPNStatusDecoder.decode(statusData(state: state, expiry: state == .connected ? "2026-08-04T12:59:30Z" : nil, connectedAt: state == .connected ? "2026-08-04T12:00:00Z" : nil))
            let view = MenuPresenter.present(status)
            try expect(view.statusItemTitle.isEmpty, "empty status title \(state.rawValue)")
            try expect(view.symbolName == symbol, "symbol \(state.rawValue)")
            try expect(view.primaryText == title, "title \(state.rawValue)")
        }
    }

    static func dynamicMenuActionsAndChecks() throws {
        let connected = try VPNStatusDecoder.decode(statusData(automatic: true))
        let menu = MenuModel.make(status: connected, launchAtLogin: .enabled)
        try expect(menu[.currentState]?.title.contains("Connected") == true, "current state")
        try expect(menu[.primaryConnection]?.title == "Reconnect", "connected primary title")
        try expect(menu[.primaryConnection]?.command == .reconnect, "connected primary command")
        try expect(menu[.disconnect]?.isEnabled == true, "connected disconnect enabled")
        try expect(menu[.launchAtLogin]?.isChecked == true, "launch checked")
        try expect(MenuAction.allCases == [.currentState, .primaryConnection, .disconnect, .resetCredentials, .launchAtLogin, .quit], "menu excludes diagnostics")
        let disabled = MenuModel.make(status: try VPNStatusDecoder.decode(statusData(state: .disabled, expiry: nil, connectedAt: nil)), launchAtLogin: .disabled)
        try expect(disabled[.primaryConnection]?.title == "Connect", "disabled primary title")
        try expect(disabled[.primaryConnection]?.command == .connect, "disabled primary command")
        try expect(disabled[.disconnect]?.isEnabled == false, "disabled disconnect disabled")
        let error = MenuModel.make(status: try VPNStatusDecoder.decode(statusData(state: .error, expiry: nil, connectedAt: nil)), launchAtLogin: .disabled)
        try expect(error[.primaryConnection]?.title == "Reconnect", "error primary title")
        try expect(error[.primaryConnection]?.isEnabled == true, "error primary enabled")
        try expect(error[.primaryConnection]?.command == .reconnect, "error primary command")
        let backoff = MenuModel.make(status: try VPNStatusDecoder.decode(statusData(state: .backoff, expiry: nil, connectedAt: nil)), launchAtLogin: .disabled)
        try expect(backoff[.primaryConnection]?.title == "Reconnect Now", "backoff primary title")
        try expect(backoff[.primaryConnection]?.command == .reconnect, "backoff primary command")
    }

    static func updateFeedAndCheckerRuntime() throws {
        let policy = UpdatePolicy(
            currentVersion: SemanticVersion("0.1.1")!,
            feedURL: URL(string: "https://raw.githubusercontent.com/IRCVLab/EZ-HYU-VPN/main/update.json")!,
            allowedReleaseHost: "github.com",
            allowedReleasePathPrefix: "/IRCVLab/EZ-HYU-VPN/releases/"
        )
        let feed = Data(#"{"schema_version":1,"version":"0.1.2","release_url":"https://github.com/IRCVLab/EZ-HYU-VPN/releases/tag/v0.1.2"}"#.utf8)
        let offer = try UpdateFeedDecoder.offer(from: feed, policy: policy)
        try expect(offer?.version.description == "0.1.2", "newer semantic version offered")
        try expect(SemanticVersion("0.10.0")! > SemanticVersion("0.9.9")!, "semantic components compare numerically")
        for invalidVersion in ["1", "1.2", "v1.2.3", "01.2.3", "1.2.3-beta"] {
            try expect(SemanticVersion(invalidVersion) == nil, "strict semantic version rejects \(invalidVersion)")
        }
        let equalFeed = Data(#"{"schema_version":1,"version":"0.1.1","release_url":"https://github.com/IRCVLab/EZ-HYU-VPN/releases/tag/v0.1.1"}"#.utf8)
        let equalOffer = try UpdateFeedDecoder.offer(from: equalFeed, policy: policy)
        try expect(equalOffer == nil, "equal version suppressed")
        for malformed in [
            Data(repeating: 0x20, count: UpdateFeedDecoder.maxBytes + 1),
            Data(#"{"schema_version":1,"version":"0.1.2"}"#.utf8),
            Data(#"{"schema_version":1,"version":"0.1.2","release_url":"https://github.com/IRCVLab/EZ-HYU-VPN/releases/tag/v0.1.2","extra":true}"#.utf8),
            Data(#"{"schema_version":1,"schema_version":1,"version":"0.1.2","release_url":"https://github.com/IRCVLab/EZ-HYU-VPN/releases/tag/v0.1.2"}"#.utf8),
            Data(#"{"schema_version":1.0,"version":"0.1.2","release_url":"https://github.com/IRCVLab/EZ-HYU-VPN/releases/tag/v0.1.2"}"#.utf8),
            Data(#"{"schema_version":true,"version":"0.1.2","release_url":"https://github.com/IRCVLab/EZ-HYU-VPN/releases/tag/v0.1.2"}"#.utf8),
            Data(#"{"schema_version":1,"version":"0.1.2","release_url":"http://github.com/IRCVLab/EZ-HYU-VPN/releases/tag/v0.1.2"}"#.utf8),
            Data(#"{"schema_version":1,"version":"0.1.2","release_url":"https://evil.example/IRCVLab/EZ-HYU-VPN/releases/tag/v0.1.2"}"#.utf8),
            Data(#"{"schema_version":1,"version":"0.1.2","release_url":"https://github.com/other/project/releases/tag/v0.1.2"}"#.utf8),
        ] {
            try expectThrows("strict malformed update feed") { _ = try UpdateFeedDecoder.offer(from: malformed, policy: policy) }
        }

        var loadCount = 0
        var finish: ((Result<Data, Error>) -> Void)?
        let checker = HTTPSUpdateChecker(policy: policy) { _, completion in loadCount += 1; finish = completion }
        var offers: [UpdateOffer?] = []
        checker.check { offers.append($0) }
        checker.check { offers.append($0) }
        try expect(loadCount == 1, "concurrent checks coalesce into one load")
        finish?(.success(feed))
        try expect(offers.count == 2 && offers.allSatisfy { $0?.version.description == "0.1.2" }, "coalesced checks receive one validated offer")

        let failing = HTTPSUpdateChecker(policy: policy) { _, completion in completion(.failure(UpdateCheckError.invalidFeed)) }
        var failureCalled = false
        failing.check { failureCalled = true; try? expect($0 == nil, "loader failure is silent nil offer") }
        try expect(failureCalled, "loader failure completes")
    }

    static func updateMenuSourceContract() throws {
        let root = packageRoot().deletingLastPathComponent()
        let source = try String(contentsOf: root.appendingPathComponent("macos/Sources/HYUVPNMenuApp/AppDelegate.swift"))
        for required in [
            "startUpdateChecks()",
            "6 * 60 * 60",
            "addUpdateAction(to: menu)",
            "Update Available: v",
            "hyu.vpn.update.lastAnnouncedVersion",
            "hyu.vpn.update.lastCheckTime",
            "NSWorkspace.shared.open(offer.releaseURL)",
            "withTitle: \"Download\"",
            "withTitle: \"Later\"",
            "HYUUpdateFeedURL",
            "HYUUpdateAllowedReleaseHost",
            "HYUUpdateAllowedReleasePathPrefix",
        ] {
            try expect(source.contains(required), "update menu source contains \(required)")
        }
    }

    static func primaryActionDisabledTransientStates() throws {
        let expected: [(VPNConnectionState, String)] = [
            (.connecting, "Connecting…"),
            (.disconnecting, "Disconnecting…"),
            (.waitingForNetwork, "Waiting for Network"),
        ]
        for (state, title) in expected {
            let menu = MenuModel.make(status: try VPNStatusDecoder.decode(statusData(state: state, expiry: nil, connectedAt: nil)), launchAtLogin: .disabled)
            try expect(menu[.primaryConnection]?.title == title, "transient title \(state.rawValue)")
            try expect(menu[.primaryConnection]?.isEnabled == false, "transient disabled \(state.rawValue)")
            try expect(menu[.primaryConnection]?.command == nil, "transient command nil \(state.rawValue)")
        }
    }

    static func loginItemStateProjectionsAndActions() throws {
        let cases: [(FakeLoginItemStatus, LoginItemState, Bool, Bool, String)] = [
            (.enabled, .enabled, true, true, "Launch at Login"),
            (.notRegistered, .disabled, false, true, "Launch at Login"),
            (.requiresApproval, .approvalRequired, false, true, "Launch at Login (Open System Settings…)") ,
            (.notFound, .disabled, false, true, "Launch at Login"),
            (.unknown(code: "LOGIN_ITEM_STATUS_UNKNOWN"), .unavailable(code: "LOGIN_ITEM_STATUS_UNKNOWN"), false, false, "Launch at Login Unavailable"),
        ]
        for (status, state, checked, enabled, title) in cases {
            var controller = LoginItemController(platform: FakeLoginItemPlatform(currentStatus: status))
            try expect(controller.state() == state, "state projection for \(status)")
            let menu = MenuModel.make(status: try VPNStatusDecoder.decode(statusData()), launchAtLogin: state)
            try expect(menu[.launchAtLogin]?.isChecked == checked, "menu check for \(status)")
            try expect(menu[.launchAtLogin]?.isEnabled == enabled, "menu enabled state for \(status)")
            try expect(menu[.launchAtLogin]?.title == title, "menu title for \(status)")
        }

        let registerProbe = FakeLoginItemProbe()
        var register = LoginItemController(platform: FakeLoginItemPlatform(currentStatus: .notRegistered, probe: registerProbe))
        try register.setEnabled(true)
        try expect(register.state() == .enabled, "register changes runtime status")
        try expect(registerProbe.events == [.register], "register platform called once")

        let unregisterProbe = FakeLoginItemProbe()
        var unregister = LoginItemController(platform: FakeLoginItemPlatform(currentStatus: .enabled, probe: unregisterProbe))
        try unregister.setEnabled(false)
        try expect(unregister.state() == .disabled, "unregister changes runtime status")
        try expect(unregisterProbe.events == [.unregister], "unregister platform called once")

        let approvalProbe = FakeLoginItemProbe()
        var approval = LoginItemController(platform: FakeLoginItemPlatform(currentStatus: .requiresApproval, probe: approvalProbe))
        try approval.handleMenuSelection()
        try expect(approvalProbe.events == [.openSettings], "approval opens settings instead of register loop")

        var registerFailure = LoginItemController(platform: FakeLoginItemPlatform(currentStatus: .notRegistered, registerError: "LOGIN_ITEM_REGISTER_FAILED"))
        try expectThrows("register failure is unavailable") { try registerFailure.setEnabled(true) }
        try expect(registerFailure.state() == .disabled, "register failure does not override runtime disabled state")

        var unregisterFailure = LoginItemController(platform: FakeLoginItemPlatform(currentStatus: .enabled, unregisterError: "LOGIN_ITEM_UNREGISTER_FAILED"))
        try expectThrows("unregister failure is unavailable") { try unregisterFailure.setEnabled(false) }
        try expect(unregisterFailure.state() == .enabled, "unregister failure does not override runtime enabled state")
    }



    static func loginItemErrorNormalization() throws {
        let domain = "com.apple.ServiceManagement"
        let expected: [(Int, Bool, String)] = [
            (3, true, "LOGIN_ITEM_INVALID_SIGNATURE"),
            (4, true, "LOGIN_ITEM_AUTHORIZATION_FAILED"),
            (5, true, "LOGIN_ITEM_TOOL_NOT_VALID"),
            (6, false, "LOGIN_ITEM_NOT_REGISTERED"),
            (11, true, "LOGIN_ITEM_LAUNCH_DENIED_BY_USER"),
            (12, true, "LOGIN_ITEM_ALREADY_REGISTERED"),
        ]
        for (code, registering, expectedCode) in expected {
            let normalized = SMAppServiceLoginItemPlatform.normalizeForTest(error: NSError(domain: domain, code: code), registering: registering)
            try expect(normalized == .unavailable(code: expectedCode), "SM error code \(code) normalizes to \(expectedCode)")
        }

        var alreadyRegistered = LoginItemController(platform: FakeLoginItemPlatform(currentStatus: .enabled, registerError: "LOGIN_ITEM_ALREADY_REGISTERED"))
        try alreadyRegistered.setEnabled(true)
        try expect(alreadyRegistered.state() == .enabled, "already registered remains idempotent success")

        var notRegistered = LoginItemController(platform: FakeLoginItemPlatform(currentStatus: .notRegistered, unregisterError: "LOGIN_ITEM_NOT_REGISTERED"))
        try notRegistered.setEnabled(false)
        try expect(notRegistered.state() == .disabled, "not registered remains idempotent success")
    }

    static func loginItemRuntimeTruthAfterOperationFailure() throws {
        let probe = FakeLoginItemProbe()
        probe.status = .notRegistered
        var controller = LoginItemController(platform: FakeLoginItemPlatform(currentStatus: .notRegistered, registerError: "LOGIN_ITEM_INVALID_SIGNATURE", probe: probe))
        try expectThrows("register failure records operation result") { try controller.setEnabled(true) }
        probe.status = .enabled
        try expect(controller.state() == .enabled, "runtime status wins after operation failure")
    }

    static func loginItemFirstLaunchPolicy() throws {
        try expect(LoginItemStartupPolicy.shouldRegisterOnLaunch(userChoice: nil, state: .disabled), "first launch disabled registers")
        try expect(LoginItemStartupPolicy.shouldRegisterOnLaunch(userChoice: true, state: .disabled), "explicit on registers if runtime disabled")
        try expect(!LoginItemStartupPolicy.shouldRegisterOnLaunch(userChoice: false, state: .disabled), "explicit off suppresses registration")
        try expect(!LoginItemStartupPolicy.shouldRegisterOnLaunch(userChoice: nil, state: .enabled), "enabled runtime does not register again")
        try expect(!LoginItemStartupPolicy.shouldRegisterOnLaunch(userChoice: nil, state: .approvalRequired), "approval-required opens only by menu selection")
        try expect(!LoginItemStartupPolicy.shouldRegisterOnLaunch(userChoice: nil, state: .unavailable(code: "LOGIN_ITEM_STATUS_UNKNOWN")), "unknown runtime is not treated as not found or disabled")
    }

    static func liveMenuIncludesNativeLoginItemControl() throws {
        let root = packageRoot().deletingLastPathComponent()
        let appDelegateSource = try String(contentsOf: root.appendingPathComponent("macos/Sources/HYUVPNMenuApp/AppDelegate.swift"))
        let mainSource = try String(contentsOf: root.appendingPathComponent("macos/Sources/HYUVPNMenuApp/main.swift"))
        let adaptersSource = try String(contentsOf: root.appendingPathComponent("macos/Sources/HYUVPNMenuApp/SystemAdapters.swift"))
        try expect(appDelegateSource.contains("addLaunchAtLoginAction"), "live menu includes launch-at-login row")
        try expect(appDelegateSource.contains("hyu.vpn.launchAtLogin.userChoice"), "first-launch explicit-off preference is app-owned")
        try expect(mainSource.contains("--unregister-login-item"), "unregister CLI mode exists before AppKit startup")
        try expect(adaptersSource.contains("SMAppService.mainApp"), "runtime adapter uses SMAppService main app")
    }

    static func bootstrapSplitsAppKitAndArgumentGate() throws {
        let root = packageRoot().deletingLastPathComponent()
        let mainSource = try String(contentsOf: root.appendingPathComponent("macos/Sources/HYUVPNMenuApp/main.swift"))
        let appDelegateSource = try String(contentsOf: root.appendingPathComponent("macos/Sources/HYUVPNMenuApp/AppDelegate.swift"))
        try expect(!mainSource.contains("final class AppDelegate"), "main split from AppDelegate implementation")
        try expect(mainSource.contains("ProcessInfo.processInfo.arguments"), "bootstrap reads argv before launch")
        try expect(mainSource.contains("--register-login-item"), "register-login-item mode recognized")
        try expect(mainSource.contains("--unregister-login-item"), "unregister-login-item mode recognized")
        try expect(mainSource.contains("EX_USAGE"), "invalid argv exits EX_USAGE")
        try expect(mainSource.contains("LOGIN_ITEM_NOT_REGISTERED"), "unregister mode returns stable already-absent code")
        try expect(mainSource.contains("LOGIN_ITEM_REGISTER_FAILED"), "register mode returns stable failure code")
        let argsIndex = try requireIndex(of: "ProcessInfo.processInfo.arguments", in: mainSource, message: "argv parse source index")
        let appKitIndex = try requireIndex(of: "NSApplication.shared", in: mainSource, message: "AppKit source index")
        try expect(argsIndex < appKitIndex, "argv gate precedes AppKit startup")
        try expect(mainSource.contains("withExtendedLifetime(delegate)"), "delegate retained strongly through app run")
        try expect(mainSource.contains("let application = NSApplication.shared"), "AppKit bootstrap remains in main")
        try expect(appDelegateSource.contains("final class AppDelegate"), "AppDelegate moved to dedicated file")
        let binary = packageRoot().appendingPathComponent(".build/debug/HYUVPNMenuApp")
        if FileManager.default.isExecutableFile(atPath: binary.path) {
            let process = Process()
            process.executableURL = binary
            process.arguments = ["--bad"]
            try process.run()
            process.waitUntilExit()
            try expect(process.terminationStatus == EX_USAGE, "bad args exit 64 before AppKit startup")
        }
    }

    static func controlTowerMenuCopyAndIconContract() throws {
        let root = packageRoot().deletingLastPathComponent()
        let appSource = try String(contentsOf: root.appendingPathComponent("macos/Sources/HYUVPNMenuApp/AppDelegate.swift"))
        let coreSource = try String(contentsOf: root.appendingPathComponent("macos/Sources/HYUVPNMenuCore/MenuCore.swift"))
        try expect(!appSource.contains("import UserNotifications"), "control tower removes UserNotifications")
        for forbidden in ["countdown", "duration", "expiresAt", "sessionExpiresAt"] {
            try expect(!appSource.contains(forbidden), "no legacy expiry UI token \(forbidden)")
        }
        for required in ["HYU VPN: Status Unavailable", "NSPasteboard.general", "forMode: .common", "Quit HYU VPN", "button.title = \"\"", "button.toolTip = textualState", "accessibilityDescription: textualState", "button.setAccessibilityLabel(textualState)", "button.setAccessibilityHelp(textualState)", "\"Connecting…\"", "\"Disconnecting…\"", "\"Waiting for Network\""] {
            try expect(appSource.contains(required), "menu/icon contract contains \(required)")
        }
        try expect(coreSource.contains("OTP:"), "menu/icon contract contains OTP:")
        let rebuildStart = try requireIndex(of: "private func rebuildMenu()", in: appSource, message: "rebuildMenu exists")
        let rebuildEnd = try requireIndex(of: "    private func addOTPAction", in: appSource, message: "rebuildMenu end")
        let rebuild = String(appSource[rebuildStart..<rebuildEnd])
        try expect(rebuild.components(separatedBy: "NSMenuItem.separator()").count - 1 == 2, "menu has exactly two separators")
        let expectedOrder = [
            "menu.addItem(disabledItem(title: statusLineText()))",
            "addOTPAction(to: menu)",
            "addPrimaryAction(to: menu)",
            "addDisconnectAction(to: menu)",
            "menu.addItem(NSMenuItem.separator())",
            "addResetAction(to: menu)",
            "addLaunchAtLoginAction(to: menu)",
            "addUpdateAction(to: menu)",
            "menu.addItem(NSMenuItem.separator())",
            "addQuitAction(to: menu)",
        ]
        var searchStart = rebuild.startIndex
        for token in expectedOrder {
            guard let range = rebuild.range(of: token, range: searchStart..<rebuild.endIndex) else { throw HarnessFailure(description: "menu order missing \(token)") }
            searchStart = range.upperBound
        }
        try expect(appSource.contains("addPrimaryAction"), "single dynamic primary action helper")
        try expect(appSource.contains("Disconnect"), "disconnect row present")
    }

    static func lifecycleCoordinatorRuntime() throws {
        var coordinator = AppLifecycleCoordinator()
        try expect(coordinator.handle(.appLaunched).effects == [.runControl(command: .connect, operation: .connect, timeout: 3)], "launch enables always-on VPN through the backend")
        try expect(coordinator.handle(.controlCompleted(operation: .connect, result: ControlResult(status: .ok, errorCode: nil))).effects.isEmpty, "startup connect completion is absorbed")
        try expect(coordinator.handle(.primaryConnectRequested).effects == [.runControl(command: .connect, operation: .connect, timeout: 3)], "explicit connect starts once")
        try expect(coordinator.handle(.controlCompleted(operation: .connect, result: ControlResult(status: .ok, errorCode: nil))).effects.isEmpty, "explicit connect completion is absorbed")

        var disconnect = AppLifecycleCoordinator()
        _ = disconnect.handle(.appLaunched)
        _ = disconnect.handle(.controlCompleted(operation: .connect, result: ControlResult(status: .ok, errorCode: nil)))
        try expect(disconnect.handle(.disconnectRequested).effects == [.runControl(command: .disconnect, operation: .disconnect, timeout: 3)], "explicit disconnect starts while idle")

        var terminateIdle = AppLifecycleCoordinator()
        _ = terminateIdle.handle(.appLaunched)
        _ = terminateIdle.handle(.controlCompleted(operation: .connect, result: ControlResult(status: .ok, errorCode: nil)))
        try expect(terminateIdle.handle(.terminateRequested) == .init(terminationDirective: .terminateLater, effects: [.runControl(command: .disconnect, operation: .quit, timeout: 15)]), "idle terminate starts one quit disconnect")
        try expect(terminateIdle.handle(.controlCompleted(operation: .quit, result: ControlResult(status: .ok, errorCode: nil))).effects == [.replyToTermination(true)], "quit success replies true")
        try expect(terminateIdle.handle(.terminateRequested) == .init(terminationDirective: .terminateNow, effects: []), "post-success terminate returns terminateNow")
        try expect(terminateIdle.handle(.startupRetryTimerFired).effects.isEmpty, "no effects after reply true")

        var terminateConnect = AppLifecycleCoordinator()
        _ = terminateConnect.handle(.appLaunched)
        try expect(terminateConnect.handle(.terminateRequested) == .init(terminationDirective: .terminateLater, effects: []), "terminate during connect waits")
        try expect(terminateConnect.handle(.terminateRequested) == .init(terminationDirective: .terminateLater, effects: []), "duplicate terminate adds nothing")
        try expect(terminateConnect.handle(.controlCompleted(operation: .connect, result: ControlResult(status: .ok, errorCode: nil))).effects == [.runControl(command: .disconnect, operation: .quit, timeout: 15)], "post-connect terminate starts one quit disconnect")

        var terminateDisconnect = AppLifecycleCoordinator()
        _ = terminateDisconnect.handle(.appLaunched)
        _ = terminateDisconnect.handle(.controlCompleted(operation: .connect, result: ControlResult(status: .ok, errorCode: nil)))
        _ = terminateDisconnect.handle(.disconnectRequested)
        try expect(terminateDisconnect.handle(.terminateRequested) == .init(terminationDirective: .terminateLater, effects: []), "terminate attaches to existing disconnect")
        try expect(terminateDisconnect.handle(.controlCompleted(operation: .disconnect, result: ControlResult(status: .timeout, errorCode: "CONTROL_TIMEOUT"))).effects == [.replyToTermination(false), .showTerminationFailureAlert("CONTROL_TIMEOUT")], "failure replies false before alert")
    }

    static func safeQuitWithoutDiagnosticsContract() throws {
        let root = packageRoot().deletingLastPathComponent()
        let appSource = try String(contentsOf: root.appendingPathComponent("macos/Sources/HYUVPNMenuApp/AppDelegate.swift"))
        let coreSource = try String(contentsOf: root.appendingPathComponent("macos/Sources/HYUVPNMenuCore/ControlTowerCore.swift"))
        for required in ["applicationShouldTerminate", ".terminateLater", ".terminateNow", ".replyToTermination(let allow)", "NSApp.reply(toApplicationShouldTerminate: allow)", "NSApp.sendAction(#selector(NSApplication.terminate(_:)), to: nil, from: self)"] {
            try expect(appSource.contains(required), "safe quit contract contains \(required)")
        }
        try expect(coreSource.contains("timeout: 15"), "quit disconnect timeout remains 15 seconds in core coordinator")
        try expect(coreSource.contains(".replyToTermination(false), .showTerminationFailureAlert"), "reply(false) is ordered before alert effect")
        for forbidden in ["NSApp.terminate(nil)", "addDiagnosticsAction", "showDiagnostics", "Diagnostics…"] {
            try expect(!appSource.contains(forbidden), "safe quit menu omits forbidden token \(forbidden)")
        }
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


    static func bundleAssembler() throws {
        let root = packageRoot()
        let fixture = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("hyu-bundle-\(UUID().uuidString)")
        let inputs = fixture.appendingPathComponent("inputs")
        let destination = fixture.appendingPathComponent("output")
        try FileManager.default.createDirectory(at: inputs, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: fixture) }
        let executable = inputs.appendingPathComponent("HYUVPNMenuApp")
        let reader = inputs.appendingPathComponent("hyu-vpn-credential-reader")
        for input in [executable, reader] {
            try FileManager.default.copyItem(at: URL(fileURLWithPath: "/usr/bin/true"), to: input)
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: input.path)
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = [root.appendingPathComponent("Scripts/assemble-menu-app.sh").path, executable.path, destination.path, "0.1.1"]
        try process.run(); process.waitUntilExit()
        try expect(process.terminationStatus == 0, "assembler exit")
        let app = destination.appendingPathComponent("HYU VPN.app")
        let plist = app.appendingPathComponent("Contents/Info.plist")
        let binary = app.appendingPathComponent("Contents/MacOS/HYUVPNMenuApp")
        let bundledReader = app.appendingPathComponent("Contents/MacOS/HYUVPNCredentialReader")
        let icon = app.appendingPathComponent("Contents/Resources/AppIcon.icns")
        try expect(FileManager.default.isExecutableFile(atPath: binary.path), "bundle executable")
        try expect(FileManager.default.isExecutableFile(atPath: bundledReader.path), "bundled native credential reader")
        try expect(FileManager.default.fileExists(atPath: icon.path), "bundle icon")
        let info = NSDictionary(contentsOf: plist) as? [String: Any]
        try expect(info?["CFBundleExecutable"] as? String == "HYUVPNMenuApp", "plist executable")
        try expect(info?["CFBundleName"] as? String == "HYU VPN", "plist name")
        try expect(info?["CFBundleIconFile"] as? String == "AppIcon", "plist icon")
        try expect(info?["CFBundleShortVersionString"] as? String == "0.1.1", "plist release version")
        try expect(info?["HYUUpdateFeedURL"] as? String == "https://raw.githubusercontent.com/IRCVLab/EZ-HYU-VPN/main/update.json", "plist update feed")
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
        try expect(sink.presentations.allSatisfy { $0.statusItemTitle.isEmpty }, "atomic replace keeps status title empty")
    }

    static func atomicWrite(_ data: Data, to url: URL) throws {
        let tmp = url.deletingLastPathComponent().appendingPathComponent(".status.\(UUID().uuidString).tmp")
        try data.write(to: tmp)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: tmp.path)
        _ = try FileManager.default.replaceItemAt(url, withItemAt: tmp, backupItemName: nil, options: [])
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









    static func menuCoreHasNoDirectFoundationProcessRunSurface() throws {
        let root = packageRoot().deletingLastPathComponent()
        let source = try String(contentsOf: root.appendingPathComponent("macos/Sources/HYUVPNMenuCore/MenuCore.swift"))
        try expect(!source.contains("Process()"), "MenuCore must not create Foundation.Process")
        try expect(!source.contains("hyu-vpn-control"), "MenuCore must not reference legacy hyu-vpn-control")
        try expect(!source.contains("usesShell"), "MenuCore must not expose shell fallback")
    }


    static func controlTowerCredentialValidation() throws {
        let valid = CredentialResetInput(username: "shchoi00", password: "correct horse", passwordConfirmation: "correct horse", totpSeed: "jbsw y3dp-ehpk3pxp", totpSeedConfirmation: "JBSWY3DPEHPK3PXP")
        let normalized = try CredentialValidator.validate(valid)
        try expect(normalized.normalizedTOTPSeed == "JBSWY3DPEHPK3PXP", "normalized seed")
        try expectThrows("blank seed rejected") { _ = try CredentialValidator.validate(CredentialResetInput(username: "shchoi00", password: "pw", passwordConfirmation: "pw", totpSeed: "", totpSeedConfirmation: "")) }
        try expectThrows("password mismatch") { _ = try CredentialValidator.validate(CredentialResetInput(username: "canary-user", password: "canary-pass", passwordConfirmation: "different", totpSeed: "", totpSeedConfirmation: "")) }
        let padded = String(repeating: "A", count: 10) + "======"
        let validatedPadded = try CredentialValidator.validate(CredentialResetInput(username: "shchoi00", password: "pw", passwordConfirmation: "pw", totpSeed: padded, totpSeedConfirmation: padded))
        try expect(validatedPadded.normalizedTOTPSeed == padded, "valid strict padded seed")
        try expectThrows("invalid base32 residue") { _ = try CredentialValidator.validate(CredentialResetInput(username: "shchoi00", password: "pw", passwordConfirmation: "pw", totpSeed: String(repeating: "A", count: 17), totpSeedConfirmation: String(repeating: "A", count: 17))) }
        try expectThrows("invalid base32 padding") { _ = try CredentialValidator.validate(CredentialResetInput(username: "shchoi00", password: "pw", passwordConfirmation: "pw", totpSeed: String(repeating: "A", count: 14) + "==", totpSeedConfirmation: String(repeating: "A", count: 14) + "==")) }
        let errors: [CredentialValidationError] = [.passwordMismatch, .totpSeedRequired, .totpSeedMismatch, .totpSeedInvalidAlphabetOrPadding]
        try expect(errors.allSatisfy { !$0.description.contains("canary") && !$0.code.contains("canary") }, "stable redacted validation errors")
    }

    static func controlTowerTransactionPolicyGate() throws {
        let store = HarnessCredentialStore(initial: [.username: "old-user", .password: "old-pass", .totpSeed: "OLDTOTPSEEDVALUE1"], failOnWriteCall: 3)
        let resetter = HarnessTOTPResetter()
        var reconnects = 0
        let failed = CredentialTransaction(store: store, totpResetter: resetter) { reconnects += 1 }.apply(ValidatedCredentials(username: "canary-user", password: "canary-pass", normalizedTOTPSeed: "JBSWY3DPEHPK3PXP"))
        try expect(failed == .failure(code: .writeFailed), "third write failure")
        try expect(store.values[.username] == "old-user" && store.values[.password] == "old-pass" && store.values[.totpSeed] == "OLDTOTPSEEDVALUE1", "rollback restored originals")
        try expect(reconnects == 0 && resetter.resetCount == 0, "no reconnect or reset after failed transaction")
        let successResetter = HarnessTOTPResetter()
        let success = CredentialTransaction(store: HarnessCredentialStore(initial: [:]), totpResetter: successResetter) { reconnects += 1 }.apply(ValidatedCredentials(username: "new-user", password: "new-pass", normalizedTOTPSeed: "JBSWY3DPEHPK3PXP"))
        try expect(success == .success && successResetter.resetCount == 1 && reconnects == 1, "success resets after commit and reconnects once")
        let blankResetter = HarnessTOTPResetter()
        let blank = CredentialTransaction(store: HarnessCredentialStore(initial: [:]), totpResetter: blankResetter).apply(ValidatedCredentials(username: "new-user", password: "new-pass", normalizedTOTPSeed: nil))
        try expect(blank == .success && blankResetter.resetCount == 0, "blank TOTP transaction does not call resetter")
        let readFailure = CredentialTransaction(store: HarnessCredentialStore(initial: [:], failReadKey: .password), totpResetter: HarnessTOTPResetter()).apply(ValidatedCredentials(username: "canary-user", password: "canary-pass", normalizedTOTPSeed: nil))
        try expect(readFailure == .failure(code: .readFailed) && readFailure.description == "READ_FAILED", "read failure stable code")
        let rollbackStore = HarnessCredentialStore(initial: [:], failRemoveKeys: [.totpSeed])
        let rollbackFailure = CredentialTransaction(store: rollbackStore, totpResetter: HarnessTOTPResetter(fail: true)) { reconnects += 1 }.apply(ValidatedCredentials(username: "new-user", password: "new-pass", normalizedTOTPSeed: "JBSWY3DPEHPK3PXP"))
        try expect(rollbackFailure == .failure(code: .rollbackFailed), "best-effort rollback failure code")
        try expect(rollbackStore.events.contains("remove:totpSeed") && rollbackStore.events.contains("remove:password") && rollbackStore.events.contains("remove:username"), "rollback continued after remove failure")
        var policy = StartupConnectPolicy()
        for _ in 0..<29 { try expect(policy.next(after: .controlUnavailable) == .retry(after: 1), "transient retry before bound") }
        try expect(policy.next(after: .controlUnavailable) == .stop, "thirtieth attempt stops")
        var codePolicy = StartupConnectPolicy()
        try expect(codePolicy.next(after: .failure(code: "CONTROL_UNAVAILABLE")) == .retry(after: 1), "normalized control unavailable transient")
        var failurePolicy = StartupConnectPolicy()
        try expect(failurePolicy.next(after: .failure(code: "AUTH_FAILED")) == .stop, "non-transient stop")
        var gate = OperationGate()
        try expect(gate.begin(.connect), "first operation begins")
        try expect(!gate.begin(.credentialSave) && !gate.begin(.quit), "overlap rejected")
        gate.finish(.connect)
        try expect(gate.begin(.quit), "finish permits new operation")
        try expect(LoginItemState.approvalRequired == .approvalRequired, "login item model available")
    }

    static func nativeCredentialResetSourceContract() throws {
        let root = packageRoot().deletingLastPathComponent()
        let appSource = try String(contentsOf: root.appendingPathComponent("macos/Sources/HYUVPNMenuApp/AppDelegate.swift"))
        let controllerSource = try String(contentsOf: root.appendingPathComponent("macos/Sources/HYUVPNMenuApp/CredentialResetController.swift"))
        try expect(appSource.contains("Reset Login Information…"), "exact reset menu copy present")
        try expect(appSource.range(of: "Disconnect")!.lowerBound < appSource.range(of: "Reset Login Information…")!.lowerBound, "reset follows disconnect")
        try expect(appSource.range(of: "Reset Login Information…")!.lowerBound < appSource.range(of: "Launch at Login")!.lowerBound, "reset precedes launch at login")
        for label in ["HYU ID", "Password", "Confirm Password", "TOTP Setup Secret", "Confirm TOTP Secret"] {
            try expect(controllerSource.contains(label), "native sheet contains label \(label)")
        }
        try expect(controllerSource.components(separatedBy: "NSSecureTextField").count - 1 >= 4, "four secure text field references")
        try expect(controllerSource.contains("CredentialValidator.validate"), "existing validator used")
        try expect(controllerSource.contains("validationMessage"), "validation remains in native sheet")
        try expect(controllerSource.contains("prefillUsername"), "username prefill seam exists")
        try expect(appSource.contains("resetController?.dismissWithoutSaving()"), "quit while form open cancels native form before lifecycle termination")
        try expect(appSource.contains("pendingResetPayload = nil"), "submitted reset payload cleared on cancellation and failure effects")
        try expect(appSource.contains("NSApp.activate") && appSource.contains("controller.present()"), "reset uses standalone native window activation")
        try expect(!appSource.contains("button?.window") && !controllerSource.contains("beginSheet"), "reset does not attach to status bar private window")
        try expect(!controllerSource.contains("Terminal") && !controllerSource.contains("installer"), "reset controller avoids terminal and installer")
    }

    static func encryptedCredentialAndTOTPSourceContract() throws {
        let root = packageRoot().deletingLastPathComponent()
        let source = try String(contentsOf: root.appendingPathComponent("macos/Sources/HYUVPNMenuApp/SystemAdapters.swift"))
        for required in ["import CryptoKit", "AES.GCM.seal", "AES.GCM.open", "credentials.key", "credentials.enc", "credentials.lock", "gp-vpn-username", "gp-vpn-password", "gp-vpn-totp", "O_NOFOLLOW", "O_CLOEXEC", "flock", "LOCK_EX", "fstatat", "AT_SYMLINK_NOFOLLOW", "unlinkat", "totp-counter.lock", "totp-counter", "0o600", "0o700"] {
            try expect(source.contains(required), "system adapter source contains \(required)")
        }
        try expect(!source.contains("totp-counter.json"), "system adapter omits retired Python TOTP state names")
        for forbidden in ["import Security", "SecItem", "SecAccess", "KeychainCredential", "/usr/bin/security", "Process(", "posix_spawn", "NSTask", "NSLog", "os_log", "print("] {
            try expect(!source.contains(forbidden), "system adapter source omits \(forbidden)")
        }
        try expect(source.contains("private static let services: [String: CredentialKey]"), "reader has a closed service map")
        try expect(source.contains("Set(Self.services.values) == Set(CredentialKey.allCases)"), "service map covers only enum keys")
        try expect(!source.contains("setAttributes"), "credential and TOTP storage avoid path-following chmod")
    }

    static func totpResetterRuntimeSecureDeleteAndMissingState() throws {
        let first = try makeTOTPFixture()
        defer { try? FileManager.default.removeItem(at: first.home) }
        try writeSecureFile(first.lock, Data("lock".utf8), mode: 0o600)
        try writeSecureFile(first.state, Data("state".utf8), mode: 0o600)
        try FileTOTPStateResetter(home: first.home).resetTOTPState()
        try expect(!FileManager.default.fileExists(atPath: first.state.path), "secure state deleted")
        try expect(FileManager.default.fileExists(atPath: first.lock.path), "lock preserved after state delete")

        let second = try makeTOTPFixture()
        defer { try? FileManager.default.removeItem(at: second.home) }
        try writeSecureFile(second.lock, Data("lock".utf8), mode: 0o600)
        try FileTOTPStateResetter(home: second.home).resetTOTPState()
        try expect(!FileManager.default.fileExists(atPath: second.state.path), "missing state remains missing")
        try expect(FileManager.default.fileExists(atPath: second.lock.path), "lock preserved when state missing")
    }

    static func totpResetterRuntimeUnsafeMetadataFailsClosed() throws {
        try expect(!FileTOTPMetadataPolicy.isSafe(ownerUID: getuid() + 1, mode: S_IFREG | 0o600, directory: false, expectedMode: 0o600), "wrong owner rejected by real metadata policy")

        let parentSymlink = try makeTOTPFixture(createRoot: false)
        defer { try? FileManager.default.removeItem(at: parentSymlink.home) }
        let unsafeTarget = parentSymlink.home.appendingPathComponent("unsafe-target", isDirectory: true)
        try FileManager.default.createDirectory(at: unsafeTarget, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: unsafeTarget.path)
        try FileManager.default.createSymbolicLink(atPath: parentSymlink.root.path, withDestinationPath: unsafeTarget.path)
        try writeSecureFile(unsafeTarget.appendingPathComponent("totp-counter"), Data("state".utf8), mode: 0o600)
        try expectThrows("parent symlink") { try FileTOTPStateResetter(home: parentSymlink.home).resetTOTPState() }
        try expect(FileManager.default.fileExists(atPath: unsafeTarget.appendingPathComponent("totp-counter").path), "parent symlink target state preserved")

        try assertUnsafeFixture(name: "parent-wrong-mode", prepare: { fixture in
            try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: fixture.root.path)
        }, preservedPath: \.state)
        try assertUnsafeFixture(name: "lock-symlink", prepare: { fixture in
            try FileManager.default.removeItem(at: fixture.lock)
            let target = fixture.home.appendingPathComponent("lock-target")
            try writeSecureFile(target, Data("target".utf8), mode: 0o600)
            try FileManager.default.createSymbolicLink(atPath: fixture.lock.path, withDestinationPath: target.path)
        }, preservedPath: \.state)
        try assertUnsafeFixture(name: "lock-wrong-mode", prepare: { fixture in
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: fixture.lock.path)
        }, preservedPath: \.state)
        try assertUnsafeFixture(name: "lock-wrong-type", prepare: { fixture in
            try FileManager.default.removeItem(at: fixture.lock)
            try FileManager.default.createDirectory(at: fixture.lock, withIntermediateDirectories: false)
        }, preservedPath: \.state)
        try assertUnsafeFixture(name: "state-symlink", prepare: { fixture in
            try FileManager.default.removeItem(at: fixture.state)
            let target = fixture.home.appendingPathComponent("state-target")
            try writeSecureFile(target, Data("target".utf8), mode: 0o600)
            try FileManager.default.createSymbolicLink(atPath: fixture.state.path, withDestinationPath: target.path)
        }, preservedPath: \.state)
        try assertUnsafeFixture(name: "state-wrong-mode", prepare: { fixture in
            try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: fixture.state.path)
        }, preservedPath: \.state)
        try assertUnsafeFixture(name: "state-wrong-type", prepare: { fixture in
            try FileManager.default.removeItem(at: fixture.state)
            try FileManager.default.createDirectory(at: fixture.state, withIntermediateDirectories: false)
        }, preservedPath: \.state)
    }

    static func totpResetterRuntimeFlockCoordination() throws {
        let fixture = try makeTOTPFixture()
        defer { try? FileManager.default.removeItem(at: fixture.home) }
        try writeSecureFile(fixture.lock, Data("lock".utf8), mode: 0o600)
        try writeSecureFile(fixture.state, Data("state".utf8), mode: 0o600)
        let fd = open(fixture.lock.path, O_RDWR | O_CLOEXEC)
        try expect(fd >= 0, "lock fd opened")
        defer { close(fd) }
        try expect(flock(fd, LOCK_EX) == 0, "exclusive lock held by test")
        let semaphore = DispatchSemaphore(value: 0)
        let resetState = LockedResetState()
        DispatchQueue.global(qos: .utility).async {
            do { try FileTOTPStateResetter(home: fixture.home).resetTOTPState() }
            catch { resetState.lock.lock(); resetState.error = error; resetState.lock.unlock() }
            resetState.lock.lock(); resetState.completed = true; resetState.lock.unlock()
            semaphore.signal()
        }
        Thread.sleep(forTimeInterval: 0.3)
        resetState.lock.lock(); let blocked = !resetState.completed; resetState.lock.unlock()
        try expect(blocked, "resetter blocks behind existing flock")
        try expect(FileManager.default.fileExists(atPath: fixture.state.path), "state not deleted while lock held")
        try expect(flock(fd, LOCK_UN) == 0, "exclusive lock released")
        try expect(semaphore.wait(timeout: .now() + 3) == .success, "resetter completed after release")
        resetState.lock.lock(); let error = resetState.error; resetState.lock.unlock()
        if let error { throw error }
        try expect(!FileManager.default.fileExists(atPath: fixture.state.path), "state deleted after lock release")
        try expect(FileManager.default.fileExists(atPath: fixture.lock.path), "lock preserved after coordinated delete")
    }

    static func encryptedCredentialStoreRuntime() throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("hyu-credentials-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let store = EncryptedCredentialStore(root: root)
        try store.write("reader-user", for: .username)
        try store.write("reader-password", for: .password)
        try store.write("JBSWY3DPEHPK3PXP", for: .totpSeed)
        let storedUsername = try store.read(.username)
        let storedPassword = try store.read(.password)
        try expect(storedUsername == "reader-user", "encrypted store reads username")
        try expect(storedPassword == "reader-password", "encrypted store reads password")
        let ciphertext = try Data(contentsOf: root.appendingPathComponent("credentials.enc"))
        try expect(!String(decoding: ciphertext, as: UTF8.self).contains("reader-password"), "ciphertext excludes plaintext credentials")
        let keyAttributes = try FileManager.default.attributesOfItem(atPath: root.appendingPathComponent("credentials.key").path)
        let encryptedAttributes = try FileManager.default.attributesOfItem(atPath: root.appendingPathComponent("credentials.enc").path)
        let rootAttributes = try FileManager.default.attributesOfItem(atPath: root.path)
        try expect((rootAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o700, "credential directory mode is 0700")
        try expect((keyAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o600, "key mode is 0600")
        try expect((encryptedAttributes[.posixPermissions] as? NSNumber)?.intValue == 0o600, "ciphertext mode is 0600")
        try store.remove(.password)
        let removedPassword = try store.read(.password)
        try expect(removedPassword == nil, "encrypted store removes one credential")
        try Data("tampered".utf8).write(to: root.appendingPathComponent("credentials.enc"))
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: root.appendingPathComponent("credentials.enc").path)
        try expectThrows("tampered ciphertext") { _ = try store.read(.username) }

        let unsafeRoot = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("hyu-credentials-unsafe-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: unsafeRoot) }
        let unsafeStore = EncryptedCredentialStore(root: unsafeRoot)
        try unsafeStore.write("reader-user", for: .username)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: unsafeRoot.appendingPathComponent("credentials.key").path)
        try expectThrows("unsafe key permissions") { _ = try unsafeStore.read(.username) }

        let symlinkRoot = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("hyu-credentials-symlink-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: symlinkRoot) }
        let symlinkStore = EncryptedCredentialStore(root: symlinkRoot)
        try symlinkStore.write("reader-user", for: .username)
        let encryptedURL = symlinkRoot.appendingPathComponent("credentials.enc")
        let encryptedTarget = symlinkRoot.appendingPathComponent("credentials-target")
        try FileManager.default.moveItem(at: encryptedURL, to: encryptedTarget)
        try FileManager.default.createSymbolicLink(atPath: encryptedURL.path, withDestinationPath: encryptedTarget.path)
        try expectThrows("symlink ciphertext") { _ = try symlinkStore.read(.username) }
    }

    static func menuTOTPProviderAndClipboardPolicyRuntime() throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("hyu-menu-totp-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        let store = EncryptedCredentialStore(root: root)
        try store.write("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", for: .totpSeed)
        let stateURL = root.appendingPathComponent("totp-counter")
        let stateBefore = Data("{\"last_counter\":42}".utf8)
        try stateBefore.write(to: stateURL)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: stateURL.path)

        let provider = MenuTOTPProvider(store: store)
        let snapshot = provider.snapshot(at: Date(timeIntervalSince1970: 0))
        let stateAfter = try Data(contentsOf: stateURL)
        try expect(snapshot == TOTPDisplaySnapshot(code: "755224", secondsRemaining: 30), "menu provider generates expected display value")
        try expect(stateAfter == stateBefore, "menu provider never consumes connector TOTP counter state")

        try expect(OTPClipboardPolicy.copyableCode("123456") == "123456", "clipboard accepts six ASCII digits")
        try expect(OTPClipboardPolicy.copyableCode("12345") == nil, "clipboard rejects short code")
        try expect(OTPClipboardPolicy.copyableCode("１２３４５６") == nil, "clipboard rejects non-ASCII digits")
        try expect(OTPClipboardPolicy.copyableCode("GEZDGNBVGY3TQOJQ") == nil, "clipboard rejects setup seed")
    }

    static func rustIPCClientRuntimeFixturesAndRequestIDs() throws {
        let cases: [(String, String, VPNCommand, String)] = [
            ("connect-request-v1.frame", "swift-connect-1", .connect, "connect-ack-response-v1.frame"),
            ("disconnect-request-v1.frame", "swift-disconnect-1", .disconnect, "disconnect-ack-response-v1.frame"),
            ("reconnect-request-v1.frame", "swift-reconnect-1", .reconnect, "reconnect-ack-response-v1.frame"),
            ("automatic-on-request-v1.frame", "swift-automatic-on-1", .automaticReconnect(true), "automatic-on-ack-response-v1.frame"),
            ("automatic-off-request-v1.frame", "swift-automatic-off-1", .automaticReconnect(false), "automatic-off-ack-response-v1.frame"),
        ]
        for (requestFixture, requestID, command, responseFixture) in cases {
            let operations = HarnessSocketOperations(responseFrame: try fixtureData(responseFixture), peerEffectiveUID: getuid())
            let client = RustIPCClient(
                socketPath: URL(fileURLWithPath: "/tmp/hyu-vpn.sock"),
                metadata: HarnessSocketMetadataProvider(),
                requestIDGenerator: { requestID },
                timeouts: .init(connect: 0.2, write: 0.2, read: 0.2, total: 0.5),
                operations: operations,
                monotonicClock: HarnessMonotonicClock()
            )
            let outcome = client.requestSynchronouslyForTest(command)
            try expect(outcome == Result<VPNResponse, VPNServiceError>.success(.ack), "fixture ack request \(requestID): \(outcome)")
            let expectedFrame = try fixtureData(requestFixture)
            try expect(operations.writtenFrame == expectedFrame, "exact framed request \(requestFixture)")
        }

        let mismatchClient = RustIPCClient(
            socketPath: URL(fileURLWithPath: "/tmp/hyu-vpn.sock"),
            metadata: HarnessSocketMetadataProvider(),
            requestIDGenerator: { "swift-connect-1" },
            timeouts: .init(connect: 0.2, write: 0.2, read: 0.2, total: 0.5),
            operations: HarnessSocketOperations(responseFrame: framed(json: #"{"schema_version":1,"request_id":"other-id","result":"ack"}"#), peerEffectiveUID: getuid()),
            monotonicClock: HarnessMonotonicClock()
        )
        try expect(mismatchClient.requestSynchronouslyForTest(.connect) == Result<VPNResponse, VPNServiceError>.failure(.protocolViolation), "mismatched request id is rejected")
    }

    static func passiveOTPPreviewPollingPreservesSnapshotCountdownCopy() throws {
        let firstClient = RustIPCClient(
            socketPath: URL(fileURLWithPath: "/tmp/hyu-vpn.sock"),
            metadata: HarnessSocketMetadataProvider(),
            requestIDGenerator: { "swift-current-otp-1" },
            timeouts: .init(connect: 0.2, write: 0.2, read: 0.2, total: 0.5),
            operations: HarnessSocketOperations(responseFrame: framed(json: #"{"schema_version":1,"request_id":"swift-current-otp-1","result":"current_otp","code":"123456","remaining_seconds":17}"#), peerEffectiveUID: getuid()),
            monotonicClock: HarnessMonotonicClock()
        )
        let secondClient = RustIPCClient(
            socketPath: URL(fileURLWithPath: "/tmp/hyu-vpn.sock"),
            metadata: HarnessSocketMetadataProvider(),
            requestIDGenerator: { "swift-current-otp-1" },
            timeouts: .init(connect: 0.2, write: 0.2, read: 0.2, total: 0.5),
            operations: HarnessSocketOperations(responseFrame: framed(json: #"{"schema_version":1,"request_id":"swift-current-otp-1","result":"current_otp","code":"123456","remaining_seconds":16}"#), peerEffectiveUID: getuid()),
            monotonicClock: HarnessMonotonicClock()
        )
        guard case .success(.currentOTP(let firstSnapshot)) = firstClient.requestSynchronouslyForTest(.currentOTP) else {
            throw HarnessFailure(description: "first preview succeeded")
        }
        guard case .success(.currentOTP(let secondSnapshot)) = secondClient.requestSynchronouslyForTest(.currentOTP) else {
            throw HarnessFailure(description: "second preview succeeded")
        }
        let firstModel = OTPMenuPresenter.model(snapshot: firstSnapshot)
        let secondModel = OTPMenuPresenter.model(snapshot: secondSnapshot)
        try expect(firstSnapshot.code == secondSnapshot.code, "passive preview preserves same code across one-second polling")
        try expect(firstSnapshot.secondsRemaining == 17 && secondSnapshot.secondsRemaining == 16, "countdown advances without consuming preview")
        try expect(firstModel.code == "123456" && secondModel.code == "123456", "menu model preserves copyable code across polling")
        try expect(OTPClipboardPolicy.copyableCode(firstModel.code ?? "") == "123456", "copied otp remains valid")
        try expect(OTPClipboardPolicy.copyableCode(secondModel.code ?? "") == "123456", "copied otp remains valid after second poll")
    }

    static func serviceRefreshCoordinatorDropsStaleForcedResults() throws {
        var coordinator = ServiceRefreshCoordinator()
        try expect(coordinator.begin(force: true) == 1, "first refresh generation starts")
        try expect(coordinator.begin(force: true) == nil, "forced refresh while active stays single-flight")
        try expect(!coordinator.shouldApply(generation: 1), "stale generation is rejected once forced replacement is queued")
        try expect(coordinator.finish(generation: 1) == 2, "queued forced replacement starts next generation")
        try expect(coordinator.shouldApply(generation: 2), "latest generation applies")
    }

    static func nativeCredentialReaderClosedCommandSurface() throws {
        let store = HarnessCredentialStore(initial: [.username: "reader-user", .password: "reader-password", .totpSeed: "JBSWY3DPEHPK3PXP"])
        var output = ""
        try expect(CredentialReaderCommand.run(arguments: ["gp-vpn-username"], store: store) { output += $0 } == 0, "reader returns success for username")
        try expect(output == "reader-user", "reader emits only the requested secret")
        output = ""
        try expect(CredentialReaderCommand.run(arguments: ["unknown-service"], store: store) { output += $0 } == 64, "reader rejects arbitrary service names")
        try expect(output.isEmpty, "invalid reader request emits nothing")
        try expect(CredentialReaderCommand.run(arguments: [], store: store) { output += $0 } == 64, "reader rejects missing service")
        try expect(CredentialReaderCommand.run(arguments: ["gp-vpn-password", "extra"], store: store) { output += $0 } == 64, "reader rejects extra arguments")
    }

    static func credentialResetControllerRuntimeBehavior() throws {
        let result = MainActor.assumeIsolated { runCredentialResetControllerProbe() }
        try expect(result.editableFieldCount == 5, "actual controller has five editable fields")
        try expect(result.secureFieldCount == 4, "actual controller has four secure fields")
        try expect(result.mismatchKeptOpen, "mismatch keeps window open")
        try expect(result.mismatchCompletionCount == 0, "mismatch does not complete")
        try expect(result.mismatchMessage == "Passwords do not match.", "mismatch shows stable native validation copy")
        try expect(!result.mismatchMessage.contains("one") && !result.mismatchMessage.contains("two"), "validation omits submitted values")
        try expect(result.cancelReturnedNil && result.cancelClearedFields, "cancel returns nil and clears fields")
        try expect(result.closeReturnedNil && result.closeCompletionCount == 1 && result.closeClearedFields, "window close returns nil exactly once and clears fields")
        try expect(result.submitReturnedValue && result.submitClearedFields, "successful completion returns value and clears fields")
    }

    struct ControllerProbeResult {
        let editableFieldCount: Int
        let secureFieldCount: Int
        let mismatchKeptOpen: Bool
        let mismatchMessage: String
        let mismatchCompletionCount: Int
        let cancelReturnedNil: Bool
        let cancelClearedFields: Bool
        let closeReturnedNil: Bool
        let closeCompletionCount: Int
        let closeClearedFields: Bool
        let submitReturnedValue: Bool
        let submitClearedFields: Bool
    }

    @MainActor static func runCredentialResetControllerProbe() -> ControllerProbeResult {
        _ = NSApplication.shared
        var mismatchCompletionCount = 0
        var mismatchValue: ValidatedCredentials?
        let mismatch = CredentialResetController(prefillUsername: "prefilled") { _, value in
            mismatchCompletionCount += 1
            mismatchValue = value
        }
        mismatch.present()
        let editableCount = inputFields(in: mismatch.harnessWindow?.contentView).count
        let secureCount = inputFields(in: mismatch.harnessWindow?.contentView).filter { $0 is NSSecureTextField }.count
        mismatch.harnessSetValues(first: "one", firstConfirmation: "two", second: "", secondConfirmation: "")
        mismatch.harnessSubmit()
        let mismatchMessage = mismatch.harnessValidationMessage
        let mismatchOpen = mismatch.harnessWindow != nil && mismatchValue == nil
        let mismatchCountBeforeCleanup = mismatchCompletionCount

        var cancelReturnedNil = false
        let cancel = CredentialResetController(prefillUsername: "prefilled") { _, value in cancelReturnedNil = value == nil }
        cancel.present()
        cancel.harnessSetValues(first: "one", firstConfirmation: "one", second: "", secondConfirmation: "")
        cancel.harnessCancel()
        let cancelCleared = fieldsCleared(cancel)

        var closeCompletionCount = 0
        var closeReturnedNil = false
        let close = CredentialResetController(prefillUsername: "prefilled") { _, value in
            closeCompletionCount += 1
            closeReturnedNil = value == nil
        }
        close.present()
        close.harnessSetValues(first: "one", firstConfirmation: "one", second: "", secondConfirmation: "")
        close.harnessWindow?.close()
        let closeCleared = fieldsCleared(close)

        var submitReturnedValue = false
        let submit = CredentialResetController(prefillUsername: "prefilled") { _, value in submitReturnedValue = value != nil }
        submit.present()
        submit.harnessSetValues(first: "one", firstConfirmation: "one", second: "JBSWY3DPEHPK3PXP", secondConfirmation: "JBSWY3DPEHPK3PXP")
        submit.harnessSubmit()
        let submitCleared = fieldsCleared(submit)
        mismatch.dismissWithoutSaving()

        return ControllerProbeResult(editableFieldCount: editableCount, secureFieldCount: secureCount, mismatchKeptOpen: mismatchOpen, mismatchMessage: mismatchMessage, mismatchCompletionCount: mismatchCountBeforeCleanup, cancelReturnedNil: cancelReturnedNil, cancelClearedFields: cancelCleared, closeReturnedNil: closeReturnedNil, closeCompletionCount: closeCompletionCount, closeClearedFields: closeCleared, submitReturnedValue: submitReturnedValue, submitClearedFields: submitCleared)
    }

    @MainActor static func fieldsCleared(_ controller: CredentialResetController) -> Bool {
        controller.harnessFieldValues.allSatisfy { $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
    }

    @MainActor static func inputFields(in root: NSView?) -> [NSTextField] {
        guard let root else { return [] }
        var result: [NSTextField] = []
        if let field = root as? NSTextField, field.isEditable { result.append(field) }
        for child in root.subviews { result.append(contentsOf: inputFields(in: child)) }
        return result
    }

    struct TOTPFixture { let home: URL; let root: URL; let lock: URL; let state: URL }

    static func makeTOTPFixture(createRoot: Bool = true) throws -> TOTPFixture {
        let home = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("hyu-totp-\(UUID().uuidString)", isDirectory: true)
        let support = home.appendingPathComponent("Library/Application Support", isDirectory: true)
        let root = support.appendingPathComponent("hyu-openconnect", isDirectory: true)
        try FileManager.default.createDirectory(at: support, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: home.path)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: home.appendingPathComponent("Library", isDirectory: true).path)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: support.path)
        if createRoot {
            try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        }
        return TOTPFixture(home: home, root: root, lock: root.appendingPathComponent("totp-counter.lock"), state: root.appendingPathComponent("totp-counter"))
    }

    static func writeSecureFile(_ url: URL, _ data: Data, mode: Int) throws {
        try data.write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
    }

    static func assertUnsafeFixture(name: String, prepare: (TOTPFixture) throws -> Void, preservedPath: KeyPath<TOTPFixture, URL>) throws {
        let fixture = try makeTOTPFixture()
        defer { try? FileManager.default.removeItem(at: fixture.home) }
        try writeSecureFile(fixture.lock, Data("lock".utf8), mode: 0o600)
        try writeSecureFile(fixture.state, Data("state".utf8), mode: 0o600)
        try prepare(fixture)
        try expectThrows(name) { try FileTOTPStateResetter(home: fixture.home).resetTOTPState() }
        try expect(pathExists(fixture[keyPath: preservedPath]), "\(name) preserved protected path")
        try expect(pathExists(fixture.lock) || name == "lock-wrong-type", "\(name) did not delete lock unexpectedly")
    }

    static func pathExists(_ url: URL) -> Bool {
        var info = stat()
        return lstat(url.path, &info) == 0
    }

    static func credentialResetLifecycleRuntime() throws {
        var coordinator = AppLifecycleCoordinator()
        try expect(coordinator.handle(.credentialResetRequested).effects == [.runCredentialTransaction], "reset starts one service transaction")
        try expect(coordinator.handle(.credentialResetRequested).effects.isEmpty, "duplicate reset suppressed")
        try expect(coordinator.handle(.disconnectRequested).effects.isEmpty, "disconnect suppressed during reset")
        try expect(coordinator.handle(.credentialTransactionCompleted(.success)).effects.isEmpty, "successful service replacement completes without reconnect effect")

        var failedTransaction = AppLifecycleCoordinator()
        _ = failedTransaction.handle(.credentialResetRequested)
        try expect(failedTransaction.handle(.credentialTransactionCompleted(.failure(code: .totpResetFailed))).effects == [.showCredentialResetError("TOTP_RESET_FAILED")], "transaction failure reports one error")

        var terminating = AppLifecycleCoordinator()
        _ = terminating.handle(.credentialResetRequested)
        try expect(terminating.handle(.terminateRequested).effects == [.dismissCredentialReset], "termination dismisses reset UI while request is active")
        try expect(terminating.handle(.credentialTransactionCompleted(.success)).effects == [.replyToTermination(true)], "termination waits for transaction completion before replying")
    }

}


final class HarnessCredentialStore: CredentialStore {
    enum StoreFailure: Error { case injected }
    var values: [CredentialKey: String?]
    var events: [String] = []
    private let failOnWriteCall: Int?
    private let failReadKey: CredentialKey?
    private let failRemoveKeys: Set<CredentialKey>
    private var writeCalls = 0
    init(initial: [CredentialKey: String], failOnWriteCall: Int? = nil, failReadKey: CredentialKey? = nil, failRemoveKeys: Set<CredentialKey> = []) { self.values = initial.mapValues { Optional($0) }; self.failOnWriteCall = failOnWriteCall; self.failReadKey = failReadKey; self.failRemoveKeys = failRemoveKeys }
    func read(_ key: CredentialKey) throws -> String? { events.append("read:\(key.rawValue)"); if key == failReadKey { throw StoreFailure.injected }; return values[key] ?? nil }
    func write(_ value: String, for key: CredentialKey) throws { writeCalls += 1; events.append("write:\(key.rawValue):\(value)"); if writeCalls == failOnWriteCall { throw StoreFailure.injected }; values[key] = value }
    func remove(_ key: CredentialKey) throws { events.append("remove:\(key.rawValue)"); if failRemoveKeys.contains(key) { throw StoreFailure.injected }; values.removeValue(forKey: key) }
}
final class HarnessTOTPResetter: TOTPStateResetting { enum ResetFailure: Error { case injected }; private let fail: Bool; private(set) var resetCount = 0; init(fail: Bool = false) { self.fail = fail }; func resetTOTPState() throws { resetCount += 1; if fail { throw ResetFailure.injected } } }

struct FakeMetadata: FileMetadataProviding {
    var ownerUID: uid_t; var fileMode: mode_t; var parentMode: mode_t; var isSymlink: Bool; var isRegular: Bool
    func metadata(for path: String) throws -> FileMetadata { FileMetadata(ownerUID: ownerUID, mode: path.hasSuffix("status.json") ? fileMode : parentMode, isSymlink: isSymlink, isRegularFile: isRegular, isExecutable: true) }
}
final class RecordingStatusSink: StatusUpdateSink { var presentations: [MenuPresentation] = []; func apply(_ presentation: MenuPresentation) { presentations.append(presentation) } }
final class SequenceStatusReader: StatusReading { var results: [Result<VPNStatus, Error>]; init(_ results: [Result<VPNStatus, Error>]) { self.results = results }; func readStatus() throws -> VPNStatus { try results.removeFirst().get() } }

final class SemaphoreStatusSink: StatusUpdateSink {
    private let lock = NSLock()
    private let semaphore: DispatchSemaphore
    private let expected: Int
    private(set) var presentations: [MenuPresentation] = []

    init(expected: Int) {
        self.expected = expected
        self.semaphore = DispatchSemaphore(value: 0)
    }

    func apply(_ presentation: MenuPresentation) {
        lock.lock()
        presentations.append(presentation)
        let shouldSignal = presentations.count >= expected
        lock.unlock()
        if shouldSignal { semaphore.signal() }
    }

    func wait(seconds: TimeInterval) -> Bool {
        semaphore.wait(timeout: .now() + seconds) == .success
    }
}

private func harnessFixtureDirectory() -> URL {
    Harness.packageRoot()
        .deletingLastPathComponent()
        .appendingPathComponent("tests/fixtures/protocol", isDirectory: true)
}

private func fixtureData(_ name: String) throws -> Data {
    try Data(contentsOf: harnessFixtureDirectory().appendingPathComponent(name))
}

private func framed(json: String) -> Data {
    let payload = Data(json.utf8)
    var frame = Data()
    var length = UInt32(payload.count).bigEndian
    withUnsafeBytes(of: &length) { frame.append(contentsOf: $0) }
    frame.append(payload)
    return frame
}

private struct HarnessMonotonicClock: RustIPCMonotonicClock {
    func nowNanoseconds() -> UInt64 { 0 }
}

private struct HarnessSocketMetadataProvider: SocketMetadataProviding {
    func metadata(for path: String) throws -> SocketFileMetadata {
        if path.hasSuffix(".sock") {
            return SocketFileMetadata(ownerUID: getuid(), mode: 0o600, isSymlink: false, isDirectory: false, isSocket: true, deviceID: 1, inode: 2)
        }
        return SocketFileMetadata(ownerUID: getuid(), mode: 0o700, isSymlink: false, isDirectory: true, isSocket: false, deviceID: 1, inode: 1)
    }
}

private final class HarnessSocketOperations: RustIPCSocketOperations, @unchecked Sendable {
    private var unreadResponse: Data
    private(set) var writtenFrame = Data()
    private let peerEffectiveUID: uid_t

    init(responseFrame: Data, peerEffectiveUID: uid_t) {
        self.unreadResponse = responseFrame
        self.peerEffectiveUID = peerEffectiveUID
    }

    func socket() -> Int32 { 42 }
    func setNoSigPipe(_ descriptor: Int32) {}
    func setNonBlocking(_ descriptor: Int32) throws {}
    func connect(_ descriptor: Int32, _ address: UnsafePointer<sockaddr>, _ length: socklen_t) -> Int32 { 0 }
    func poll(_ fds: UnsafeMutablePointer<pollfd>, _ count: nfds_t, _ timeout: Int32) -> Int32 {
        fds.pointee.revents = fds.pointee.events
        return 1
    }
    func read(_ descriptor: Int32, _ buffer: UnsafeMutableRawPointer, _ count: Int) -> Int {
        guard !unreadResponse.isEmpty else { return 0 }
        let amount = min(count, unreadResponse.count)
        unreadResponse.copyBytes(to: buffer.assumingMemoryBound(to: UInt8.self), count: amount)
        unreadResponse.removeFirst(amount)
        return amount
    }
    func write(_ descriptor: Int32, _ buffer: UnsafeRawPointer, _ count: Int) -> Int {
        writtenFrame.append(buffer.assumingMemoryBound(to: UInt8.self), count: count)
        return count
    }
    func socketError(_ descriptor: Int32) throws -> Int32 { 0 }
    func peerEffectiveUID(_ descriptor: Int32) throws -> uid_t { peerEffectiveUID }
    func close(_ descriptor: Int32) {}
}
