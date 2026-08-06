import Foundation
import Darwin
import HYUVPNPrivilegedHelper

struct HarnessFailure: Error, CustomStringConvertible { let description: String }
func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws { if !condition() { throw HarnessFailure(description: message) } }
func expectThrows(_ message: String, _ body: () throws -> Void) throws {
    do { try body(); throw HarnessFailure(description: "expected throw: \(message)") } catch is HarnessFailure { throw HarnessFailure(description: "expected throw: \(message)") } catch { }
}

@main struct Harness {
    static func main() {
        let argv = normalizedHarnessArguments(CommandLine.arguments)
        if argv.count != 1 {
            runHelperConfigFixtureMode(arguments: argv)
            return
        }
        do {
            if ProcessInfo.processInfo.environment["HYU_HELPER_HARNESS_FORCE_FAILURE"] == "1" {
                throw HarnessFailure(description: "deliberate failure requested")
            }
            let tests: [(String, () throws -> Void)] = [
                ("header-reader-does-not-overread", testHeaderReader),
                ("command-surface-allows-only-four", testCommandSurface),
                ("auth-binds-sudo-user-uid-console", testAuthorization),
                ("config-rejects-homebrew-front-door", testConfigRejectsHomebrewFrontDoor),
                ("config-accepts-root-runtime-shape", testConfigAcceptsRuntimeShape),
                ("config-rejects-unbound-runtime-shapes", testConfigRejectsUnboundRuntimeShapes),
                ("installed-guard-secure-path-and-wrapperd-manifest", testInstalledGuardSecurePathAndManifest),
                ("helper-config-fixture-mode-arguments", testHelperConfigFixtureModeArguments),
                ("helper-config-fixture-mode-decodes-temp-file", testHelperConfigFixtureModeDecodesTempFile),
                ("record-rejects-invalid-identity-bounds", testRecordValidation),
                ("argv-env-and-normal-exit-cleanup", testArgvEnvAndCleanup),
                ("start-refuses-existing-session", testStartRefusesExistingSession),
                ("spawn-failure-releases-lock", testSpawnFailureCleanup),
                ("metadata-failure-aborts-prepared-child", testMetadataFailureAbortsPreparedChild),
                ("commit-failure-preserves-record-when-teardown-fails", testCommitFailurePreservesRecordOnTeardownFailure),
                ("signal-after-commit-cleans-recorded-child", testSignalAfterCommitCleanup),
                ("nonzero-child-exit-clean-ledger-cleans-session", testNonzeroExitCleanLedgerCleansSession),
                ("nonzero-child-exit-dirty-ledger-preserves-session", testNonzeroExitDirtyLedgerPreservesSession),
                ("channel-loss-tears-down-and-cleans", testChannelLossCleanup),
                ("stop-term-kill-removes-record", testStopTermKill),
                ("stop-ledger-repair-required-preserves-evidence", testStopLedgerRepairRequiredPreservesEvidence),
                ("stop-mismatch-does-not-signal", testStopMismatchNoSignal),
                ("status-json", testStatusJSON),
                ("status-loads-tunnel-from-recorded-ledger", testStatusLoadsTunnelFromRecordedLedger),
                ("status-rejects-repair-required-ledger-tunnel", testStatusRejectsRepairRequiredLedgerTunnel),
                ("status-repair-required-on-mismatch", testStatusRepairRequired),
                ("repair-invokes-ledger-and-cleans-session", testRepairInvokesLedgerAndCleansSession),
                ("repair-foreign-mismatch-preserves-evidence", testRepairForeignMismatchPreservesEvidence),
                ("network-preinit-allows-absent-tundev", testPreInitWithoutTunnelDeviceRecordsBaseline),
                ("network-connect-expands-preinit-route-intent", testConnectExpandsPreInitRouteIntent),
                ("network-connect-requires-tundev-after-preinit", testConnectRequiresTunnelAfterPreInit),
                ("network-zero-exit-without-routes-fails-postcondition", testZeroExitWithoutRoutesFailsPostcondition),
                ("network-no-route-failure-retains-resolver-probe-for-repair", testNoRouteFailureRetainsResolverProbeForRepair),
                ("network-repair-captures-tunnel-resolver-before-mutation", testRepairCapturesTunnelResolverBeforeMutation),
                ("network-repair-restores-removed-gateway-baseline-route", testRepairRestoresRemovedGatewayBaselineRoute),
                ("network-repair-restores-missing-foreign-baseline-host-route", testRepairRestoresMissingForeignBaselineHostRoute),
                ("network-repair-retires-clean-ledger-after-default-network-change", testRepairRetiresCleanLedgerAfterDefaultNetworkChange),
                ("network-repair-restores-exact-retained-setup-dns-after-default-network-change", testRepairRestoresExactRetainedSetupDNSAfterDefaultNetworkChange),
                ("network-repair-keeps-stale-ledger-when-applied-route-remains", testRepairKeepsStaleLedgerWhenAppliedRouteRemains),
                ("network-repair-keeps-stale-ledger-on-mixed-setup-dns", testRepairKeepsStaleLedgerOnMixedSetupDNS),
                ("network-repair-keeps-stale-ledger-on-route-key-collision", testRepairKeepsStaleLedgerOnRouteKeyCollision),
                ("network-repair-keeps-stale-ledger-on-network-identity-change", testRepairKeepsStaleLedgerOnNetworkIdentityChange),
                ("system-network-tools-accepts-dhcp-missing-setup-dns", testSystemNetworkToolsAcceptsDHCPMissingSetupDNS),
                ("system-network-tools-normalizes-static-host-route-mask", testSystemNetworkToolsNormalizesStaticHostRouteMask),
                ("system-network-tools-resolves-explicit-network-host-route", testSystemNetworkToolsResolvesExplicitNetworkHostRoute),
                ("system-network-tools-rejects-cloned-host-route-as-static", testSystemNetworkToolsRejectsClonedHostRouteAsStatic),
                ("system-network-tools-rejects-default-route-for-host-query", testSystemNetworkToolsRejectsDefaultRouteForHostQuery),
                ("system-network-tools-restores-gateway-route-without-interface-modifier", testSystemNetworkToolsRestoresGatewayRouteWithoutInterfaceModifier),
                ("network-sanitized-env-preserves-vpnpid-and-mask", testSanitizedEnvironmentPreservesVPNPIDAndMask),
                ("network-preinit-ledger-drift-blocks-upstream", testPreInitLedgerDriftBlocksUpstream),
                ("network-strict-ipv4-split-inputs", testStrictIPv4SplitInputs),
                ("network-invalid-tunnel-rejected-before-preinit", testInvalidTunnelRejectedBeforePreInit),
                ("ledger-schema-route-records-and-resolver-order", testLedgerSchemaRouteRecordsAndResolverOrder),
                ("fake-lock-concurrent-rejection", testFakeLockConcurrentRejection),
                ("system-child-birthtime-monitor", testSystemChildBirthtimeMonitor),
                ("system-monitor-sigterm-cleans-child-group", { try testSystemSignalCleanup(SIGTERM) }),
                ("system-monitor-sigint-cleans-child-group", { try testSystemSignalCleanup(SIGINT) })
            ]
            for (name, test) in tests {
                print("RUN \(name)")
                try test()
                print("PASS \(name)")
            }
            print("HARNESS PASS \(tests.count) tests")
        } catch {
            FileHandle.standardError.write(Data("HARNESS FAIL: \(error)\n".utf8))
            exit(1)
        }
    }


    static func normalizedHarnessArguments(_ arguments: [String]) -> [String] {
        guard arguments.count > 1, arguments[1] == "--" else { return arguments }
        return [arguments[0]] + arguments.dropFirst(2)
    }

    static func runHelperConfigFixtureMode(arguments: [String]) {
        guard arguments.count == 3, arguments[1] == "--validate-helper-config-fixture" else {
            print("FAIL invalid-arguments")
            exit(64)
        }
        do {
            try validateHelperConfigFixture(path: arguments[2])
            print("PASS helper-config-fixture")
        } catch {
            print("FAIL helper-config-fixture")
            exit(1)
        }
    }

    static func validateHelperConfigFixture(path: String) throws {
        guard isAllowedHelperConfigFixturePath(path) else { throw HarnessFailure(description: "invalid fixture path") }
        let url = URL(fileURLWithPath: path).standardizedFileURL
        let data = try Data(contentsOf: url)
        guard !data.isEmpty, data.count <= 4096 else { throw HarnessFailure(description: "invalid fixture size") }
        let metadata = FakeMetadata.secure(paths: helperConfigArtifactPaths())
        _ = try HelperConfiguration.decode(data: data, metadata: metadata, validateRuntime: false)
    }

    static func isAllowedHelperConfigFixturePath(_ path: String) -> Bool {
        guard !path.contains("\n"), path.utf8.count <= 1024 else { return false }
        let fixture = URL(fileURLWithPath: path).standardizedFileURL.path
        let tmp = FileManager.default.temporaryDirectory.standardizedFileURL.path
        return fixture == tmp || fixture.hasPrefix(tmp.hasSuffix("/") ? tmp : tmp + "/")
    }

    static func helperConfigArtifactPaths() -> [String] {
        [
            "/",
            "/Library", "/Library/Application Support", "/Library/Application Support/HYU VPN", "/Library/Application Support/HYU VPN/runtime", "/Library/Application Support/HYU VPN/runtime/current", "/Library/Application Support/HYU VPN/runtime/current/bin", "/Library/Application Support/HYU VPN/runtime/current/bin/openconnect",
            "/Library/Application Support/HYU VPN/runtime/vpnc", "/Library/PrivilegedHelperTools/com.hyu.vpn.vpnc-wrapper",
            "/Library/Application Support/HYU VPN/runtime/gp-hip-report",
            "/private", "/private/var", "/private/var/db", "/private/var/db/hyu-vpn", "/private/var/db/hyu-vpn/ledger"
        ]
    }

    static func testHeaderReader() throws {        let input = CountingByteInput(Array("HYU-Username: alice@hanyang.ac.kr\n\nOTP".utf8))
        let request = try BoundedStartHeaderReader.read(from: input)
        try expect(request.username == "alice@hanyang.ac.kr", "username parsed")
        try expect(input.remaining == Array("OTP".utf8), "OTP bytes remain unread")
        try expectThrows("bad header") { _ = try BoundedStartHeaderReader.read(from: CountingByteInput(Array("HYU-Username: bad user\n\n".utf8))) }
    }

    static func testCommandSurface() throws {
        let parsed = try HelperCommand.parse(["helper", "start"])
        try expect(parsed == .start, "start parses")
        try expectThrows("extra args") { _ = try HelperCommand.parse(["helper", "start", "alice"]) }
    }


    static func testAuthorization() throws {
        try InvocationIdentity(effectiveUID: 0, sudoUID: 501, sudoUser: "alice", consoleUID: 501, sudoAccountUID: 501).validateStartAuthorization()
        try expectThrows("uid mismatch") { try InvocationIdentity(effectiveUID: 0, sudoUID: 502, sudoUser: "alice", consoleUID: 501, sudoAccountUID: 502).validateStartAuthorization() }
        try expectThrows("account mismatch") { try InvocationIdentity(effectiveUID: 0, sudoUID: 501, sudoUser: "alice", consoleUID: 501, sudoAccountUID: 502).validateStartAuthorization() }
    }

    static func testConfigRejectsHomebrewFrontDoor() throws {
        let config = HelperConfiguration(openConnectExecutable: URL(fileURLWithPath: "/opt/homebrew/bin/openconnect"), vpncScript: URL(fileURLWithPath: "/Library/PrivilegedHelperTools/com.hyu.vpn.vpnc-wrapper"), hipWrapper: URL(fileURLWithPath: "/Library/Application Support/HYU VPN/runtime/gp-hip-report"), stateDirectory: URL(fileURLWithPath: "/private/var/db/hyu-vpn"), ledgerDirectory: URL(fileURLWithPath: "/private/var/db/hyu-vpn/ledger"), executableSHA256: String(repeating: "a", count: 64), vpncScriptSHA256: String(repeating: "b", count: 64), hipWrapperSHA256: String(repeating: "c", count: 64))
        try expectThrows("front door rejected") { try config.validateStaticShape() }
    }

    static func testConfigAcceptsRuntimeShape() throws {
        let config = HelperConfiguration(openConnectExecutable: URL(fileURLWithPath: "/Library/Application Support/HYU VPN/runtime/current/bin/openconnect"), vpncScript: URL(fileURLWithPath: "/Library/PrivilegedHelperTools/com.hyu.vpn.vpnc-wrapper"), hipWrapper: URL(fileURLWithPath: "/Library/Application Support/HYU VPN/runtime/gp-hip-report"), stateDirectory: URL(fileURLWithPath: "/private/var/db/hyu-vpn"), ledgerDirectory: URL(fileURLWithPath: "/private/var/db/hyu-vpn/ledger"), executableSHA256: String(repeating: "a", count: 64), vpncScriptSHA256: String(repeating: "b", count: 64), hipWrapperSHA256: String(repeating: "c", count: 64))
        try config.validateStaticShape()
        try expect(config.vpncScript.path == HelperConfiguration.fallbackProduction().vpncScript.path, "production wrapper path bound")
        try expect(!config.vpncScript.path.contains(" "), "vpnc shell command path has no whitespace")
    }

    static func testConfigRejectsUnboundRuntimeShapes() throws {
        for path in [
            "/Library/Application Support/HYU VPN/runtime/openconnect/9.12/bin/openconnect",
            "/Library/Application Support/HYU VPN/runtime/current/openconnect",
            "/Library/Application Support/HYU VPN/runtime/current/bin/openconnect2"
        ] {
            let config = HelperConfiguration(openConnectExecutable: URL(fileURLWithPath: path), vpncScript: URL(fileURLWithPath: "/Library/PrivilegedHelperTools/com.hyu.vpn.vpnc-wrapper"), hipWrapper: URL(fileURLWithPath: "/Library/Application Support/HYU VPN/runtime/gp-hip-report"), stateDirectory: URL(fileURLWithPath: "/private/var/db/hyu-vpn"), ledgerDirectory: URL(fileURLWithPath: "/private/var/db/hyu-vpn/ledger"), executableSHA256: String(repeating: "a", count: 64), vpncScriptSHA256: String(repeating: "b", count: 64), hipWrapperSHA256: String(repeating: "c", count: 64))
            try expectThrows("unbound runtime rejected: \(path)") { try config.validateStaticShape() }
        }
    }


    static func testHelperConfigFixtureModeArguments() throws {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("helper-config.json").path
        try expect(Harness.isAllowedHelperConfigFixturePath(tmp), "temp fixture path allowed")
        try expect(!Harness.isAllowedHelperConfigFixturePath("/Library/Application Support/HYU VPN/helper-config.json"), "installed path rejected")
        try expect(!Harness.isAllowedHelperConfigFixturePath(tmp + "\nspoof"), "newline path rejected")
    }

    static func testHelperConfigFixtureModeDecodesTempFile() throws {
        let url = try writeHelperConfigFixture(extra: nil)
        try validateHelperConfigFixture(path: url.path)
        let bad = try writeHelperConfigFixture(extra: "unexpected")
        try expectThrows("unknown key rejected") { try validateHelperConfigFixture(path: bad.path) }
    }

    static func testInstalledGuardSecurePathAndManifest() throws {
        var metadata = FakeMetadata.secure(paths: ["/", "/Library", "/Library/Application Support", "/Library/Application Support/HYU VPN", "/Library/Application Support/HYU VPN/runtime", "/Library/Application Support/HYU VPN/runtime/vpnc", InstalledExecutionGuard.wrapperDaemonPath, InstalledExecutionGuard.wrapperDaemonHashManifestPath])
        try InstalledExecutionGuard.validateInstalledPathSecurity(path: InstalledExecutionGuard.wrapperDaemonPath, metadata: metadata)
        try InstalledExecutionGuard.validateInstalledPathSecurity(path: InstalledExecutionGuard.wrapperDaemonHashManifestPath, metadata: metadata)
        try InstalledExecutionGuard.validateHash(actualSHA256: String(repeating: "a", count: 64), manifestText: String(repeating: "a", count: 64) + "\n")
        metadata.modes["/Library/Application Support/HYU VPN/runtime/vpnc"] = 0o775
        try expectThrows("writable parent rejected") { try InstalledExecutionGuard.validateInstalledPathSecurity(path: InstalledExecutionGuard.wrapperDaemonPath, metadata: metadata) }
        metadata.modes["/Library/Application Support/HYU VPN/runtime/vpnc"] = 0o755
        metadata.symlinks.insert(InstalledExecutionGuard.wrapperDaemonHashManifestPath)
        try expectThrows("manifest symlink rejected") { try InstalledExecutionGuard.validateInstalledPathSecurity(path: InstalledExecutionGuard.wrapperDaemonHashManifestPath, metadata: metadata) }
        try expectThrows("hash mismatch") { try InstalledExecutionGuard.validateHash(actualSHA256: String(repeating: "a", count: 64), manifestText: String(repeating: "b", count: 64)) }
    }

    static func testRecordValidation() throws {
        var harness = HelperHarness()
        try harness.installRecord(pid: 1)
        try expectThrows("pid > 1") { _ = try harness.run(command: .stop) }
        harness = HelperHarness(); try harness.installRecord(nonce: "short")
        try expectThrows("nonce bounds") { _ = try harness.run(command: .stop) }
        harness = HelperHarness(); try harness.installRecord(ledgerNonce: "othernonce")
        try expectThrows("ledger nonce") { _ = try harness.run(command: .stop) }
        harness = HelperHarness(); try harness.installRecord(ledgerPath: harness.config.ledgerDirectory.appendingPathComponent("nonce12345.ledger.evil"))
        try expectThrows("exact ledger path") { _ = try harness.run(command: .stop) }
    }

    static func testArgvEnvAndCleanup() throws {
        var harness = HelperHarness()
        let result = try harness.run(command: .start, startRequest: StartRequest(username: "vpn.user@hanyang.ac.kr"))
        try expect(result.status == .started, "start result")
        let spawn = try require(harness.process.spawned, "spawned")
        try expect(spawn.argv.contains("--authgroup=HYU-ExternalGW-General"), "authgroup")
        try expect(spawn.argv.contains("--csd-user=alice"), "csd user")
        try expect(!spawn.argv.contains("--server=secure.hanyang.ac.kr"), "no server flag")
        try expect(spawn.argv.last == "secure.hanyang.ac.kr", "positional portal")
        try expect(spawn.environment == ["HYU_NONCE": "nonce12345", "HYU_SESSION_LEDGER": harness.config.ledgerDirectory.appendingPathComponent("nonce12345.ledger").path], "only fixed HYU env")
        try expect(spawn.environment["DYLD_INSERT_LIBRARIES"] == nil && spawn.environment["PASSWORD"] == nil, "no hostile loader or secret env")
        try expect(harness.process.signalGuardBegun && harness.process.signalGuardEnded, "signal guard covers lifecycle")
        try expect(harness.store.record == nil, "record removed after foreground exit")
        try expect(harness.lock.releasedUIDs == [501], "lock released")
    }

    static func testStartRefusesExistingSession() throws {
        var harness = HelperHarness()
        try harness.installRecord()
        try expectThrows("existing session") { _ = try harness.run(command: .start, startRequest: StartRequest(username: "alice")) }
        try expect(harness.process.spawned == nil, "no spawn on existing session")
    }

    static func testStatusJSON() throws {
        var harness = HelperHarness()
        try harness.installRecord(tunnel: "utun9")
        harness.process.liveIdentity = .matching(pid: 2222, pgid: 3333, birth: 77, executable: harness.config.openConnectExecutable.path)
        let result = try harness.run(command: .status)
        let doc = try require(result.statusDocument, "status doc")
        try expect(doc.state == "running", "running")
        try expect(doc.tunnel_interface == "utun9", "interface")
        let line = try doc.singleLineJSON()
        try expect(!line.contains("\n"), "single line")
    }

    static func testStatusLoadsTunnelFromRecordedLedger() throws {
        var (harness, root) = try helperHarnessWithRecordedLedger(status: "recorded", tunnel: "utun7")
        defer { try? FileManager.default.removeItem(at: root) }
        let result = try harness.run(command: .status)
        try expect(result.status == .running, "recorded live ledger remains running")
        try expect(result.statusDocument?.tunnel_interface == "utun7", "status derives owned tunnel from ledger")
    }

    static func testStatusRejectsRepairRequiredLedgerTunnel() throws {
        var (harness, root) = try helperHarnessWithRecordedLedger(status: "repair-required", tunnel: "utun7")
        defer { try? FileManager.default.removeItem(at: root) }
        let result = try harness.run(command: .status)
        try expect(result.status == .repairRequired, "repair-required ledger is not reported as owned running tunnel")
        try expect(result.statusDocument?.tunnel_interface == nil, "repair-required tunnel remains unowned")
    }


    static func testSpawnFailureCleanup() throws {
        var harness = HelperHarness()
        harness.process.spawnError = HelperError.processMismatch
        try expectThrows("spawn failure") { _ = try harness.run(command: .start, startRequest: StartRequest(username: "alice")) }
        try expect(harness.lock.releasedUIDs == [501], "lock released")
        try expect(harness.store.record == nil, "no record")
    }

    static func testMetadataFailureAbortsPreparedChild() throws {
        var harness = HelperHarness()
        harness.store.saveError = HelperError.insecurePath("record")
        try expectThrows("metadata failure") { _ = try harness.run(command: .start, startRequest: StartRequest(username: "alice")) }
        try expect(harness.process.aborted == [1200], "prepared child aborted")
        try expect(harness.lock.releasedUIDs == [501], "lock released")
    }

    static func testCommitFailurePreservesRecordOnTeardownFailure() throws {
        var harness = HelperHarness()
        harness.process.commitError = HelperError.processMismatch
        harness.process.killError = HelperError.processMismatch
        try expectThrows("teardown incomplete") { _ = try harness.run(command: .start, startRequest: StartRequest(username: "alice")) }
        try expect(harness.store.record != nil, "durable record preserved for repair")
        try expect(harness.lock.releasedUIDs == [501], "lock released")
    }

    static func testSignalAfterCommitCleanup() throws {
        var harness = HelperHarness()
        harness.process.injectSignalAfterCommit = true
        harness.process.waitResults = [false, true]
        _ = try harness.run(command: .start, startRequest: StartRequest(username: "alice"))
        try expect(harness.process.signalGuardBegun && harness.process.signalGuardEnded, "guard active across commit")
        try expect(harness.process.signals == [.termGroup(pgid: 1200), .killGroup(pgid: 1200)], "signal after commit cleans group")
        try expect(harness.store.record == nil, "record removed after proven signal cleanup")
    }

    static func testNonzeroExitCleanLedgerCleansSession() throws {
        var harness = HelperHarness()
        harness.process.monitorExitStatus = 1
        harness.ledgerCoordinator.verifyResult = nil
        try expectThrows("nonzero child") { _ = try harness.run(command: .start, startRequest: StartRequest(username: "alice")) }
        try expect(harness.store.record == nil, "clean ledger removal clears stale nonzero session")
    }

    static func testNonzeroExitDirtyLedgerPreservesSession() throws {
        var harness = HelperHarness()
        harness.process.monitorExitStatus = 1
        harness.ledgerCoordinator.verifyResult = HelperError.teardownIncomplete("ledger repair-required")
        try expectThrows("nonzero child") { _ = try harness.run(command: .start, startRequest: StartRequest(username: "alice")) }
        try expect(harness.store.record != nil, "dirty ledger preserves nonzero child repair evidence")
    }

    static func testChannelLossCleanup() throws {
        var harness = HelperHarness()
        harness.process.channelLossAfterSpawn = true
        harness.process.waitResults = [false, true]
        _ = try harness.run(command: .start, startRequest: StartRequest(username: "alice"))
        try expect(harness.process.signals == [.termGroup(pgid: 1200), .killGroup(pgid: 1200)], "term kill")
        try expect(harness.store.record == nil, "record removed")
        try expect(harness.lock.releasedUIDs == [501], "lock released")
    }

    static func testStopTermKill() throws {
        var harness = HelperHarness()
        try harness.installRecord()
        harness.process.liveIdentity = .matching(pid: 2222, pgid: 3333, birth: 77, executable: harness.config.openConnectExecutable.path)
        harness.process.waitResults = [false, true]
        let result = try harness.run(command: .stop)
        try expect(result.status == .stopped, "stopped")
        try expect(harness.process.signals == [.termGroup(pgid: 3333), .killGroup(pgid: 3333)], "term kill")
        try expect(harness.store.record == nil, "record removed")
    }

    static func testStopLedgerRepairRequiredPreservesEvidence() throws {
        var harness = HelperHarness()
        try harness.installRecord()
        harness.process.liveIdentity = .matching(pid: 2222, pgid: 3333, birth: 77, executable: harness.config.openConnectExecutable.path)
        harness.process.waitResults = [true]
        harness.ledgerCoordinator.verifyResult = HelperError.teardownIncomplete("ledger repair-required")
        try expectThrows("ledger blocks stop cleanup") { _ = try harness.run(command: .stop) }
        try expect(harness.store.record != nil, "durable session preserved when ledger remains repair-required")
    }

    static func testStopMismatchNoSignal() throws {
        var harness = HelperHarness()
        try harness.installRecord()
        harness.process.liveIdentity = .matching(pid: 9999, pgid: 3333, birth: 77, executable: harness.config.openConnectExecutable.path)
        try expectThrows("mismatch") { _ = try harness.run(command: .stop) }
        try expect(harness.process.signals.isEmpty, "no signals")
    }

    static func testStatusRepairRequired() throws {
        var harness = HelperHarness()
        try harness.installRecord()
        harness.process.liveIdentity = nil
        let result = try harness.run(command: .status)
        try expect(result.status == .repairRequired, "repair required")
        try expect(result.statusDocument?.state == "repair-required", "json state")
    }

    static func testRepairInvokesLedgerAndCleansSession() throws {
        var harness = HelperHarness()
        try harness.installRecord()
        harness.process.liveIdentity = nil
        let result = try harness.run(command: .repair)
        try expect(result.status == .stopped, "repair completed")
        try expect(harness.ledgerCoordinator.repairedNonces == ["nonce12345"], "actual ledger repair invoked")
        try expect(harness.store.record == nil, "successful repair cleans session")
    }

    static func testRepairForeignMismatchPreservesEvidence() throws {
        var harness = HelperHarness()
        try harness.installRecord()
        harness.process.liveIdentity = nil
        harness.ledgerCoordinator.repairResult = HelperError.processMismatch
        try expectThrows("foreign mismatch") { _ = try harness.run(command: .repair) }
        try expect(harness.store.record != nil, "foreign repair mismatch preserves evidence")
        try expect(harness.ledgerCoordinator.repairedNonces == ["nonce12345"], "repair attempted exact nonce")
    }

    static func testSystemNetworkToolsAcceptsDHCPMissingSetupDNS() throws {
        let dir = try harnessTempDir()
        let scutil = dir.appendingPathComponent("scutil")
        try """
        #!/bin/sh
        input="$(cat)"
        case "$1:$input" in
          "--dns:"*)
            printf '%s\\n' 'DNS configuration'
            printf '%s\\n' 'resolver #1'
            printf '%s\\n' '  nameserver[0] : 9.9.9.9'
            ;;
          *"Setup:/Network/Service/service-wifi/DNS"*)
            printf '%s\\n' '  No such key'
            ;;
          *"State:/Network/Service/service-wifi/DNS"*)
            printf '%s\\n' '<dictionary> {'
            printf '%s\\n' '  ServerAddresses : <array> {'
            printf '%s\\n' '    0 : 9.9.9.9'
            printf '%s\\n' '  }'
            printf '%s\\n' '}'
            ;;
          *"State:/Network/Global/DNS"*)
            printf '%s\\n' '<dictionary> {'
            printf '%s\\n' '  ServerAddresses : <array> {'
            printf '%s\\n' '    0 : 9.9.9.9'
            printf '%s\\n' '  }'
            printf '%s\\n' '}'
            ;;
          *)
            printf '%s\\n' '  No such key'
            ;;
        esac
        """.write(to: scutil, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: scutil.path)
        let paths = RuntimePaths(
            ledgerRoot: dir,
            upstream: dir.appendingPathComponent("vpnc-script"),
            route: dir.appendingPathComponent("route"),
            scutil: scutil,
            sysctl: dir.appendingPathComponent("sysctl"),
            networksetup: dir.appendingPathComponent("networksetup")
        )

        let snapshot = try SystemNetworkTools(paths: paths).resolver(serviceID: "service-wifi", baselineInterface: "en0", tunnelInterface: nil)

        let setupKey = "Setup:/Network/Service/service-wifi/DNS"
        let stateKey = "State:/Network/Service/service-wifi/DNS"
        try expect(snapshot.servers.isEmpty, "missing setup DNS records no manual DNS servers")
        try expect(snapshot.serversPresent == false, "missing setup DNS preserves absent ServerAddresses")
        try expect(snapshot.surfaces[setupKey]?.keyPresent == false, "missing setup DNS key recorded as absent")
        try expect(snapshot.surfaces[stateKey]?.servers == ["9.9.9.9"], "DHCP state DNS still captured for drift and repair")
    }

    static func testSystemNetworkToolsNormalizesStaticHostRouteMask() throws {
        let tools = try systemNetworkToolsWithRouteOutput("""
           route to: 198.51.100.9
        destination: 198.51.100.9
            gateway: 192.0.2.1
          interface: en0
              flags: <UP,GATEWAY,HOST,DONE,STATIC>
        """)

        let route = try tools.route(destination: "198.51.100.9", netmask: "255.255.255.255")

        try expect(route?.destination == "198.51.100.9", "static host route destination preserved")
        try expect(route?.gateway == "192.0.2.1", "static host route gateway preserved")
        try expect(route?.interface == "en0", "static host route interface preserved")
        try expect(route?.netmask == "255.255.255.255", "missing Darwin host mask normalized to IPv4 /32")
    }

    static func testSystemNetworkToolsResolvesExplicitNetworkHostRoute() throws {
        let tools = try systemNetworkToolsWithRouteScript("""
        #!/bin/sh
        case "$*" in
          "-n get 198.51.100.9")
            cat <<'HYU_ROUTE_OUTPUT'
           route to: 198.51.100.9
        destination: 198.51.100.9
            gateway: 10.200.200.44
          interface: utun10
              flags: <UP,GATEWAY,HOST,DONE,WASCLONED,IFSCOPE,IFREF>
        HYU_ROUTE_OUTPUT
            ;;
          "-n get -net 198.51.100.9 -netmask 255.255.255.255")
            cat <<'HYU_ROUTE_OUTPUT'
           route to: 198.51.100.9
        destination: 198.51.100.9
               mask: 255.255.255.255
            gateway: 10.200.200.44
          interface: utun10
              flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>
        HYU_ROUTE_OUTPUT
            ;;
          *) exit 64 ;;
        esac
        """)

        let route = try tools.route(destination: "198.51.100.9", netmask: "255.255.255.255")

        try expect(route?.destination == "198.51.100.9", "explicit /32 network route destination preserved")
        try expect(route?.gateway == "10.200.200.44", "explicit /32 network route gateway preserved")
        try expect(route?.interface == "utun10", "explicit /32 network route interface preserved")
        try expect(route?.netmask == "255.255.255.255", "explicit /32 network route mask preserved")
    }

    static func testSystemNetworkToolsRejectsClonedHostRouteAsStatic() throws {
        let tools = try systemNetworkToolsWithRouteOutput("""
           route to: 198.51.100.9
        destination: 198.51.100.9
            gateway: 192.0.2.1
          interface: en0
              flags: <UP,GATEWAY,HOST,DONE,WASCLONED>
        """)

        let route = try tools.route(destination: "198.51.100.9", netmask: "255.255.255.255")

        try expect(route == nil, "kernel-cloned host route is not accepted as wrapper-owned static route")
    }

    static func testSystemNetworkToolsRejectsDefaultRouteForHostQuery() throws {
        let tools = try systemNetworkToolsWithRouteOutput("""
           route to: 198.51.100.9
        destination: default
               mask: default
            gateway: 192.0.2.1
          interface: en0
              flags: <UP,GATEWAY,DONE,STATIC,GLOBAL>
        """)

        let route = try tools.route(destination: "198.51.100.9", netmask: "255.255.255.255")

        try expect(route == nil, "default route lookup result is not accepted as an explicit host route")
    }


    static func testPreInitLedgerDriftBlocksUpstream() throws {
        let fixture = try HarnessNetworkFixture()
        let env = fixture.validEnv()
        try fixture.runner.run(reason: "pre-init", nonce: fixture.nonce, environment: env, suppliedLedgerPath: fixture.ledger)
        fixture.tools.defaultGateway = "192.0.2.254"
        try expectThrows("drift blocks connect") { try fixture.runner.run(reason: "connect", nonce: fixture.nonce, environment: env, suppliedLedgerPath: fixture.ledger) }
        try expect(fixture.upstream.reasons == ["pre-init"], "connect upstream not called after drift")
        let saved = try NetworkLedgerStore(path: fixture.ledger, expectedOwnerUID: UInt32(getuid())).load(expectedNonce: fixture.nonce)
        try expect(saved.status == "repair-required", "ledger marked repair-required")
    }

    static func testPreInitWithoutTunnelDeviceRecordsBaseline() throws {
        let fixture = try HarnessNetworkFixture()
        // OpenConnect 9.21 invokes pre-init before os_setup_tun() and therefore
        // explicitly unsets TUNDEV when no interface was forced with -i.
        let env = ["HYU_SESSION_LEDGER": fixture.ledger.path]
        try fixture.runner.run(reason: "pre-init", nonce: fixture.nonce, environment: env, suppliedLedgerPath: fixture.ledger)
        try expect(fixture.upstream.reasons == ["pre-init"], "pre-init upstream called once")
        let saved = try NetworkLedgerStore(path: fixture.ledger, expectedOwnerUID: UInt32(getuid())).load(expectedNonce: fixture.nonce)
        try expect(saved.status == "recorded", "pre-init baseline recorded")
        try expect(saved.routeRecords.isEmpty, "pre-init baseline has no route intent")
    }

    static func testConnectExpandsPreInitRouteIntent() throws {
        let fixture = try HarnessNetworkFixture()
        let preInitEnv = ["HYU_SESSION_LEDGER": fixture.ledger.path]
        try fixture.runner.run(reason: "pre-init", nonce: fixture.nonce, environment: preInitEnv, suppliedLedgerPath: fixture.ledger)
        fixture.upstream.onRun = { reason, _ in
            guard reason == "connect" else { return }
            let saved = try NetworkLedgerStore(path: fixture.ledger, expectedOwnerUID: UInt32(getuid())).load(expectedNonce: fixture.nonce)
            fixture.upstream.sawRouteIntent = saved.routeRecords.contains { $0.applied.destination == "10.0.0.0" && $0.applied.gateway == "10.10.0.1" && $0.applied.interface == "utun7" }
            fixture.tools.routes = saved.routeRecords.map { RouteSnapshot(destination: $0.applied.destination, gateway: $0.applied.gateway, interface: $0.applied.interface, netmask: $0.applied.netmask, protocol: $0.applied.protocol) }
        }
        try fixture.runner.run(reason: "connect", nonce: fixture.nonce, environment: fixture.validEnv(), suppliedLedgerPath: fixture.ledger)
        try expect(fixture.upstream.reasons == ["pre-init", "connect"], "pre-init and connect upstream called")
        try expect(fixture.upstream.sawRouteIntent, "route intent persisted before connect upstream")
        let saved = try NetworkLedgerStore(path: fixture.ledger, expectedOwnerUID: UInt32(getuid())).load(expectedNonce: fixture.nonce)
        try expect(saved.routeRecords.count == 2, "connect expanded protected and gateway routes")
        try expect(saved.tunnelInterface == "utun7", "connect recorded tunnel interface")
    }

    static func testConnectRequiresTunnelAfterPreInit() throws {
        let fixture = try HarnessNetworkFixture()
        try fixture.runner.run(
            reason: "pre-init",
            nonce: fixture.nonce,
            environment: ["HYU_SESSION_LEDGER": fixture.ledger.path],
            suppliedLedgerPath: fixture.ledger
        )
        var connectEnv = fixture.validEnv()
        connectEnv.removeValue(forKey: "TUNDEV")

        try expectThrows("connect requires TUNDEV") {
            try fixture.runner.run(reason: "connect", nonce: fixture.nonce, environment: connectEnv, suppliedLedgerPath: fixture.ledger)
        }
        try expect(fixture.upstream.reasons == ["pre-init"], "missing connect tunnel rejected before upstream mutation")
    }

    static func testZeroExitWithoutRoutesFailsPostcondition() throws {
        let fixture = try HarnessNetworkFixture()
        do {
            try fixture.runner.run(reason: "connect", nonce: fixture.nonce, environment: fixture.validEnv(), suppliedLedgerPath: fixture.ledger)
            throw HarnessFailure(description: "zero-exit upstream without routes was accepted")
        } catch let error as HelperError {
            try expect(error == .networkPostconditionFailed, "postcondition error preserved")
        }
        try expect(fixture.upstream.calls == 1, "upstream called once")
        let saved = try NetworkLedgerStore(path: fixture.ledger, expectedOwnerUID: UInt32(getuid())).load(expectedNonce: fixture.nonce)
        try expect(saved.status == "repair-required", "missing routes require repair")
        try expect(saved.tunnelInterface == "utun7", "failed connect retains the validated repair probe without claiming success")
    }

    static func testNoRouteFailureRetainsResolverProbeForRepair() throws {
        let fixture = try HarnessNetworkFixture()
        fixture.tools.includeTunnelSurface = true

        do {
            try fixture.runner.run(reason: "connect", nonce: fixture.nonce, environment: fixture.validEnv(), suppliedLedgerPath: fixture.ledger)
            throw HarnessFailure(description: "missing routes were accepted")
        } catch let error as HelperError {
            try expect(error == .networkPostconditionFailed, "missing routes preserve postcondition failure")
        }

        let failed = try NetworkLedgerStore(path: fixture.ledger, expectedOwnerUID: UInt32(getuid())).load(expectedNonce: fixture.nonce)
        try expect(failed.status == "repair-required", "failed connect requires repair")
        try expect(failed.tunnelInterface == "utun7", "failed connect retains validated resolver probe tunnel")

        try fixture.runner.run(reason: "repair", nonce: fixture.nonce, environment: [:], suppliedLedgerPath: fixture.ledger)

        try expect(!FileManager.default.fileExists(atPath: fixture.ledger.path), "repair removes failed no-route ledger")
    }

    static func testRepairCapturesTunnelResolverBeforeMutation() throws {
        let fixture = try HarnessNetworkFixture()
        fixture.tools.includeTunnelSurface = true
        fixture.upstream.onRun = { reason, _ in
            guard reason == "connect" else { return }
            let saved = try NetworkLedgerStore(path: fixture.ledger, expectedOwnerUID: UInt32(getuid())).load(expectedNonce: fixture.nonce)
            fixture.tools.routes = saved.routeRecords.map(\.applied.routeSnapshot)
        }

        try fixture.runner.run(reason: "connect", nonce: fixture.nonce, environment: fixture.validEnv(), suppliedLedgerPath: fixture.ledger)

        let recorded = try NetworkLedgerStore(path: fixture.ledger, expectedOwnerUID: UInt32(getuid())).load(expectedNonce: fixture.nonce)
        let tunnelSurface = "State:/Network/Interface/utun7/DNS"
        try expect(recorded.dnsBefore?.surfaces[tunnelSurface]?.keyPresent == false, "baseline records missing tunnel DNS surface")
        try expect(recorded.dnsApplied?.surfaces[tunnelSurface]?.keyPresent == false, "applied snapshot records tunnel DNS surface")
        try expect(recorded.dnsBefore?.activeInterface == "en0", "baseline keeps the physical interface active")
        try expect(recorded.dnsApplied?.activeInterface == "utun7", "applied snapshot records the actual tunnel interface")

        try fixture.runner.run(reason: "repair", nonce: fixture.nonce, environment: [:], suppliedLedgerPath: fixture.ledger)

        try expect(!FileManager.default.fileExists(atPath: fixture.ledger.path), "repair removes clean ledger")
        try expect(fixture.tools.routes.isEmpty, "repair removes applied routes")
    }

    static func testRepairRestoresRemovedGatewayBaselineRoute() throws {
        let fixture = try HarnessNetworkFixture()
        let gatewayBypass = RouteSnapshot(
            destination: "198.51.100.9",
            gateway: "192.0.2.1",
            interface: "en0",
            netmask: "255.255.255.255",
            protocol: "ipv4"
        )
        fixture.tools.routes = [gatewayBypass]
        fixture.upstream.onRun = { reason, _ in
            guard reason == "connect" else { return }
            let intent = try NetworkLedgerStore(path: fixture.ledger, expectedOwnerUID: UInt32(getuid())).load(expectedNonce: fixture.nonce)
            fixture.tools.routes = intent.routeRecords.map(\.applied.routeSnapshot)
        }

        try fixture.runner.run(reason: "connect", nonce: fixture.nonce, environment: fixture.validEnv(), suppliedLedgerPath: fixture.ledger)

        let recorded = try NetworkLedgerStore(path: fixture.ledger, expectedOwnerUID: UInt32(getuid())).load(expectedNonce: fixture.nonce)
        guard let bypassRecord = recorded.routeRecords.first(where: { $0.applied.destination == gatewayBypass.destination }) else {
            throw HarnessFailure(description: "missing gateway bypass record")
        }
        try expect(bypassRecord.before == gatewayBypass, "OpenConnect gateway bypass captured before wrapper mutation")
        try expect(bypassRecord.applied.routeSnapshot == gatewayBypass, "gateway bypass intent is idempotent")

        // OpenConnect may remove the portal-bypass route when the child exits.
        // The wrapper recorded it as part of the exact pre-mutation baseline,
        // so repair must restore it rather than silently accepting route loss.
        fixture.tools.routes = []
        try NetworkLedgerStore(path: fixture.ledger, expectedOwnerUID: UInt32(getuid())).save(recorded.withStatus("repair-required"))

        try fixture.runner.run(reason: "repair", nonce: fixture.nonce, environment: [:], suppliedLedgerPath: fixture.ledger)

        try expect(!FileManager.default.fileExists(atPath: fixture.ledger.path), "restored gateway baseline removes stale ledger")
        try expect(fixture.tools.restoredRoutes == [gatewayBypass], "repair restores the missing gateway baseline route")
        try expect(fixture.tools.routes == [gatewayBypass], "gateway baseline route is present after repair")
    }

    static func testRepairRestoresMissingForeignBaselineHostRoute() throws {
        let fixture = try HarnessNetworkFixture()
        let foreignRoute = RouteSnapshot(
            destination: "203.0.113.77",
            gateway: "192.0.2.1",
            interface: "en0",
            netmask: "255.255.255.255",
            protocol: "ipv4"
        )
        fixture.tools.routes = [foreignRoute]
        fixture.upstream.onRun = { reason, _ in
            guard reason == "connect" else { return }
            let intent = try NetworkLedgerStore(path: fixture.ledger, expectedOwnerUID: UInt32(getuid())).load(expectedNonce: fixture.nonce)
            fixture.tools.routes = intent.routeRecords.map(\.applied.routeSnapshot)
        }

        var environment = fixture.validEnv()
        environment["CISCO_SPLIT_INC_0_ADDR"] = foreignRoute.destination
        environment["CISCO_SPLIT_INC_0_MASK"] = foreignRoute.netmask
        try fixture.runner.run(reason: "connect", nonce: fixture.nonce, environment: environment, suppliedLedgerPath: fixture.ledger)

        let recorded = try NetworkLedgerStore(path: fixture.ledger, expectedOwnerUID: UInt32(getuid())).load(expectedNonce: fixture.nonce)
        fixture.tools.routes = []
        try NetworkLedgerStore(path: fixture.ledger, expectedOwnerUID: UInt32(getuid())).save(recorded.withStatus("repair-required"))

        try fixture.runner.run(reason: "repair", nonce: fixture.nonce, environment: [:], suppliedLedgerPath: fixture.ledger)

        try expect(!FileManager.default.fileExists(atPath: fixture.ledger.path), "successful foreign-route restore removes ledger")
        try expect(fixture.tools.restoredRoutes == [foreignRoute], "repair restores only the missing foreign baseline route")
        try expect(fixture.tools.routes == [foreignRoute], "foreign route is present after repair")
    }

    static func testRepairRetiresCleanLedgerAfterDefaultNetworkChange() throws {
        let (fixture, _, _) = try staleNetworkLedgerFixture()

        try fixture.runner.run(reason: "repair", nonce: fixture.nonce, environment: [:], suppliedLedgerPath: fixture.ledger)

        try expect(!FileManager.default.fileExists(atPath: fixture.ledger.path), "clean stale ledger is retired after the physical network changes")
        try expect(fixture.tools.restoredRoutes.isEmpty, "repair never restores a route through the obsolete gateway")
        try expect(fixture.tools.restoredResolvers.isEmpty, "repair never overwrites resolver state from the new network")
    }

    static func testRepairKeepsStaleLedgerWhenAppliedRouteRemains() throws {
        let (fixture, tunnelRoute, _) = try staleNetworkLedgerFixture()
        fixture.tools.routes = [tunnelRoute]

        try expectThrows("applied tunnel route blocks stale ledger retirement") {
            try fixture.runner.run(reason: "repair", nonce: fixture.nonce, environment: [:], suppliedLedgerPath: fixture.ledger)
        }

        try expect(FileManager.default.fileExists(atPath: fixture.ledger.path), "route residue keeps repair evidence")
        try expect(fixture.tools.routes == [tunnelRoute], "foreign or owned route is not mutated by stale retirement")
    }

    static func testRepairKeepsStaleLedgerOnMixedSetupDNS() throws {
        let (fixture, _, _) = try staleNetworkLedgerFixture()
        fixture.tools.resolverServers = ["166.104.100.100", "203.0.113.53"]
        fixture.tools.resolverServersPresent = true

        try expectThrows("mixed Setup DNS is ambiguous and blocks stale ledger repair") {
            try fixture.runner.run(reason: "repair", nonce: fixture.nonce, environment: [:], suppliedLedgerPath: fixture.ledger)
        }

        try expect(FileManager.default.fileExists(atPath: fixture.ledger.path), "ambiguous DNS keeps repair evidence")
        try expect(fixture.tools.restoredDNSServers.isEmpty, "ambiguous DNS is not overwritten")
    }

    static func testRepairKeepsStaleLedgerOnRouteKeyCollision() throws {
        let (fixture, tunnelRoute, _) = try staleNetworkLedgerFixture()
        let foreign = RouteSnapshot(destination: tunnelRoute.destination, gateway: "192.0.2.254", interface: "en0", netmask: tunnelRoute.netmask, protocol: tunnelRoute.protocol)
        fixture.tools.routes = [foreign]

        try expectThrows("foreign route with the same key blocks stale ledger retirement") {
            try fixture.runner.run(reason: "repair", nonce: fixture.nonce, environment: [:], suppliedLedgerPath: fixture.ledger)
        }

        try expect(FileManager.default.fileExists(atPath: fixture.ledger.path), "route-key collision keeps repair evidence")
        try expect(fixture.tools.routes == [foreign], "foreign route collision is left untouched")
    }

    static func testRepairKeepsStaleLedgerOnNetworkIdentityChange() throws {
        let mutations: [(HarnessNetworkTools) -> Void] = [
            { $0.rebootIdentityValue = 4243 },
            { $0.primaryServiceIDValue = "service-other" },
            { $0.defaultInterface = "en1" },
        ]
        for mutate in mutations {
            let (fixture, _, _) = try staleNetworkLedgerFixture()
            mutate(fixture.tools)

            try expectThrows("boot, service, or interface drift blocks stale ledger retirement") {
                try fixture.runner.run(reason: "repair", nonce: fixture.nonce, environment: [:], suppliedLedgerPath: fixture.ledger)
            }

            try expect(FileManager.default.fileExists(atPath: fixture.ledger.path), "identity drift keeps repair evidence")
        }
    }

    static func staleNetworkLedgerFixture() throws -> (HarnessNetworkFixture, RouteSnapshot, ResolverSnapshot) {
        let fixture = try HarnessNetworkFixture()
        let oldDefault = RouteSnapshot(destination: "default", gateway: "192.0.2.1", interface: "en0", netmask: "0.0.0.0", protocol: "ipv4")
        let oldBypass = RouteSnapshot(destination: "198.51.100.9", gateway: "192.0.2.1", interface: "en0", netmask: "255.255.255.255", protocol: "ipv4")
        let tunnelRoute = RouteSnapshot(destination: "10.0.0.0", gateway: "10.10.0.1", interface: "utun7", netmask: "255.0.0.0", protocol: "ipv4")
        let records = [
            RouteRecord(before: nil, applied: RouteDelta(operation: "add", destination: tunnelRoute.destination, gateway: tunnelRoute.gateway, interface: tunnelRoute.interface, netmask: tunnelRoute.netmask, protocol: tunnelRoute.protocol), after: tunnelRoute),
            RouteRecord(before: oldBypass, applied: RouteDelta(operation: "add", destination: oldBypass.destination, gateway: oldBypass.gateway, interface: oldBypass.interface, netmask: oldBypass.netmask, protocol: oldBypass.protocol), after: oldBypass),
        ]
        let setupKey = "Setup:/Network/Service/service-wifi/DNS"
        let stateKey = "State:/Network/Service/service-wifi/DNS"
        let missing = ResolverFieldSnapshot(servers: [], searchDomains: [], serversPresent: false, searchDomainsPresent: false, keyPresent: false)
        let beforeDNS = ResolverSnapshot(
            serviceID: "service-wifi",
            servers: [],
            searchDomains: [],
            activeInterface: "en0",
            serversPresent: false,
            searchDomainsPresent: false,
            surfaces: [setupKey: missing, stateKey: ResolverFieldSnapshot(servers: ["9.9.9.9"], searchDomains: [])]
        )
        let appliedDNS = ResolverSnapshot(
            serviceID: "service-wifi",
            servers: ["166.104.100.100"],
            searchDomains: [],
            activeInterface: "utun7",
            surfaces: [setupKey: ResolverFieldSnapshot(servers: ["166.104.100.100"], searchDomains: []), stateKey: ResolverFieldSnapshot(servers: ["166.104.100.100", "9.9.9.9"], searchDomains: [])]
        )
        try NetworkLedgerStore(path: fixture.ledger, expectedOwnerUID: UInt32(getuid())).save(
            NetworkLedger(
                sessionNonce: fixture.nonce,
                rebootIdentity: 4242,
                serviceIDBefore: "service-wifi",
                defaultInterfaceBefore: "en0",
                defaultRouteBefore: oldDefault,
                tunnelInterface: "utun7",
                routeDeltasApplied: records.map(\.applied),
                routeRecords: records,
                dnsBefore: beforeDNS,
                dnsApplied: appliedDNS,
                status: "repair-required",
                timestamp: Date(timeIntervalSince1970: 1)
            )
        )
        fixture.tools.defaultGateway = "192.0.2.254"
        fixture.tools.resolverServers = []
        fixture.tools.resolverSearchDomains = []
        fixture.tools.resolverServersPresent = false
        fixture.tools.resolverSearchDomainsPresent = false
        fixture.tools.resolverSurfaces = [
            setupKey: missing,
            stateKey: ResolverFieldSnapshot(servers: ["166.104.100.100", "166.104.100.200"], searchDomains: []),
        ]
        fixture.tools.includeTunnelSurface = true
        fixture.tools.routes = []
        return (fixture, tunnelRoute, appliedDNS)
    }

    static func testRepairRestoresExactRetainedSetupDNSAfterDefaultNetworkChange() throws {
        let fixture = try HarnessNetworkFixture()
        let oldDefault = RouteSnapshot(destination: "default", gateway: "172.16.65.254", interface: "en0", netmask: "default", protocol: "ipv4")
        let tunnelRoute = RouteSnapshot(destination: "166.104.100.100", gateway: "10.200.200.61", interface: "utun10", netmask: "255.255.255.255", protocol: "ipv4")
        let records = [
            RouteRecord(before: nil, applied: RouteDelta(operation: "add", destination: tunnelRoute.destination, gateway: tunnelRoute.gateway, interface: tunnelRoute.interface, netmask: tunnelRoute.netmask, protocol: tunnelRoute.protocol), after: tunnelRoute),
        ]
        let beforeDNS = ResolverSnapshot(serviceID: "service-wifi", servers: [], searchDomains: [], activeInterface: "en0", serversPresent: false, searchDomainsPresent: false)
        let appliedDNS = ResolverSnapshot(serviceID: "service-wifi", servers: ["166.104.100.100"], searchDomains: [], activeInterface: "utun10", serversPresent: true, searchDomainsPresent: false)
        try NetworkLedgerStore(path: fixture.ledger, expectedOwnerUID: UInt32(getuid())).save(
            NetworkLedger(
                sessionNonce: fixture.nonce,
                rebootIdentity: 4242,
                serviceIDBefore: "service-wifi",
                defaultInterfaceBefore: "en0",
                defaultRouteBefore: oldDefault,
                tunnelInterface: "utun10",
                routeDeltasApplied: records.map(\.applied),
                routeRecords: records,
                dnsBefore: beforeDNS,
                dnsApplied: appliedDNS,
                status: "repair-required",
                timestamp: Date(timeIntervalSince1970: 1)
            )
        )
        fixture.tools.defaultGateway = "192.168.0.1"
        fixture.tools.resolverServers = appliedDNS.servers
        fixture.tools.resolverSearchDomains = []
        fixture.tools.resolverServersPresent = true
        fixture.tools.resolverSearchDomainsPresent = false
        fixture.tools.includeTunnelSurface = true
        fixture.tools.routes = []

        try fixture.runner.run(reason: "repair", nonce: fixture.nonce, environment: [:], suppliedLedgerPath: fixture.ledger)

        try expect(!FileManager.default.fileExists(atPath: fixture.ledger.path), "DNS-only stale repair removes ledger after clearing retained VPN DNS")
        try expect(fixture.tools.restoredRoutes.isEmpty, "DNS-only stale repair does not restore obsolete routes")
        try expect(fixture.tools.restoredDNSServers == [beforeDNS], "DNS-only stale repair restores the exact recorded Setup DNS field once")
        try expect(fixture.tools.restoredSearchDomains.isEmpty, "unchanged search domains are not overwritten")
        try expect(fixture.tools.resolverServers.isEmpty, "DNS-only stale repair clears retained VPN DNS servers")
    }

    static func testSystemNetworkToolsRestoresGatewayRouteWithoutInterfaceModifier() throws {
        let dir = try harnessTempDir()
        let route = dir.appendingPathComponent("route")
        let log = dir.appendingPathComponent("route-argv.log")
        try """
        #!/bin/sh
        printf '%s\\n' "$*" >> '\(log.path)'
        if [ "$1" = "-n" ] && [ "$2" = "get" ]; then
          cat <<'ROUTE'
           route to: 198.51.100.9
        destination: 198.51.100.9
            gateway: 192.0.2.1
          interface: en0
              flags: <UP,GATEWAY,HOST,DONE,STATIC>
        ROUTE
        fi
        """.write(to: route, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: route.path)
        let paths = RuntimePaths(ledgerRoot: dir, upstream: dir.appendingPathComponent("vpnc-script"), route: route, scutil: dir.appendingPathComponent("scutil"), sysctl: dir.appendingPathComponent("sysctl"), networksetup: dir.appendingPathComponent("networksetup"))
        let tools = SystemNetworkTools(paths: paths)
        let baseline = RouteSnapshot(destination: "198.51.100.9", gateway: "192.0.2.1", interface: "en0", netmask: "255.255.255.255", protocol: "ipv4")

        try tools.restoreRoute(baseline)

        let calls = try String(contentsOf: log, encoding: .utf8).split(separator: "\n").map(String.init)
        try expect(calls.first == "-n add -net 198.51.100.9 -netmask 255.255.255.255 192.0.2.1", "gateway route restore does not misuse the direct-interface modifier")
    }

    static func testSanitizedEnvironmentPreservesVPNPIDAndMask() throws {
        let sanitized = NetworkWrapperRunner.sanitizedEnvironment([
            "VPNPID": "12345",
            "CISCO_SPLIT_INC": "1",
            "CISCO_SPLIT_INC_0_ADDR": "10.0.0.0",
            "CISCO_SPLIT_INC_0_MASKLEN": "8",
            "PASSWORD": "CANARY"
        ])
        try expect(sanitized["VPNPID"] == "12345", "numeric VPNPID preserved")
        try expect(sanitized["CISCO_SPLIT_INC_0_MASK"] == "255.0.0.0", "mask synthesized from mask length")
        try expect(sanitized["CISCO_SPLIT_INC_0_MASKLEN"] == nil, "mask length removed after canonicalization")
        try expect(sanitized["PASSWORD"] == nil, "secret key stripped")
        try expect(NetworkWrapperRunner.sanitizedEnvironment(["VPNPID": "../CANARY"])["VPNPID"] == nil, "unsafe VPNPID stripped")
        try expect(NetworkWrapperRunner.sanitizedEnvironment(["VPNPID": "0"])["VPNPID"] == nil, "zero VPNPID stripped")
        try expect(NetworkWrapperRunner.sanitizedEnvironment(["VPNPID": "0001"])["VPNPID"] == nil, "non-canonical VPNPID stripped")
        try expect(NetworkWrapperRunner.sanitizedEnvironment(["VPNPID": "2147483648"])["VPNPID"] == nil, "out-of-range VPNPID stripped")
        try expect(NetworkWrapperRunner.sanitizedEnvironment(["VPNPID": "2147483647"])["VPNPID"] == "2147483647", "maximum pid_t VPNPID preserved")

        let conflictingMask = NetworkWrapperRunner.sanitizedEnvironment([
            "CISCO_SPLIT_INC": "1",
            "CISCO_SPLIT_INC_0_ADDR": "10.0.0.0",
            "CISCO_SPLIT_INC_0_MASK": "255.0.0.0",
            "CISCO_SPLIT_INC_0_MASKLEN": "$(CANARY)"
        ])
        try expect(conflictingMask["CISCO_SPLIT_INC_0_MASK"] == "255.0.0.0", "canonical mask preserved")
        try expect(conflictingMask["CISCO_SPLIT_INC_0_MASKLEN"] == nil, "conflicting raw mask length stripped")
    }

    static func testStrictIPv4SplitInputs() throws {
        for mutate in [
            { (env: inout [String: String]) in env["CISCO_SPLIT_INC_0_ADDR"] = "010.0.0.1" },
            { (env: inout [String: String]) in env["CISCO_SPLIT_INC_0_ADDR"] = "-net" },
            { (env: inout [String: String]) in env["VPNGATEWAY"] = "198.051.100.9" },
            { (env: inout [String: String]) in env["CISCO_SPLIT_INC_0_MASK"] = "255.0.255.0" },
            { (env: inout [String: String]) in env["TUNDEV"] = "utun7\nremove State:/Network/Global/DNS" }
        ] {
            let fixture = try HarnessNetworkFixture()
            var env = fixture.validEnv()
            mutate(&env)
            try expectThrows("bad split input") { try fixture.runner.run(reason: "connect", nonce: fixture.nonce, environment: env, suppliedLedgerPath: fixture.ledger) }
            try expect(fixture.upstream.calls == 0, "invalid network input rejected before upstream mutation")
        }
    }

    static func testInvalidTunnelRejectedBeforePreInit() throws {
        let fixture = try HarnessNetworkFixture()
        let env = [
            "HYU_SESSION_LEDGER": fixture.ledger.path,
            "TUNDEV": "utun7\nremove State:/Network/Global/DNS",
        ]

        try expectThrows("invalid pre-init tunnel") {
            try fixture.runner.run(reason: "pre-init", nonce: fixture.nonce, environment: env, suppliedLedgerPath: fixture.ledger)
        }
        try expect(fixture.upstream.calls == 0, "invalid tunnel rejected before pre-init upstream")
    }

    static func testLedgerSchemaRouteRecordsAndResolverOrder() throws {
        let dir = try harnessTempDir()
        let ledgerURL = dir.appendingPathComponent("nonceabc123.ledger")
        let ledger = NetworkLedger(sessionNonce: "nonceabc123", rebootIdentity: 42, serviceIDBefore: "service-wifi", defaultInterfaceBefore: "en0", defaultRouteBefore: RouteSnapshot(destination: "default", gateway: "192.0.2.1", interface: "en0", netmask: "0.0.0.0", protocol: "ipv4"), tunnelInterface: "utun7", routeDeltasApplied: [RouteDelta(operation: "add", destination: "10.0.0.0", gateway: "10.10.0.1", interface: "utun7", netmask: "255.0.0.0", protocol: "ipv4")], dnsBefore: ResolverSnapshot(serviceID: "service-wifi", servers: ["9.9.9.9"], searchDomains: ["home.example"], activeInterface: "en0"), dnsApplied: ResolverSnapshot(serviceID: "service-wifi", servers: ["166.104.1.2", "166.104.1.1"], searchDomains: ["vpn.hanyang.ac.kr", "hanyang.ac.kr"], activeInterface: "utun7"), status: "recorded", timestamp: Date(timeIntervalSince1970: 1))
        let store = NetworkLedgerStore(path: ledgerURL, expectedOwnerUID: UInt32(getuid()))
        try store.save(ledger)
        let object = try JSONSerialization.jsonObject(with: Data(contentsOf: ledgerURL)) as! [String: Any]
        try expect(object["routeRecords"] != nil, "schema includes routeRecords")
        let dns = object["dnsApplied"] as! [String: Any]
        try expect(dns["servers"] as? [String] == ["166.104.1.2", "166.104.1.1"], "server order preserved")
        try expect(dns["searchDomains"] as? [String] == ["vpn.hanyang.ac.kr", "hanyang.ac.kr"], "search order preserved")
    }

    static func testFakeLockConcurrentRejection() throws {
        let lock = FakeSessionLock()
        try lock.acquire(consoleUID: 501)
        try expectThrows("concurrent") { try lock.acquire(consoleUID: 501) }
        try lock.release(consoleUID: 501)
        try lock.acquire(consoleUID: 501)
    }

    static func testSystemChildBirthtimeMonitor() throws {
        let process = SystemProcessController()
        let child = try process.prepareSpawn(SpawnRequest(executable: URL(fileURLWithPath: "/bin/sleep"), arguments: ["1"], inheritStdin: true, inheritStdout: true, usesShell: false))
        try expect(child.birthTime > 0, "birth time")
        try process.commitSpawn(child)
        let live = try require(try process.liveIdentity(for: child.pid), "live child")
        try expect(live.birthTime == child.birthTime, "birth matches")
        let record = SessionRecord(pid: child.pid, processGroupID: child.processGroupID, processBirthTime: child.birthTime, sessionNonce: "nonce12345", consoleUID: UInt32(getuid()), portal: "secure.hanyang.ac.kr", executableIdentity: ExecutableIdentity(path: live.executablePath, fileID: "unused"), launchTime: Date(), ledger: OpaqueLedger(path: URL(fileURLWithPath: "/tmp/ledger/nonce12345.ledger"), nonce: "nonce12345"))
        let outcome = try process.monitorForeground(record: record) { _ in throw HarnessFailure(description: "unexpected channel loss") }
        try expect(outcome == .exited(status: 0), "zero child exit classified")
    }

    static func testSystemSignalCleanup(_ signalNumber: Int32) throws {
        let process = SystemProcessController()
        let child = try process.prepareSpawn(SpawnRequest(executable: URL(fileURLWithPath: "/bin/sleep"), arguments: ["30"], inheritStdin: true, inheritStdout: true, usesShell: false))
        try process.commitSpawn(child)
        let live = try require(try process.liveIdentity(for: child.pid), "live signal child")
        let record = SessionRecord(pid: child.pid, processGroupID: child.processGroupID, processBirthTime: child.birthTime, sessionNonce: "nonce12345", consoleUID: UInt32(getuid()), portal: "secure.hanyang.ac.kr", executableIdentity: ExecutableIdentity(path: live.executablePath, fileID: "unused"), launchTime: Date(), ledger: OpaqueLedger(path: URL(fileURLWithPath: "/tmp/ledger/nonce12345.ledger"), nonce: "nonce12345"))
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.2) { kill(getpid(), signalNumber) }
        let signalOutcome = try process.monitorForeground(record: record) { freshRecord in
            try process.validateBeforeSignal(freshRecord)
            try process.terminateProcessGroup(freshRecord.processGroupID)
            if try !process.waitForExit(pid: freshRecord.pid, timeout: 2) {
                try process.validateBeforeSignal(freshRecord)
                try process.killProcessGroup(freshRecord.processGroupID)
                let killed = try process.waitForExit(pid: freshRecord.pid, timeout: 2)
                try expect(killed, "killed child exits")
            }
        }
        try expect(signalOutcome == .channelLoss, "signal classified as channel loss")
        let afterSignal = try process.liveIdentity(for: child.pid)
        try expect(afterSignal == nil, "signal cleaned child")
    }
}

func require<T>(_ value: T?, _ message: String) throws -> T { guard let value else { throw HarnessFailure(description: message) }; return value }

final class CountingByteInput: ByteInput {
    private let bytes: [UInt8]
    private var index = 0
    init(_ bytes: [UInt8]) { self.bytes = bytes }
    var remaining: [UInt8] { Array(bytes.dropFirst(index)) }
    func readOneByte() throws -> UInt8? { guard index < bytes.count else { return nil }; defer { index += 1 }; return bytes[index] }
}

struct HelperHarness {
    var config = HelperConfiguration.testFixture()
    var metadata: FakeMetadata
    var process = FakeProcessController()
    var store = InMemorySessionStore()
    var lock = FakeSessionLock()
    var identity = InvocationIdentity(effectiveUID: 0, sudoUID: 501, sudoUser: "alice", consoleUID: 501, sudoAccountUID: 501)
    var ledgerCoordinator = FakeLedgerCoordinator()
    init() { metadata = FakeMetadata.secure(paths: config.requiredSecurePaths.map(\.path) + ["/", "/rooted"]) }
    mutating func run(command: HelperCommand, startRequest: StartRequest? = nil) throws -> HelperResult {
        var helper = PrivilegedHelper(configuration: config, metadata: metadata, process: process, store: store, lock: lock, clock: FixedClock(), nonceGenerator: FixedNonceGenerator(), identity: identity, ledgerCoordinator: ledgerCoordinator)
        let result = try helper.run(command: command, startRequest: startRequest)
        process = helper.process as! FakeProcessController
        store = helper.store as! InMemorySessionStore
        lock = helper.lock as! FakeSessionLock
        ledgerCoordinator = helper.ledgerCoordinator as! FakeLedgerCoordinator
        return result
    }
    mutating func installRecord(pid: Int32 = 2222, pgid: Int32 = 3333, birth: UInt64 = 77, nonce: String = "nonce12345", ledgerNonce: String = "nonce12345", tunnel: String? = nil, ledgerPath: URL? = nil) throws {
        try store.save(SessionRecord(pid: pid, processGroupID: pgid, processBirthTime: birth, sessionNonce: nonce, consoleUID: 501, portal: config.portal, executableIdentity: ExecutableIdentity(path: config.openConnectExecutable.path, fileID: "file-1"), launchTime: Date(), ledger: OpaqueLedger(path: ledgerPath ?? config.ledgerDirectory.appendingPathComponent("\(ledgerNonce).ledger"), nonce: ledgerNonce), tunnelInterface: tunnel))
    }
}

struct FakeMetadata: FileMetadataProviding {
    var owners: [String: UInt32] = [:]
    var modes: [String: mode_t] = [:]
    var symlinks = Set<String>()
    var identities: [String: String] = [:]
    var failPath: String?
    static func secure(paths: [String]) -> FakeMetadata { var fake = FakeMetadata(); for path in paths { fake.owners[path] = 0; fake.modes[path] = 0o755; fake.identities[path] = "file-1" }; return fake }
    func metadata(for path: String) throws -> SecureFileMetadata { if path == failPath { throw HelperError.insecurePath(path) }; guard let owner = owners[path], let mode = modes[path] else { throw HelperError.insecurePath(path) }; return SecureFileMetadata(ownerUID: owner, mode: mode, isSymlink: symlinks.contains(path), fileID: identities[path] ?? path) }
}
final class InMemorySessionStore: SessionStoring { var record: SessionRecord?; var saveError: Error?; func load() throws -> SessionRecord? { record }; func save(_ record: SessionRecord) throws { if let saveError { throw saveError }; self.record = record }; func remove() throws { record = nil } }
final class FakeSessionLock: SessionLocking { var acquiredUIDs: [UInt32] = []; var releasedUIDs: [UInt32] = []; private var held = Set<UInt32>(); func acquire(consoleUID: UInt32) throws { if held.contains(consoleUID) { throw HelperError.sessionExists }; held.insert(consoleUID); acquiredUIDs.append(consoleUID) }; func release(consoleUID: UInt32) throws { held.remove(consoleUID); releasedUIDs.append(consoleUID) } }
final class FakeLedgerCoordinator: SessionLedgerCoordinating { var verifyResult: Error?; var repairResult: Error?; var verifiedNonces: [String] = []; var repairedNonces: [String] = []; func verifyTeardownComplete(record: SessionRecord) throws { verifiedNonces.append(record.sessionNonce); if let verifyResult { throw verifyResult } }; func repair(record: SessionRecord, configuration: HelperConfiguration) throws { repairedNonces.append(record.sessionNonce); if let repairResult { throw repairResult } } }
struct FixedClock: ClockProviding { func now() -> Date { Date(timeIntervalSince1970: 123) } }
struct FixedNonceGenerator: NonceGenerating { func makeNonce() throws -> String { "nonce12345" } }
final class FakeProcessController: ProcessControlling {
    struct Spawned { let argv: [String]; let environment: [String: String] }
    enum Signal: Equatable { case termGroup(pgid: Int32), killGroup(pgid: Int32) }
    var spawned: Spawned?
    var spawnError: Error?
    var commitError: Error?
    var killError: Error?
    var channelLossAfterSpawn = false
    var liveIdentity: LiveProcessIdentity?
    var signals: [Signal] = []
    var aborted: [Int32] = []
    var waitResults: [Bool] = []
    var signalGuardBegun = false
    var signalGuardEnded = false
    var injectSignalAfterCommit = false
    var monitorExitStatus: Int32 = 0
    func beginLifecycleSignalGuard() throws { signalGuardBegun = true }
    func endLifecycleSignalGuard() { signalGuardEnded = true }
    func prepareSpawn(_ request: SpawnRequest) throws -> SpawnedProcess { if let spawnError { throw spawnError }; spawned = Spawned(argv: request.arguments, environment: request.environment); liveIdentity = .matching(pid: 1200, pgid: 1200, birth: 42, executable: request.executable.path); return SpawnedProcess(pid: 1200, processGroupID: 1200, birthTime: 42) }
    func commitSpawn(_ process: SpawnedProcess) throws { if let commitError { throw commitError }; if injectSignalAfterCommit { channelLossAfterSpawn = true } }
    func abortSpawn(_ process: SpawnedProcess) throws { aborted.append(process.pid); try killProcessGroup(process.processGroupID) }
    func liveIdentity(for pid: Int32) throws -> LiveProcessIdentity? { liveIdentity }
    func terminateProcessGroup(_ pgid: Int32) throws { signals.append(.termGroup(pgid: pgid)) }
    func killProcessGroup(_ pgid: Int32) throws { signals.append(.killGroup(pgid: pgid)); if let killError { throw killError }; liveIdentity = nil }
    func waitForExit(pid: Int32, timeout: TimeInterval) throws -> Bool { waitResults.isEmpty ? false : waitResults.removeFirst() }
    func monitorForeground(record: SessionRecord, onChannelLoss: (SessionRecord) throws -> Void) throws -> MonitorOutcome { if channelLossAfterSpawn { try onChannelLoss(record); return .channelLoss }; return .exited(status: monitorExitStatus) }
    func validateBeforeSignal(_ record: SessionRecord) throws {}
}


final class HarnessNetworkTools: NetworkTooling {
    var rebootIdentityValue: UInt64 = 4242
    var primaryServiceIDValue = "service-wifi"
    var defaultInterface = "en0"
    var defaultGateway = "192.0.2.1"
    var routes: [RouteSnapshot] = []
    var restoredRoutes: [RouteSnapshot] = []
    var resolverServers = ["9.9.9.9"]
    var resolverSearchDomains = ["home.example"]
    var resolverServersPresent = true
    var resolverSearchDomainsPresent = true
    var resolverSurfaces: [String: ResolverFieldSnapshot]?
    var restoredResolvers: [ResolverSnapshot] = []
    var restoredDNSServers: [ResolverSnapshot] = []
    var restoredSearchDomains: [ResolverSnapshot] = []
    var includeTunnelSurface = false
    func rebootIdentity() throws -> UInt64 { rebootIdentityValue }
    func primaryServiceID() throws -> String { primaryServiceIDValue }
    func defaultRoute() throws -> RouteSnapshot { RouteSnapshot(destination: "default", gateway: defaultGateway, interface: defaultInterface, netmask: "0.0.0.0", protocol: "ipv4") }
    func route(destination: String, netmask: String?) throws -> RouteSnapshot? { routes.first { $0.destination == destination && (netmask == nil || $0.netmask == netmask) } }
    func resolver(serviceID: String, baselineInterface: String, tunnelInterface: String?) throws -> ResolverSnapshot {
        var surfaces = resolverSurfaces ?? ["setup": ResolverFieldSnapshot(servers: resolverServers, searchDomains: resolverSearchDomains, serversPresent: resolverServersPresent, searchDomainsPresent: resolverSearchDomainsPresent)]
        if includeTunnelSurface, let tunnelInterface {
            surfaces["State:/Network/Interface/\(tunnelInterface)/DNS"] = ResolverFieldSnapshot(
                servers: [],
                searchDomains: [],
                serversPresent: false,
                searchDomainsPresent: false,
                keyPresent: false
            )
        }
        return ResolverSnapshot(serviceID: serviceID, servers: resolverServers, searchDomains: resolverSearchDomains, activeInterface: tunnelInterface ?? baselineInterface, serversPresent: resolverServersPresent, searchDomainsPresent: resolverSearchDomainsPresent, surfaces: surfaces)
    }
    func serviceName(for serviceID: String) throws -> String { "Wi-Fi" }
    func deleteRoute(_ delta: RouteDelta) throws {
        routes.removeAll { $0.destination == delta.destination && $0.netmask == delta.netmask }
    }
    func restoreRoute(_ route: RouteSnapshot) throws {
        restoredRoutes.append(route)
        routes.removeAll { $0.destination == route.destination && $0.netmask == route.netmask }
        routes.append(route)
    }
    func restoreResolver(serviceID: String, snapshot: ResolverSnapshot) throws {
        restoredResolvers.append(snapshot)
        try restoreDNSServers(serviceID: serviceID, snapshot: snapshot)
        try restoreSearchDomains(serviceID: serviceID, snapshot: snapshot)
    }
    func restoreDNSServers(serviceID: String, snapshot: ResolverSnapshot) throws {
        restoredDNSServers.append(snapshot)
        resolverServers = snapshot.servers
        resolverServersPresent = snapshot.serversPresent
    }
    func restoreSearchDomains(serviceID: String, snapshot: ResolverSnapshot) throws {
        restoredSearchDomains.append(snapshot)
        resolverSearchDomains = snapshot.searchDomains
        resolverSearchDomainsPresent = snapshot.searchDomainsPresent
    }
    func restoreResolverSurfaces(serviceID: String, snapshot: ResolverSnapshot, current: ResolverSnapshot) throws {
        try restoreResolver(serviceID: serviceID, snapshot: snapshot)
    }
}
final class HarnessCountingUpstream: VpncUpstreamRunning {
    var calls = 0
    var reasons: [String] = []
    var sawRouteIntent = false
    var onRun: ((String, [String: String]) throws -> Void)?
    func run(reason: String, environment: [String: String]) throws -> Int32 { calls += 1; reasons.append(reason); try onRun?(reason, environment); return 0 }
}
struct HarnessNetworkFixture {
    let nonce = "nonceabc123"
    let root: URL
    let ledger: URL
    let tools: HarnessNetworkTools
    let upstream: HarnessCountingUpstream
    let runner: NetworkWrapperRunner
    init() throws {
        root = try harnessTempDir()
        ledger = root.appendingPathComponent("nonceabc123.ledger")
        tools = HarnessNetworkTools()
        upstream = HarnessCountingUpstream()
        let paths = RuntimePaths(ledgerRoot: root, upstream: root.appendingPathComponent("vpnc-script"), route: root.appendingPathComponent("route"), scutil: root.appendingPathComponent("scutil"), sysctl: root.appendingPathComponent("sysctl"), networksetup: root.appendingPathComponent("networksetup"))
        runner = NetworkWrapperRunner(paths: paths, expectedOwnerUID: UInt32(getuid()), tools: tools, upstream: upstream)
    }
    func validEnv() -> [String: String] { ["HYU_SESSION_LEDGER": ledger.path, "TUNDEV": "utun7", "INTERNAL_IP4_ADDRESS": "10.10.0.1", "VPNGATEWAY": "198.51.100.9", "CISCO_SPLIT_INC": "1", "CISCO_SPLIT_INC_0_ADDR": "10.0.0.0", "CISCO_SPLIT_INC_0_MASK": "255.0.0.0", "CISCO_SPLIT_EXC": "0", "CISCO_IPV6_SPLIT_INC": "0", "CISCO_IPV6_SPLIT_EXC": "0"] }
}
func harnessTempDir() throws -> URL { let url = FileManager.default.temporaryDirectory.appendingPathComponent("hyu-helper-harness-\(UUID().uuidString)"); try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true); return url }

func systemNetworkToolsWithRouteOutput(_ output: String) throws -> SystemNetworkTools {
    try systemNetworkToolsWithRouteScript("""
    #!/bin/sh
    cat <<'HYU_ROUTE_OUTPUT'
    \(output)
    HYU_ROUTE_OUTPUT
    """)
}

func systemNetworkToolsWithRouteScript(_ script: String) throws -> SystemNetworkTools {
    let dir = try harnessTempDir()
    let route = dir.appendingPathComponent("route")
    try script.write(to: route, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: route.path)
    let paths = RuntimePaths(
        ledgerRoot: dir,
        upstream: dir.appendingPathComponent("vpnc-script"),
        route: route,
        scutil: dir.appendingPathComponent("scutil"),
        sysctl: dir.appendingPathComponent("sysctl"),
        networksetup: dir.appendingPathComponent("networksetup")
    )
    return SystemNetworkTools(paths: paths)
}

func helperHarnessWithRecordedLedger(status: String, tunnel: String) throws -> (HelperHarness, URL) {
    let root = try harnessTempDir()
    let ledgerDirectory = root.appendingPathComponent("ledger")
    let nonce = "nonce12345"
    let ledger = ledgerDirectory.appendingPathComponent("\(nonce).ledger")
    var harness = HelperHarness()
    harness.config = HelperConfiguration(
        openConnectExecutable: root.appendingPathComponent("openconnect"),
        vpncScript: root.appendingPathComponent("vpnc-wrapper"),
        hipWrapper: root.appendingPathComponent("hip-report"),
        stateDirectory: root,
        ledgerDirectory: ledgerDirectory
    )
    harness.metadata = FakeMetadata.secure(paths: harness.config.requiredSecurePaths.map(\.path) + [root.path])
    try NetworkLedgerStore(path: ledger, expectedOwnerUID: UInt32(geteuid())).save(
        NetworkLedger(
            sessionNonce: nonce,
            rebootIdentity: 42,
            serviceIDBefore: "service-wifi",
            defaultInterfaceBefore: "en0",
            defaultRouteBefore: RouteSnapshot(destination: "default", gateway: "192.0.2.1", interface: "en0", netmask: nil, protocol: "ipv4"),
            tunnelInterface: tunnel,
            routeDeltasApplied: [],
            dnsBefore: nil,
            dnsApplied: nil,
            status: status,
            timestamp: Date(timeIntervalSince1970: 123)
        )
    )
    try harness.installRecord(ledgerPath: ledger)
    harness.process.liveIdentity = .matching(pid: 2222, pgid: 3333, birth: 77, executable: harness.config.openConnectExecutable.path)
    return (harness, root)
}


func writeHelperConfigFixture(extra: String?) throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("hyu-helper-config-fixture-\(UUID().uuidString).json")
    var object: [String: String] = [
        "openConnectExecutable": "/Library/Application Support/HYU VPN/runtime/current/bin/openconnect",
        "vpncScript": "/Library/PrivilegedHelperTools/com.hyu.vpn.vpnc-wrapper",
        "hipWrapper": "/Library/Application Support/HYU VPN/runtime/gp-hip-report",
        "stateDirectory": "/private/var/db/hyu-vpn",
        "ledgerDirectory": "/private/var/db/hyu-vpn/ledger",
        "openConnectExecutableSHA256": String(repeating: "a", count: 64),
        "vpncScriptSHA256": String(repeating: "b", count: 64),
        "hipWrapperSHA256": String(repeating: "c", count: 64)
    ]
    if let extra { object[extra] = "bad" }
    try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]).write(to: url)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    return url
}
