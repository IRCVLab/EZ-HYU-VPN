import Foundation
import Darwin
import Testing
@testable import HYUVPNPrivilegedHelper

@Suite struct NetworkLedgerModelTests {
    @Test func atomicLedgerWriteUsesExactBoundedSchemaAnd0600Mode() throws {
        let directory = try temporaryDirectory()
        let ledgerURL = directory.appendingPathComponent("nonceabc123.ledger")
        let ledger = NetworkLedger(
            sessionNonce: "nonceabc123",
            rebootIdentity: 424242,
            serviceIDBefore: "service-wifi",
            defaultInterfaceBefore: "en0",
            defaultRouteBefore: RouteSnapshot(destination: "default", gateway: "192.0.2.1", interface: "en0", netmask: "0.0.0.0", protocol: "ipv4"),
            tunnelInterface: "utun7",
            routeDeltasApplied: [
                RouteDelta(operation: "add", destination: "10.0.0.0", gateway: "10.10.0.1", interface: "utun7", netmask: "255.0.0.0", protocol: "ipv4"),
                RouteDelta(operation: "add", destination: "172.16.0.0", gateway: "10.10.0.1", interface: "utun7", netmask: "255.240.0.0", protocol: "ipv4")
            ],
            dnsBefore: ResolverSnapshot(serviceID: "service-wifi", servers: ["9.9.9.9"], searchDomains: ["home.example"], activeInterface: "en0"),
            dnsApplied: ResolverSnapshot(serviceID: "service-wifi", servers: ["166.104.1.2", "166.104.1.1"], searchDomains: ["vpn.hanyang.ac.kr", "hanyang.ac.kr"], activeInterface: "utun7"),
            status: "recorded",
            timestamp: Date(timeIntervalSince1970: 1_775_000_000)
        )

        let store = NetworkLedgerStore(path: ledgerURL, maxBytes: 4096, expectedOwnerUID: UInt32(getuid()))
        try store.save(ledger)

        var statInfo = stat()
        #expect(stat(ledgerURL.path, &statInfo) == 0)
        #expect((statInfo.st_mode & 0o777) == 0o600)
        let data = try Data(contentsOf: ledgerURL)
        #expect(data.count <= 4096)
        let object = try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(Set(object.keys) == ["schemaVersion", "sessionNonce", "rebootIdentity", "serviceIDBefore", "defaultInterfaceBefore", "defaultRouteBefore", "tunnelInterface", "routeDeltasApplied", "routeRecords", "dnsBefore", "dnsApplied", "status", "timestamp"])
        let routeDeltas = try #require(object["routeDeltasApplied"] as? [[String: Any]])
        #expect(routeDeltas.map { $0["destination"] as? String } == ["10.0.0.0", "172.16.0.0"])
        let dnsApplied = try #require(object["dnsApplied"] as? [String: Any])
        #expect(dnsApplied["servers"] as? [String] == ["166.104.1.2", "166.104.1.1"])
        #expect(dnsApplied["searchDomains"] as? [String] == ["vpn.hanyang.ac.kr", "hanyang.ac.kr"])
        let decoded = try store.load(expectedNonce: "nonceabc123")
        #expect(decoded.status == "recorded")
        #expect(decoded.routeDeltasApplied.first?.destination == "10.0.0.0")
    }

    @Test func repairPlanRequiresExactRebootServiceRouteAndResolverMatch() throws {
        let ledger = NetworkLedger(
            sessionNonce: "nonceabc123",
            rebootIdentity: 42,
            serviceIDBefore: "service-wifi",
            defaultInterfaceBefore: "en0",
            defaultRouteBefore: RouteSnapshot(destination: "default", gateway: "192.0.2.1", interface: "en0", netmask: "0.0.0.0", protocol: "ipv4"),
            tunnelInterface: "utun7",
            routeDeltasApplied: [RouteDelta(operation: "add", destination: "10.0.0.0", gateway: "10.10.0.1", interface: "utun7", netmask: "255.0.0.0", protocol: "ipv4")],
            dnsBefore: ResolverSnapshot(serviceID: "service-wifi", servers: ["9.9.9.9"], searchDomains: ["home.example"], activeInterface: "en0"),
            dnsApplied: ResolverSnapshot(serviceID: "service-wifi", servers: ["166.104.1.1"], searchDomains: ["hanyang.ac.kr"], activeInterface: "utun7"),
            status: "recorded",
            timestamp: Date(timeIntervalSince1970: 1_775_000_000)
        )
        let matching = NetworkSnapshot(rebootIdentity: 42, serviceID: "service-wifi", defaultInterface: "en0", tunnelInterface: "utun7", routes: ledger.routeDeltasApplied.map(\.routeSnapshot), resolver: ledger.dnsApplied!)
        #expect(NetworkLedgerRepairPlanner.plan(for: ledger, current: matching).status == "healed")
        var changedService = matching
        changedService.serviceID = "service-ethernet"
        #expect(NetworkLedgerRepairPlanner.plan(for: ledger, current: changedService).status == "repair-required")
        var changedBoot = matching
        changedBoot.rebootIdentity = 43
        #expect(NetworkLedgerRepairPlanner.plan(for: ledger, current: changedBoot).status == "repair-required")
        var changedRoute = matching
        changedRoute.routes = [RouteSnapshot(destination: "10.0.0.0", gateway: "10.10.0.99", interface: "utun7", netmask: "255.0.0.0", protocol: "ipv4")]
        #expect(NetworkLedgerRepairPlanner.plan(for: ledger, current: changedRoute).status == "repair-required")
        var changedDNS = matching
        changedDNS.resolver = ResolverSnapshot(serviceID: "service-wifi", servers: ["1.1.1.1"], searchDomains: ["hanyang.ac.kr"], activeInterface: "utun7")
        #expect(NetworkLedgerRepairPlanner.plan(for: ledger, current: changedDNS).status == "repair-required")
    }

    @Test func canonicalRuntimeContractSeparatesWrapperAndUpstreamScript() throws {
        let wrapper = URL(fileURLWithPath: FileManager.default.currentDirectoryPath).deletingLastPathComponent().appendingPathComponent("privileged/hyu-vpnc-wrapper")
        let source = try String(contentsOf: wrapper, encoding: .utf8)
        #expect(source.contains("/Library/Application Support/HYU VPN/runtime/vpnc/hyu-vpnc-wrapperd"))
        #expect(!source.contains("/Library/Application Support/HYU VPN/runtime/hyu-vpnc-wrapperd"))
        #expect(RuntimePaths.production.upstream.path == "/Library/Application Support/HYU VPN/runtime/vpnc/vpnc-script")
        #expect(HelperConfiguration.fallbackProduction().vpncScript.path == "/Library/PrivilegedHelperTools/com.hyu.vpn.vpnc-wrapper")
        #expect(!HelperConfiguration.fallbackProduction().vpncScript.path.contains(" "))
        #expect(HelperConfiguration.fallbackProduction().openConnectExecutable.path == "/Library/Application Support/HYU VPN/runtime/current/bin/openconnect")
        let good = HelperConfiguration(
            openConnectExecutable: URL(fileURLWithPath: "/Library/Application Support/HYU VPN/runtime/current/bin/openconnect"),
            vpncScript: URL(fileURLWithPath: "/Library/PrivilegedHelperTools/com.hyu.vpn.vpnc-wrapper"),
            hipWrapper: URL(fileURLWithPath: "/Library/Application Support/HYU VPN/runtime/gp-hip-report"),
            stateDirectory: URL(fileURLWithPath: "/private/var/db/hyu-vpn"),
            ledgerDirectory: URL(fileURLWithPath: "/private/var/db/hyu-vpn/ledger"),
            executableSHA256: String(repeating: "a", count: 64),
            vpncScriptSHA256: String(repeating: "b", count: 64),
            hipWrapperSHA256: String(repeating: "c", count: 64)
        )
        try good.validateStaticShape()
        let unboundVersioned = HelperConfiguration(
            openConnectExecutable: URL(fileURLWithPath: "/Library/Application Support/HYU VPN/runtime/openconnect/9.12/bin/openconnect"),
            vpncScript: good.vpncScript,
            hipWrapper: good.hipWrapper,
            stateDirectory: good.stateDirectory,
            ledgerDirectory: good.ledgerDirectory,
            executableSHA256: good.executableSHA256,
            vpncScriptSHA256: good.vpncScriptSHA256,
            hipWrapperSHA256: good.hipWrapperSHA256
        )
        #expect(throws: (any Error).self) { try unboundVersioned.validateStaticShape() }
        let bad = HelperConfiguration(
            openConnectExecutable: good.openConnectExecutable,
            vpncScript: URL(fileURLWithPath: "/Library/Application Support/HYU VPN/runtime/vpnc/vpnc-script"),
            hipWrapper: good.hipWrapper,
            stateDirectory: good.stateDirectory,
            ledgerDirectory: good.ledgerDirectory,
            executableSHA256: good.executableSHA256,
            vpncScriptSHA256: good.vpncScriptSHA256,
            hipWrapperSHA256: good.hipWrapperSHA256
        )
        #expect(throws: (any Error).self) { try bad.validateStaticShape() }
        for forbidden in ["HYU_TEST_ROOT", "HYU_TEST_LOG_DIR", "HYU_COMMAND_DIR", "HYU_VPNC_UPSTREAM", "eval "] {
            #expect(!source.contains(forbidden))
        }
    }

    @Test func resolverProbeFailsClosedExceptExplicitMissingDynamicStoreKeys() throws {
        let dir = try temporaryDirectory()
        let scutil = dir.appendingPathComponent("fake-scutil")
        let log = dir.appendingPathComponent("stdin.log")
        try writeExecutable(scutil, #"""
#!/bin/sh
if [ "${1:-}" = "--dns" ]; then
  if [ "${HYU_FAKE_EFFECTIVE_FAIL:-0}" = "1" ]; then exit 7; fi
  printf 'DNS configuration
resolver #1
  nameserver[0] : 9.9.9.9
'
  exit 0
fi
input="$(cat)"
printf '%s
---
' "$input" >> '__LOG__'
case "$input" in
  *Setup:/Network/Service/service-wifi/DNS*) printf '{
  ServerAddresses : <array> {
    0 : 9.9.9.9
  }
}
'; exit 0 ;;
  *State:/Network/Service/service-wifi/DNS*) printf 'No such key
'; exit 0 ;;
  *State:/Network/Global/DNS*) printf 'transient scutil failure
' >&2; exit 9 ;;
  *) printf 'No such key
'; exit 0 ;;
esac
"""#.replacingOccurrences(of: "__LOG__", with: log.path))
        let paths = RuntimePaths(ledgerRoot: dir, upstream: dir.appendingPathComponent("vpnc-script"), route: dir.appendingPathComponent("route"), scutil: scutil, sysctl: dir.appendingPathComponent("sysctl"), networksetup: dir.appendingPathComponent("networksetup"))
        let tools = SystemNetworkTools(paths: paths, runner: BoundedProcessRunner(timeout: 2, maxOutputBytes: 16_384))
        #expect(throws: (any Error).self) { _ = try tools.resolver(serviceID: "service-wifi", baselineInterface: "en0", tunnelInterface: String?.none) }

        try writeExecutable(scutil, #"""
#!/bin/sh
if [ "${1:-}" = "--dns" ]; then exit 8; fi
input="$(cat)"
case "$input" in
  *Setup:/Network/Service/service-wifi/DNS*) printf '{
  ServerAddresses : <array> {
    0 : 9.9.9.9
  }
}
'; exit 0 ;;
  *) printf 'No such key
'; exit 0 ;;
esac
"""#)
        #expect(throws: (any Error).self) { _ = try tools.resolver(serviceID: "service-wifi", baselineInterface: "en0", tunnelInterface: String?.none) }
    }

    @Test func installedExecutionGuardAllowsOnlyCanonicalPaths() throws {
        try InstalledExecutionGuard.validate(actualExecutablePath: "/Library/PrivilegedHelperTools/com.hyu.vpn.helper", allowedCanonicalPath: InstalledExecutionGuard.privilegedHelperPath)
        try InstalledExecutionGuard.validate(actualExecutablePath: "/Library/Application Support/HYU VPN/runtime/vpnc/hyu-vpnc-wrapperd", allowedCanonicalPath: InstalledExecutionGuard.wrapperDaemonPath)
        #expect(throws: (any Error).self) { try InstalledExecutionGuard.validate(actualExecutablePath: FileManager.default.currentDirectoryPath + "/.build/debug/hyu-vpnc-wrapperd", allowedCanonicalPath: InstalledExecutionGuard.wrapperDaemonPath) }
        #expect(throws: (any Error).self) { try InstalledExecutionGuard.validate(actualExecutablePath: FileManager.default.currentDirectoryPath + "/.build/debug/hyu-vpn-privileged-helper", allowedCanonicalPath: InstalledExecutionGuard.privilegedHelperPath) }
    }

    @Test func installedExecutionGuardUsesCurrentExecutableNotArgv0AndChecksIdentity() throws {
        let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let helperMain = try String(contentsOf: root.appendingPathComponent("Sources/HYUVPNPrivilegedHelperCLI/main.swift"), encoding: .utf8)
        let wrapperMain = try String(contentsOf: root.appendingPathComponent("Sources/HYUVPNCWrapperD/main.swift"), encoding: .utf8)
        #expect(helperMain.contains("validateCurrentExecutable"))
        #expect(wrapperMain.contains("validateCurrentExecutable"))
        #expect(!helperMain.contains("CommandLine.arguments.first"))
        #expect(!wrapperMain.contains("CommandLine.arguments.first"))

        let installed = InstalledExecutionIdentity(canonicalPath: "/Library/PrivilegedHelperTools/com.hyu.vpn.helper", device: 10, inode: 20)
        try InstalledExecutionGuard.validate(actual: installed, installed: installed)
        #expect(throws: (any Error).self) {
            try InstalledExecutionGuard.validate(actual: InstalledExecutionIdentity(canonicalPath: installed.canonicalPath, device: 10, inode: 21), installed: installed)
        }
        #expect(throws: (any Error).self) {
            try InstalledExecutionGuard.validate(actual: InstalledExecutionIdentity(canonicalPath: "/tmp/spoofed-helper", device: 10, inode: 20), installed: installed)
        }
    }

    @Test func connectPersistsExactRouteIntentBeforeUpstreamAndRepairUsesLedgerWithoutEnvironment() throws {
        let dir = try temporaryDirectory()
        let ledger = dir.appendingPathComponent("nonceabc123.ledger")
        let tools = Round9NetworkTools()
        let upstream = Round9AssertingUpstream(ledger: ledger, tools: tools)
        let paths = RuntimePaths(ledgerRoot: dir, upstream: dir.appendingPathComponent("vpnc-script"), route: dir.appendingPathComponent("route"), scutil: dir.appendingPathComponent("scutil"), sysctl: dir.appendingPathComponent("sysctl"), networksetup: dir.appendingPathComponent("networksetup"))
        let runner = NetworkWrapperRunner(paths: paths, expectedOwnerUID: UInt32(getuid()), tools: tools, upstream: upstream)
        let env = [
            "HYU_SESSION_LEDGER": ledger.path,
            "TUNDEV": "utun7",
            "INTERNAL_IP4_ADDRESS": "10.10.0.1",
            "VPNGATEWAY": "198.51.100.9",
            "CISCO_SPLIT_INC": "1",
            "CISCO_SPLIT_INC_0_ADDR": "10.0.0.0",
            "CISCO_SPLIT_INC_0_MASKLEN": "8",
            "CISCO_SPLIT_EXC": "0",
            "CISCO_IPV6_SPLIT_INC": "0",
            "CISCO_IPV6_SPLIT_EXC": "0"
        ]
        #expect(throws: (any Error).self) { try runner.run(reason: "connect", nonce: "nonceabc123", environment: env, suppliedLedgerPath: ledger) }
        #expect(upstream.sawIntentBeforeMutation)
        #expect(FileManager.default.fileExists(atPath: ledger.path))
        try runner.run(reason: "repair", nonce: "nonceabc123", environment: [:], suppliedLedgerPath: ledger)
        #expect(!FileManager.default.fileExists(atPath: ledger.path))
        #expect(tools.deletedRoutes.sorted() == ["10.0.0.0|10.10.0.1|utun7|255.0.0.0", "198.51.100.9|192.0.2.1|en0|255.255.255.255"])
    }


    @Test func installedGuardRequiresSecureCanonicalFileParentsAndWrapperdHashManifest() throws {
        var metadata = Round10Metadata.secure(paths: ["/", "/Library", "/Library/Application Support", "/Library/Application Support/HYU VPN", "/Library/Application Support/HYU VPN/runtime", "/Library/Application Support/HYU VPN/runtime/vpnc", InstalledExecutionGuard.wrapperDaemonPath, InstalledExecutionGuard.wrapperDaemonHashManifestPath])
        try InstalledExecutionGuard.validateInstalledPathSecurity(path: InstalledExecutionGuard.wrapperDaemonPath, metadata: metadata)
        try InstalledExecutionGuard.validateInstalledPathSecurity(path: InstalledExecutionGuard.wrapperDaemonHashManifestPath, metadata: metadata)
        try InstalledExecutionGuard.validateHash(actualSHA256: String(repeating: "a", count: 64), manifestText: String(repeating: "a", count: 64) + "\n")
        metadata.modes["/Library/Application Support/HYU VPN/runtime"] = 0o775
        #expect(throws: (any Error).self) { try InstalledExecutionGuard.validateInstalledPathSecurity(path: InstalledExecutionGuard.wrapperDaemonPath, metadata: metadata) }
        metadata.modes["/Library/Application Support/HYU VPN/runtime"] = 0o755
        metadata.symlinks.insert(InstalledExecutionGuard.wrapperDaemonHashManifestPath)
        #expect(throws: (any Error).self) { try InstalledExecutionGuard.validateInstalledPathSecurity(path: InstalledExecutionGuard.wrapperDaemonHashManifestPath, metadata: metadata) }
        #expect(throws: (any Error).self) { try InstalledExecutionGuard.validateHash(actualSHA256: String(repeating: "a", count: 64), manifestText: String(repeating: "b", count: 64) + "\n") }
    }

    @Test func existingPreInitLedgerDriftFailsRepairRequiredBeforeUpstream() throws {
        let dir = try temporaryDirectory()
        let ledger = dir.appendingPathComponent("nonceabc123.ledger")
        let tools = Round10DriftTools()
        let upstream = Round10CountingUpstream()
        let paths = RuntimePaths(ledgerRoot: dir, upstream: dir.appendingPathComponent("vpnc-script"), route: dir.appendingPathComponent("route"), scutil: dir.appendingPathComponent("scutil"), sysctl: dir.appendingPathComponent("sysctl"), networksetup: dir.appendingPathComponent("networksetup"))
        let runner = NetworkWrapperRunner(paths: paths, expectedOwnerUID: UInt32(getuid()), tools: tools, upstream: upstream)
        let env = round10ValidEnv(ledger: ledger)
        var preInitEnv = env
        preInitEnv.removeValue(forKey: "TUNDEV")
        try runner.run(reason: "pre-init", nonce: "nonceabc123", environment: preInitEnv, suppliedLedgerPath: ledger)
        tools.defaultGateway = "192.0.2.254"
        #expect(throws: (any Error).self) { try runner.run(reason: "connect", nonce: "nonceabc123", environment: env, suppliedLedgerPath: ledger) }
        #expect(upstream.calls == 1)
        let saved = try NetworkLedgerStore(path: ledger, expectedOwnerUID: UInt32(getuid())).load(expectedNonce: "nonceabc123")
        #expect(saved.status == "repair-required")
    }

    @Test func zeroExitWithoutAppliedTunnelRoutesFailsPostcondition() throws {
        let dir = try temporaryDirectory()
        let ledger = dir.appendingPathComponent("nonceabc123.ledger")
        let upstream = Round10CountingUpstream()
        let paths = RuntimePaths(ledgerRoot: dir, upstream: dir.appendingPathComponent("vpnc-script"), route: dir.appendingPathComponent("route"), scutil: dir.appendingPathComponent("scutil"), sysctl: dir.appendingPathComponent("sysctl"), networksetup: dir.appendingPathComponent("networksetup"))
        let runner = NetworkWrapperRunner(paths: paths, expectedOwnerUID: UInt32(getuid()), tools: Round10DriftTools(), upstream: upstream)

        do {
            try runner.run(reason: "connect", nonce: "nonceabc123", environment: round10ValidEnv(ledger: ledger), suppliedLedgerPath: ledger)
            Issue.record("zero-exit upstream without applied routes must fail")
        } catch let error as HelperError {
            #expect(error == .networkPostconditionFailed)
        }

        #expect(upstream.calls == 1)
        let saved = try NetworkLedgerStore(path: ledger, expectedOwnerUID: UInt32(getuid())).load(expectedNonce: "nonceabc123")
        #expect(saved.status == "repair-required")
        #expect(saved.tunnelInterface == "utun7")
    }

    @Test func noRouteFailureRetainsResolverProbeTunnelForRepair() throws {
        let dir = try temporaryDirectory()
        let ledger = dir.appendingPathComponent("nonceabc123.ledger")
        let tools = TunnelSurfaceNetworkTools()
        let paths = RuntimePaths(ledgerRoot: dir, upstream: dir.appendingPathComponent("vpnc-script"), route: dir.appendingPathComponent("route"), scutil: dir.appendingPathComponent("scutil"), sysctl: dir.appendingPathComponent("sysctl"), networksetup: dir.appendingPathComponent("networksetup"))
        let runner = NetworkWrapperRunner(paths: paths, expectedOwnerUID: UInt32(getuid()), tools: tools, upstream: Round10CountingUpstream())

        do {
            try runner.run(reason: "connect", nonce: "nonceabc123", environment: round10ValidEnv(ledger: ledger), suppliedLedgerPath: ledger)
            Issue.record("missing routes must fail")
        } catch let error as HelperError {
            #expect(error == .networkPostconditionFailed)
        }

        let failed = try NetworkLedgerStore(path: ledger, expectedOwnerUID: UInt32(getuid())).load(expectedNonce: "nonceabc123")
        #expect(failed.status == "repair-required")
        #expect(failed.tunnelInterface == "utun7")

        try runner.run(reason: "repair", nonce: "nonceabc123", environment: [:], suppliedLedgerPath: ledger)
        #expect(!FileManager.default.fileExists(atPath: ledger.path))
    }

    @Test func repairAcceptsTheTunnelResolverSurfaceCapturedBeforeNetworkMutation() throws {
        let dir = try temporaryDirectory()
        let ledger = dir.appendingPathComponent("nonceabc123.ledger")
        let tools = TunnelSurfaceNetworkTools()
        let upstream = TunnelSurfaceApplyingUpstream(tools: tools)
        let paths = RuntimePaths(
            ledgerRoot: dir,
            upstream: dir.appendingPathComponent("vpnc-script"),
            route: dir.appendingPathComponent("route"),
            scutil: dir.appendingPathComponent("scutil"),
            sysctl: dir.appendingPathComponent("sysctl"),
            networksetup: dir.appendingPathComponent("networksetup")
        )
        let runner = NetworkWrapperRunner(
            paths: paths,
            expectedOwnerUID: UInt32(getuid()),
            tools: tools,
            upstream: upstream
        )

        try runner.run(
            reason: "connect",
            nonce: "nonceabc123",
            environment: round10ValidEnv(ledger: ledger),
            suppliedLedgerPath: ledger
        )

        let recorded = try NetworkLedgerStore(path: ledger, expectedOwnerUID: UInt32(getuid())).load(expectedNonce: "nonceabc123")
        #expect(recorded.status == "recorded")
        #expect(recorded.dnsBefore?.surfaces["State:/Network/Interface/utun7/DNS"]?.keyPresent == false)
        #expect(recorded.dnsApplied?.surfaces["State:/Network/Interface/utun7/DNS"]?.keyPresent == false)
        #expect(recorded.dnsBefore?.activeInterface == "en0")
        #expect(recorded.dnsApplied?.activeInterface == "utun7")

        try runner.run(reason: "repair", nonce: "nonceabc123", environment: [:], suppliedLedgerPath: ledger)

        #expect(!FileManager.default.fileExists(atPath: ledger.path))
        #expect(tools.routes.isEmpty)
    }

    @Test func repairRestoresRemovedGatewayBaselineRoute() throws {
        let dir = try temporaryDirectory()
        let ledger = dir.appendingPathComponent("nonceabc123.ledger")
        let tools = TunnelSurfaceNetworkTools()
        let gatewayBypass = RouteSnapshot(destination: "198.51.100.9", gateway: "192.0.2.1", interface: "en0", netmask: "255.255.255.255", protocol: "ipv4")
        tools.routes = [gatewayBypass]
        let paths = RuntimePaths(ledgerRoot: dir, upstream: dir.appendingPathComponent("vpnc-script"), route: dir.appendingPathComponent("route"), scutil: dir.appendingPathComponent("scutil"), sysctl: dir.appendingPathComponent("sysctl"), networksetup: dir.appendingPathComponent("networksetup"))
        let runner = NetworkWrapperRunner(paths: paths, expectedOwnerUID: UInt32(getuid()), tools: tools, upstream: TunnelSurfaceApplyingUpstream(tools: tools))

        try runner.run(reason: "connect", nonce: "nonceabc123", environment: round10ValidEnv(ledger: ledger), suppliedLedgerPath: ledger)

        let recorded = try NetworkLedgerStore(path: ledger, expectedOwnerUID: UInt32(getuid())).load(expectedNonce: "nonceabc123")
        let bypassRecord = try #require(recorded.routeRecords.first { $0.applied.destination == gatewayBypass.destination })
        #expect(bypassRecord.before == gatewayBypass)
        #expect(bypassRecord.applied.routeSnapshot == gatewayBypass)
        tools.routes = []
        try NetworkLedgerStore(path: ledger, expectedOwnerUID: UInt32(getuid())).save(recorded.withStatus("repair-required"))

        try runner.run(reason: "repair", nonce: "nonceabc123", environment: [:], suppliedLedgerPath: ledger)

        #expect(!FileManager.default.fileExists(atPath: ledger.path))
        #expect(tools.restoredRoutes == [gatewayBypass])
        #expect(tools.routes == [gatewayBypass])
    }

    @Test func repairStillRestoresMissingForeignBaselineHostRoute() throws {
        let dir = try temporaryDirectory()
        let ledger = dir.appendingPathComponent("nonceabc123.ledger")
        let tools = TunnelSurfaceNetworkTools()
        let foreignRoute = RouteSnapshot(destination: "203.0.113.77", gateway: "192.0.2.1", interface: "en0", netmask: "255.255.255.255", protocol: "ipv4")
        tools.routes = [foreignRoute]
        let paths = RuntimePaths(ledgerRoot: dir, upstream: dir.appendingPathComponent("vpnc-script"), route: dir.appendingPathComponent("route"), scutil: dir.appendingPathComponent("scutil"), sysctl: dir.appendingPathComponent("sysctl"), networksetup: dir.appendingPathComponent("networksetup"))
        let runner = NetworkWrapperRunner(paths: paths, expectedOwnerUID: UInt32(getuid()), tools: tools, upstream: TunnelSurfaceApplyingUpstream(tools: tools))

        var environment = round10ValidEnv(ledger: ledger)
        environment["CISCO_SPLIT_INC_0_ADDR"] = foreignRoute.destination
        environment["CISCO_SPLIT_INC_0_MASK"] = foreignRoute.netmask
        try runner.run(reason: "connect", nonce: "nonceabc123", environment: environment, suppliedLedgerPath: ledger)

        let recorded = try NetworkLedgerStore(path: ledger, expectedOwnerUID: UInt32(getuid())).load(expectedNonce: "nonceabc123")
        tools.routes = []
        try NetworkLedgerStore(path: ledger, expectedOwnerUID: UInt32(getuid())).save(recorded.withStatus("repair-required"))

        try runner.run(reason: "repair", nonce: "nonceabc123", environment: [:], suppliedLedgerPath: ledger)

        #expect(!FileManager.default.fileExists(atPath: ledger.path))
        #expect(tools.restoredRoutes == [foreignRoute])
        #expect(tools.routes == [foreignRoute])
    }

    @Test func repairRetiresCleanLedgerAfterDefaultNetworkChangeWithoutRestoringObsoleteState() throws {
        let fixture = try staleNetworkEpochFixture()

        try fixture.runner.run(reason: "repair", nonce: "nonceabc123", environment: [:], suppliedLedgerPath: fixture.ledger)

        #expect(!FileManager.default.fileExists(atPath: fixture.ledger.path))
        #expect(fixture.tools.restoredRoutes.isEmpty)
        #expect(fixture.tools.restoredDNSServers.isEmpty)
        #expect(fixture.tools.restoredSearchDomains.isEmpty)
        #expect(fixture.tools.resolverSurfaces?["State:/Network/Service/service-wifi/DNS"]?.servers == ["166.104.100.100", "166.104.100.200"])
    }

    @Test func repairRestoresOnlyExactRetainedSetupDNSAfterDefaultNetworkChange() throws {
        let fixture = try staleNetworkEpochFixture()
        fixture.tools.resolverServers = fixture.appliedDNS.servers
        fixture.tools.resolverServersPresent = fixture.appliedDNS.serversPresent

        try fixture.runner.run(reason: "repair", nonce: "nonceabc123", environment: [:], suppliedLedgerPath: fixture.ledger)

        #expect(!FileManager.default.fileExists(atPath: fixture.ledger.path))
        #expect(fixture.tools.restoredRoutes.isEmpty)
        #expect(fixture.tools.restoredDNSServers.count == 1)
        #expect(fixture.tools.restoredSearchDomains.isEmpty)
        #expect(fixture.tools.resolverServers.isEmpty)
        #expect(!fixture.tools.resolverServersPresent)
    }

    @Test func staleNetworkRetirementRejectsAppliedRouteMixedSetupDNSAndForeignRouteCollision() throws {
        do {
            let fixture = try staleNetworkEpochFixture()
            fixture.tools.routes = [fixture.tunnelRoute]
            #expect(throws: (any Error).self) { try fixture.runner.run(reason: "repair", nonce: "nonceabc123", environment: [:], suppliedLedgerPath: fixture.ledger) }
            #expect(FileManager.default.fileExists(atPath: fixture.ledger.path))
            #expect(fixture.tools.routes == [fixture.tunnelRoute])
        }
        do {
            let fixture = try staleNetworkEpochFixture()
            fixture.tools.resolverServers = ["166.104.100.100", "203.0.113.53"]
            fixture.tools.resolverServersPresent = true
            #expect(throws: (any Error).self) { try fixture.runner.run(reason: "repair", nonce: "nonceabc123", environment: [:], suppliedLedgerPath: fixture.ledger) }
            #expect(FileManager.default.fileExists(atPath: fixture.ledger.path))
            #expect(fixture.tools.restoredDNSServers.isEmpty)
            #expect(fixture.tools.restoredSearchDomains.isEmpty)
        }
        do {
            let fixture = try staleNetworkEpochFixture()
            let foreign = RouteSnapshot(destination: fixture.tunnelRoute.destination, gateway: "192.0.2.254", interface: "en0", netmask: fixture.tunnelRoute.netmask, protocol: fixture.tunnelRoute.protocol)
            fixture.tools.routes = [foreign]
            #expect(throws: (any Error).self) { try fixture.runner.run(reason: "repair", nonce: "nonceabc123", environment: [:], suppliedLedgerPath: fixture.ledger) }
            #expect(FileManager.default.fileExists(atPath: fixture.ledger.path))
            #expect(fixture.tools.routes == [foreign])
        }
    }

    @Test func staleNetworkRetirementRequiresSameBootServiceAndInterface() throws {
        let mutations: [(TunnelSurfaceNetworkTools) -> Void] = [
            { $0.rebootIdentityValue = 4243 },
            { $0.primaryServiceIDValue = "service-other" },
            { $0.defaultInterface = "en1" },
        ]
        for mutate in mutations {
            let fixture = try staleNetworkEpochFixture()
            mutate(fixture.tools)
            #expect(throws: (any Error).self) { try fixture.runner.run(reason: "repair", nonce: "nonceabc123", environment: [:], suppliedLedgerPath: fixture.ledger) }
            #expect(FileManager.default.fileExists(atPath: fixture.ledger.path))
        }
    }

    @Test func systemNetworkToolsRestoresGatewayRouteWithoutDirectInterfaceModifier() throws {
        let dir = try temporaryDirectory()
        let route = dir.appendingPathComponent("route")
        let log = dir.appendingPathComponent("route-argv.log")
        try writeExecutable(route, """
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
        """)
        let paths = RuntimePaths(ledgerRoot: dir, upstream: dir.appendingPathComponent("vpnc-script"), route: route, scutil: dir.appendingPathComponent("scutil"), sysctl: dir.appendingPathComponent("sysctl"), networksetup: dir.appendingPathComponent("networksetup"))
        let tools = SystemNetworkTools(paths: paths)
        let baseline = RouteSnapshot(destination: "198.51.100.9", gateway: "192.0.2.1", interface: "en0", netmask: "255.255.255.255", protocol: "ipv4")

        try tools.restoreRoute(baseline)

        let calls = try String(contentsOf: log, encoding: .utf8).split(separator: "\n").map(String.init)
        #expect(calls.first == "-n add -net 198.51.100.9 -netmask 255.255.255.255 192.0.2.1")
    }

    @Test func sanitizedEnvironmentPreservesNumericVPNPIDAndSynthesizesIPv4Mask() {
        let sanitized = NetworkWrapperRunner.sanitizedEnvironment([
            "VPNPID": "12345",
            "CISCO_SPLIT_INC": "1",
            "CISCO_SPLIT_INC_0_ADDR": "10.0.0.0",
            "CISCO_SPLIT_INC_0_MASKLEN": "8",
            "PASSWORD": "CANARY"
        ])

        #expect(sanitized["VPNPID"] == "12345")
        #expect(sanitized["CISCO_SPLIT_INC_0_MASK"] == "255.0.0.0")
        #expect(sanitized["CISCO_SPLIT_INC_0_MASKLEN"] == nil)
        #expect(sanitized["PASSWORD"] == nil)
        #expect(NetworkWrapperRunner.sanitizedEnvironment(["VPNPID": "../CANARY"])["VPNPID"] == nil)
        #expect(NetworkWrapperRunner.sanitizedEnvironment(["VPNPID": "0"])["VPNPID"] == nil)
        #expect(NetworkWrapperRunner.sanitizedEnvironment(["VPNPID": "0001"])["VPNPID"] == nil)
        #expect(NetworkWrapperRunner.sanitizedEnvironment(["VPNPID": "2147483648"])["VPNPID"] == nil)
        #expect(NetworkWrapperRunner.sanitizedEnvironment(["VPNPID": "2147483647"])["VPNPID"] == "2147483647")
    }

    @Test func sanitizedEnvironmentDropsMaskLengthWhenCanonicalMaskExists() {
        let sanitized = NetworkWrapperRunner.sanitizedEnvironment([
            "CISCO_SPLIT_INC": "1",
            "CISCO_SPLIT_INC_0_ADDR": "10.0.0.0",
            "CISCO_SPLIT_INC_0_MASK": "255.0.0.0",
            "CISCO_SPLIT_INC_0_MASKLEN": "$(CANARY)"
        ])

        #expect(sanitized["CISCO_SPLIT_INC_0_MASK"] == "255.0.0.0")
        #expect(sanitized["CISCO_SPLIT_INC_0_MASKLEN"] == nil)
    }

    @Test func splitInputsRequireCanonicalIPv4AndContiguousMasks() throws {
        let dir = try temporaryDirectory()
        let ledger = dir.appendingPathComponent("nonceabc123.ledger")
        let paths = RuntimePaths(ledgerRoot: dir, upstream: dir.appendingPathComponent("vpnc-script"), route: dir.appendingPathComponent("route"), scutil: dir.appendingPathComponent("scutil"), sysctl: dir.appendingPathComponent("sysctl"), networksetup: dir.appendingPathComponent("networksetup"))
        for mutation in [
            { (env: inout [String: String]) in env["CISCO_SPLIT_INC_0_ADDR"] = "010.0.0.1" },
            { (env: inout [String: String]) in env["CISCO_SPLIT_INC_0_ADDR"] = "-net" },
            { (env: inout [String: String]) in env["VPNGATEWAY"] = "198.051.100.9" },
            { (env: inout [String: String]) in env["CISCO_SPLIT_INC_0_MASK"] = "255.0.255.0" },
            { (env: inout [String: String]) in env["TUNDEV"] = "utun7\nremove State:/Network/Global/DNS" }
        ] {
            let upstream = Round10CountingUpstream()
            let runner = NetworkWrapperRunner(paths: paths, expectedOwnerUID: UInt32(getuid()), tools: Round10DriftTools(), upstream: upstream)
            var env = round10ValidEnv(ledger: ledger)
            mutation(&env)
            #expect(throws: (any Error).self) { try runner.run(reason: "connect", nonce: "nonceabc123", environment: env, suppliedLedgerPath: ledger) }
            #expect(upstream.calls == 0)
            try? FileManager.default.removeItem(at: ledger)
        }
    }

    @Test func invalidTunnelIsRejectedBeforePreInitUpstream() throws {
        let dir = try temporaryDirectory()
        let ledger = dir.appendingPathComponent("nonceabc123.ledger")
        let upstream = Round10CountingUpstream()
        let paths = RuntimePaths(ledgerRoot: dir, upstream: dir.appendingPathComponent("vpnc-script"), route: dir.appendingPathComponent("route"), scutil: dir.appendingPathComponent("scutil"), sysctl: dir.appendingPathComponent("sysctl"), networksetup: dir.appendingPathComponent("networksetup"))
        let runner = NetworkWrapperRunner(paths: paths, expectedOwnerUID: UInt32(getuid()), tools: Round10DriftTools(), upstream: upstream)
        let env = [
            "HYU_SESSION_LEDGER": ledger.path,
            "TUNDEV": "utun7\nremove State:/Network/Global/DNS",
        ]

        #expect(throws: (any Error).self) {
            try runner.run(reason: "pre-init", nonce: "nonceabc123", environment: env, suppliedLedgerPath: ledger)
        }
        #expect(upstream.calls == 0)
    }

    @Test func connectWithoutTunnelIsRejectedAfterPreInitBeforeUpstream() throws {
        let dir = try temporaryDirectory()
        let ledger = dir.appendingPathComponent("nonceabc123.ledger")
        let upstream = Round10CountingUpstream()
        let paths = RuntimePaths(ledgerRoot: dir, upstream: dir.appendingPathComponent("vpnc-script"), route: dir.appendingPathComponent("route"), scutil: dir.appendingPathComponent("scutil"), sysctl: dir.appendingPathComponent("sysctl"), networksetup: dir.appendingPathComponent("networksetup"))
        let runner = NetworkWrapperRunner(paths: paths, expectedOwnerUID: UInt32(getuid()), tools: Round10DriftTools(), upstream: upstream)
        let preInitEnv = ["HYU_SESSION_LEDGER": ledger.path]
        try runner.run(reason: "pre-init", nonce: "nonceabc123", environment: preInitEnv, suppliedLedgerPath: ledger)
        var connectEnv = round10ValidEnv(ledger: ledger)
        connectEnv.removeValue(forKey: "TUNDEV")

        #expect(throws: (any Error).self) {
            try runner.run(reason: "connect", nonce: "nonceabc123", environment: connectEnv, suppliedLedgerPath: ledger)
        }
        #expect(upstream.calls == 1)
    }

}

private func temporaryDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("hyu-ledger-tests-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}


private func writeExecutable(_ url: URL, _ contents: String) throws {
    try contents.write(to: url, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
}


private final class Round9AssertingUpstream: VpncUpstreamRunning {
    let ledger: URL
    let tools: Round9NetworkTools
    var sawIntentBeforeMutation = false
    init(ledger: URL, tools: Round9NetworkTools) { self.ledger = ledger; self.tools = tools }
    func run(reason: String, environment: [String: String]) throws -> Int32 {
        let saved = try NetworkLedgerStore(path: ledger, expectedOwnerUID: UInt32(getuid())).load(expectedNonce: "nonceabc123")
        let applied = Dictionary(uniqueKeysWithValues: saved.routeRecords.map { ($0.applied.destination, $0.applied) })
        sawIntentBeforeMutation = applied["10.0.0.0"]?.gateway == "10.10.0.1"
            && applied["10.0.0.0"]?.interface == "utun7"
            && applied["10.0.0.0"]?.netmask == "255.0.0.0"
            && applied["198.51.100.9"]?.gateway == "192.0.2.1"
            && applied["198.51.100.9"]?.interface == "en0"
            && applied["198.51.100.9"]?.netmask == "255.255.255.255"
        tools.routes = saved.routeRecords.map(\.applied.routeSnapshot)
        throw HelperError.processMismatch
    }
}

private final class Round9NetworkTools: NetworkTooling {
    var routes: [RouteSnapshot] = []
    var deletedRoutes: [String] = []
    func rebootIdentity() throws -> UInt64 { 4242 }
    func primaryServiceID() throws -> String { "service-wifi" }
    func defaultRoute() throws -> RouteSnapshot { RouteSnapshot(destination: "default", gateway: "192.0.2.1", interface: "en0", netmask: "0.0.0.0", protocol: "ipv4") }
    func route(destination: String, netmask: String?) throws -> RouteSnapshot? { routes.first { $0.destination == destination && (netmask == nil || $0.netmask == netmask) } }
    func resolver(serviceID: String, baselineInterface: String, tunnelInterface: String?) throws -> ResolverSnapshot { ResolverSnapshot(serviceID: serviceID, servers: ["9.9.9.9"], searchDomains: ["home.example"], activeInterface: tunnelInterface ?? baselineInterface) }
    func serviceName(for serviceID: String) throws -> String { "Wi-Fi" }
    func deleteRoute(_ delta: RouteDelta) throws {
        deletedRoutes.append("\(delta.destination)|\(delta.gateway ?? "")|\(delta.interface ?? "")|\(delta.netmask ?? "")")
        routes.removeAll { $0.destination == delta.destination && $0.gateway == delta.gateway && $0.interface == delta.interface && $0.netmask == delta.netmask }
    }
    func restoreRoute(_ route: RouteSnapshot) throws { routes.append(route) }
    func restoreResolver(serviceID: String, snapshot: ResolverSnapshot) throws {}
}


private func round10ValidEnv(ledger: URL) -> [String: String] { ["HYU_SESSION_LEDGER": ledger.path, "TUNDEV": "utun7", "INTERNAL_IP4_ADDRESS": "10.10.0.1", "VPNGATEWAY": "198.51.100.9", "CISCO_SPLIT_INC": "1", "CISCO_SPLIT_INC_0_ADDR": "10.0.0.0", "CISCO_SPLIT_INC_0_MASK": "255.0.0.0", "CISCO_SPLIT_EXC": "0", "CISCO_IPV6_SPLIT_INC": "0", "CISCO_IPV6_SPLIT_EXC": "0"] }

private final class Round10CountingUpstream: VpncUpstreamRunning { var calls = 0; func run(reason: String, environment: [String: String]) throws -> Int32 { calls += 1; return 0 } }
private final class Round10DriftTools: NetworkTooling {
    var defaultGateway = "192.0.2.1"
    func rebootIdentity() throws -> UInt64 { 4242 }
    func primaryServiceID() throws -> String { "service-wifi" }
    func defaultRoute() throws -> RouteSnapshot { RouteSnapshot(destination: "default", gateway: defaultGateway, interface: "en0", netmask: "0.0.0.0", protocol: "ipv4") }
    func route(destination: String, netmask: String?) throws -> RouteSnapshot? { nil }
    func resolver(serviceID: String, baselineInterface: String, tunnelInterface: String?) throws -> ResolverSnapshot { ResolverSnapshot(serviceID: serviceID, servers: ["9.9.9.9"], searchDomains: ["home.example"], activeInterface: baselineInterface) }
    func serviceName(for serviceID: String) throws -> String { "Wi-Fi" }
    func deleteRoute(_ delta: RouteDelta) throws {}
    func restoreRoute(_ route: RouteSnapshot) throws {}
    func restoreResolver(serviceID: String, snapshot: ResolverSnapshot) throws {}
}

private final class TunnelSurfaceApplyingUpstream: VpncUpstreamRunning {
    let tools: TunnelSurfaceNetworkTools
    init(tools: TunnelSurfaceNetworkTools) { self.tools = tools }
    func run(reason: String, environment: [String: String]) throws -> Int32 {
        guard reason == "connect" else { return 0 }
        tools.routes = [
            RouteSnapshot(destination: "10.0.0.0", gateway: "10.10.0.1", interface: "utun7", netmask: "255.0.0.0", protocol: "ipv4"),
            RouteSnapshot(destination: "198.51.100.9", gateway: "192.0.2.1", interface: "en0", netmask: "255.255.255.255", protocol: "ipv4"),
        ]
        return 0
    }
}

private final class TunnelSurfaceNetworkTools: NetworkTooling {
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
    func rebootIdentity() throws -> UInt64 { rebootIdentityValue }
    func primaryServiceID() throws -> String { primaryServiceIDValue }
    func defaultRoute() throws -> RouteSnapshot { RouteSnapshot(destination: "default", gateway: defaultGateway, interface: defaultInterface, netmask: "0.0.0.0", protocol: "ipv4") }
    func route(destination: String, netmask: String?) throws -> RouteSnapshot? { routes.first { $0.destination == destination && (netmask == nil || $0.netmask == netmask) } }
    func resolver(serviceID: String, baselineInterface: String, tunnelInterface: String?) throws -> ResolverSnapshot {
        let setup = ResolverFieldSnapshot(servers: resolverServers, searchDomains: resolverSearchDomains, serversPresent: resolverServersPresent, searchDomainsPresent: resolverSearchDomainsPresent)
        var surfaces = resolverSurfaces ?? ["setup": setup]
        if let tunnelInterface {
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
    func deleteRoute(_ delta: RouteDelta) throws { routes.removeAll { $0.destination == delta.destination && $0.netmask == delta.netmask } }
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
}

private struct StaleNetworkEpochFixture {
    let ledger: URL
    let tools: TunnelSurfaceNetworkTools
    let runner: NetworkWrapperRunner
    let tunnelRoute: RouteSnapshot
    let appliedDNS: ResolverSnapshot
}

private func staleNetworkEpochFixture() throws -> StaleNetworkEpochFixture {
    let dir = try temporaryDirectory()
    let ledger = dir.appendingPathComponent("nonceabc123.ledger")
    let tools = TunnelSurfaceNetworkTools()
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
        serversPresent: true,
        searchDomainsPresent: false,
        surfaces: [setupKey: ResolverFieldSnapshot(servers: ["166.104.100.100"], searchDomains: []), stateKey: ResolverFieldSnapshot(servers: ["166.104.100.100", "9.9.9.9"], searchDomains: [])]
    )
    try NetworkLedgerStore(path: ledger, expectedOwnerUID: UInt32(getuid())).save(
        NetworkLedger(
            sessionNonce: "nonceabc123",
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
    tools.defaultGateway = "192.0.2.254"
    tools.resolverServers = []
    tools.resolverSearchDomains = []
    tools.resolverServersPresent = false
    tools.resolverSearchDomainsPresent = false
    tools.resolverSurfaces = [
        setupKey: missing,
        stateKey: ResolverFieldSnapshot(servers: ["166.104.100.100", "166.104.100.200"], searchDomains: []),
    ]
    let paths = RuntimePaths(ledgerRoot: dir, upstream: dir.appendingPathComponent("vpnc-script"), route: dir.appendingPathComponent("route"), scutil: dir.appendingPathComponent("scutil"), sysctl: dir.appendingPathComponent("sysctl"), networksetup: dir.appendingPathComponent("networksetup"))
    let runner = NetworkWrapperRunner(paths: paths, expectedOwnerUID: UInt32(getuid()), tools: tools, upstream: Round10CountingUpstream())
    return StaleNetworkEpochFixture(ledger: ledger, tools: tools, runner: runner, tunnelRoute: tunnelRoute, appliedDNS: appliedDNS)
}


private struct Round10Metadata: FileMetadataProviding {
    var owners: [String: UInt32] = [:]
    var modes: [String: mode_t] = [:]
    var symlinks = Set<String>()
    static func secure(paths: [String]) -> Round10Metadata {
        var metadata = Round10Metadata()
        for path in paths { metadata.owners[path] = 0; metadata.modes[path] = 0o755 }
        return metadata
    }
    func metadata(for path: String) throws -> SecureFileMetadata {
        guard let owner = owners[path], let mode = modes[path] else { throw HelperError.insecurePath(path) }
        return SecureFileMetadata(ownerUID: owner, mode: mode, isSymlink: symlinks.contains(path), fileID: path)
    }
}
