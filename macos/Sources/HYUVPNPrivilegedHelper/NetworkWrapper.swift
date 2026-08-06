import Foundation
import Dispatch

public struct RuntimePaths: Equatable, Sendable {
    public let ledgerRoot: URL
    public let upstream: URL
    public let route: URL
    public let scutil: URL
    public let sysctl: URL
    public let networksetup: URL

    public init(ledgerRoot: URL, upstream: URL, route: URL, scutil: URL, sysctl: URL, networksetup: URL) {
        self.ledgerRoot = ledgerRoot
        self.upstream = upstream
        self.route = route
        self.scutil = scutil
        self.sysctl = sysctl
        self.networksetup = networksetup
    }

    public static let production = RuntimePaths(
        ledgerRoot: URL(fileURLWithPath: "/private/var/db/hyu-vpn/ledger"),
        upstream: URL(fileURLWithPath: "/Library/Application Support/HYU VPN/runtime/vpnc/vpnc-script"),
        route: URL(fileURLWithPath: "/sbin/route"),
        scutil: URL(fileURLWithPath: "/usr/sbin/scutil"),
        sysctl: URL(fileURLWithPath: "/usr/sbin/sysctl"),
        networksetup: URL(fileURLWithPath: "/usr/sbin/networksetup")
    )
}

public protocol NetworkTooling {
    func rebootIdentity() throws -> UInt64
    func primaryServiceID() throws -> String
    func defaultRoute() throws -> RouteSnapshot
    func route(destination: String, netmask: String?) throws -> RouteSnapshot?
    func resolver(serviceID: String, baselineInterface: String, tunnelInterface: String?) throws -> ResolverSnapshot
    func serviceName(for serviceID: String) throws -> String
    func deleteRoute(_ delta: RouteDelta) throws
    func restoreRoute(_ route: RouteSnapshot) throws
    func restoreResolver(serviceID: String, snapshot: ResolverSnapshot) throws
    func restoreDNSServers(serviceID: String, snapshot: ResolverSnapshot) throws
    func restoreSearchDomains(serviceID: String, snapshot: ResolverSnapshot) throws
    func restoreResolverSurfaces(serviceID: String, snapshot: ResolverSnapshot, current: ResolverSnapshot) throws
}

public extension NetworkTooling {
    func restoreDNSServers(serviceID: String, snapshot: ResolverSnapshot) throws { try restoreResolver(serviceID: serviceID, snapshot: snapshot) }
    func restoreSearchDomains(serviceID: String, snapshot: ResolverSnapshot) throws { try restoreResolver(serviceID: serviceID, snapshot: snapshot) }
    func restoreResolverSurfaces(serviceID: String, snapshot: ResolverSnapshot, current: ResolverSnapshot) throws { try restoreResolver(serviceID: serviceID, snapshot: snapshot) }
}

public protocol VpncUpstreamRunning {
    func run(reason: String, environment: [String: String]) throws -> Int32
}

public struct BoundedProcessResult: Equatable { public let status: Int32; public let stdout: String; public let stderr: String }

private final class LockedDataSink: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()
    private let cap: Int
    init(cap: Int) { self.cap = cap }
    func append(_ value: Data) {
        lock.lock()
        defer { lock.unlock() }
        guard data.count < cap else { return }
        data.append(value.prefix(cap - data.count))
    }
    func get() -> Data { lock.lock(); defer { lock.unlock() }; return data }
}

public struct BoundedProcessRunner {
    public let timeout: TimeInterval
    public let maxOutputBytes: Int
    public init(timeout: TimeInterval = 5, maxOutputBytes: Int = 262_144) { self.timeout = timeout; self.maxOutputBytes = maxOutputBytes }

    public func run(_ executable: URL, _ arguments: [String], environment: [String: String], stdin: String? = nil) throws -> BoundedProcessResult {
        guard timeout > 0, maxOutputBytes > 0 else { throw HelperError.badConfiguration }
        var stdoutPipe = [Int32](repeating: 0, count: 2)
        var stderrPipe = [Int32](repeating: 0, count: 2)
        var stdinPipe = [Int32](repeating: 0, count: 2)
        guard pipe(&stdoutPipe) == 0, pipe(&stderrPipe) == 0 else { throw HelperError.processMismatch }
        var hasStdin = false
        if stdin != nil { guard pipe(&stdinPipe) == 0 else { close(stdoutPipe[0]); close(stdoutPipe[1]); close(stderrPipe[0]); close(stderrPipe[1]); throw HelperError.processMismatch }; hasStdin = true }

        var actions: posix_spawn_file_actions_t?
        var attrs: posix_spawnattr_t?
        posix_spawn_file_actions_init(&actions)
        posix_spawnattr_init(&attrs)
        defer { posix_spawn_file_actions_destroy(&actions); posix_spawnattr_destroy(&attrs) }
        posix_spawn_file_actions_adddup2(&actions, stdoutPipe[1], STDOUT_FILENO)
        posix_spawn_file_actions_adddup2(&actions, stderrPipe[1], STDERR_FILENO)
        if hasStdin { posix_spawn_file_actions_adddup2(&actions, stdinPipe[0], STDIN_FILENO) }
        posix_spawn_file_actions_addclose(&actions, stdoutPipe[0]); posix_spawn_file_actions_addclose(&actions, stderrPipe[0])
        posix_spawn_file_actions_addclose(&actions, stdoutPipe[1]); posix_spawn_file_actions_addclose(&actions, stderrPipe[1])
        if hasStdin { posix_spawn_file_actions_addclose(&actions, stdinPipe[0]); posix_spawn_file_actions_addclose(&actions, stdinPipe[1]) }
        posix_spawnattr_setflags(&attrs, Int16(POSIX_SPAWN_SETPGROUP))
        posix_spawnattr_setpgroup(&attrs, 0)

        let argvStrings = [executable.path] + arguments
        let argv = argvStrings.map { strdup($0) } + [nil]
        let envp = environment.map { strdup("\($0.key)=\($0.value)") } + [nil]
        defer { for ptr in argv { if let ptr { free(UnsafeMutableRawPointer(ptr)) } }; for ptr in envp { if let ptr { free(UnsafeMutableRawPointer(ptr)) } } }
        var pid = pid_t(0)
        let spawnResult = posix_spawn(&pid, executable.path, &actions, &attrs, argv, envp)
        close(stdoutPipe[1]); close(stderrPipe[1])
        if hasStdin { close(stdinPipe[0]) }
        guard spawnResult == 0 else {
            close(stdoutPipe[0]); close(stderrPipe[0]); if hasStdin { close(stdinPipe[1]) }
            throw HelperError.processMismatch
        }
        if let stdin, hasStdin {
            let bytes = Array(stdin.utf8)
            _ = bytes.withUnsafeBytes { raw in write(stdinPipe[1], raw.baseAddress, raw.count) }
            close(stdinPipe[1])
        }

        let group = DispatchGroup()
        let outSink = LockedDataSink(cap: maxOutputBytes)
        let errSink = LockedDataSink(cap: maxOutputBytes)
        drain(fd: stdoutPipe[0], into: outSink, group: group)
        drain(fd: stderrPipe[0], into: errSink, group: group)

        let deadline = Date().addingTimeInterval(timeout)
        var status: Int32 = 0
        while Date() < deadline {
            let waited = waitpid(pid, &status, WNOHANG)
            if waited == pid { if kill(-pid, 0) == 0 { kill(-pid, SIGKILL); _ = group.wait(timeout: .now() + 1); throw HelperError.processMismatch }; _ = group.wait(timeout: .now() + 1); return BoundedProcessResult(status: exitStatus(status), stdout: String(decoding: outSink.get(), as: UTF8.self), stderr: String(decoding: errSink.get(), as: UTF8.self)) }
            usleep(20_000)
        }
        kill(-pid, SIGTERM)
        let termDeadline = Date().addingTimeInterval(0.5)
        while Date() < termDeadline {
            let waited = waitpid(pid, &status, WNOHANG)
            if waited == pid { if kill(-pid, 0) == 0 { kill(-pid, SIGKILL); _ = waitpid(pid, &status, 0) }; _ = group.wait(timeout: .now() + 1); throw HelperError.processMismatch }
            usleep(20_000)
        }
        kill(-pid, SIGKILL)
        _ = waitpid(pid, &status, 0)
        _ = group.wait(timeout: .now() + 1)
        throw HelperError.processMismatch
    }

    private func drain(fd: Int32, into sink: LockedDataSink, group: DispatchGroup) {
        group.enter()
        DispatchQueue.global().async {
            var buffer = [UInt8](repeating: 0, count: 8192)
            while true {
                let count = read(fd, &buffer, buffer.count)
                if count <= 0 { break }
                sink.append(Data(buffer.prefix(count)))
            }
            close(fd)
            group.leave()
        }
    }

    private func exitStatus(_ status: Int32) -> Int32 {
        let wstatus = status & 0x7f
        if wstatus == 0 { return (status >> 8) & 0xff }
        if wstatus != 0x7f { return 128 + wstatus }
        return status
    }
}

public struct ProcessVpncUpstream: VpncUpstreamRunning {
    public let executable: URL
    public let runner: BoundedProcessRunner
    public init(executable: URL, runner: BoundedProcessRunner = BoundedProcessRunner(timeout: 20)) { self.executable = executable; self.runner = runner }
    public func run(reason: String, environment: [String: String]) throws -> Int32 {
        var env = NetworkWrapperRunner.sanitizedEnvironment(environment)
        env["reason"] = reason
        return try runner.run(executable, [], environment: env).status
    }
}

public struct SystemNetworkTools: NetworkTooling {
    public let paths: RuntimePaths
    public let runner: BoundedProcessRunner
    public init(paths: RuntimePaths = .production, runner: BoundedProcessRunner = BoundedProcessRunner()) { self.paths = paths; self.runner = runner }

    public func rebootIdentity() throws -> UInt64 {
        let out = try checked(paths.sysctl, ["-n", "kern.boottime"])
        guard let match = out.range(of: #"sec\s*=\s*(\d+)"#, options: .regularExpression), let value = String(out[match]).components(separatedBy: CharacterSet.decimalDigits.inverted).compactMap(UInt64.init).first, value > 1 else { throw HelperError.processMismatch }
        return value
    }

    public func primaryServiceID() throws -> String {
        let out = try checked(paths.scutil, [], stdin: "show State:/Network/Global/IPv4\n")
        guard let service = firstMatch(out, pattern: #"PrimaryService\s*:\s*(\S+)"#), !service.isEmpty else { throw HelperError.processMismatch }
        return service
    }

    public func defaultRoute() throws -> RouteSnapshot {
        guard let route = try routeGet("default"), !(route.gateway ?? "").isEmpty, !(route.interface ?? "").isEmpty else { throw HelperError.processMismatch }
        return route
    }

    public func route(destination: String, netmask: String?) throws -> RouteSnapshot? { try routeGet(destination, requestedNetmask: netmask) }

    public func resolver(serviceID: String, baselineInterface: String, tunnelInterface: String?) throws -> ResolverSnapshot {
        let setupKey = "Setup:/Network/Service/\(serviceID)/DNS"
        let stateKey = "State:/Network/Service/\(serviceID)/DNS"
        let globalKey = "State:/Network/Global/DNS"
        let physicalKey = "State:/Network/Interface/\(baselineInterface)/DNS"
        let tunnelKey = tunnelInterface.map { "State:/Network/Interface/\($0)/DNS" }
        // DHCP-provided DNS commonly has no persistent Setup:/.../DNS key.
        // Treat that absence as a valid baseline surface rather than a process
        // mismatch; the State:/Global/effective surfaces below still capture
        // the live DNS values needed for drift detection and repair.
        let setup = try dnsState(for: setupKey, required: false)
        let state = try dnsState(for: stateKey, required: false)
        let global = try dnsState(for: globalKey, required: false)
        let physical = try dnsState(for: physicalKey, required: false)
        let tunnel = try tunnelKey.map { try dnsState(for: $0, required: false) } ?? missingDNSState()
        let effectiveResult = try runner.run(paths.scutil, ["--dns"], environment: NetworkWrapperRunner.sanitizedEnvironment([:]))
        guard effectiveResult.status == 0, !effectiveResult.stdout.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw HelperError.processMismatch }
        let effective = parseEffectiveDNS(effectiveResult.stdout)
        var surfaces: [String: ResolverFieldSnapshot] = [
            setupKey: field(setup),
            stateKey: field(state),
            globalKey: field(global),
            physicalKey: field(physical),
            "Effective:/scutil/--dns": field(effective)
        ]
        if let tunnelKey { surfaces[tunnelKey] = field(tunnel) }
        return ResolverSnapshot(serviceID: serviceID, servers: setup.servers, searchDomains: setup.searches, activeInterface: tunnelInterface ?? baselineInterface, serversPresent: setup.serversPresent, searchDomainsPresent: setup.searchesPresent, surfaces: surfaces)
    }

    public func serviceName(for serviceID: String) throws -> String {
        let out = try checked(paths.scutil, [], stdin: "show Setup:/Network/Service/\(serviceID)\n")
        guard let name = firstMatch(out, pattern: #"UserDefinedName\s*:\s*(.+)"#), !name.isEmpty else { throw HelperError.processMismatch }
        return name.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    public func deleteRoute(_ delta: RouteDelta) throws {
        var args = ["-n", "delete", "-net", delta.destination]
        if let netmask = delta.netmask, !netmask.isEmpty { args += ["-netmask", netmask] }
        if let gateway = delta.gateway, !gateway.isEmpty { args.append(gateway) }
        _ = try checked(paths.route, args)
        if let route = try route(destination: delta.destination, netmask: delta.netmask), route == delta.routeSnapshot { throw HelperError.processMismatch }
    }

    public func restoreRoute(_ route: RouteSnapshot) throws {
        guard let gateway = route.gateway, !gateway.isEmpty else { throw HelperError.processMismatch }
        var args = ["-n", "add", route.destination == "default" ? "default" : "-net", route.destination]
        if let netmask = route.netmask, !netmask.isEmpty, route.destination != "default" { args += ["-netmask", netmask] }
        args.append(gateway)
        // Darwin's `-interface` marks a directly reachable (non-gateway)
        // route; appending it to a gateway route produces an invalid restore
        // command. Let the kernel resolve the interface from the gateway and
        // then fail closed if the exact recorded interface is not observed.
        _ = try checked(paths.route, args)
        guard try self.route(destination: route.destination, netmask: route.netmask) == route else { throw HelperError.processMismatch }
    }

    public func restoreResolver(serviceID: String, snapshot: ResolverSnapshot) throws {
        try restoreDNSServers(serviceID: serviceID, snapshot: snapshot)
        try restoreSearchDomains(serviceID: serviceID, snapshot: snapshot)
    }

    public func restoreDNSServers(serviceID: String, snapshot: ResolverSnapshot) throws {
        let name = try serviceName(for: serviceID)
        _ = try checked(paths.networksetup, ["-setdnsservers", name] + (snapshot.servers.isEmpty ? ["Empty"] : snapshot.servers))
    }

    public func restoreSearchDomains(serviceID: String, snapshot: ResolverSnapshot) throws {
        let name = try serviceName(for: serviceID)
        _ = try checked(paths.networksetup, ["-setsearchdomains", name] + (snapshot.searchDomains.isEmpty ? ["Empty"] : snapshot.searchDomains))
    }

    public func restoreResolverSurfaces(serviceID: String, snapshot: ResolverSnapshot, current: ResolverSnapshot) throws {
        try restoreResolver(serviceID: serviceID, snapshot: snapshot)
        // DynamicStore resolver keys are mutated only at the exact service/global/interface keys
        // captured in the ledger. If scutil cannot apply the exact before shape, verification
        // below leaves the ledger repair-required instead of widening mutation scope.
        for (key, fields) in snapshot.surfaces where key.hasPrefix("State:/") {
            try restoreDynamicDNS(key: key, fields: fields, current: current.surfaces[key])
        }
    }

    private func restoreDynamicDNS(key: String, fields: ResolverFieldSnapshot?, current: ResolverFieldSnapshot?) throws {
        guard let fields else { return }
        if !fields.keyPresent {
            guard let current else { return }
            if current.otherFingerprint == nil || current.otherFingerprint?.isEmpty == true {
                _ = try checked(paths.scutil, [], stdin: "remove \(key)\n")
            } else {
                var input = "get \(key)\n"
                input += "d.remove ServerAddresses\n"
                input += "d.remove SearchDomains\n"
                input += "set \(key)\n"
                _ = try checked(paths.scutil, [], stdin: input)
            }
            return
        }
        var input = "get \(key)\n"
        input += "d.remove ServerAddresses\n"
        input += "d.remove SearchDomains\n"
        if fields.serversPresent {
            input += "d.add ServerAddresses * \(fields.servers.joined(separator: " "))\n"
        }
        if fields.searchDomainsPresent {
            input += "d.add SearchDomains * \(fields.searchDomains.joined(separator: " "))\n"
        }
        input += "set \(key)\n"
        _ = try checked(paths.scutil, [], stdin: input)
    }

    private func routeGet(_ requestedDestination: String, requestedNetmask: String? = nil) throws -> RouteSnapshot? {
        let result = try runner.run(paths.route, ["-n", "get", requestedDestination], environment: NetworkWrapperRunner.sanitizedEnvironment([:]))
        if result.status != 0, requestedDestination != "default" { return nil }
        guard result.status == 0 else { throw HelperError.processMismatch }
        if let route = parsedRouteGet(result.stdout, requestedDestination: requestedDestination, requestedNetmask: requestedNetmask, allowStaticHostMaskNormalization: true) {
            return route
        }
        if requestedDestination == "default" { throw HelperError.processMismatch }
        guard requestedNetmask == "255.255.255.255" else { return nil }

        // Darwin may return a WASCLONED host lookup for an explicit /32 route
        // installed with `route add -net ... -netmask 255.255.255.255`. Query
        // the exact network form before deciding that the parent route is absent.
        let exact = try runner.run(
            paths.route,
            ["-n", "get", "-net", requestedDestination, "-netmask", "255.255.255.255"],
            environment: NetworkWrapperRunner.sanitizedEnvironment([:])
        )
        guard exact.status == 0 else { return nil }
        let exactFlags = routeFlags(exact.stdout)
        guard exactFlags.contains("STATIC"), exactFlags.contains("GATEWAY"), !exactFlags.contains("WASCLONED") else { return nil }
        return parsedRouteGet(exact.stdout, requestedDestination: requestedDestination, requestedNetmask: requestedNetmask, allowStaticHostMaskNormalization: false)
    }

    private func parsedRouteGet(_ output: String, requestedDestination: String, requestedNetmask: String?, allowStaticHostMaskNormalization: Bool) -> RouteSnapshot? {
        let actualDestination = firstMatch(output, pattern: #"(?:^|\n)\s*destination:\s*(\S+)"#) ?? (requestedDestination == "default" ? "default" : "")
        let gateway = firstMatch(output, pattern: #"(?:^|\n)\s*gateway:\s*(\S+)"#) ?? ""
        let interface = firstMatch(output, pattern: #"(?:^|\n)\s*interface:\s*(\S+)"#) ?? ""
        let flags = routeFlags(output)
        let parsedNetmask = firstMatch(output, pattern: #"(?:^|\n)\s*mask:\s*(\S+)"#) ?? firstMatch(output, pattern: #"(?:^|\n)\s*netmask:\s*(\S+)"#)
        let isOwnedStaticHostRoute = requestedNetmask == "255.255.255.255"
            && allowStaticHostMaskNormalization
            && actualDestination == requestedDestination
            && flags.contains("HOST")
            && flags.contains("STATIC")
            && !flags.contains("WASCLONED")
        let netmask = parsedNetmask ?? (requestedDestination == "default" ? "0.0.0.0" : (isOwnedStaticHostRoute ? "255.255.255.255" : ""))
        guard !gateway.isEmpty, !interface.isEmpty else { return nil }
        if requestedDestination != "default" {
            guard actualDestination == requestedDestination else { return nil }
            if let requestedNetmask, !requestedNetmask.isEmpty, netmask != requestedNetmask { return nil }
        }
        return RouteSnapshot(destination: requestedDestination == "default" ? "default" : actualDestination, gateway: gateway, interface: interface, netmask: netmask, protocol: "ipv4")
    }

    private func routeFlags(_ output: String) -> Set<String> {
        Set((firstMatch(output, pattern: #"(?:^|\n)\s*flags:\s*<([^>]+)>"#) ?? "")
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).uppercased() })
    }

    private func checked(_ executable: URL, _ arguments: [String], stdin: String? = nil) throws -> String {
        let result = try runner.run(executable, arguments, environment: NetworkWrapperRunner.sanitizedEnvironment([:]), stdin: stdin)
        guard result.status == 0 else { throw HelperError.processMismatch }
        return result.stdout
    }

    private func dnsState(for key: String, required: Bool) throws -> (servers: [String], searches: [String], serversPresent: Bool, searchesPresent: Bool, keyPresent: Bool, otherFingerprint: String?) {
        let result = try runner.run(paths.scutil, [], environment: NetworkWrapperRunner.sanitizedEnvironment([:]), stdin: "show \(key)\n")
        guard result.status == 0 else { throw HelperError.processMismatch }
        if isExplicitMissingKey(result.stdout) { if required { throw HelperError.processMismatch }; return missingDNSState() }
        guard !result.stdout.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw HelperError.processMismatch }
        return parseDNSState(result.stdout)
    }

    private func missingDNSState() -> (servers: [String], searches: [String], serversPresent: Bool, searchesPresent: Bool, keyPresent: Bool, otherFingerprint: String?) {
        ([], [], false, false, false, nil)
    }

    private func isExplicitMissingKey(_ text: String) -> Bool {
        text.trimmingCharacters(in: .whitespacesAndNewlines) == "No such key"
    }

    private func parseDNSState(_ text: String) -> (servers: [String], searches: [String], serversPresent: Bool, searchesPresent: Bool, keyPresent: Bool, otherFingerprint: String?) {
        var servers: [String] = []
        var searches: [String] = []
        var serversPresent = false
        var searchesPresent = false
        let keyPresent = !isExplicitMissingKey(text) && !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        var otherLines: [String] = []
        var section: String?
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("ServerAddresses") { section = "servers"; serversPresent = true; continue }
            if line.hasPrefix("SearchDomains") { section = "searches"; searchesPresent = true; continue }
            if line.hasPrefix("}") { section = nil; continue }
            if line.hasPrefix("DomainName"), let value = line.split(separator: ":", maxSplits: 1).last?.trimmingCharacters(in: .whitespaces), !value.isEmpty { searchesPresent = true; searches.append(value); continue }
            guard let section, let value = line.range(of: #"^\d+\s*:\s*(\S+)"#, options: .regularExpression).map({ String(line[$0]).split(separator: ":", maxSplits: 1).last!.trimmingCharacters(in: .whitespaces) }) else { if keyPresent && !line.isEmpty && line != "{" { otherLines.append(line) }; continue }
            if section == "servers" { servers.append(value) }
            if section == "searches" { searches.append(value) }
        }
        return (servers, searches, serversPresent, searchesPresent, keyPresent, otherLines.sorted().joined(separator: "|"))
    }

    private func parseEffectiveDNS(_ text: String) -> (servers: [String], searches: [String], serversPresent: Bool, searchesPresent: Bool, keyPresent: Bool, otherFingerprint: String?) {
        var servers: [String] = []
        var searches: [String] = []
        for raw in text.split(separator: "\n").map(String.init) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if let value = line.range(of: #"^nameserver\[\d+\]\s*:\s*(\S+)"#, options: .regularExpression).map({ String(line[$0]).split(separator: ":", maxSplits: 1).last!.trimmingCharacters(in: .whitespaces) }) { servers.append(value) }
            if let value = line.range(of: #"^search domain\[\d+\]\s*:\s*(\S+)"#, options: .regularExpression).map({ String(line[$0]).split(separator: ":", maxSplits: 1).last!.trimmingCharacters(in: .whitespaces) }) { searches.append(value) }
        }
        return (servers, searches, !servers.isEmpty, !searches.isEmpty, !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, nil)
    }

    private func field(_ parsed: (servers: [String], searches: [String], serversPresent: Bool, searchesPresent: Bool, keyPresent: Bool, otherFingerprint: String?)) -> ResolverFieldSnapshot {
        ResolverFieldSnapshot(servers: parsed.servers, searchDomains: parsed.searches, serversPresent: parsed.serversPresent, searchDomainsPresent: parsed.searchesPresent, keyPresent: parsed.keyPresent, otherFingerprint: parsed.otherFingerprint?.isEmpty == true ? nil : parsed.otherFingerprint)
    }

    private func firstMatch(_ text: String, pattern: String) -> String? { matches(text, pattern: pattern).first }
    private func matches(_ text: String, pattern: String) -> [String] {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let ns = text as NSString
        return regex.matches(in: text, range: NSRange(location: 0, length: ns.length)).compactMap { $0.numberOfRanges > 1 ? ns.substring(with: $0.range(at: 1)) : nil }
    }
}

public struct NetworkWrapperRunner {
    public let paths: RuntimePaths
    public let expectedOwnerUID: UInt32
    public let tools: NetworkTooling
    public let upstream: VpncUpstreamRunning

    public init(paths: RuntimePaths = .production, expectedOwnerUID: UInt32 = 0, tools: NetworkTooling? = nil, upstream: VpncUpstreamRunning? = nil) {
        self.paths = paths
        self.expectedOwnerUID = expectedOwnerUID
        self.tools = tools ?? SystemNetworkTools(paths: paths)
        self.upstream = upstream ?? ProcessVpncUpstream(executable: paths.upstream)
    }

    public static func sanitizedEnvironment(_ environment: [String: String]) -> [String: String] {
        let exact: Set<String> = ["reason", "HYU_NONCE", "HYU_SESSION_LEDGER", "VPNGATEWAY", "TUNDEV", "IDLE_TIMEOUT", "INTERNAL_IP4_ADDRESS", "INTERNAL_IP4_MTU", "INTERNAL_IP4_NETMASK", "INTERNAL_IP4_NETMASKLEN", "INTERNAL_IP4_NETADDR", "INTERNAL_IP4_DNS", "INTERNAL_IP4_NBNS", "INTERNAL_IP6_DNS", "CISCO_DEF_DOMAIN", "CISCO_SPLIT_DNS", "CISCO_SPLIT_INC", "CISCO_SPLIT_EXC", "CISCO_IPV6_SPLIT_INC", "CISCO_IPV6_SPLIT_EXC"]
        var result = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        for key in exact { if let value = environment[key], value.utf8.count <= 4096 { result[key] = value } }
        let indexed = #"^CISCO(_IPV6)?_SPLIT_(INC|EXC)_\d+_(ADDR|MASK|PROTOCOL|SPORT|DPORT)$"#
        for (key, value) in environment where key.range(of: indexed, options: .regularExpression) != nil && value.utf8.count <= 1024 { result[key] = value }
        if let vpnPID = environment["VPNPID"], let parsed = Int32(vpnPID), parsed > 0, String(parsed) == vpnPID {
            result["VPNPID"] = vpnPID
        }
        if let count = Int(result["CISCO_SPLIT_INC"] ?? ""), (0...128).contains(count) {
            for index in 0..<count {
                let mask = "CISCO_SPLIT_INC_\(index)_MASK"
                let maskLength = "CISCO_SPLIT_INC_\(index)_MASKLEN"
                if result[mask] == nil, let rawLength = environment[maskLength], let length = Int(rawLength), String(length) == rawLength, (0...32).contains(length) {
                    result[mask] = ipv4Mask(length: length)
                }
            }
        }
        return result
    }

    private static func ipv4Mask(length: Int) -> String {
        let mask: UInt32 = length == 0 ? 0 : UInt32.max << UInt32(32 - length)
        return [24, 16, 8, 0].map { String((mask >> UInt32($0)) & 0xff) }.joined(separator: ".")
    }

    public func run(reason: String, nonce: String, environment: [String: String], suppliedLedgerPath: URL? = nil) throws {
        guard ["pre-init", "connect", "attempt-reconnect", "reconnect", "disconnect", "repair"].contains(reason) else { throw HelperError.invalidCommand }
        guard nonce.range(of: "^[A-Za-z0-9._-]{1,128}$", options: .regularExpression) != nil else { throw HelperError.badConfiguration }
        let ledgerPath = paths.ledgerRoot.appendingPathComponent("\(nonce).ledger")
        if let suppliedLedgerPath, suppliedLedgerPath.path != ledgerPath.path { throw HelperError.processMismatch }
        try withLedgerLock(nonce: nonce) {
            switch reason {
            case "pre-init", "connect", "attempt-reconnect", "reconnect": try connectLike(reason: reason, nonce: nonce, ledgerPath: ledgerPath, environment: environment)
            case "disconnect", "repair": try disconnectLike(reason: reason, nonce: nonce, ledgerPath: ledgerPath, environment: environment)
            default: throw HelperError.invalidCommand
            }
        }
    }

    private func withLedgerLock<T>(nonce: String, body: () throws -> T) throws -> T {
        try FileManager.default.createDirectory(at: paths.ledgerRoot, withIntermediateDirectories: true)
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: paths.ledgerRoot.path)
        let lockPath = paths.ledgerRoot.appendingPathComponent(".\(nonce).lock")
        let fd = open(lockPath.path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
        if fd == -1 { throw HelperError.insecurePath(lockPath.path) }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == expectedOwnerUID, (st.st_mode & 0o777) == 0o600 else { close(fd); throw HelperError.insecurePath(lockPath.path) }
        _ = fchmod(fd, 0o600)
        if expectedOwnerUID == 0 { _ = fchown(fd, expectedOwnerUID, 0) }
        defer { flock(fd, LOCK_UN); fsync(fd); close(fd) }
        guard flock(fd, LOCK_EX) == 0 else { throw HelperError.processMismatch }
        return try body()
    }

    private func connectLike(reason: String, nonce: String, ledgerPath: URL, environment: [String: String]) throws {
        let store = NetworkLedgerStore(path: ledgerPath, expectedOwnerUID: expectedOwnerUID)
        if reason == "pre-init" {
            // OpenConnect calls pre-init before os_setup_tun(). Unless -i forced
            // an interface name, it deliberately unsets TUNDEV for this phase.
            // Validate a supplied value, but do not require one until connect.
            if let suppliedTunnel = environment["TUNDEV"] {
                _ = try validatedTunnelInterface(suppliedTunnel)
            }
            let baseline: NetworkLedger
            if FileManager.default.fileExists(atPath: ledgerPath.path) {
                baseline = try store.load(expectedNonce: nonce)
                if baseline.status == "repair-required" { throw HelperError.teardownIncomplete("existing repair-required ledger") }
                guard baseline.routeRecords.isEmpty else { throw HelperError.processMismatch }
            } else {
                baseline = try makeBaseline(nonce: nonce, destinations: [])
                try store.save(baseline)
            }
            let before = try snapshot(destinations: [], environment: [:])
            guard preflightSafe(ledger: baseline, current: before) else { try store.save(baseline.withStatus("repair-required")); throw HelperError.networkPreflightDrift }
            let code: Int32
            do {
                code = try upstream.run(reason: reason, environment: Self.sanitizedEnvironment(environment))
            } catch {
                try? store.save(baseline.withStatus("repair-required"))
                throw HelperError.networkUpstreamFailed
            }
            let after: NetworkSnapshotData
            do {
                after = try snapshot(destinations: [], environment: [:])
            } catch {
                try? store.save(baseline.withStatus("repair-required"))
                throw HelperError.networkPostconditionFailed
            }
            guard code == 0 else { try store.save(baseline.withStatus("repair-required")); throw HelperError.networkUpstreamFailed }
            guard baselineRestored(ledger: baseline, current: after) else { try store.save(baseline.withStatus("repair-required")); throw HelperError.networkPostconditionFailed }
            return
        }
        let tunnelInterface = try validatedTunnelInterface(environment["TUNDEV"])
        let destinations = try splitDestinations(environment)
        var baseline: NetworkLedger
        if FileManager.default.fileExists(atPath: ledgerPath.path) {
            baseline = try store.load(expectedNonce: nonce)
            if baseline.status == "repair-required" { throw HelperError.teardownIncomplete("existing repair-required ledger") }
            if baseline.routeRecords.isEmpty {
                let current = try snapshot(destinations: [], environment: [:])
                guard preflightSafe(ledger: baseline, current: current) else { try store.save(baseline.withStatus("repair-required")); throw HelperError.networkPreflightDrift }
                baseline = try makeBaseline(nonce: nonce, destinations: destinations, tunnelInterface: tunnelInterface)
                try store.save(baseline)
            }
        } else {
            baseline = try makeBaseline(nonce: nonce, destinations: destinations, tunnelInterface: tunnelInterface)
            try store.save(baseline)
        }
        let preflight = try snapshot(destinations: baseline.routeRecords.map { ($0.applied.destination, $0.applied.netmask ?? "") }, environment: environment)
        guard preflightSafe(ledger: baseline, current: preflight) else { try store.save(baseline.withStatus("repair-required")); throw HelperError.networkPreflightDrift }
        let intentLedger = try ledgerWithPersistedIntent(baseline: baseline, destinations: destinations, environment: environment)
        try store.save(intentLedger)
        let code: Int32
        do {
            code = try upstream.run(reason: reason, environment: Self.sanitizedEnvironment(environment))
        } catch {
            try? saveRepairRequired(store: store, baseline: intentLedger, destinations: destinations, environment: environment)
            throw HelperError.networkUpstreamFailed
        }
        let after: NetworkSnapshotData
        do {
            after = try snapshot(destinations: destinations, environment: environment)
        } catch {
            try? store.save(intentLedger.withStatus("repair-required"))
            throw HelperError.networkPostconditionFailed
        }
        let records = makeRouteRecords(baseline: intentLedger, after: after)
        let postconditionSatisfied = connectPostconditionSatisfied(intent: intentLedger, after: after, expectedTunnel: tunnelInterface)
        let status = code == 0 && postconditionSatisfied ? "recorded" : "repair-required"
        let recordedTunnel = after.tunnelInterface.isEmpty ? intentLedger.tunnelInterface : after.tunnelInterface
        let updated = NetworkLedger(schemaVersion: 1, sessionNonce: nonce, rebootIdentity: intentLedger.rebootIdentity, serviceIDBefore: intentLedger.serviceIDBefore, defaultInterfaceBefore: intentLedger.defaultInterfaceBefore, defaultRouteBefore: intentLedger.defaultRouteBefore, tunnelInterface: recordedTunnel, routeDeltasApplied: records.map(\.applied), routeRecords: records, dnsBefore: intentLedger.dnsBefore, dnsApplied: after.resolver, status: status, timestamp: intentLedger.timestamp)
        try store.save(updated)
        if code != 0 { throw HelperError.networkUpstreamFailed }
        if !postconditionSatisfied { throw HelperError.networkPostconditionFailed }
    }

    private func connectPostconditionSatisfied(intent: NetworkLedger, after: NetworkSnapshotData, expectedTunnel: String?) -> Bool {
        guard let expectedTunnel, !expectedTunnel.isEmpty, after.tunnelInterface == expectedTunnel else { return false }
        let actual = Dictionary(uniqueKeysWithValues: after.routes.map { (routeKey($0), $0) })
        return intent.routeRecords.allSatisfy { record in
            actual[routeKey(record.applied)] == record.applied.routeSnapshot
        }
    }

    private func disconnectLike(reason: String, nonce: String, ledgerPath: URL, environment: [String: String]) throws {
        let store = NetworkLedgerStore(path: ledgerPath, expectedOwnerUID: expectedOwnerUID)
        let ledger = try store.load(expectedNonce: nonce)
        let destinations = ledger.routeRecords.map { ($0.applied.destination, $0.applied.netmask ?? "") }
        var snapshotEnvironment = environment
        if snapshotEnvironment["TUNDEV"] == nil, let tunnelInterface = ledger.tunnelInterface {
            snapshotEnvironment["TUNDEV"] = tunnelInterface
        }
        let preflight = try snapshot(destinations: destinations, environment: snapshotEnvironment)
        guard preflightSafe(ledger: ledger, current: preflight, allowRepairRequired: reason == "repair") else { try store.save(ledger.withStatus("repair-required")); throw HelperError.processMismatch }
        if reason == "disconnect" {
            let code = try upstream.run(reason: reason, environment: Self.sanitizedEnvironment(environment))
            if code != 0 { try store.save(ledger.withStatus("repair-required")); throw HelperError.processMismatch }
        }
        let post = try snapshot(destinations: destinations, environment: snapshotEnvironment)
        let plan = repairActions(ledger: ledger, current: post)
        guard plan.safe else { try store.save(ledger.withStatus("repair-required")); throw HelperError.processMismatch }
        do {
            for action in plan.routeActions {
                if let delete = action.delete { try tools.deleteRoute(delete) }
                if let restore = action.restore { try tools.restoreRoute(restore) }
            }
            if let before = ledger.dnsBefore, let service = ledger.serviceIDBefore {
                if plan.restoreAllResolverSurfaces { try tools.restoreResolverSurfaces(serviceID: service, snapshot: before, current: post.resolver) }
                else {
                    if plan.restoreDNSServers { try tools.restoreDNSServers(serviceID: service, snapshot: before) }
                    if plan.restoreSearchDomains { try tools.restoreSearchDomains(serviceID: service, snapshot: before) }
                }
            }
        } catch {
            try store.save(ledger.withStatus("repair-required"))
            throw error
        }
        let verified = try snapshot(destinations: destinations, environment: snapshotEnvironment)
        guard baselineRestored(ledger: ledger, current: verified) else { try store.save(ledger.withStatus("repair-required")); throw HelperError.teardownIncomplete("post-repair snapshot did not match baseline") }
        try removeLedgerAndSyncDirectory(ledgerPath)
    }

    private func saveRepairRequired(store: NetworkLedgerStore, baseline: NetworkLedger, destinations: [(String, String)], environment: [String: String]) throws {
        if let current = try? snapshot(destinations: destinations, environment: environment) {
            let records = makeRouteRecords(baseline: baseline, after: current)
            let recordedTunnel = current.tunnelInterface.isEmpty ? baseline.tunnelInterface : current.tunnelInterface
            let updated = NetworkLedger(schemaVersion: 1, sessionNonce: baseline.sessionNonce, rebootIdentity: baseline.rebootIdentity, serviceIDBefore: baseline.serviceIDBefore, defaultInterfaceBefore: baseline.defaultInterfaceBefore, defaultRouteBefore: baseline.defaultRouteBefore, tunnelInterface: recordedTunnel, routeDeltasApplied: records.map(\.applied), routeRecords: records, dnsBefore: baseline.dnsBefore, dnsApplied: current.resolver, status: "repair-required", timestamp: baseline.timestamp)
            try store.save(updated)
        } else {
            try store.save(baseline.withStatus("repair-required"))
        }
    }

    private func makeBaseline(nonce: String, destinations: [(String, String)], tunnelInterface: String? = nil) throws -> NetworkLedger {
        let snapshotEnvironment = tunnelInterface.map { ["TUNDEV": $0] } ?? [:]
        let before = try snapshot(destinations: destinations, environment: snapshotEnvironment)
        var records: [RouteRecord] = []
        let beforeByTarget = Dictionary(uniqueKeysWithValues: before.routes.map { (routeKey($0), $0) })
        for (destination, mask) in destinations {
            let beforeRoute = beforeByTarget["ipv4|\(destination)|\(mask)"]
            let applied = RouteDelta(operation: "add", destination: destination, gateway: nil, interface: nil, netmask: mask.isEmpty ? nil : mask, protocol: "ipv4")
            records.append(RouteRecord(before: beforeRoute, applied: applied, after: beforeRoute))
        }
        return NetworkLedger(schemaVersion: 1, sessionNonce: nonce, rebootIdentity: before.rebootIdentity, serviceIDBefore: before.serviceID, defaultInterfaceBefore: before.defaultInterface, defaultRouteBefore: before.defaultRoute, tunnelInterface: tunnelInterface, routeDeltasApplied: records.map(\.applied), routeRecords: records, dnsBefore: before.resolver, dnsApplied: nil, status: "recorded", timestamp: Date())
    }

    private func ledgerWithPersistedIntent(baseline: NetworkLedger, destinations: [(String, String)], environment: [String: String]) throws -> NetworkLedger {
        let tunnel = try validatedTunnelInterface(environment["TUNDEV"])
        guard let tunnelGateway = environment["INTERNAL_IP4_ADDRESS"], !tunnelGateway.isEmpty else { throw HelperError.badConfiguration }
        let vpnGateway = environment["VPNGATEWAY"] ?? ""
        let prior = Dictionary(uniqueKeysWithValues: baseline.routeRecords.map { (routeKey($0.applied), $0) })
        var records: [RouteRecord] = []
        for (destination, mask) in destinations {
            let key = "ipv4|\(destination)|\(mask)"
            guard let existing = prior[key] else { throw HelperError.badConfiguration }
            let applied: RouteDelta
            if !vpnGateway.isEmpty, destination == vpnGateway, mask == "255.255.255.255" {
                guard let defaultRoute = baseline.defaultRouteBefore, let gateway = defaultRoute.gateway, let interface = defaultRoute.interface, !gateway.isEmpty, !interface.isEmpty else { throw HelperError.badConfiguration }
                applied = RouteDelta(operation: "add", destination: destination, gateway: gateway, interface: interface, netmask: mask, protocol: "ipv4")
            } else {
                applied = RouteDelta(operation: "add", destination: destination, gateway: tunnelGateway, interface: tunnel, netmask: mask.isEmpty ? nil : mask, protocol: "ipv4")
            }
            records.append(RouteRecord(before: existing.before, applied: applied, after: existing.after))
        }
        return NetworkLedger(schemaVersion: baseline.schemaVersion, sessionNonce: baseline.sessionNonce, rebootIdentity: baseline.rebootIdentity, serviceIDBefore: baseline.serviceIDBefore, defaultInterfaceBefore: baseline.defaultInterfaceBefore, defaultRouteBefore: baseline.defaultRouteBefore, tunnelInterface: tunnel, routeDeltasApplied: records.map(\.applied), routeRecords: records, dnsBefore: baseline.dnsBefore, dnsApplied: baseline.dnsApplied, status: baseline.status, timestamp: baseline.timestamp)
    }

    private func snapshot(destinations: [(String, String)], environment: [String: String]) throws -> NetworkSnapshotData {
        let boot = try tools.rebootIdentity()
        let defaultRoute = try tools.defaultRoute()
        guard boot > 1, let defaultInterface = defaultRoute.interface, !defaultInterface.isEmpty, !(defaultRoute.gateway ?? "").isEmpty else { throw HelperError.processMismatch }
        let service = try tools.primaryServiceID()
        guard !service.isEmpty else { throw HelperError.processMismatch }
        let routes = try destinations.compactMap { try tools.route(destination: $0.0, netmask: $0.1.isEmpty ? nil : $0.1) }.sorted()
        let routeTunnelCandidates = routes.compactMap(\.interface).filter { $0.hasPrefix("utun") }
        for candidate in routeTunnelCandidates { _ = try validatedTunnelInterface(candidate) }
        let tunnel = routeTunnelCandidates.first ?? ""
        let requestedTunnel: String?
        if !tunnel.isEmpty {
            requestedTunnel = tunnel
        } else if let candidate = environment["TUNDEV"], !candidate.isEmpty {
            requestedTunnel = try validatedTunnelInterface(candidate)
        } else {
            requestedTunnel = nil
        }
        let probedResolver = try tools.resolver(serviceID: service, baselineInterface: defaultInterface, tunnelInterface: requestedTunnel)
        let resolver = ResolverSnapshot(
            serviceID: probedResolver.serviceID,
            servers: probedResolver.servers,
            searchDomains: probedResolver.searchDomains,
            activeInterface: tunnel.isEmpty ? defaultInterface : tunnel,
            serversPresent: probedResolver.serversPresent,
            searchDomainsPresent: probedResolver.searchDomainsPresent,
            surfaces: probedResolver.surfaces
        )
        return NetworkSnapshotData(rebootIdentity: boot, serviceID: service, defaultInterface: defaultInterface, defaultRoute: defaultRoute, tunnelInterface: tunnel, routes: routes, resolver: resolver)
    }

    private func makeRouteRecords(baseline: NetworkLedger, after: NetworkSnapshotData) -> [RouteRecord] {
        let prior = Dictionary(uniqueKeysWithValues: baseline.routeRecords.map { (routeKey($0.applied), $0) })
        var recordsByKey = prior
        for route in after.routes {
            let delta = RouteDelta(operation: "add", destination: route.destination, gateway: route.gateway, interface: route.interface, netmask: route.netmask, protocol: route.protocol)
            let previous = prior[routeKey(delta)]
            guard (route.interface ?? "").hasPrefix("utun") || previous != nil else { continue }
            recordsByKey[routeKey(delta)] = RouteRecord(before: previous?.before ?? previous?.after, applied: delta, after: route)
        }
        return Array(recordsByKey.values).sorted()
    }

    private func preflightSafe(ledger: NetworkLedger, current: NetworkSnapshotData, allowRepairRequired: Bool = false) -> Bool {
        guard ledger.status == "recorded" || (allowRepairRequired && ledger.status == "repair-required") else { return false }
        guard ledger.rebootIdentity == current.rebootIdentity, ledger.serviceIDBefore == current.serviceID, ledger.defaultInterfaceBefore == current.defaultInterface, ledger.defaultRouteBefore == current.defaultRoute else { return false }
        for record in ledger.routeRecords {
            let matches = current.routes.filter { routeKey($0) == routeKey(record.applied) }
            guard matches.count <= 1 else { return false }
            if let currentRoute = matches.first, currentRoute != record.applied.routeSnapshot && currentRoute != record.before {
                guard allowRepairRequired, record.applied.gateway == nil, record.applied.interface == nil, currentRoute.gateway != nil, ((currentRoute.interface ?? "").hasPrefix("utun") || (record.applied.netmask == "255.255.255.255" && currentRoute.interface == ledger.defaultRouteBefore?.interface && currentRoute.gateway == ledger.defaultRouteBefore?.gateway)) else { return false }
            }
        }
        return resolverPreflightSafe(before: ledger.dnsBefore, applied: ledger.dnsApplied, current: current.resolver)
    }

    private func resolverPreflightSafe(before: ResolverSnapshot?, applied: ResolverSnapshot?, current: ResolverSnapshot) -> Bool {
        guard let before else { return false }
        if current == before { return true }
        guard current.serviceID == before.serviceID else { return false }
        if applied == nil {
            return current.servers == before.servers
                && current.searchDomains == before.searchDomains
                && current.serversPresent == before.serversPresent
                && current.searchDomainsPresent == before.searchDomainsPresent
                && current.surfaces == before.surfaces
        }
        guard let applied else { return false }
        return resolverFieldMatches(current: current, before: before, applied: applied, keyPath: \.servers, present: \.serversPresent)
            && resolverFieldMatches(current: current, before: before, applied: applied, keyPath: \.searchDomains, present: \.searchDomainsPresent)
            && Set(before.surfaces.keys) == Set(applied.surfaces.keys)
            && Set(current.surfaces.keys) == Set(before.surfaces.keys)
            && before.surfaces.keys.allSatisfy { name in
                guard let c = current.surfaces[name], let b = before.surfaces[name], let a = applied.surfaces[name] else { return false }
                return resolverSurfaceFieldMatches(current: c, before: b, applied: a, keyPath: \.servers, present: \.serversPresent)
                    && resolverSurfaceFieldMatches(current: c, before: b, applied: a, keyPath: \.searchDomains, present: \.searchDomainsPresent)
            }
    }

    private func resolverFieldMatches(current: ResolverSnapshot, before: ResolverSnapshot, applied: ResolverSnapshot, keyPath: KeyPath<ResolverSnapshot, [String]>, present: KeyPath<ResolverSnapshot, Bool>) -> Bool {
        (current[keyPath: keyPath] == before[keyPath: keyPath] && current[keyPath: present] == before[keyPath: present]) || (current[keyPath: keyPath] == applied[keyPath: keyPath] && current[keyPath: present] == applied[keyPath: present])
    }

    private func resolverSurfaceFieldMatches(current: ResolverFieldSnapshot, before: ResolverFieldSnapshot, applied: ResolverFieldSnapshot, keyPath: KeyPath<ResolverFieldSnapshot, [String]>, present: KeyPath<ResolverFieldSnapshot, Bool>) -> Bool {
        (current[keyPath: keyPath] == before[keyPath: keyPath] && current[keyPath: present] == before[keyPath: present]) || (current[keyPath: keyPath] == applied[keyPath: keyPath] && current[keyPath: present] == applied[keyPath: present])
    }

    private func baselineRestored(ledger: NetworkLedger, current: NetworkSnapshotData) -> Bool {
        guard ledger.rebootIdentity == current.rebootIdentity, ledger.serviceIDBefore == current.serviceID, ledger.defaultInterfaceBefore == current.defaultInterface, ledger.defaultRouteBefore == current.defaultRoute, current.resolver == ledger.dnsBefore else { return false }
        for record in ledger.routeRecords {
            let currentRoute = current.routes.first { routeKey($0) == routeKey(record.applied) }
            if currentRoute != record.before { return false }
        }
        return true
    }

    private func removeLedgerAndSyncDirectory(_ ledgerPath: URL) throws {
        try FileManager.default.removeItem(at: ledgerPath)
        let dirfd = open(ledgerPath.deletingLastPathComponent().path, O_RDONLY | O_CLOEXEC)
        if dirfd >= 0 { fsync(dirfd); close(dirfd) }
    }

    private struct RouteRepairAction { let delete: RouteDelta?; let restore: RouteSnapshot? }

    private func repairActions(ledger: NetworkLedger, current: NetworkSnapshotData) -> (safe: Bool, routeActions: [RouteRepairAction], restoreDNSServers: Bool, restoreSearchDomains: Bool, restoreAllResolverSurfaces: Bool) {
        guard preflightSafe(ledger: ledger, current: current, allowRepairRequired: true) else { return (false, [], false, false, false) }
        var actions: [RouteRepairAction] = []
        for record in ledger.routeRecords {
            let currentRoute = current.routes.first { routeKey($0) == routeKey(record.applied) }
            if currentRoute == record.before { continue }
            if currentRoute == record.applied.routeSnapshot { actions.append(RouteRepairAction(delete: record.applied, restore: record.before)); continue }
            if let currentRoute, exactIntentRouteOwned(ledger: ledger, record: record, current: currentRoute) {
                let delete = RouteDelta(operation: "add", destination: currentRoute.destination, gateway: currentRoute.gateway, interface: currentRoute.interface, netmask: currentRoute.netmask, protocol: currentRoute.protocol)
                actions.append(RouteRepairAction(delete: delete, restore: record.before)); continue
            }
            if currentRoute == nil, let before = record.before { actions.append(RouteRepairAction(delete: nil, restore: before)); continue }
            if currentRoute == nil { continue }
            return (false, [], false, false, false)
        }
        guard let beforeDNS = ledger.dnsBefore, resolverPreflightSafe(before: beforeDNS, applied: ledger.dnsApplied, current: current.resolver) else { return (false, [], false, false, false) }
        guard let appliedDNS = ledger.dnsApplied else { return (true, actions, false, false, false) }
        let serversApplied = current.resolver.servers == appliedDNS.servers && current.resolver.serversPresent == appliedDNS.serversPresent
        let searchApplied = current.resolver.searchDomains == appliedDNS.searchDomains && current.resolver.searchDomainsPresent == appliedDNS.searchDomainsPresent
        let surfacesApplied = beforeDNS.surfaces.keys.contains { name in
            guard name != "setup" else { return false }
            guard let currentSurface = current.resolver.surfaces[name], let appliedSurface = appliedDNS.surfaces[name], let beforeSurface = beforeDNS.surfaces[name] else { return true }
            return currentSurface == appliedSurface && currentSurface != beforeSurface
        }
        return (true, actions, serversApplied, searchApplied, surfacesApplied)
    }

    private func exactIntentRouteOwned(ledger: NetworkLedger, record: RouteRecord, current: RouteSnapshot) -> Bool {
        guard current.protocol == "ipv4", routeKey(current) == routeKey(record.applied), let gateway = current.gateway, !gateway.isEmpty else { return false }
        if let expectedGateway = record.applied.gateway, let expectedInterface = record.applied.interface {
            return gateway == expectedGateway && current.interface == expectedInterface
        }
        guard record.applied.netmask == "255.255.255.255" else { return false }
        return current.interface == ledger.defaultRouteBefore?.interface && gateway == ledger.defaultRouteBefore?.gateway
    }

    private func splitDestinations(_ environment: [String: String]) throws -> [(String, String)] {
        if environment.contains(where: { key, value in key.hasPrefix("INTERNAL_IP6_") && !value.isEmpty }) { throw HelperError.badConfiguration }
        let ipv6Keys = environment.keys.filter { $0.hasPrefix("CISCO_IPV6_SPLIT_") }
        let ipv6CountKeys = Set(["CISCO_IPV6_SPLIT_INC", "CISCO_IPV6_SPLIT_EXC"])
        for key in ipv6Keys {
            if ipv6CountKeys.contains(key) { guard environment[key] == "0" else { throw HelperError.badConfiguration } }
            else { throw HelperError.badConfiguration }
        }
        guard Int(environment["CISCO_SPLIT_EXC"] ?? "0") == 0 else { throw HelperError.badConfiguration }
        guard !environment.keys.contains(where: { $0.hasPrefix("CISCO_SPLIT_EXC_") }) else { throw HelperError.badConfiguration }
        guard let rawCount = Int(environment["CISCO_SPLIT_INC"] ?? "0"), (1...128).contains(rawCount) else { throw HelperError.badConfiguration }
        var seen = Set<String>()
        var result: [(String, String)] = []
        for index in 0..<rawCount {
            guard let rawAddress = environment["CISCO_SPLIT_INC_\(index)_ADDR"], !rawAddress.isEmpty else { throw HelperError.badConfiguration }
            let address = try canonicalIPv4Literal(rawAddress)
            let mask = try normalizedIPv4Mask(environment["CISCO_SPLIT_INC_\(index)_MASK"] ?? environment["CISCO_SPLIT_INC_\(index)_MASKLEN"] ?? "")
            guard !isDefaultRoute(address: address, mask: mask) else { throw HelperError.badConfiguration }
            let key = "ipv4|\(address)|\(mask)"
            guard seen.insert(key).inserted else { throw HelperError.badConfiguration }
            result.append((address, mask))
        }
        if let rawGateway = environment["VPNGATEWAY"], !rawGateway.isEmpty {
            let gateway = try canonicalIPv4Literal(rawGateway)
            let key = "ipv4|\(gateway)|255.255.255.255"
            guard seen.insert(key).inserted else { throw HelperError.badConfiguration }
            result.append((gateway, "255.255.255.255"))
        }
        return result
    }

    private func validatedTunnelInterface(_ value: String?) throws -> String {
        guard let value, value.range(of: "^utun[0-9]{1,8}$", options: .regularExpression) != nil else {
            throw HelperError.badConfiguration
        }
        return value
    }

    private func canonicalIPv4Literal(_ raw: String) throws -> String {
        guard !raw.hasPrefix("-") else { throw HelperError.badConfiguration }
        var addr = in_addr()
        guard raw.withCString({ inet_pton(AF_INET, $0, &addr) }) == 1 else { throw HelperError.badConfiguration }
        var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        var copy = addr
        guard inet_ntop(AF_INET, &copy, &buffer, socklen_t(buffer.count)) != nil else { throw HelperError.badConfiguration }
        let canonical = String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
        guard canonical == raw else { throw HelperError.badConfiguration }
        return canonical
    }

    private func normalizedIPv4Mask(_ raw: String) throws -> String {
        guard !raw.isEmpty else { return "" }
        guard !raw.hasPrefix("-") else { throw HelperError.badConfiguration }
        if let prefix = Int(raw), String(prefix) == raw, (0...32).contains(prefix) {
            let value = prefix == 0 ? UInt32(0) : UInt32.max << UInt32(32 - prefix)
            return [24, 16, 8, 0].map { String((value >> UInt32($0)) & 0xff) }.joined(separator: ".")
        }
        let parts = raw.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { throw HelperError.badConfiguration }
        var value = UInt32(0)
        var canonicalParts: [String] = []
        for part in parts {
            guard let byte = UInt8(part), String(byte) == part else { throw HelperError.badConfiguration }
            value = (value << 8) | UInt32(byte)
            canonicalParts.append(String(byte))
        }
        let inverted = ~value
        guard inverted == UInt32.max || (inverted & (inverted &+ 1)) == 0 else { throw HelperError.badConfiguration }
        return canonicalParts.joined(separator: ".")
    }

    private func isDefaultRoute(address: String, mask: String) -> Bool {
        return address == "default" || address == "0.0.0.0" || mask == "0.0.0.0"
    }

    private func routeKey(_ route: RouteSnapshot) -> String { "\(route.protocol)|\(route.destination)|\(route.netmask ?? "")" }
    private func routeKey(_ delta: RouteDelta) -> String { "\(delta.protocol)|\(delta.destination)|\(delta.netmask ?? "")" }
}

private struct NetworkSnapshotData {
    let rebootIdentity: UInt64
    let serviceID: String
    let defaultInterface: String
    let defaultRoute: RouteSnapshot
    let tunnelInterface: String
    let routes: [RouteSnapshot]
    let resolver: ResolverSnapshot
}
