import Foundation
import Darwin

private let networkLedgerStableBootIdentityMarker: UInt64 = 1 << 63

public struct RouteSnapshot: Codable, Hashable, Comparable {
    public let destination: String
    public let gateway: String?
    public let interface: String?
    public let netmask: String?
    public let `protocol`: String

    public init(destination: String, gateway: String?, interface: String?, netmask: String?, protocol: String) {
        self.destination = StringBoundaries.cleanRequired(destination, max: 128)
        self.gateway = gateway.map { StringBoundaries.cleanRequired($0, max: 128) }
        self.interface = interface.map { StringBoundaries.cleanRequired($0, max: 32) }
        self.netmask = netmask.map { StringBoundaries.cleanRequired($0, max: 64) }
        self.protocol = StringBoundaries.cleanRequired(`protocol`, max: 16)
    }

    enum CodingKeys: String, CodingKey { case destination, gateway, interface, netmask, `protocol` }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(destination, forKey: .destination)
        try c.encode(gateway, forKey: .gateway)
        try c.encode(interface, forKey: .interface)
        try c.encode(netmask, forKey: .netmask)
        try c.encode(`protocol`, forKey: .protocol)
    }

    public static func < (lhs: RouteSnapshot, rhs: RouteSnapshot) -> Bool {
        [lhs.destination, lhs.netmask ?? "", lhs.gateway ?? "", lhs.interface ?? "", lhs.protocol]
            .lexicographicallyPrecedes([rhs.destination, rhs.netmask ?? "", rhs.gateway ?? "", rhs.interface ?? "", rhs.protocol])
    }
}

public struct RouteDelta: Codable, Hashable, Comparable {
    public let operation: String
    public let destination: String
    public let gateway: String?
    public let interface: String?
    public let netmask: String?
    public let `protocol`: String

    public init(operation: String, destination: String, gateway: String?, interface: String?, netmask: String?, protocol: String) {
        self.operation = StringBoundaries.cleanRequired(operation, max: 16)
        self.destination = StringBoundaries.cleanRequired(destination, max: 128)
        self.gateway = gateway.map { StringBoundaries.cleanRequired($0, max: 128) }
        self.interface = interface.map { StringBoundaries.cleanRequired($0, max: 32) }
        self.netmask = netmask.map { StringBoundaries.cleanRequired($0, max: 64) }
        self.protocol = StringBoundaries.cleanRequired(`protocol`, max: 16)
    }

    enum CodingKeys: String, CodingKey { case operation, destination, gateway, interface, netmask, `protocol` }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(operation, forKey: .operation)
        try c.encode(destination, forKey: .destination)
        try c.encode(gateway, forKey: .gateway)
        try c.encode(interface, forKey: .interface)
        try c.encode(netmask, forKey: .netmask)
        try c.encode(`protocol`, forKey: .protocol)
    }

    public var routeSnapshot: RouteSnapshot {
        RouteSnapshot(destination: destination, gateway: gateway, interface: interface, netmask: netmask, protocol: `protocol`)
    }

    public static func < (lhs: RouteDelta, rhs: RouteDelta) -> Bool {
        [lhs.destination, lhs.netmask ?? "", lhs.gateway ?? "", lhs.interface ?? "", lhs.operation, lhs.protocol]
            .lexicographicallyPrecedes([rhs.destination, rhs.netmask ?? "", rhs.gateway ?? "", rhs.interface ?? "", rhs.operation, rhs.protocol])
    }
}

public struct RouteRecord: Codable, Hashable, Comparable {
    public let before: RouteSnapshot?
    public let applied: RouteDelta
    public let after: RouteSnapshot?

    public init(before: RouteSnapshot?, applied: RouteDelta, after: RouteSnapshot?) {
        self.before = before
        self.applied = applied
        self.after = after
    }

    enum CodingKeys: String, CodingKey { case before, applied, after }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(before, forKey: .before)
        try c.encode(applied, forKey: .applied)
        try c.encode(after, forKey: .after)
    }

    public static func < (lhs: RouteRecord, rhs: RouteRecord) -> Bool { lhs.applied < rhs.applied }
}

public struct ResolverFieldSnapshot: Codable, Hashable {
    public let servers: [String]
    public let searchDomains: [String]
    public let serversPresent: Bool
    public let searchDomainsPresent: Bool
    public let keyPresent: Bool
    public let otherFingerprint: String?

    public init(servers: [String], searchDomains: [String], serversPresent: Bool = true, searchDomainsPresent: Bool = true, keyPresent: Bool = true, otherFingerprint: String? = nil) {
        self.servers = StringBoundaries.orderedUnique(servers, maxItems: 16, maxString: 128)
        self.searchDomains = StringBoundaries.orderedUnique(searchDomains, maxItems: 32, maxString: 128)
        self.serversPresent = serversPresent
        self.searchDomainsPresent = searchDomainsPresent
        self.keyPresent = keyPresent
        self.otherFingerprint = otherFingerprint.map { StringBoundaries.cleanRequired($0, max: 256) }
    }

    enum CodingKeys: String, CodingKey { case servers, searchDomains, serversPresent, searchDomainsPresent, keyPresent, otherFingerprint }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(servers, forKey: .servers)
        try c.encode(searchDomains, forKey: .searchDomains)
        try c.encode(serversPresent, forKey: .serversPresent)
        try c.encode(searchDomainsPresent, forKey: .searchDomainsPresent)
        try c.encode(keyPresent, forKey: .keyPresent)
        try c.encode(otherFingerprint, forKey: .otherFingerprint)
    }
}

public struct ResolverSnapshot: Codable, Hashable {
    public let serviceID: String?
    public let servers: [String]
    public let searchDomains: [String]
    public let activeInterface: String?
    public let serversPresent: Bool
    public let searchDomainsPresent: Bool
    public let surfaces: [String: ResolverFieldSnapshot]

    public init(serviceID: String?, servers: [String], searchDomains: [String], activeInterface: String?, serversPresent: Bool = true, searchDomainsPresent: Bool = true, surfaces: [String: ResolverFieldSnapshot]? = nil) {
        self.serviceID = serviceID.map { StringBoundaries.cleanRequired($0, max: 128) }
        self.servers = StringBoundaries.orderedUnique(servers, maxItems: 16, maxString: 128)
        self.searchDomains = StringBoundaries.orderedUnique(searchDomains, maxItems: 32, maxString: 128)
        self.activeInterface = activeInterface.map { StringBoundaries.cleanRequired($0, max: 32) }
        self.serversPresent = serversPresent
        self.searchDomainsPresent = searchDomainsPresent
        let fallback = ResolverFieldSnapshot(servers: self.servers, searchDomains: self.searchDomains, serversPresent: serversPresent, searchDomainsPresent: searchDomainsPresent, keyPresent: true)
        let rawSurfaces = surfaces ?? ["setup": fallback]
        self.surfaces = Dictionary(uniqueKeysWithValues: rawSurfaces.compactMap { key, value in
            let cleaned = StringBoundaries.cleanRequired(key, max: 160)
            guard !cleaned.isEmpty else { return nil }
            return (cleaned, value)
        })
    }
    enum CodingKeys: String, CodingKey { case serviceID, servers, searchDomains, activeInterface, serversPresent, searchDomainsPresent, surfaces }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(serviceID, forKey: .serviceID)
        try c.encode(servers, forKey: .servers)
        try c.encode(searchDomains, forKey: .searchDomains)
        try c.encode(activeInterface, forKey: .activeInterface)
        try c.encode(serversPresent, forKey: .serversPresent)
        try c.encode(searchDomainsPresent, forKey: .searchDomainsPresent)
        try c.encode(surfaces, forKey: .surfaces)
    }
}

public struct NetworkLedger: Codable, Equatable {
    public let schemaVersion: Int
    public let sessionNonce: String
    public let rebootIdentity: UInt64
    public let serviceIDBefore: String?
    public let defaultInterfaceBefore: String?
    public let defaultRouteBefore: RouteSnapshot?
    public let tunnelInterface: String?
    public let routeDeltasApplied: [RouteDelta]
    public let routeRecords: [RouteRecord]
    public let dnsBefore: ResolverSnapshot?
    public let dnsApplied: ResolverSnapshot?
    public let status: String
    public let timestamp: Date

    enum CodingKeys: String, CodingKey, CaseIterable {
        case schemaVersion, sessionNonce, rebootIdentity, serviceIDBefore, defaultInterfaceBefore, defaultRouteBefore, tunnelInterface, routeDeltasApplied, routeRecords, dnsBefore, dnsApplied, status, timestamp
    }

    public init(schemaVersion: Int = 1, sessionNonce: String, rebootIdentity: UInt64, serviceIDBefore: String?, defaultInterfaceBefore: String?, defaultRouteBefore: RouteSnapshot?, tunnelInterface: String?, routeDeltasApplied: [RouteDelta], routeRecords: [RouteRecord]? = nil, dnsBefore: ResolverSnapshot?, dnsApplied: ResolverSnapshot?, status: String, timestamp: Date) {
        self.schemaVersion = schemaVersion
        self.sessionNonce = StringBoundaries.cleanNonce(sessionNonce)
        self.rebootIdentity = rebootIdentity
        self.serviceIDBefore = serviceIDBefore.map { StringBoundaries.cleanRequired($0, max: 128) }
        self.defaultInterfaceBefore = defaultInterfaceBefore.map { StringBoundaries.cleanRequired($0, max: 32) }
        self.defaultRouteBefore = defaultRouteBefore
        self.tunnelInterface = tunnelInterface.map { StringBoundaries.cleanRequired($0, max: 32) }
        self.routeDeltasApplied = Array(routeDeltasApplied.sorted().prefix(128))
        let records = routeRecords ?? routeDeltasApplied.map { RouteRecord(before: nil, applied: $0, after: $0.routeSnapshot) }
        self.routeRecords = Array(records.sorted().prefix(128))
        self.dnsBefore = dnsBefore
        self.dnsApplied = dnsApplied
        self.status = StringBoundaries.cleanStatus(status)
        self.timestamp = timestamp
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        guard Set(c.allKeys.map(\.stringValue)) == Set(CodingKeys.allCases.map(\.stringValue)) else { throw HelperError.badConfiguration }
        let schema = try c.decode(Int.self, forKey: .schemaVersion)
        guard schema == 1 else { throw HelperError.badConfiguration }
        let nonce = StringBoundaries.cleanNonce(try c.decode(String.self, forKey: .sessionNonce))
        guard nonce != "invalid" else { throw HelperError.badConfiguration }
        let reboot = try c.decode(UInt64.self, forKey: .rebootIdentity)
        guard reboot > 0 else { throw HelperError.badConfiguration }
        let deltas = try c.decode([RouteDelta].self, forKey: .routeDeltasApplied)
        let records = try c.decode([RouteRecord].self, forKey: .routeRecords)
        guard deltas.count <= 128, records.count <= 128 else { throw HelperError.badConfiguration }
        let rawStatus = try c.decode(String.self, forKey: .status)
        guard ["recorded", "healed", "repair-required"].contains(rawStatus) else { throw HelperError.badConfiguration }
        self.init(schemaVersion: schema, sessionNonce: nonce, rebootIdentity: reboot, serviceIDBefore: try c.decodeIfPresent(String.self, forKey: .serviceIDBefore), defaultInterfaceBefore: try c.decodeIfPresent(String.self, forKey: .defaultInterfaceBefore), defaultRouteBefore: try c.decodeIfPresent(RouteSnapshot.self, forKey: .defaultRouteBefore), tunnelInterface: try c.decodeIfPresent(String.self, forKey: .tunnelInterface), routeDeltasApplied: deltas, routeRecords: records, dnsBefore: try c.decodeIfPresent(ResolverSnapshot.self, forKey: .dnsBefore), dnsApplied: try c.decodeIfPresent(ResolverSnapshot.self, forKey: .dnsApplied), status: rawStatus, timestamp: try c.decode(Date.self, forKey: .timestamp))
    }


    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(schemaVersion, forKey: .schemaVersion)
        try c.encode(sessionNonce, forKey: .sessionNonce)
        try c.encode(rebootIdentity, forKey: .rebootIdentity)
        try c.encode(serviceIDBefore, forKey: .serviceIDBefore)
        try c.encode(defaultInterfaceBefore, forKey: .defaultInterfaceBefore)
        try c.encode(defaultRouteBefore, forKey: .defaultRouteBefore)
        try c.encode(tunnelInterface, forKey: .tunnelInterface)
        try c.encode(routeDeltasApplied, forKey: .routeDeltasApplied)
        try c.encode(routeRecords, forKey: .routeRecords)
        try c.encode(dnsBefore, forKey: .dnsBefore)
        try c.encode(dnsApplied, forKey: .dnsApplied)
        try c.encode(status, forKey: .status)
        try c.encode(timestamp, forKey: .timestamp)
    }

    public func withStatus(_ newStatus: String) -> NetworkLedger {
        NetworkLedger(schemaVersion: schemaVersion, sessionNonce: sessionNonce, rebootIdentity: rebootIdentity, serviceIDBefore: serviceIDBefore, defaultInterfaceBefore: defaultInterfaceBefore, defaultRouteBefore: defaultRouteBefore, tunnelInterface: tunnelInterface, routeDeltasApplied: routeDeltasApplied, routeRecords: routeRecords, dnsBefore: dnsBefore, dnsApplied: dnsApplied, status: newStatus, timestamp: timestamp)
    }
}

public struct NetworkSnapshot: Equatable {
    public var rebootIdentity: UInt64
    public var serviceID: String?
    public var defaultInterface: String?
    public var tunnelInterface: String?
    public var routes: [RouteSnapshot]
    public var resolver: ResolverSnapshot?

    public init(rebootIdentity: UInt64, serviceID: String?, defaultInterface: String?, tunnelInterface: String?, routes: [RouteSnapshot], resolver: ResolverSnapshot?) {
        self.rebootIdentity = rebootIdentity
        self.serviceID = serviceID
        self.defaultInterface = defaultInterface
        self.tunnelInterface = tunnelInterface
        self.routes = routes.sorted()
        self.resolver = resolver
    }
}

public struct NetworkLedgerRepairPlan: Equatable {
    public let status: String
    public let routesToRemove: [RouteDelta]
    public let resolverToRestore: ResolverSnapshot?
}

public enum NetworkLedgerRepairPlanner {
    public static func plan(for ledger: NetworkLedger, current: NetworkSnapshot) -> NetworkLedgerRepairPlan {
        guard ledger.status != "repair-required", ledger.rebootIdentity & networkLedgerStableBootIdentityMarker != 0, ledger.rebootIdentity == current.rebootIdentity, ledger.serviceIDBefore == current.serviceID, ledger.defaultInterfaceBefore == current.defaultInterface else { return NetworkLedgerRepairPlan(status: "repair-required", routesToRemove: [], resolverToRestore: nil) }
        var removals: [RouteDelta] = []
        for record in ledger.routeRecords {
            if let currentRoute = current.routes.first(where: { $0.destination == record.applied.destination }) {
                guard currentRoute == record.applied.routeSnapshot else { return NetworkLedgerRepairPlan(status: "repair-required", routesToRemove: [], resolverToRestore: nil) }
                removals.append(record.applied)
            }
        }
        if current.resolver == ledger.dnsBefore { return NetworkLedgerRepairPlan(status: "healed", routesToRemove: removals, resolverToRestore: nil) }
        if current.resolver == ledger.dnsApplied { return NetworkLedgerRepairPlan(status: "healed", routesToRemove: removals, resolverToRestore: ledger.dnsBefore) }
        return NetworkLedgerRepairPlan(status: "repair-required", routesToRemove: [], resolverToRestore: nil)
    }
}

public struct NetworkLedgerStore {
    private let path: URL
    private let maxBytes: Int
    private let expectedOwnerUID: UInt32
    public init(path: URL, maxBytes: Int = 65_536, expectedOwnerUID: UInt32 = 0) {
        self.path = path
        self.maxBytes = maxBytes
        self.expectedOwnerUID = expectedOwnerUID
    }

    public func load(expectedNonce: String) throws -> NetworkLedger {
        guard maxBytes > 0 else { throw HelperError.badConfiguration }
        let expectedNonce = StringBoundaries.cleanNonce(expectedNonce)
        guard expectedNonce != "invalid", path.lastPathComponent == "\(expectedNonce).ledger" else { throw HelperError.insecurePath(path.path) }
        let fd = open(path.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if fd == -1 { throw HelperError.insecurePath(path.path) }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == expectedOwnerUID, (st.st_mode & 0o777) == 0o600, st.st_size >= 0, st.st_size <= maxBytes else { throw HelperError.insecurePath(path.path) }
        var buffer = [UInt8](repeating: 0, count: Int(st.st_size))
        var offset = 0
        while offset < buffer.count {
            let remaining = buffer.count - offset
            let count = buffer.withUnsafeMutableBytes { raw -> Int in
                guard let base = raw.baseAddress else { return 0 }
                return read(fd, base.advanced(by: offset), remaining)
            }
            if count <= 0 { throw HelperError.insecurePath(path.path) }
            offset += count
        }
        let data = Data(buffer)
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw HelperError.badConfiguration }
        try RawLedgerValidator.validate(object)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let ledger = try decoder.decode(NetworkLedger.self, from: data)
        guard ledger.sessionNonce == expectedNonce else { throw HelperError.processMismatch }
        return ledger
    }

    public func save(_ ledger: NetworkLedger) throws {
        guard maxBytes > 0, ledger.schemaVersion == 1, ledger.sessionNonce != "invalid", path.lastPathComponent == "\(ledger.sessionNonce).ledger" else { throw HelperError.insecurePath(path.path) }
        let directory = path.deletingLastPathComponent()
        try ensureSafeDirectory(directory)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(ledger)
        guard data.count <= maxBytes else { throw HelperError.insecurePath(path.path) }
        let temp = directory.appendingPathComponent(".\(path.lastPathComponent).\(UUID().uuidString).tmp")
        let fd = open(temp.path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0o600)
        if fd == -1 { throw HelperError.insecurePath(temp.path) }
        var closeNeeded = true
        do {
            try data.withUnsafeBytes { raw in
                guard let base = raw.baseAddress else { return }
                var written = 0
                while written < data.count {
                    let count = write(fd, base.advanced(by: written), data.count - written)
                    if count <= 0 { throw HelperError.insecurePath(temp.path) }
                    written += count
                }
            }
            if fchmod(fd, 0o600) != 0 { throw HelperError.insecurePath(temp.path) }
            if fchown(fd, expectedOwnerUID, 0) != 0, expectedOwnerUID == 0 { throw HelperError.insecurePath(temp.path) }
            if fsync(fd) != 0 { throw HelperError.insecurePath(temp.path) }
            close(fd)
            closeNeeded = false
            if rename(temp.path, path.path) != 0 { throw HelperError.insecurePath(path.path) }
            let dirfd = open(directory.path, O_RDONLY | O_CLOEXEC)
            if dirfd >= 0 { fsync(dirfd); close(dirfd) }
        } catch {
            if closeNeeded { close(fd) }
            try? FileManager.default.removeItem(at: temp)
            throw error
        }
    }

    private func ensureSafeDirectory(_ directory: URL) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        var current = directory.path
        while true {
            var st = stat()
            guard lstat(current, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR, st.st_uid == expectedOwnerUID, (st.st_mode & 0o022) == 0 else { throw HelperError.insecurePath(current) }
            if expectedOwnerUID != 0 || current == "/" { break }
            let next = URL(fileURLWithPath: current).deletingLastPathComponent().path
            if next == current || next.isEmpty { break }
            current = next
        }
    }
}

private enum RawLedgerValidator {
    private static let topKeys = Set(NetworkLedger.CodingKeys.allCases.map(\.stringValue))
    private static let routeSnapshotKeys: Set<String> = ["destination", "gateway", "interface", "netmask", "protocol"]
    private static let routeDeltaKeys: Set<String> = ["operation", "destination", "gateway", "interface", "netmask", "protocol"]
    private static let routeRecordKeys: Set<String> = ["before", "applied", "after"]
    private static let resolverKeys: Set<String> = ["serviceID", "servers", "searchDomains", "activeInterface", "serversPresent", "searchDomainsPresent", "surfaces"]
    private static let resolverFieldKeys: Set<String> = ["servers", "searchDomains", "serversPresent", "searchDomainsPresent", "keyPresent", "otherFingerprint"]

    static func validate(_ object: [String: Any]) throws {
        guard Set(object.keys) == topKeys, object["schemaVersion"] as? Int == 1, let nonce = object["sessionNonce"] as? String, valid(nonce, max: 128, pattern: "^[A-Za-z0-9._-]{1,128}$"), let reboot = object["rebootIdentity"] as? UInt64 ?? (object["rebootIdentity"] as? Int).map(UInt64.init), reboot > 0, let status = object["status"] as? String, ["recorded", "healed", "repair-required"].contains(status), object["timestamp"] is String else { throw HelperError.badConfiguration }
        if !(object["serviceIDBefore"] is NSNull) { try validateOptionalString(object["serviceIDBefore"], max: 128) }
        if !(object["defaultInterfaceBefore"] is NSNull) { try validateOptionalString(object["defaultInterfaceBefore"], max: 32) }
        if !(object["tunnelInterface"] is NSNull) { try validateOptionalString(object["tunnelInterface"], max: 32) }
        try validateNullableRoute(object["defaultRouteBefore"])
        guard let deltas = object["routeDeltasApplied"] as? [[String: Any]], deltas.count <= 128 else { throw HelperError.badConfiguration }
        try deltas.forEach(validateRouteDelta)
        guard let records = object["routeRecords"] as? [[String: Any]], records.count <= 128 else { throw HelperError.badConfiguration }
        try records.forEach(validateRouteRecord)
        try validateNullableResolver(object["dnsBefore"])
        try validateNullableResolver(object["dnsApplied"])
    }

    private static func validateNullableRoute(_ value: Any?) throws {
        if value is NSNull { return }
        guard let route = value as? [String: Any] else { throw HelperError.badConfiguration }
        try validateRouteSnapshot(route)
    }
    private static func validateNullableResolver(_ value: Any?) throws {
        if value is NSNull { return }
        guard let resolver = value as? [String: Any] else { throw HelperError.badConfiguration }
        try validateResolver(resolver)
    }
    private static func validateRouteRecord(_ object: [String: Any]) throws {
        guard Set(object.keys) == routeRecordKeys, let applied = object["applied"] as? [String: Any] else { throw HelperError.badConfiguration }
        try validateNullableRoute(object["before"])
        try validateRouteDelta(applied)
        try validateNullableRoute(object["after"])
    }
    private static func validateRouteSnapshot(_ object: [String: Any]) throws {
        guard Set(object.keys) == routeSnapshotKeys, let destination = object["destination"] as? String, valid(destination, max: 128), let proto = object["protocol"] as? String, proto == "ipv4" else { throw HelperError.badConfiguration }
        try validateOptionalString(object["gateway"], max: 128)
        try validateOptionalString(object["interface"], max: 32)
        try validateOptionalString(object["netmask"], max: 64)
    }
    private static func validateRouteDelta(_ object: [String: Any]) throws {
        guard Set(object.keys) == routeDeltaKeys, let operation = object["operation"] as? String, operation == "add" else { throw HelperError.badConfiguration }
        try validateRouteSnapshot(object.filter { $0.key != "operation" })
    }
    private static func validateResolver(_ object: [String: Any]) throws {
        guard Set(object.keys) == resolverKeys else { throw HelperError.badConfiguration }
        if !(object["serviceID"] is NSNull) { try validateOptionalString(object["serviceID"], max: 128) }
        if !(object["activeInterface"] is NSNull) { try validateOptionalString(object["activeInterface"], max: 32) }
        guard let servers = object["servers"] as? [String], servers.count <= 16, let searches = object["searchDomains"] as? [String], searches.count <= 32, object["serversPresent"] is Bool, object["searchDomainsPresent"] is Bool, let surfaces = object["surfaces"] as? [String: Any], !surfaces.isEmpty, surfaces.count <= 10 else { throw HelperError.badConfiguration }
        try servers.forEach { if !valid($0, max: 128) { throw HelperError.badConfiguration } }
        try searches.forEach { if !valid($0, max: 128) { throw HelperError.badConfiguration } }
        for (name, value) in surfaces {
            guard valid(name, max: 160), let surface = value as? [String: Any], Set(surface.keys) == resolverFieldKeys, let s = surface["servers"] as? [String], s.count <= 16, let d = surface["searchDomains"] as? [String], d.count <= 32, surface["serversPresent"] is Bool, surface["searchDomainsPresent"] is Bool, surface["keyPresent"] is Bool else { throw HelperError.badConfiguration }
            if !(surface["otherFingerprint"] is NSNull) { try validateOptionalString(surface["otherFingerprint"], max: 256) }
            try s.forEach { if !valid($0, max: 128) { throw HelperError.badConfiguration } }
            try d.forEach { if !valid($0, max: 128) { throw HelperError.badConfiguration } }
        }
    }
    private static func validateOptionalString(_ value: Any?, max: Int) throws { if value is NSNull { return }; guard let string = value as? String, valid(string, max: max) else { throw HelperError.badConfiguration } }
    private static func valid(_ value: String, max: Int, pattern: String? = nil) -> Bool {
        guard !value.isEmpty, value.count <= max, value.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value < 0x7f && $0 != "\"" && $0 != "\\" }) else { return false }
        if let pattern { return value.range(of: pattern, options: .regularExpression) != nil }
        return true
    }
}

private enum StringBoundaries {
    static func cleanRequired(_ value: String, max: Int) -> String {
        let filtered = value.unicodeScalars.filter { scalar in scalar.value >= 0x20 && scalar.value < 0x7f && scalar != "\"" && scalar != "\\" }
        return String(String.UnicodeScalarView(filtered)).prefixString(max)
    }
    static func orderedUnique(_ values: [String], maxItems: Int, maxString: Int) -> [String] {
        var seen = Set<String>()
        var result: [String] = []
        for value in values {
            let cleaned = cleanRequired(value, max: maxString)
            guard !cleaned.isEmpty, seen.insert(cleaned).inserted else { continue }
            result.append(cleaned)
            if result.count == maxItems { break }
        }
        return result
    }
    static func cleanNonce(_ nonce: String) -> String {
        let cleaned = cleanRequired(nonce, max: 128)
        guard cleaned.range(of: "^[A-Za-z0-9._-]{1,128}$", options: .regularExpression) != nil else { return "invalid" }
        return cleaned
    }
    static func cleanStatus(_ status: String) -> String { ["recorded", "healed", "repair-required"].contains(status) ? status : "repair-required" }
}

private extension String { func prefixString(_ max: Int) -> String { String(prefix(max)) } }
