import Foundation
import Darwin
import SystemConfiguration
import CryptoKit


public enum HelperError: Error, Equatable, CustomStringConvertible {
    case invalidCommand
    case malformedStartHeader
    case unauthorized
    case insecurePath(String)
    case forbiddenPath(String)
    case processMismatch
    case sessionExists
    case badConfiguration
    case teardownIncomplete(String)
    case childExited(Int32)

    public var description: String {
        switch self {
        case .invalidCommand: "invalid command"
        case .malformedStartHeader: "malformed start header"
        case .unauthorized: "unauthorized invocation"
        case .insecurePath(let path): "insecure path: \(path)"
        case .forbiddenPath(let path): "forbidden path: \(path)"
        case .processMismatch: "recorded process did not match live process"
        case .sessionExists: "session already exists"
        case .badConfiguration: "bad helper configuration"
        case .teardownIncomplete(let detail): "teardown incomplete: \(detail)"
        case .childExited(let status): "child exited with status \(status)"
        }
    }
}

public enum HelperCommand: Equatable {
    case start, stop, status, repair

    public static func parse(_ argv: [String]) throws -> HelperCommand {
        guard argv.count == 2 else { throw HelperError.invalidCommand }
        switch argv[1] {
        case "start": return .start
        case "stop": return .stop
        case "status": return .status
        case "repair": return .repair
        default: throw HelperError.invalidCommand
        }
    }
}

public struct StartRequest: Equatable {
    public let username: String
    public init(username: String) { self.username = username }
}

public enum StartHeaderParser {
    public static let maxHeaderBytes = 512
    private static let maxUsernameLength = 128
    private static let prefix = "HYU-Username: "

    public static func parse(_ data: Data) throws -> StartRequest {
        let bytes = Array(data)
        guard let headerEnd = firstDoubleNewline(in: bytes), headerEnd <= maxHeaderBytes, headerEnd + 2 == bytes.count else {
            throw HelperError.malformedStartHeader
        }
        let headerBytes = bytes[..<headerEnd]
        guard let header = String(bytes: headerBytes, encoding: .utf8) else { throw HelperError.malformedStartHeader }
        let lines = header.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        guard lines.count == 1, lines[0].hasPrefix(prefix) else { throw HelperError.malformedStartHeader }
        let username = String(lines[0].dropFirst(prefix.count))
        guard isValidUsername(username) else { throw HelperError.malformedStartHeader }
        return StartRequest(username: username)
    }

    private static func firstDoubleNewline(in bytes: [UInt8]) -> Int? {
        guard bytes.count >= 2 else { return nil }
        for index in 0..<(bytes.count - 1) where bytes[index] == 0x0A && bytes[index + 1] == 0x0A { return index }
        return nil
    }

    private static func isValidUsername(_ username: String) -> Bool {
        guard !username.isEmpty, username.count <= maxUsernameLength else { return false }
        return username.unicodeScalars.allSatisfy { scalar in
            let value = scalar.value
            return (48...57).contains(value) || (65...90).contains(value) || (97...122).contains(value) || scalar == "." || scalar == "_" || scalar == "-" || scalar == "@"
        }
    }
}

public protocol ByteInput {
    func readOneByte() throws -> UInt8?
}

public final class FileHandleByteInput: ByteInput {
    private let fileHandle: FileHandle
    public init(_ fileHandle: FileHandle) { self.fileHandle = fileHandle }
    public func readOneByte() throws -> UInt8? {
        let data = fileHandle.readData(ofLength: 1)
        return data.first
    }
}

public enum BoundedStartHeaderReader {
    public static func read(from input: ByteInput, maxBytes: Int = StartHeaderParser.maxHeaderBytes) throws -> StartRequest {
        var bytes: [UInt8] = []
        while bytes.count <= maxBytes {
            guard let byte = try input.readOneByte() else { throw HelperError.malformedStartHeader }
            bytes.append(byte)
            if bytes.count >= 2, bytes[bytes.count - 2] == 0x0A, bytes[bytes.count - 1] == 0x0A {
                return try StartHeaderParser.parse(Data(bytes))
            }
        }
        throw HelperError.malformedStartHeader
    }
}

public struct InvocationIdentity: Equatable {
    public let effectiveUID: UInt32
    public let sudoUID: UInt32?
    public let sudoUser: String
    public let consoleUID: UInt32
    public let sudoAccountUID: UInt32?

    public init(effectiveUID: UInt32, sudoUID: UInt32?, sudoUser: String, consoleUID: UInt32, sudoAccountUID: UInt32? = nil) {
        self.effectiveUID = effectiveUID
        self.sudoUID = sudoUID
        self.sudoUser = sudoUser
        self.consoleUID = consoleUID
        self.sudoAccountUID = sudoAccountUID
    }

    public func validateStartAuthorization() throws {
        guard effectiveUID == 0, let sudoUID, sudoUID == consoleUID, !sudoUser.isEmpty, sudoAccountUID == sudoUID else { throw HelperError.unauthorized }
    }

    public static func current(environment: [String: String] = ProcessInfo.processInfo.environment) -> InvocationIdentity {
        InvocationIdentity(effectiveUID: geteuid(), sudoUID: environment["SUDO_UID"].flatMap(UInt32.init), sudoUser: environment["SUDO_USER"] ?? "", consoleUID: ConsoleUser.currentUID(), sudoAccountUID: AccountResolver.uid(for: environment["SUDO_USER"] ?? ""))
    }
}

private enum AccountResolver {
    static func uid(for name: String) -> UInt32? {
        guard !name.isEmpty, let pwd = getpwnam(name) else { return nil }
        return pwd.pointee.pw_uid
    }
}

private enum ConsoleUser {
    static func currentUID() -> UInt32 {
        var uid: uid_t = 0
        var gid: gid_t = 0
        if let cfName = SCDynamicStoreCopyConsoleUser(nil, &uid, &gid) {
            _ = cfName
            return uid
        }
        return getuid()
    }
}

public struct HelperConfiguration: Equatable {
    public let openConnectExecutable: URL
    public let vpncScript: URL
    public let hipWrapper: URL
    public let stateDirectory: URL
    public let ledgerDirectory: URL
    public let executableSHA256: String?
    public let vpncScriptSHA256: String?
    public let hipWrapperSHA256: String?
    public let portal: String = "secure.hanyang.ac.kr"
    public let protocolName: String = "gp"
    public let authGroup: String = "HYU-ExternalGW-General"

    public init(openConnectExecutable: URL, vpncScript: URL, hipWrapper: URL, stateDirectory: URL, ledgerDirectory: URL, executableSHA256: String? = nil, vpncScriptSHA256: String? = nil, hipWrapperSHA256: String? = nil) {
        self.openConnectExecutable = openConnectExecutable
        self.vpncScript = vpncScript
        self.hipWrapper = hipWrapper
        self.stateDirectory = stateDirectory
        self.ledgerDirectory = ledgerDirectory
        self.executableSHA256 = executableSHA256
        self.vpncScriptSHA256 = vpncScriptSHA256
        self.hipWrapperSHA256 = hipWrapperSHA256
    }

    public var requiredSecurePaths: [URL] { [openConnectExecutable, vpncScript, hipWrapper, stateDirectory, ledgerDirectory] }

    public static func load(from path: URL, metadata: FileMetadataProviding, maxBytes: Int = 4096, validateRuntime: Bool = true) throws -> HelperConfiguration {
        guard maxBytes > 0 else { throw HelperError.badConfiguration }
        try validateConfigFile(path: path, metadata: metadata)
        let fd = open(path.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if fd == -1 { throw HelperError.insecurePath(path.path) }
        defer { close(fd) }
        try validateConfigFileFD(fd: fd, path: path, maxBytes: maxBytes)
        var bytes: [UInt8] = []
        var buffer = [UInt8](repeating: 0, count: min(1024, maxBytes))
        while true {
            let count = read(fd, &buffer, buffer.count)
            guard count >= 0 else { throw HelperError.insecurePath(path.path) }
            if count == 0 { break }
            bytes.append(contentsOf: buffer.prefix(Int(count)))
            guard bytes.count <= maxBytes else { throw HelperError.insecurePath(path.path) }
        }
        return try decode(data: Data(bytes), metadata: metadata, validateRuntime: validateRuntime)
    }

    public static func decode(data: Data, metadata: FileMetadataProviding, validateRuntime: Bool = true) throws -> HelperConfiguration {
        guard !data.isEmpty, data.count <= 4096 else { throw HelperError.badConfiguration }
        let allowedKeys: Set<String> = ["openConnectExecutable", "vpncScript", "hipWrapper", "stateDirectory", "ledgerDirectory", "openConnectExecutableSHA256", "vpncScriptSHA256", "hipWrapperSHA256"]
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any], Set(object.keys) == allowedKeys else { throw HelperError.badConfiguration }
        struct Raw: Decodable { let openConnectExecutable: String; let vpncScript: String; let hipWrapper: String; let stateDirectory: String; let ledgerDirectory: String; let openConnectExecutableSHA256: String; let vpncScriptSHA256: String; let hipWrapperSHA256: String }
        let raw = try JSONDecoder().decode(Raw.self, from: data)
        let config = HelperConfiguration(openConnectExecutable: URL(fileURLWithPath: raw.openConnectExecutable), vpncScript: URL(fileURLWithPath: raw.vpncScript), hipWrapper: URL(fileURLWithPath: raw.hipWrapper), stateDirectory: URL(fileURLWithPath: raw.stateDirectory), ledgerDirectory: URL(fileURLWithPath: raw.ledgerDirectory), executableSHA256: raw.openConnectExecutableSHA256, vpncScriptSHA256: raw.vpncScriptSHA256, hipWrapperSHA256: raw.hipWrapperSHA256)
        if validateRuntime { try config.validate(using: metadata) } else { try config.validateStaticShape() }
        return config
    }

    private static func validateConfigFile(path: URL, metadata: FileMetadataProviding) throws {
        let item = try metadata.metadata(for: path.path)
        guard item.ownerUID == 0, item.mode == 0o600, !item.isSymlink else { throw HelperError.insecurePath(path.path) }
        var current = path.deletingLastPathComponent().path
        while true {
            let parent = try metadata.metadata(for: current)
            guard parent.ownerUID == 0, !parent.isSymlink, (parent.mode & 0o022) == 0 else { throw HelperError.insecurePath(current) }
            if current == "/" { break }
            current = URL(fileURLWithPath: current).deletingLastPathComponent().path
            if current.isEmpty { current = "/" }
        }
    }

    private static func validateConfigFileFD(fd: Int32, path: URL, maxBytes: Int) throws {
        var item = stat()
        if fstat(fd, &item) != 0 { throw HelperError.insecurePath(path.path) }
        guard (item.st_mode & S_IFMT) == S_IFREG, item.st_uid == 0, (item.st_mode & 0o777) == 0o600, item.st_size <= maxBytes else { throw HelperError.insecurePath(path.path) }
    }

    public static func production(metadata: FileMetadataProviding = SystemFileMetadataProvider(), validateRuntime: Bool = true) throws -> HelperConfiguration {
        try load(from: URL(fileURLWithPath: "/Library/Application Support/HYU VPN/helper-config.json"), metadata: metadata, validateRuntime: validateRuntime)
    }

    public static func fallbackProduction() -> HelperConfiguration {
        HelperConfiguration(
            openConnectExecutable: URL(fileURLWithPath: "/Library/Application Support/HYU VPN/runtime/openconnect/9.12/bin/openconnect"),
            vpncScript: URL(fileURLWithPath: "/Library/Application Support/HYU VPN/runtime/vpnc/hyu-vpnc-wrapper"),
            hipWrapper: URL(fileURLWithPath: "/Library/Application Support/HYU VPN/runtime/gp-hip-report"),
            stateDirectory: URL(fileURLWithPath: "/private/var/db/hyu-vpn"),
            ledgerDirectory: URL(fileURLWithPath: "/private/var/db/hyu-vpn/ledger")
        )
    }

    public static func testFixture() -> HelperConfiguration {
        HelperConfiguration(
            openConnectExecutable: URL(fileURLWithPath: "/rooted/openconnect"),
            vpncScript: URL(fileURLWithPath: "/rooted/vpnc-script"),
            hipWrapper: URL(fileURLWithPath: "/rooted/gp-hip-report"),
            stateDirectory: URL(fileURLWithPath: "/rooted/state"),
            ledgerDirectory: URL(fileURLWithPath: "/rooted/ledger")
        )
    }

    public func validate(using metadata: FileMetadataProviding) throws {
        try validateStaticShape()
        for url in requiredSecurePaths {
            try validatePathAndParents(url.path, using: metadata)
        }
        if !openConnectExecutable.path.hasPrefix("/rooted/") {
            guard executableSHA256 != nil, vpncScriptSHA256 != nil, hipWrapperSHA256 != nil else { throw HelperError.badConfiguration }
        }
        try validateHash(path: openConnectExecutable.path, expected: executableSHA256)
        try validateHash(path: vpncScript.path, expected: vpncScriptSHA256)
        try validateHash(path: hipWrapper.path, expected: hipWrapperSHA256)
    }

    public func validateStaticShape() throws {
        for url in requiredSecurePaths {
            let path = url.path
            guard !path.contains("/../"), !path.hasSuffix("/..") else { throw HelperError.forbiddenPath(path) }
            guard path.hasPrefix("/Library/Application Support/HYU VPN/runtime/") || path.hasPrefix("/private/var/db/hyu-vpn") || path.hasPrefix("/rooted/") else { throw HelperError.forbiddenPath(path) }
        }
        guard openConnectExecutable.path == "/rooted/openconnect" || openConnectExecutable.path.range(of: "^/Library/Application Support/HYU VPN/runtime/openconnect/[^/]+/bin/openconnect$", options: .regularExpression) != nil else { throw HelperError.forbiddenPath(openConnectExecutable.path) }
        guard vpncScript.path == "/rooted/vpnc-script" || vpncScript.path == "/Library/Application Support/HYU VPN/runtime/vpnc/hyu-vpnc-wrapper" else { throw HelperError.forbiddenPath(vpncScript.path) }
        guard hipWrapper.path == "/rooted/gp-hip-report" || hipWrapper.path.hasPrefix("/Library/Application Support/HYU VPN/runtime/") else { throw HelperError.forbiddenPath(hipWrapper.path) }
        guard stateDirectory.path == "/private/var/db/hyu-vpn" || stateDirectory.path == "/rooted/state" else { throw HelperError.forbiddenPath(stateDirectory.path) }
        guard ledgerDirectory.path == stateDirectory.appendingPathComponent("ledger").path || ledgerDirectory.path == "/rooted/ledger" else { throw HelperError.forbiddenPath(ledgerDirectory.path) }
        try validateHashFormat(executableSHA256)
        try validateHashFormat(vpncScriptSHA256)
        try validateHashFormat(hipWrapperSHA256)
    }

    private func validateHashFormat(_ value: String?) throws {
        guard let value else { return }
        guard value.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil else { throw HelperError.badConfiguration }
    }

    private func validateHash(path: String, expected: String?) throws {
        guard let expected else { return }
        try validateHashFormat(expected)
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if fd == -1 { throw HelperError.insecurePath(path) }
        defer { close(fd) }
        var context = SHA256()
        var buffer = [UInt8](repeating: 0, count: 8192)
        while true {
            let count = read(fd, &buffer, buffer.count)
            if count < 0 { throw HelperError.insecurePath(path) }
            if count == 0 { break }
            context.update(data: Data(buffer.prefix(Int(count))))
        }
        let digest = context.finalize().map { String(format: "%02x", $0) }.joined()
        guard digest == expected else { throw HelperError.badConfiguration }
    }

    private func validatePathAndParents(_ path: String, using metadata: FileMetadataProviding) throws {
        var current = path
        while true {
            let item = try metadata.metadata(for: current)
            guard item.ownerUID == 0, !item.isSymlink, (item.mode & 0o022) == 0 else { throw HelperError.insecurePath(current) }
            if current == "/" { break }
            current = URL(fileURLWithPath: current).deletingLastPathComponent().path
            if current.isEmpty { current = "/" }
        }
    }
}

public struct SecureFileMetadata: Equatable {
    public let ownerUID: UInt32
    public let mode: mode_t
    public let isSymlink: Bool
    public let fileID: String
    public init(ownerUID: UInt32, mode: mode_t, isSymlink: Bool, fileID: String) {
        self.ownerUID = ownerUID
        self.mode = mode
        self.isSymlink = isSymlink
        self.fileID = fileID
    }
}

public protocol FileMetadataProviding {
    func metadata(for path: String) throws -> SecureFileMetadata
}

public struct SystemFileMetadataProvider: FileMetadataProviding {
    public init() {}
    public func metadata(for path: String) throws -> SecureFileMetadata {
        var item = stat()
        if lstat(path, &item) != 0 { throw HelperError.insecurePath(path) }
        let isSymlink = (item.st_mode & S_IFMT) == S_IFLNK
        return SecureFileMetadata(ownerUID: item.st_uid, mode: item.st_mode & 0o777, isSymlink: isSymlink, fileID: "\(item.st_dev):\(item.st_ino)")
    }
}

public struct ExecutableIdentity: Codable, Equatable {
    public let path: String
    public let fileID: String
    public init(path: String, fileID: String) { self.path = path; self.fileID = fileID }
}

public struct OpaqueLedger: Codable, Equatable {
    public let path: URL
    public let nonce: String
    public init(path: URL, nonce: String) { self.path = path; self.nonce = nonce }
}

public struct SessionRecord: Codable, Equatable {
    public let pid: Int32
    public let processGroupID: Int32
    public let processBirthTime: UInt64
    public var sessionNonce: String
    public var consoleUID: UInt32
    public var portal: String
    public let executableIdentity: ExecutableIdentity
    public let launchTime: Date
    public let ledger: OpaqueLedger
    public let tunnelInterface: String?

    public init(pid: Int32, processGroupID: Int32, processBirthTime: UInt64, sessionNonce: String, consoleUID: UInt32, portal: String, executableIdentity: ExecutableIdentity, launchTime: Date, ledger: OpaqueLedger, tunnelInterface: String? = nil) {
        self.pid = pid
        self.processGroupID = processGroupID
        self.processBirthTime = processBirthTime
        self.sessionNonce = sessionNonce
        self.consoleUID = consoleUID
        self.portal = portal
        self.executableIdentity = executableIdentity
        self.launchTime = launchTime
        self.ledger = ledger
        self.tunnelInterface = tunnelInterface
    }

    public func validateForUse(configuration: HelperConfiguration) throws {
        guard pid > 1, processGroupID > 1, processBirthTime > 0 else { throw HelperError.processMismatch }
        guard portal == configuration.portal, !sessionNonce.isEmpty, sessionNonce.range(of: "^[A-Za-z0-9_-]{8,128}$", options: .regularExpression) != nil else { throw HelperError.processMismatch }
        guard ledger.nonce == sessionNonce, ledger.path.path == configuration.ledgerDirectory.appendingPathComponent("\(sessionNonce).ledger").path else { throw HelperError.processMismatch }
        if let tunnelInterface {
            guard tunnelInterface.range(of: "^utun[0-9]{1,8}$", options: .regularExpression) != nil else { throw HelperError.processMismatch }
        }
    }
}

public protocol SessionStoring: AnyObject {
    func load() throws -> SessionRecord?
    func save(_ record: SessionRecord) throws
    func remove() throws
}

public final class FileSessionStore: SessionStoring {
    private let path: URL
    private let maxBytes: Int
    public init(path: URL, maxBytes: Int = 4096) {
        self.path = path
        self.maxBytes = maxBytes
    }
    public func load() throws -> SessionRecord? {
        guard maxBytes > 0, maxBytes <= 65_536 else { throw HelperError.badConfiguration }
        guard FileManager.default.fileExists(atPath: path.path) else { return nil }
        let fd = open(path.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if fd == -1 { throw HelperError.insecurePath(path.path) }
        defer { close(fd) }
        try validateRecordFile(fd: fd)
        var bytes: [UInt8] = []
        var buffer = [UInt8](repeating: 0, count: min(1024, maxBytes))
        while true {
            let count = read(fd, &buffer, buffer.count)
            if count < 0 {
                if errno == EINTR { continue }
                throw HelperError.insecurePath(path.path)
            }
            if count == 0 { break }
            bytes.append(contentsOf: buffer.prefix(Int(count)))
            guard bytes.count <= maxBytes else { throw HelperError.insecurePath(path.path) }
        }
        let data = Data(bytes)
        try validateSessionRecordSchema(data)
        return try JSONDecoder().decode(SessionRecord.self, from: data)
    }
    public func save(_ record: SessionRecord) throws {
        let directory = path.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700, .ownerAccountID: 0], ofItemAtPath: directory.path)
        guard maxBytes > 0, maxBytes <= 65_536 else { throw HelperError.badConfiguration }
        let data = try JSONEncoder().encode(record)
        guard data.count <= maxBytes else { throw HelperError.insecurePath(path.path) }
        let temp = directory.appendingPathComponent(".session.\(UUID().uuidString).tmp")
        let fd = open(temp.path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0o600)
        if fd == -1 { throw HelperError.insecurePath(temp.path) }
        var fdOpen = true
        do {
            var written = 0
            try data.withUnsafeBytes { raw in
                guard let base = raw.baseAddress else { return }
                while written < data.count {
                    let result = write(fd, base.advanced(by: written), data.count - written)
                    if result <= 0 { throw HelperError.insecurePath(temp.path) }
                    written += result
                }
            }
            if fsync(fd) != 0 { throw HelperError.insecurePath(temp.path) }
            if fchmod(fd, 0o600) != 0 { throw HelperError.insecurePath(temp.path) }
            if fchown(fd, 0, 0) != 0 { throw HelperError.insecurePath(temp.path) }
            close(fd)
            fdOpen = false
            _ = try FileManager.default.replaceItemAt(path, withItemAt: temp, backupItemName: nil, options: [])
            let dirfd = open(directory.path, O_RDONLY | O_CLOEXEC)
            if dirfd >= 0 { fsync(dirfd); close(dirfd) }
        } catch {
            if fdOpen { close(fd) }
            try? FileManager.default.removeItem(at: temp)
            throw error
        }
    }
    public func remove() throws {
        let rc = unlink(path.path)
        if rc != 0, errno != ENOENT { throw POSIXError(.EIO) }
        let dirfd = open(path.deletingLastPathComponent().path, O_RDONLY | O_CLOEXEC)
        if dirfd >= 0 { fsync(dirfd); close(dirfd) }
    }

    private func validateRecordFile(fd: Int32) throws {
        guard maxBytes > 0, maxBytes <= 65_536 else { throw HelperError.badConfiguration }
        var item = stat()
        if fstat(fd, &item) != 0 { throw HelperError.insecurePath(path.path) }
        guard (item.st_mode & S_IFMT) == S_IFREG, item.st_uid == 0, (item.st_mode & 0o777) == 0o600, item.st_size <= maxBytes else {
            throw HelperError.insecurePath(path.path)
        }
    }

    private func validateSessionRecordSchema(_ data: Data) throws {
        let required: Set<String> = ["pid", "processGroupID", "processBirthTime", "sessionNonce", "consoleUID", "portal", "executableIdentity", "launchTime", "ledger"]
        let optional: Set<String> = ["tunnelInterface"]
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw HelperError.badConfiguration }
        let keys = Set(object.keys)
        guard required.isSubset(of: keys), keys.isSubset(of: required.union(optional)) else { throw HelperError.badConfiguration }
        guard let executable = object["executableIdentity"] as? [String: Any], Set(executable.keys) == ["path", "fileID"] else { throw HelperError.badConfiguration }
        guard let ledger = object["ledger"] as? [String: Any], Set(ledger.keys) == ["path", "nonce"] else { throw HelperError.badConfiguration }
    }
}

public struct SpawnRequest: Equatable {
    public let executable: URL
    public let arguments: [String]
    public let inheritStdin: Bool
    public let inheritStdout: Bool
    public let usesShell: Bool
    public let environment: [String: String]
    public init(executable: URL, arguments: [String], inheritStdin: Bool, inheritStdout: Bool, usesShell: Bool, environment: [String: String] = [:]) {
        self.executable = executable
        self.arguments = arguments
        self.inheritStdin = inheritStdin
        self.inheritStdout = inheritStdout
        self.usesShell = usesShell
        self.environment = environment
    }
}

public struct SpawnedProcess: Equatable {
    public let pid: Int32
    public let processGroupID: Int32
    public let birthTime: UInt64
    public init(pid: Int32, processGroupID: Int32, birthTime: UInt64) {
        self.pid = pid
        self.processGroupID = processGroupID
        self.birthTime = birthTime
    }
}

public struct LiveProcessIdentity: Equatable {
    public let pid: Int32
    public let processGroupID: Int32
    public let birthTime: UInt64
    public let executablePath: String
    public init(pid: Int32, processGroupID: Int32, birthTime: UInt64, executablePath: String) {
        self.pid = pid
        self.processGroupID = processGroupID
        self.birthTime = birthTime
        self.executablePath = executablePath
    }
    public static func matching(pid: Int32, pgid: Int32, birth: UInt64, executable: String) -> LiveProcessIdentity {
        LiveProcessIdentity(pid: pid, processGroupID: pgid, birthTime: birth, executablePath: executable)
    }
}

public enum MonitorOutcome: Equatable {
    case exited(status: Int32)
    case channelLoss
}

public protocol ProcessControlling: AnyObject {
    func beginLifecycleSignalGuard() throws
    func endLifecycleSignalGuard()
    func prepareSpawn(_ request: SpawnRequest) throws -> SpawnedProcess
    func commitSpawn(_ process: SpawnedProcess) throws
    func abortSpawn(_ process: SpawnedProcess) throws
    func liveIdentity(for pid: Int32) throws -> LiveProcessIdentity?
    func terminateProcessGroup(_ pgid: Int32) throws
    func killProcessGroup(_ pgid: Int32) throws
    func waitForExit(pid: Int32, timeout: TimeInterval) throws -> Bool
    func monitorForeground(record: SessionRecord, onChannelLoss: (SessionRecord) throws -> Void) throws -> MonitorOutcome
    func validateBeforeSignal(_ record: SessionRecord) throws
}

nonisolated(unsafe) private var hyuSignalPipeWriteFD: Int32 = -1

private func hyuSignalHandler(_ signalNumber: Int32) -> Void {
    var byte = UInt8(signalNumber == SIGINT ? 2 : 1)
    if hyuSignalPipeWriteFD >= 0 { _ = write(hyuSignalPipeWriteFD, &byte, 1) }
}

public final class SystemProcessController: ProcessControlling {
    private var suspendedChildren = Set<Int32>()
    private var signalReadFD: Int32 = -1
    private var signalWriteFD: Int32 = -1
    private var previousWriteFD: Int32 = -1
    private var oldTerm = sigaction()
    private var oldInt = sigaction()
    private var signalGuardActive = false
    public init() {}

    public func beginLifecycleSignalGuard() throws {
        guard !signalGuardActive else { return }
        var signalPipe: [Int32] = [0, 0]
        guard pipe(&signalPipe) == 0 else { throw POSIXError(.EIO) }
        setNonBlocking(signalPipe[0])
        setNonBlocking(signalPipe[1])
        setCloseOnExec(signalPipe[0])
        setCloseOnExec(signalPipe[1])
        previousWriteFD = hyuSignalPipeWriteFD
        hyuSignalPipeWriteFD = signalPipe[1]
        signalReadFD = signalPipe[0]
        signalWriteFD = signalPipe[1]
        var action = sigaction()
        action.__sigaction_u.__sa_handler = hyuSignalHandler
        sigemptyset(&action.sa_mask)
        action.sa_flags = 0
        sigaction(SIGTERM, &action, &oldTerm)
        sigaction(SIGINT, &action, &oldInt)
        signalGuardActive = true
    }

    public func endLifecycleSignalGuard() {
        guard signalGuardActive else { return }
        sigaction(SIGTERM, &oldTerm, nil)
        sigaction(SIGINT, &oldInt, nil)
        hyuSignalPipeWriteFD = previousWriteFD
        close(signalReadFD)
        close(signalWriteFD)
        signalReadFD = -1
        signalWriteFD = -1
        signalGuardActive = false
    }

    public func prepareSpawn(_ request: SpawnRequest) throws -> SpawnedProcess {
        var ackPipe: [Int32] = [0, 0]
        guard pipe(&ackPipe) == 0 else { throw POSIXError(.EIO) }
        setCloseOnExec(ackPipe[1])
        var attr: posix_spawnattr_t? = nil
        var attrInitialized = false
        do {
            guard posix_spawnattr_init(&attr) == 0 else { throw POSIXError(.EIO) }
            attrInitialized = true
            let flags = Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_START_SUSPENDED)
            guard posix_spawnattr_setflags(&attr, flags) == 0 else { throw POSIXError(.EIO) }
            guard posix_spawnattr_setpgroup(&attr, 0) == 0 else { throw POSIXError(.EIO) }
            let argvStrings = [request.executable.path] + request.arguments
            let envStrings = (["PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"].merging(request.environment) { current, _ in current }).sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }
            var childPid = pid_t(0)
            let spawnResult = try withCStringArray(argvStrings) { argv in
                try withCStringArray(envStrings) { envp in
                    request.executable.path.withCString { pathPointer in
                        posix_spawn(&childPid, pathPointer, nil, &attr, argv, envp)
                    }
                }
            }
            guard spawnResult == 0 else { throw POSIXError(POSIXErrorCode(rawValue: spawnResult) ?? .EIO) }
            close(ackPipe[1])
            ackPipe[1] = -1
            try waitForExecTransition(readFD: ackPipe[0], pid: childPid)
            let pgid = getpgid(childPid)
            guard pgid == childPid else { kill(childPid, SIGKILL); _ = waitpid(childPid, nil, 0); throw HelperError.processMismatch }
            let birth = processBirthTime(pid: childPid)
            guard birth > 0 else { killpg(childPid, SIGKILL); _ = waitpid(childPid, nil, 0); throw HelperError.processMismatch }
            suspendedChildren.insert(childPid)
            if attrInitialized { posix_spawnattr_destroy(&attr) }
            close(ackPipe[0])
            return SpawnedProcess(pid: childPid, processGroupID: childPid, birthTime: birth)
        } catch {
            if ackPipe[0] >= 0 { close(ackPipe[0]) }
            if ackPipe[1] >= 0 { close(ackPipe[1]) }
            if attrInitialized { posix_spawnattr_destroy(&attr) }
            throw error
        }
    }

    public func commitSpawn(_ process: SpawnedProcess) throws {
        guard suspendedChildren.remove(process.pid) != nil else { throw HelperError.processMismatch }
        guard kill(process.pid, SIGCONT) == 0 else { throw POSIXError(.EIO) }
    }

    public func abortSpawn(_ process: SpawnedProcess) throws {
        suspendedChildren.remove(process.pid)
        _ = kill(process.pid, SIGCONT)
        if killpg(process.processGroupID, SIGKILL) != 0, errno != ESRCH { throw POSIXError(.EIO) }
        guard try waitForExit(pid: process.pid, timeout: 2) else { throw HelperError.teardownIncomplete("abort wait did not prove exit") }
    }

    public func liveIdentity(for pid: Int32) throws -> LiveProcessIdentity? {
        guard kill(pid, 0) == 0 else { return nil }
        let pgid = getpgid(pid)
        guard pgid > 0, let path = executablePath(pid: pid) else { return nil }
        let birth = processBirthTime(pid: pid)
        guard birth > 0 else { return nil }
        return LiveProcessIdentity(pid: pid, processGroupID: pgid, birthTime: birth, executablePath: path)
    }
    public func terminateProcessGroup(_ pgid: Int32) throws { if killpg(pgid, SIGTERM) != 0, errno != ESRCH { throw POSIXError(.EIO) } }
    public func killProcessGroup(_ pgid: Int32) throws { if killpg(pgid, SIGKILL) != 0, errno != ESRCH { throw POSIXError(.EIO) } }
    public func waitForExit(pid: Int32, timeout: TimeInterval) throws -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            var status: Int32 = 0
            let waited = waitpid(pid, &status, WNOHANG)
            if waited == pid { return true }
            if waited == -1, errno == ECHILD {
                if kill(pid, 0) != 0, errno == ESRCH { return true }
            }
            usleep(50_000)
        }
        return kill(pid, 0) != 0 && errno == ESRCH
    }
    public func monitorForeground(record: SessionRecord, onChannelLoss: (SessionRecord) throws -> Void) throws -> MonitorOutcome {
        if !signalGuardActive { try beginLifecycleSignalGuard() }
        let readFD = signalReadFD
        while true {
            var status: Int32 = 0
            let waited = waitpid(record.pid, &status, WNOHANG)
            if waited == record.pid { return .exited(status: status) }
            var fds = [
                pollfd(fd: STDOUT_FILENO, events: Int16(POLLHUP | POLLERR), revents: 0),
                pollfd(fd: readFD, events: Int16(POLLIN | POLLHUP | POLLERR), revents: 0)
            ]
            let pollResult = fds.withUnsafeMutableBufferPointer { poll($0.baseAddress!, nfds_t($0.count), 100) }
            if pollResult > 0 {
                if (fds[1].revents & Int16(POLLIN | POLLHUP | POLLERR)) != 0 {
                    drain(fd: readFD)
                    try onChannelLoss(record)
                    _ = try waitForExit(pid: record.pid, timeout: 2)
                    return .channelLoss
                }
                if (fds[0].revents & Int16(POLLHUP | POLLERR)) != 0 {
                    try onChannelLoss(record)
                    _ = try waitForExit(pid: record.pid, timeout: 2)
                    return .channelLoss
                }
            }
            if getppid() == 1 { try onChannelLoss(record); _ = try waitForExit(pid: record.pid, timeout: 2); return .channelLoss }
        }
    }
    public func validateBeforeSignal(_ record: SessionRecord) throws {
        guard let live = try liveIdentity(for: record.pid), live.pid == record.pid, live.processGroupID == record.processGroupID, live.birthTime == record.processBirthTime, live.executablePath == record.executableIdentity.path else { throw HelperError.processMismatch }
    }
    private func waitForExecTransition(readFD: Int32, pid: pid_t) throws {
        var fds = pollfd(fd: readFD, events: Int16(POLLIN | POLLHUP | POLLERR), revents: 0)
        while true {
            let result = poll(&fds, 1, 2000)
            if result < 0, errno == EINTR { continue }
            guard result > 0 else { kill(pid, SIGKILL); _ = waitpid(pid, nil, 0); throw HelperError.processMismatch }
            var byte: UInt8 = 0
            let count = read(readFD, &byte, 1)
            if count < 0, errno == EINTR { continue }
            guard count == 0 else { kill(pid, SIGKILL); _ = waitpid(pid, nil, 0); throw HelperError.processMismatch }
            return
        }
    }
    private func processBirthTime(pid: pid_t) -> UInt64 {
        var info = proc_bsdinfo()
        let size = MemoryLayout<proc_bsdinfo>.stride
        let result = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(size))
        guard result == Int32(size), info.pbi_pid == pid else { return 0 }
        return UInt64(info.pbi_start_tvsec) * 1_000_000 + UInt64(info.pbi_start_tvusec)
    }
    private func executablePath(pid: pid_t) -> String? {
        var pathBuffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let size = proc_pidpath(pid, &pathBuffer, UInt32(pathBuffer.count))
        guard size > 0 else { return nil }
        return String(decoding: pathBuffer.prefix(Int(size)).map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
    private func setCloseOnExec(_ fd: Int32) { _ = fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC) }
    private func setNonBlocking(_ fd: Int32) { _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) }
    private func drain(fd: Int32) { var byte: UInt8 = 0; while read(fd, &byte, 1) == 1 {} }
    private func withCStringArray<R>(_ strings: [String], _ body: (UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) throws -> R) throws -> R {
        let cStrings: [UnsafeMutablePointer<CChar>?] = strings.map { strdup($0) }
        defer { for pointer in cStrings { free(pointer) } }
        var pointers = cStrings
        pointers.append(nil)
        return try pointers.withUnsafeMutableBufferPointer { buffer in
            try body(buffer.baseAddress!)
        }
    }
}

public protocol SessionLocking: AnyObject {
    func acquire(consoleUID: UInt32) throws
    func release(consoleUID: UInt32) throws
}

public final class FileSessionLock: SessionLocking {
    private let directory: URL
    private var held: [UInt32: Int32] = [:]
    public init(directory: URL) { self.directory = directory }
    public func acquire(consoleUID: UInt32) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700, .ownerAccountID: 0], ofItemAtPath: directory.path)
        let lockURL = directory.appendingPathComponent("uid-\(consoleUID).lock")
        let fd = open(lockURL.path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
        if fd == -1 { throw POSIXError(.EIO) }
        var item = stat()
        guard fstat(fd, &item) == 0, (item.st_mode & S_IFMT) == S_IFREG else { close(fd); throw HelperError.insecurePath(lockURL.path) }
        if fchmod(fd, 0o600) != 0 { close(fd); throw POSIXError(.EIO) }
        if fchown(fd, 0, 0) != 0 { close(fd); throw POSIXError(.EIO) }
        if flock(fd, LOCK_EX | LOCK_NB) != 0 { close(fd); throw POSIXError(.EAGAIN) }
        held[consoleUID] = fd
    }
    public func release(consoleUID: UInt32) throws {
        if let fd = held.removeValue(forKey: consoleUID) {
            flock(fd, LOCK_UN)
            close(fd)
        }
        _ = directory
    }
    deinit { for (_, fd) in held { flock(fd, LOCK_UN); close(fd) } }
}

public protocol ClockProviding { func now() -> Date }
public struct SystemClock: ClockProviding {
    public init() {}
    public func now() -> Date { Date() }
}
public protocol NonceGenerating { func makeNonce() throws -> String }
public struct SecureNonceGenerator: NonceGenerating {
    public init() {}
    public func makeNonce() throws -> String { UUID().uuidString.replacingOccurrences(of: "-", with: "") }
}

public enum HelperStatus: Equatable {
    case started, stopped, inactive, running, repairRequired, repairDeferredToLedger
}

public struct HelperStatusDocument: Codable, Equatable {
    public let schema_version: Int
    public let state: String
    public let pid: Int?
    public let session_nonce: String?
    public let tunnel_interface: String?

    public init(schema_version: Int = 1, state: String, pid: Int?, session_nonce: String?, tunnel_interface: String?) {
        self.schema_version = schema_version
        self.state = state
        self.pid = pid
        self.session_nonce = session_nonce
        self.tunnel_interface = tunnel_interface
    }

    public func singleLineJSON() throws -> String {
        let data = try JSONEncoder().encode(self)
        let line = String(decoding: data, as: UTF8.self)
        guard !line.contains("\n"), line.utf8.count <= 512 else { throw HelperError.malformedStartHeader }
        return line
    }
}


public struct InstalledExecutionIdentity: Equatable, Sendable {
    public let canonicalPath: String
    public let device: UInt64
    public let inode: UInt64
    public init(canonicalPath: String, device: UInt64, inode: UInt64) {
        self.canonicalPath = URL(fileURLWithPath: canonicalPath).standardizedFileURL.path
        self.device = device
        self.inode = inode
    }
}

public enum InstalledExecutionGuard {
    public static let privilegedHelperPath = "/Library/PrivilegedHelperTools/com.hyu.vpn.helper"
    public static let wrapperDaemonPath = "/Library/Application Support/HYU VPN/runtime/vpnc/hyu-vpnc-wrapperd"
    public static let wrapperDaemonHashManifestPath = "/Library/Application Support/HYU VPN/runtime/vpnc/hyu-vpnc-wrapperd.sha256"

    public static func validate(actual: InstalledExecutionIdentity, installed: InstalledExecutionIdentity) throws {
        guard actual == installed else { throw HelperError.unauthorized }
    }

    public static func validate(actualExecutablePath: String, allowedCanonicalPath: String) throws {
        guard normalized(actualExecutablePath) == normalized(allowedCanonicalPath) else { throw HelperError.unauthorized }
    }

    public static func validateCurrentExecutable(allowedCanonicalPath: String, hashManifestPath: String? = nil, metadata: FileMetadataProviding = SystemFileMetadataProvider()) throws {
        try validateInstalledPathSecurity(path: allowedCanonicalPath, metadata: metadata)
        let actual = try currentExecutableIdentity()
        try validate(actual: actual, installed: identity(forInstalledCanonicalPath: allowedCanonicalPath))
        if let hashManifestPath {
            try validateInstalledPathSecurity(path: hashManifestPath, metadata: metadata)
            let manifest = try readManifest(path: hashManifestPath)
            try validateHash(actualSHA256: try sha256(path: actual.canonicalPath), manifestText: manifest)
        }
    }

    public static func validateInstalledPathSecurity(path: String, metadata: FileMetadataProviding) throws {
        let item = try metadata.metadata(for: path)
        guard item.ownerUID == 0, !item.isSymlink, (item.mode & 0o022) == 0 else { throw HelperError.insecurePath(path) }
        var current = URL(fileURLWithPath: path).deletingLastPathComponent().path
        while true {
            let parent = try metadata.metadata(for: current)
            guard parent.ownerUID == 0, !parent.isSymlink, (parent.mode & 0o022) == 0 else { throw HelperError.insecurePath(current) }
            if current == "/" { break }
            current = URL(fileURLWithPath: current).deletingLastPathComponent().path
            if current.isEmpty { current = "/" }
        }
    }

    public static func validateHash(actualSHA256: String, manifestText: String) throws {
        let expected = manifestText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard expected.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil, actualSHA256 == expected else { throw HelperError.unauthorized }
    }

    private static func currentExecutableIdentity() throws -> InstalledExecutionIdentity {
        var buffer = [CChar](repeating: 0, count: 4096)
        let count = proc_pidpath(getpid(), &buffer, UInt32(buffer.count))
        guard count > 0 else { throw HelperError.unauthorized }
        return try identity(forPath: String(decoding: buffer.prefix(Int(count)).map { UInt8(bitPattern: $0) }, as: UTF8.self))
    }

    private static func identity(forInstalledCanonicalPath path: String) throws -> InstalledExecutionIdentity {
        try identity(forPath: path)
    }

    private static func readManifest(path: String) throws -> String {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw HelperError.unauthorized }
        defer { close(fd) }
        var item = stat()
        guard fstat(fd, &item) == 0, (item.st_mode & S_IFMT) == S_IFREG, item.st_uid == 0, (item.st_mode & 0o022) == 0, item.st_size <= 128 else { throw HelperError.unauthorized }
        var buffer = [UInt8](repeating: 0, count: Int(item.st_size))
        let count = read(fd, &buffer, buffer.count)
        guard count >= 0 else { throw HelperError.unauthorized }
        return String(decoding: buffer.prefix(count), as: UTF8.self)
    }

    private static func sha256(path: String) throws -> String {
        let data = try Data(contentsOf: URL(fileURLWithPath: path), options: [.mappedIfSafe])
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func identity(forPath path: String) throws -> InstalledExecutionIdentity {
        let canonical = try realPath(path)
        var item = stat()
        guard stat(canonical, &item) == 0, (item.st_mode & S_IFMT) == S_IFREG else { throw HelperError.unauthorized }
        return InstalledExecutionIdentity(canonicalPath: canonical, device: UInt64(item.st_dev), inode: UInt64(item.st_ino))
    }

    private static func realPath(_ path: String) throws -> String {
        guard let resolved = realpath(path, nil) else { throw HelperError.unauthorized }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    private static func normalized(_ path: String) -> String {
        URL(fileURLWithPath: path).standardizedFileURL.path
    }
}

public struct HelperResult: Equatable {
    public let status: HelperStatus
    public let username: String?
    public let ledger: OpaqueLedger?
    public let statusDocument: HelperStatusDocument?
    public init(status: HelperStatus, username: String?, ledger: OpaqueLedger?, statusDocument: HelperStatusDocument? = nil) {
        self.status = status
        self.username = username
        self.ledger = ledger
        self.statusDocument = statusDocument
    }
}


public protocol SessionLedgerCoordinating {
    func verifyTeardownComplete(record: SessionRecord) throws
    func repair(record: SessionRecord, configuration: HelperConfiguration) throws
}

public struct NetworkSessionLedgerCoordinator: SessionLedgerCoordinating {
    public init() {}
    public func verifyTeardownComplete(record: SessionRecord) throws {
        var st = stat()
        if lstat(record.ledger.path.path, &st) != 0 {
            if errno == ENOENT { return }
            throw HelperError.insecurePath(record.ledger.path.path)
        }
        guard (st.st_mode & S_IFMT) != S_IFLNK else { throw HelperError.insecurePath(record.ledger.path.path) }
        let ledger = try NetworkLedgerStore(path: record.ledger.path, expectedOwnerUID: 0).load(expectedNonce: record.sessionNonce)
        guard ledger.status == "healed" else { throw HelperError.teardownIncomplete("ledger status \(ledger.status)") }
    }
    public func repair(record: SessionRecord, configuration: HelperConfiguration) throws {
        let paths = RuntimePaths(ledgerRoot: configuration.ledgerDirectory, upstream: configuration.vpncScript, route: RuntimePaths.production.route, scutil: RuntimePaths.production.scutil, sysctl: RuntimePaths.production.sysctl, networksetup: RuntimePaths.production.networksetup)
        try NetworkWrapperRunner(paths: paths, expectedOwnerUID: 0).run(reason: "repair", nonce: record.sessionNonce, environment: ["HYU_NONCE": record.sessionNonce, "HYU_SESSION_LEDGER": record.ledger.path.path], suppliedLedgerPath: record.ledger.path)
    }
}

public struct PrivilegedHelper {
    public let configuration: HelperConfiguration
    public let metadata: FileMetadataProviding
    public var process: any ProcessControlling
    public var store: any SessionStoring
    public var lock: any SessionLocking
    public let clock: ClockProviding
    public let nonceGenerator: NonceGenerating
    public let identity: InvocationIdentity
    public let ledgerCoordinator: any SessionLedgerCoordinating

    public init(configuration: HelperConfiguration, metadata: FileMetadataProviding, process: any ProcessControlling, store: any SessionStoring, lock: any SessionLocking, clock: ClockProviding, nonceGenerator: NonceGenerating, identity: InvocationIdentity, ledgerCoordinator: any SessionLedgerCoordinating = NetworkSessionLedgerCoordinator()) {
        self.configuration = configuration
        self.metadata = metadata
        self.process = process
        self.store = store
        self.lock = lock
        self.clock = clock
        self.nonceGenerator = nonceGenerator
        self.identity = identity
        self.ledgerCoordinator = ledgerCoordinator
    }

    public mutating func run(command: HelperCommand, startRequest: StartRequest? = nil) throws -> HelperResult {
        switch command {
        case .start:
            guard let startRequest else { throw HelperError.malformedStartHeader }
            return try start(request: startRequest)
        case .stop: return try stop()
        case .status: return try status()
        case .repair: return try repair()
        }
    }

    private mutating func start(request header: StartRequest) throws -> HelperResult {
        try configuration.validate(using: metadata)
        try identity.validateStartAuthorization()
        if try store.load() != nil { throw HelperError.sessionExists }
        try lock.acquire(consoleUID: identity.consoleUID)
        try process.beginLifecycleSignalGuard()
        var spawnedRecord: SessionRecord?
        var preparedSpawn: SpawnedProcess?
        do {
            let nonce = try nonceGenerator.makeNonce()
            let username = header.username
            let localUser = identity.sudoUser
            let arguments = [
            "--protocol=\(configuration.protocolName)",
            "--authgroup=\(configuration.authGroup)",
            "--user=\(username)",
            "--passwd-on-stdin",
            "--script=\(configuration.vpncScript.path)",
            "--csd-wrapper=\(configuration.hipWrapper.path)",
            "--csd-user=\(localUser)",
            configuration.portal
        ]
            let ledger = OpaqueLedger(path: configuration.ledgerDirectory.appendingPathComponent("\(nonce).ledger"), nonce: nonce)
            let request = SpawnRequest(executable: configuration.openConnectExecutable, arguments: arguments, inheritStdin: true, inheritStdout: true, usesShell: false, environment: ["HYU_NONCE": nonce, "HYU_SESSION_LEDGER": ledger.path.path])
            let spawned = try process.prepareSpawn(request)
            preparedSpawn = spawned
            guard spawned.pid > 1, spawned.processGroupID > 1, spawned.birthTime > 0 else { throw HelperError.processMismatch }
            let executableMeta = try metadata.metadata(for: configuration.openConnectExecutable.path)
            let record = SessionRecord(pid: spawned.pid, processGroupID: spawned.processGroupID, processBirthTime: spawned.birthTime, sessionNonce: nonce, consoleUID: identity.consoleUID, portal: configuration.portal, executableIdentity: ExecutableIdentity(path: configuration.openConnectExecutable.path, fileID: executableMeta.fileID), launchTime: clock.now(), ledger: ledger)
            spawnedRecord = record
            try store.save(record)
            try process.commitSpawn(spawned)
            let outcome = try process.monitorForeground(record: record) { freshRecord in
                try terminateVerified(record: freshRecord)
            }
            switch outcome {
            case .exited(let status):
                if status != 0 {
                    do {
                        try ledgerCoordinator.verifyTeardownComplete(record: record)
                        process.endLifecycleSignalGuard()
                        try store.remove()
                        try lock.release(consoleUID: record.consoleUID)
                        spawnedRecord = nil
                        preparedSpawn = nil
                    } catch {
                        throw HelperError.childExited(status)
                    }
                    throw HelperError.childExited(status)
                }
            case .channelLoss:
                break
            }
            try ledgerCoordinator.verifyTeardownComplete(record: record)
            process.endLifecycleSignalGuard()
            try store.remove()
            try lock.release(consoleUID: record.consoleUID)
            return HelperResult(status: .started, username: nil, ledger: ledger)
        } catch {
            var cleanupErrors: [String] = []
            var teardownProven = false
            if let record = spawnedRecord {
                do {
                    try process.abortSpawn(SpawnedProcess(pid: record.pid, processGroupID: record.processGroupID, birthTime: record.processBirthTime))
                    teardownProven = true
                } catch { cleanupErrors.append("abort: \(error)") }
                if !teardownProven {
                    do { try terminateVerified(record: record); teardownProven = true } catch { cleanupErrors.append("terminate: \(error)") }
                }
            } else if let preparedSpawn {
                do { try process.abortSpawn(preparedSpawn); teardownProven = true } catch { cleanupErrors.append("abort: \(error)") }
            }
            process.endLifecycleSignalGuard()
            do { try lock.release(consoleUID: identity.consoleUID) } catch { cleanupErrors.append("lock-release: \(error)") }
            if !cleanupErrors.isEmpty { throw HelperError.teardownIncomplete(cleanupErrors.joined(separator: "; ")) }
            throw error
        }
    }

    private mutating func stop() throws -> HelperResult {
        guard let record = try store.load() else { return HelperResult(status: .inactive, username: nil, ledger: nil) }
        try record.validateForUse(configuration: configuration)
        try validateLive(record: record)
        try terminateVerified(record: record)
        try ledgerCoordinator.verifyTeardownComplete(record: record)
        try store.remove()
        try lock.release(consoleUID: record.consoleUID)
        return HelperResult(status: .stopped, username: nil, ledger: record.ledger)
    }

    private func status() throws -> HelperResult {
        guard let record = try store.load() else {
            return HelperResult(status: .inactive, username: nil, ledger: nil, statusDocument: HelperStatusDocument(state: "stopped", pid: nil, session_nonce: nil, tunnel_interface: nil))
        }
        do {
            try record.validateForUse(configuration: configuration)
            try validateLive(record: record)
            let document = HelperStatusDocument(state: "running", pid: Int(record.pid), session_nonce: record.sessionNonce, tunnel_interface: validatedTunnelInterface(record.tunnelInterface))
            return HelperResult(status: .running, username: nil, ledger: record.ledger, statusDocument: document)
        } catch {
            let document = HelperStatusDocument(state: "repair-required", pid: nil, session_nonce: record.sessionNonce, tunnel_interface: nil)
            return HelperResult(status: .repairRequired, username: nil, ledger: record.ledger, statusDocument: document)
        }
    }

    private mutating func repair() throws -> HelperResult {
        guard let record = try store.load() else { return HelperResult(status: .inactive, username: nil, ledger: nil) }
        try record.validateForUse(configuration: configuration)
        if let live = try process.liveIdentity(for: record.pid), liveMatches(record: record, live: live) { throw HelperError.processMismatch }
        try ledgerCoordinator.repair(record: record, configuration: configuration)
        try ledgerCoordinator.verifyTeardownComplete(record: record)
        try store.remove()
        try lock.release(consoleUID: record.consoleUID)
        return HelperResult(status: .stopped, username: nil, ledger: record.ledger)
    }

    private func validateLive(record: SessionRecord) throws {
        try record.validateForUse(configuration: configuration)
        guard record.portal == configuration.portal, record.consoleUID == identity.consoleUID, !record.sessionNonce.isEmpty else { throw HelperError.processMismatch }
        guard let live = try process.liveIdentity(for: record.pid), liveMatches(record: record, live: live) else { throw HelperError.processMismatch }
    }

    private func liveMatches(record: SessionRecord, live: LiveProcessIdentity) -> Bool {
        live.pid == record.pid
            && live.processGroupID == record.processGroupID
            && live.birthTime == record.processBirthTime
            && live.executablePath == record.executableIdentity.path
    }

    private func terminateVerified(record: SessionRecord) throws {
        try validateLive(record: record)
        try process.validateBeforeSignal(record)
        try process.terminateProcessGroup(record.processGroupID)
        if try !process.waitForExit(pid: record.pid, timeout: 5) {
            try validateLive(record: record)
            try process.validateBeforeSignal(record)
            try process.killProcessGroup(record.processGroupID)
            guard try process.waitForExit(pid: record.pid, timeout: 2) else { throw HelperError.processMismatch }
        }
    }

    private func validatedTunnelInterface(_ value: String?) -> String? {
        guard let value else { return nil }
        guard value.hasPrefix("utun"), value.dropFirst(4).allSatisfy(\.isNumber), value.count <= 12 else { return nil }
        return value
    }
}
