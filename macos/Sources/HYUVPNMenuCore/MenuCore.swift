import Foundation
import Darwin

public enum StatusProtocolError: Error, Equatable, CustomStringConvertible {
    case invalid(String)
    public var description: String { switch self { case .invalid(let message): message } }
}

public enum VPNConnectionState: String, CaseIterable, Codable, Equatable, Sendable {
    case disabled
    case waitingForNetwork = "waiting-for-network"
    case connecting
    case connected
    case disconnecting
    case backoff
    case error
}

public struct VPNStatus: Equatable, Sendable {
    public let schemaVersion: Int
    public let state: VPNConnectionState
    public let automaticReconnectEnabled: Bool
    public let connectedAt: Date?
    public let sessionExpiresAt: Date?
    public let lastSuccessfulHIPAt: Date?
    public let tunnelInterface: String?
    public let nextRetryAt: Date?
    public let errorCode: String?
    public let lastTransitionAt: Date
    public let backendBuildVersion: String?

    public init(
        schemaVersion: Int = 1,
        state: VPNConnectionState,
        automaticReconnectEnabled: Bool,
        connectedAt: Date? = nil,
        sessionExpiresAt: Date? = nil,
        lastSuccessfulHIPAt: Date? = nil,
        tunnelInterface: String? = nil,
        nextRetryAt: Date? = nil,
        errorCode: String? = nil,
        lastTransitionAt: Date,
        backendBuildVersion: String? = nil
    ) {
        self.schemaVersion = schemaVersion
        self.state = state
        self.automaticReconnectEnabled = automaticReconnectEnabled
        self.connectedAt = connectedAt
        self.sessionExpiresAt = sessionExpiresAt
        self.lastSuccessfulHIPAt = lastSuccessfulHIPAt
        self.tunnelInterface = tunnelInterface
        self.nextRetryAt = nextRetryAt
        self.errorCode = errorCode
        self.lastTransitionAt = lastTransitionAt
        self.backendBuildVersion = backendBuildVersion
    }
}

public enum VPNStatusDecoder {
    public static let maxBytes = 4096
    private static let allowedKeys: Set<String> = ["schema_version", "state", "automatic_reconnect_enabled", "connected_at", "session_expires_at", "last_successful_hip_at", "tunnel_interface", "next_retry_at", "error_code", "last_transition_at", "backend_build_version"]
    private static let secretKeys: Set<String> = ["username", "password", "otp", "cookie", "authcookie", "seed", "portal"]

    public static func decode(_ data: Data, maxBytes: Int = maxBytes) throws -> VPNStatus {
        guard maxBytes > 0, maxBytes <= 1024 * 1024 else { throw StatusProtocolError.invalid("invalid max bytes") }
        guard data.count <= maxBytes else { throw StatusProtocolError.invalid("oversized status document") }
        try rejectDuplicateTopLevelKeys(in: data)
        let typedSchema = try decodeSchemaVersion(from: data)
        let object: Any
        do { object = try JSONSerialization.jsonObject(with: data, options: []) } catch { throw StatusProtocolError.invalid("malformed status document") }
        guard let document = object as? [String: Any] else { throw StatusProtocolError.invalid("status document must be an object") }
        let keys = Set(document.keys)
        for key in keys.subtracting(allowedKeys).sorted() {
            if secretKeys.contains(key.lowercased()) { throw StatusProtocolError.invalid("secret-bearing field is not allowed: \(key)") }
            throw StatusProtocolError.invalid("unknown status field: \(key)")
        }
        for key in allowedKeys.subtracting(keys).sorted() { throw StatusProtocolError.invalid("missing status field: \(key)") }
        let schema = typedSchema
        guard schema == 1 else { throw StatusProtocolError.invalid("unsupported schema_version") }
        guard let stateRaw = document["state"] as? String, let state = VPNConnectionState(rawValue: stateRaw) else { throw StatusProtocolError.invalid("invalid state") }
        let automatic = try exactBool("automatic_reconnect_enabled", document["automatic_reconnect_enabled"])
        let connectedAt = try optionalDate("connected_at", document["connected_at"])
        let expiresAt = try optionalDate("session_expires_at", document["session_expires_at"])
        let hipAt = try optionalDate("last_successful_hip_at", document["last_successful_hip_at"])
        let retryAt = try optionalDate("next_retry_at", document["next_retry_at"])
        let transitionAt = try requiredDate("last_transition_at", document["last_transition_at"])
        let tunnel = try optionalString("tunnel_interface", document["tunnel_interface"])
        if let tunnel, tunnel.range(of: #"^utun[0-9]{1,8}$"#, options: .regularExpression) == nil { throw StatusProtocolError.invalid("invalid tunnel_interface") }
        let error = try optionalString("error_code", document["error_code"])
        if let error, error.range(of: #"^[A-Z][A-Z0-9_]{0,63}$"#, options: .regularExpression) == nil { throw StatusProtocolError.invalid("invalid error_code") }
        let build = try optionalString("backend_build_version", document["backend_build_version"])
        if let build, build.range(of: #"^[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}$"#, options: .regularExpression) == nil { throw StatusProtocolError.invalid("invalid backend_build_version") }
        return VPNStatus(schemaVersion: schema, state: state, automaticReconnectEnabled: automatic, connectedAt: connectedAt, sessionExpiresAt: expiresAt, lastSuccessfulHIPAt: hipAt, tunnelInterface: tunnel, nextRetryAt: retryAt, errorCode: error, lastTransitionAt: transitionAt, backendBuildVersion: build)
    }

    private static func rejectDuplicateTopLevelKeys(in data: Data) throws {
        try StrictTopLevelJSON.rejectDuplicateTopLevelKeys(in: data, malformedMessage: "malformed status document", duplicateMessagePrefix: "duplicate status field: ")
    }

    private static func decodeSchemaVersion(from data: Data) throws -> Int {
        try StrictTopLevelJSON.decodeRequiredIntegerToken(in: data, key: "schema_version", invalidMessage: "schema_version must be an integer")
    }

    private static func exactInt(_ name: String, _ value: Any?) throws -> Int {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else { throw StatusProtocolError.invalid("\(name) must be an integer") }
        let double = number.doubleValue
        guard double.rounded() == double else { throw StatusProtocolError.invalid("\(name) must be an integer") }
        return number.intValue
    }

    private static func exactBool(_ name: String, _ value: Any?) throws -> Bool {
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { throw StatusProtocolError.invalid("\(name) must be a bool") }
        return number.boolValue
    }

    private static func optionalString(_ name: String, _ value: Any?) throws -> String? {
        if value == nil || value is NSNull { return nil }
        guard let string = value as? String else { throw StatusProtocolError.invalid("\(name) must be a string") }
        return string
    }

    private static func requiredDate(_ name: String, _ value: Any?) throws -> Date {
        guard let date = try optionalDate(name, value) else { throw StatusProtocolError.invalid("\(name) must be an ISO-8601 timestamp") }
        return date
    }

    private static func optionalDate(_ name: String, _ value: Any?) throws -> Date? {
        if value == nil || value is NSNull { return nil }
        guard let string = value as? String else { throw StatusProtocolError.invalid("\(name) must be an ISO-8601 timestamp") }
        guard string.hasSuffix("Z") || string.range(of: #"[+-][0-9]{2}:[0-9]{2}$"#, options: .regularExpression) != nil else { throw StatusProtocolError.invalid("\(name) must be timezone-aware") }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        if let parsed = formatter.date(from: string) { return parsed }
        throw StatusProtocolError.invalid("\(name) must be an ISO-8601 timestamp")
    }
}

public struct VPNStatusFileReader {
    public init() {}
    public func read(from url: URL, maxBytes: Int = VPNStatusDecoder.maxBytes) throws -> VPNStatus {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw StatusProtocolError.invalid("unable to read status document") }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw StatusProtocolError.invalid("unable to stat status document") }
        try StatusFileSecurity.validate(statusPath: url)
        guard (info.st_mode & S_IFMT) == S_IFREG else { throw StatusProtocolError.invalid("unsafe status document") }
        guard (info.st_mode & 0o777) == 0o600, info.st_uid == getuid() else { throw StatusProtocolError.invalid("unsafe status document") }
        guard info.st_size <= maxBytes else { throw StatusProtocolError.invalid("oversized status document") }
        var data = Data()
        let chunkSize = 512
        var buffer = [UInt8](repeating: 0, count: chunkSize)
        while true {
            let count = Darwin.read(fd, &buffer, chunkSize)
            guard count >= 0 else { throw StatusProtocolError.invalid("unable to read status document") }
            if count == 0 { break }
            data.append(buffer, count: count)
            guard data.count <= maxBytes else { throw StatusProtocolError.invalid("oversized status document") }
        }
        return try VPNStatusDecoder.decode(data, maxBytes: maxBytes)
    }
}

private enum StrictTopLevelJSON {
    static func rejectDuplicateTopLevelKeys(in data: Data, malformedMessage: String, duplicateMessagePrefix: String) throws {
        guard let raw = String(data: data, encoding: .utf8) else { throw StatusProtocolError.invalid(malformedMessage) }
        let keys = try topLevelObjectKeys(in: raw, malformedMessage: malformedMessage)
        var seen = Set<String>()
        for key in keys {
            guard seen.insert(key).inserted else { throw StatusProtocolError.invalid("\(duplicateMessagePrefix)\(key)") }
        }
    }

    static func decodeRequiredIntegerToken(in data: Data, key: String, invalidMessage: String) throws -> Int {
        guard let raw = String(data: data, encoding: .utf8), let token = schemaValueToken(in: raw, key: key) else {
            throw StatusProtocolError.invalid(invalidMessage)
        }
        guard !token.contains("."), !token.contains("e"), !token.contains("E"), let value = Int(token) else {
            throw StatusProtocolError.invalid(invalidMessage)
        }
        return value
    }

    static func topLevelObjectKeys(in raw: String, malformedMessage: String) throws -> [String] {
        let chars = Array(raw)
        var index = skipWhitespace(chars, 0)
        guard index < chars.count, chars[index] == "{" else { return [] }
        var depth = 0
        var keys: [String] = []
        while index < chars.count {
            let char = chars[index]
            if char == "\"" {
                guard let parsed = parseJSONString(chars, start: index) else { throw StatusProtocolError.invalid(malformedMessage) }
                let afterString = skipWhitespace(chars, parsed.next)
                if depth == 1, afterString < chars.count, chars[afterString] == ":" { keys.append(parsed.value) }
                index = parsed.next
                continue
            }
            if char == "{" { depth += 1 }
            if char == "}" { depth -= 1 }
            index += 1
        }
        return keys
    }

    static func schemaValueToken(in raw: String, key: String) -> String? {
        let chars = Array(raw)
        var index = 0
        while index < chars.count {
            if chars[index] == "\"", let parsed = parseJSONString(chars, start: index) {
                index = parsed.next
                var cursor = skipWhitespace(chars, index)
                guard cursor < chars.count, chars[cursor] == ":" else { continue }
                cursor = skipWhitespace(chars, cursor + 1)
                if parsed.value == key { return readJSONNumberToken(chars, cursor) }
            } else {
                index += 1
            }
        }
        return nil
    }

    static func parseJSONString(_ chars: [Character], start: Int) -> (value: String, next: Int)? {
        var index = start + 1
        var value = ""
        while index < chars.count {
            let char = chars[index]
            if char == "\"" { return (value, index + 1) }
            if char == "\\" {
                index += 1
                guard index < chars.count else { return nil }
                let escaped = chars[index]
                if escaped == "u" {
                    guard index + 4 < chars.count else { return nil }
                    let hex = String(chars[(index + 1)...(index + 4)])
                    guard let scalarValue = UInt32(hex, radix: 16), let scalar = UnicodeScalar(scalarValue) else { return nil }
                    value.append(Character(scalar))
                    index += 5
                    continue
                }
                switch escaped {
                case "\"": value.append("\"")
                case "\\": value.append("\\")
                case "/": value.append("/")
                case "b": value.append("\u{08}")
                case "f": value.append("\u{0c}")
                case "n": value.append("\n")
                case "r": value.append("\r")
                case "t": value.append("\t")
                default: return nil
                }
            } else {
                value.append(char)
            }
            index += 1
        }
        return nil
    }

    static func skipWhitespace(_ chars: [Character], _ start: Int) -> Int {
        var index = start
        while index < chars.count, [" ", "\n", "\r", "\t"].contains(chars[index]) { index += 1 }
        return index
    }

    static func readJSONNumberToken(_ chars: [Character], _ start: Int) -> String? {
        guard start < chars.count else { return nil }
        var index = start
        if chars[index] == "-" { index += 1 }
        let numberStart = index
        while index < chars.count, chars[index].isNumber { index += 1 }
        guard index > numberStart else { return nil }
        if index < chars.count, chars[index] == "." {
            index += 1
            while index < chars.count, chars[index].isNumber { index += 1 }
        }
        if index < chars.count, chars[index] == "e" || chars[index] == "E" {
            index += 1
            if index < chars.count, chars[index] == "+" || chars[index] == "-" { index += 1 }
            while index < chars.count, chars[index].isNumber { index += 1 }
        }
        return String(chars[start..<index])
    }
}

public struct MenuPresentation: Equatable, Sendable {
    public let statusItemTitle: String
    public let primaryText: String
    public let detailText: String
    public let symbolName: String
    public init(statusItemTitle: String, primaryText: String, detailText: String, symbolName: String) {
        self.statusItemTitle = statusItemTitle
        self.primaryText = primaryText
        self.detailText = detailText
        self.symbolName = symbolName
    }
}

public enum MenuPresenter {
    public static func present(_ status: VPNStatus, now: Date = Date()) -> MenuPresentation {
        let details = [status.tunnelInterface, status.errorCode, status.backendBuildVersion].compactMap { $0 }.joined(separator: " • ")
        return MenuPresentation(statusItemTitle: "", primaryText: title(for: status.state), detailText: details, symbolName: symbolName(for: status.state))
    }

    private static func title(for state: VPNConnectionState) -> String {
        switch state {
        case .connected: "Connected"
        case .connecting: "Connecting…"
        case .disconnecting: "Disconnecting…"
        case .disabled: "Disconnected"
        case .waitingForNetwork: "Waiting for Network"
        case .backoff: "Reconnecting…"
        case .error: "Needs Attention"
        }
    }

    private static func symbolName(for state: VPNConnectionState) -> String {
        switch state {
        case .connected: "checkmark.shield.fill"
        case .connecting: "arrow.triangle.2.circlepath"
        case .disconnecting: "shield.slash"
        case .disabled: "shield.slash"
        case .waitingForNetwork: "wifi.exclamationmark"
        case .backoff: "clock.arrow.circlepath"
        case .error: "exclamationmark.shield.fill"
        }
    }
}

public enum VPNControlCommand: Equatable, Sendable {
    case connect
    case disconnect
    case reconnect
    case setAutomaticReconnect(Bool)
}

public struct ProcessLaunchRequest: Equatable, Sendable {
    public let executablePath: String
    public let arguments: [String]
    public let usesShell: Bool
    public init(executablePath: String, arguments: [String], usesShell: Bool) { self.executablePath = executablePath; self.arguments = arguments; self.usesShell = usesShell }
}

public struct VPNControlClient: Sendable {
    public static let defaultExecutablePath = "/Library/Application Support/HYU VPN/bin/hyu-vpn-control"
    public let executablePath: String
    public init(executablePath: String = defaultExecutablePath) { self.executablePath = executablePath }
    public func request(for command: VPNControlCommand) -> ProcessLaunchRequest {
        let argument: String
        switch command {
        case .connect: argument = "connect"
        case .disconnect: argument = "disconnect"
        case .reconnect: argument = "reconnect"
        case .setAutomaticReconnect(let enabled): argument = enabled ? "automatic-on" : "automatic-off"
        }
        return ProcessLaunchRequest(executablePath: executablePath, arguments: [argument], usesShell: false)
    }
}

public enum StatusReadPurpose: Equatable, Sendable { case sanitizedStatusOnly }

public struct StatusWatcherConfiguration: Equatable, Sendable {
    public let statusPath: URL
    public let usesFileSystemEvents: Bool
    public let usesDirectoryFileEvents: Bool
    public let pollInterval: TimeInterval
    public let timerLeeway: TimeInterval
    public let allowedReadPurpose: StatusReadPurpose
    public init(statusPath: URL, usesFileSystemEvents: Bool, usesDirectoryFileEvents: Bool, pollInterval: TimeInterval, timerLeeway: TimeInterval, allowedReadPurpose: StatusReadPurpose) {
        self.statusPath = statusPath; self.usesFileSystemEvents = usesFileSystemEvents; self.usesDirectoryFileEvents = usesDirectoryFileEvents; self.pollInterval = pollInterval; self.timerLeeway = timerLeeway; self.allowedReadPurpose = allowedReadPurpose
    }
    public static func `default`(statusPath: URL) -> StatusWatcherConfiguration {
        StatusWatcherConfiguration(statusPath: statusPath, usesFileSystemEvents: true, usesDirectoryFileEvents: true, pollInterval: 30, timerLeeway: 10, allowedReadPurpose: .sanitizedStatusOnly)
    }
    public static func production(home: URL = URL(fileURLWithPath: NSHomeDirectory())) -> StatusWatcherConfiguration {
        `default`(statusPath: home.appendingPathComponent("Library/Application Support/hyu-openconnect/status.json"))
    }
}

public struct FileMetadata: Equatable, Sendable {
    public let ownerUID: uid_t
    public let mode: mode_t
    public let isSymlink: Bool
    public let isRegularFile: Bool
    public let isExecutable: Bool
    public init(ownerUID: uid_t, mode: mode_t, isSymlink: Bool, isRegularFile: Bool, isExecutable: Bool) {
        self.ownerUID = ownerUID; self.mode = mode; self.isSymlink = isSymlink; self.isRegularFile = isRegularFile; self.isExecutable = isExecutable
    }
}

public protocol FileMetadataProviding { func metadata(for path: String) throws -> FileMetadata }
public protocol ExecutableMetadataProviding { func metadata(for path: String) throws -> FileMetadata }

public struct SystemFileMetadataProvider: FileMetadataProviding, ExecutableMetadataProviding, Sendable {
    public init() {}
    public func metadata(for path: String) throws -> FileMetadata {
        var linkInfo = stat()
        guard lstat(path, &linkInfo) == 0 else { throw StatusProtocolError.invalid("metadata unavailable") }
        var targetInfo = stat()
        guard stat(path, &targetInfo) == 0 else { throw StatusProtocolError.invalid("metadata unavailable") }
        return FileMetadata(ownerUID: targetInfo.st_uid, mode: targetInfo.st_mode & 0o777, isSymlink: (linkInfo.st_mode & S_IFMT) == S_IFLNK, isRegularFile: (targetInfo.st_mode & S_IFMT) == S_IFREG, isExecutable: access(path, X_OK) == 0)
    }
}

public enum StatusFileSecurity {
    public static func validate(statusPath: URL, metadata: FileMetadataProviding = SystemFileMetadataProvider(), currentUID: uid_t = getuid()) throws {
        let parentPath = statusPath.deletingLastPathComponent().path
        let parent = try metadata.metadata(for: parentPath)
        guard parent.ownerUID == currentUID, parent.mode == 0o700, !parent.isSymlink else { throw StatusProtocolError.invalid("unsafe status parent") }
        let file = try metadata.metadata(for: statusPath.path)
        guard file.ownerUID == currentUID, file.mode == 0o600, !file.isSymlink, file.isRegularFile else { throw StatusProtocolError.invalid("unsafe status file") }
    }
}

public protocol StatusReading: AnyObject { func readStatus() throws -> VPNStatus }
@preconcurrency public protocol StatusUpdateSink: AnyObject { func apply(_ presentation: MenuPresentation) }

public final class FileStatusReader: StatusReading {
    private let url: URL
    private let reader: VPNStatusFileReader
    public init(url: URL, reader: VPNStatusFileReader = VPNStatusFileReader()) { self.url = url; self.reader = reader }
    public func readStatus() throws -> VPNStatus { try reader.read(from: url) }
}

public final class StatusWatcher {
    public let configuration: StatusWatcherConfiguration
    private let reader: StatusReading
    private weak var sink: StatusUpdateSink?
    private let now: () -> Date
    private var lastStatus: VPNStatus?
    private var directoryFileDescriptor: Int32 = -1
    private var fileSource: DispatchSourceFileSystemObject?
    private var timer: DispatchSourceTimer?

    public init(configuration: StatusWatcherConfiguration, reader: StatusReading, sink: StatusUpdateSink, now: @escaping () -> Date = Date.init) {
        self.configuration = configuration; self.reader = reader; self.sink = sink; self.now = now
    }

    deinit { stop() }

    public func start(queue: DispatchQueue = DispatchQueue.main) throws {
        try initialRead()
        let directory = configuration.statusPath.deletingLastPathComponent().path
        directoryFileDescriptor = open(directory, O_EVTONLY | O_CLOEXEC)
        if directoryFileDescriptor >= 0 {
            let source = DispatchSource.makeFileSystemObjectSource(fileDescriptor: directoryFileDescriptor, eventMask: [.write, .rename, .delete, .extend, .attrib], queue: queue)
            source.setEventHandler { [weak self] in try? self?.handleFileEvent() }
            source.setCancelHandler { [fd = directoryFileDescriptor] in if fd >= 0 { close(fd) } }
            source.resume()
            fileSource = source
        }
        let ticker = DispatchSource.makeTimerSource(queue: queue)
        ticker.schedule(deadline: .now() + configuration.pollInterval, repeating: configuration.pollInterval, leeway: .seconds(Int(configuration.timerLeeway)))
        ticker.setEventHandler { [weak self] in try? self?.handleCountdownTick() }
        ticker.resume()
        timer = ticker
    }

    public func stop() {
        timer?.cancel(); timer = nil
        fileSource?.cancel(); fileSource = nil
        if directoryFileDescriptor >= 0 { directoryFileDescriptor = -1 }
    }

    public func initialRead() throws { try readAndApply() }
    public func handleFileEvent() throws { try readAndApply() }
    public func handleCountdownTick() throws {
        if let lastStatus { sink?.apply(MenuPresenter.present(lastStatus, now: now())) } else { try readAndApply() }
    }

    private func readAndApply() throws {
        do {
            let status = try reader.readStatus()
            lastStatus = status
            (sink as? StatusValueSink)?.applyStatusValue(status)
            sink?.apply(MenuPresenter.present(status, now: now()))
        } catch {
            lastStatus = nil
            (sink as? StatusValueSink)?.applyStatusValue(nil)
            sink?.apply(MenuPresentation(statusItemTitle: "", primaryText: "Status unavailable", detailText: "CONTROL_STATUS_UNAVAILABLE", symbolName: "exclamationmark.shield.fill"))
        }
    }
}

public enum MenuAction: CaseIterable, Hashable, Sendable {
    case currentState, primaryConnection, disconnect
    case resetCredentials, launchAtLogin, diagnostics, quit
}
public struct MenuItemModel: Equatable, Sendable { public let title: String; public let isEnabled: Bool; public let isChecked: Bool; public let command: VPNControlCommand?; public init(title: String, isEnabled: Bool, isChecked: Bool, command: VPNControlCommand?) { self.title = title; self.isEnabled = isEnabled; self.isChecked = isChecked; self.command = command } }
public enum MenuModel {
    public static func make(status: VPNStatus, diagnostics: String, launchAtLogin: LoginItemState) -> [MenuAction: MenuItemModel] {
        let view = MenuPresenter.present(status)
        var model: [MenuAction: MenuItemModel] = [:]
        model[.currentState] = MenuItemModel(title: "State: \(view.primaryText)", isEnabled: false, isChecked: false, command: nil)
        model[.primaryConnection] = primaryConnection(for: status.state)
        model[.disconnect] = MenuItemModel(title: "Disconnect", isEnabled: [.connected, .connecting, .backoff, .error].contains(status.state), isChecked: false, command: .disconnect)
        model[.resetCredentials] = MenuItemModel(title: "Reset Credentials…", isEnabled: true, isChecked: false, command: nil)
        model[.launchAtLogin] = launchAtLoginItem(for: launchAtLogin)
        model[.diagnostics] = MenuItemModel(title: "Diagnostics: \(sanitize(diagnostics))", isEnabled: true, isChecked: false, command: nil)
        model[.quit] = MenuItemModel(title: "Quit Menu App", isEnabled: true, isChecked: false, command: nil)
        return model
    }

    private static func launchAtLoginItem(for state: LoginItemState) -> MenuItemModel {
        switch state {
        case .enabled:
            return MenuItemModel(title: "Launch at Login", isEnabled: true, isChecked: true, command: nil)
        case .disabled:
            return MenuItemModel(title: "Launch at Login", isEnabled: true, isChecked: false, command: nil)
        case .approvalRequired:
            return MenuItemModel(title: "Launch at Login (Open System Settings…)", isEnabled: true, isChecked: false, command: nil)
        case .unavailable:
            return MenuItemModel(title: "Launch at Login Unavailable", isEnabled: false, isChecked: false, command: nil)
        }
    }

    private static func primaryConnection(for state: VPNConnectionState) -> MenuItemModel {
        switch state {
        case .connected:
            MenuItemModel(title: "Reconnect", isEnabled: true, isChecked: false, command: .reconnect)
        case .disabled:
            MenuItemModel(title: "Connect", isEnabled: true, isChecked: false, command: .connect)
        case .error:
            MenuItemModel(title: "Reconnect", isEnabled: true, isChecked: false, command: .reconnect)
        case .backoff:
            MenuItemModel(title: "Reconnect Now", isEnabled: true, isChecked: false, command: .reconnect)
        case .connecting:
            MenuItemModel(title: "Connecting…", isEnabled: false, isChecked: false, command: nil)
        case .disconnecting:
            MenuItemModel(title: "Disconnecting…", isEnabled: false, isChecked: false, command: nil)
        case .waitingForNetwork:
            MenuItemModel(title: "Waiting for Network", isEnabled: false, isChecked: false, command: nil)
        }
    }

    public static func sanitize(_ text: String) -> String {
        var clean: [String] = []
        for rawLine in text.replacingOccurrences(of: "\r", with: "\n").split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(rawLine)
            if line.range(of: #"(?i)(password|otp|cookie|authcookie|seed|username|portal)\s*[:=]"#, options: .regularExpression) != nil { continue }
            clean.append(String(line.prefix(160)))
        }
        return clean.joined(separator: " ").prefix(512).description
    }
}

public enum ControlProcessOutcome: Equatable, Sendable {
    case success(exitCode: Int32, stdout: String, stderr: String, stdoutOverflowed: Bool)
    case failure(ControlFailure)
}
public enum ControlFailure: Equatable, Sendable { case timeout, launchFailed, insecureExecutable }
public protocol PipeCreating: AnyObject, Sendable { func makePipe(_ fds: inout [Int32]) -> Int32; func close(_ fd: Int32) }
public final class SystemPipeFactory: PipeCreating, @unchecked Sendable {
    public init() {}
    public func makePipe(_ fds: inout [Int32]) -> Int32 { pipe(&fds) }
    public func close(_ fd: Int32) { Darwin.close(fd) }
}
public protocol ChildProcessWaiting: AnyObject, Sendable { func wait(pid: pid_t, status: inout Int32, options: Int32) -> pid_t }
public final class SystemChildProcessWaiter: ChildProcessWaiting, @unchecked Sendable {
    public init() {}
    public func wait(pid: pid_t, status: inout Int32, options: Int32) -> pid_t { waitpid(pid, &status, options) }
}
protocol SpawnSetupManaging: AnyObject, Sendable {
    func setup(actions: inout posix_spawn_file_actions_t?, attrs: inout posix_spawnattr_t?, stdoutPipe: [Int32], stderrPipe: [Int32]) -> Int32
    func spawn(pid: inout pid_t, path: String, actions: inout posix_spawn_file_actions_t?, attrs: inout posix_spawnattr_t?, argv: inout [UnsafeMutablePointer<CChar>?], env: inout [UnsafeMutablePointer<CChar>?]) -> Int32
}
final class SystemSpawnSetupManager: SpawnSetupManaging, @unchecked Sendable {
    init() {}
    func setup(actions: inout posix_spawn_file_actions_t?, attrs: inout posix_spawnattr_t?, stdoutPipe: [Int32], stderrPipe: [Int32]) -> Int32 {
        let checks = [
            posix_spawn_file_actions_adddup2(&actions, stdoutPipe[1], STDOUT_FILENO),
            posix_spawn_file_actions_adddup2(&actions, stderrPipe[1], STDERR_FILENO),
            posix_spawn_file_actions_addclose(&actions, stdoutPipe[0]),
            posix_spawn_file_actions_addclose(&actions, stderrPipe[0]),
            posix_spawnattr_setflags(&attrs, Int16(POSIX_SPAWN_SETSID | POSIX_SPAWN_CLOEXEC_DEFAULT))
        ]
        return checks.first { $0 != 0 } ?? 0
    }
    func spawn(pid: inout pid_t, path: String, actions: inout posix_spawn_file_actions_t?, attrs: inout posix_spawnattr_t?, argv: inout [UnsafeMutablePointer<CChar>?], env: inout [UnsafeMutablePointer<CChar>?]) -> Int32 {
        posix_spawn(&pid, path, &actions, &attrs, &argv, &env)
    }
}
public enum ControlStatus: Equatable, Sendable { case ok, failed, timeout }
public struct ControlResult: Equatable, Sendable { public let status: ControlStatus; public let errorCode: String?; public init(status: ControlStatus, errorCode: String?) { self.status = status; self.errorCode = errorCode } }
public protocol ControlProcessRunning: AnyObject { func run(_ request: ProcessLaunchRequest, timeout: TimeInterval, maxOutputBytes: Int) throws -> ControlProcessOutcome }

public struct SecureVPNControlClient: @unchecked Sendable {
    public static let defaultExecutablePath = "/Library/Application Support/HYU VPN/bin/hyu-vpn-control"
    public let executablePath: String
    private let metadata: ExecutableMetadataProviding
    private let runner: ControlProcessRunning
    public init(executablePath: String = defaultExecutablePath, metadata: ExecutableMetadataProviding = SystemFileMetadataProvider(), runner: ControlProcessRunning = SystemControlProcessRunner()) {
        self.executablePath = executablePath; self.metadata = metadata; self.runner = runner
    }
    public func request(for command: VPNControlCommand) -> ProcessLaunchRequest { VPNControlClient(executablePath: executablePath).request(for: command) }
    public func run(_ command: VPNControlCommand, timeout: TimeInterval = 3, maxOutputBytes: Int = 2048) throws -> ControlResult {
        try validateExecutable()
        let outcome = try runner.run(request(for: command), timeout: timeout, maxOutputBytes: maxOutputBytes)
        switch outcome {
        case .success(let exitCode, let stdout, _, let stdoutOverflowed):
            if exitCode == 0 { return ControlResult(status: .ok, errorCode: nil) }
            guard !stdoutOverflowed else { return ControlResult(status: .failed, errorCode: "CONTROL_EXIT_\(exitCode)") }
            if let normalized = ControlCommandOutput.normalizeFailure(exitCode: exitCode, stdout: stdout) {
                return ControlResult(status: .failed, errorCode: normalized)
            }
            return ControlResult(status: .failed, errorCode: "CONTROL_EXIT_\(exitCode)")
        case .failure(.timeout): return ControlResult(status: .timeout, errorCode: "CONTROL_TIMEOUT")
        case .failure(.launchFailed): return ControlResult(status: .failed, errorCode: "CONTROL_LAUNCH_FAILED")
        case .failure(.insecureExecutable): throw StatusProtocolError.invalid("insecure control executable")
        }
    }
    private func validateExecutable() throws {
        let executable = try metadata.metadata(for: executablePath)
        guard executable.ownerUID == 0, !executable.isSymlink, executable.isRegularFile, executable.isExecutable, (executable.mode & 0o022) == 0 else { throw StatusProtocolError.invalid("insecure control executable") }
        var path = URL(fileURLWithPath: executablePath).deletingLastPathComponent()
        while path.path != "/" {
            let parent = try metadata.metadata(for: path.path)
            guard parent.ownerUID == 0, !parent.isSymlink, (parent.mode & 0o022) == 0 else { throw StatusProtocolError.invalid("insecure control parent") }
            path.deleteLastPathComponent()
        }
    }
}

public final class SystemControlProcessRunner: ControlProcessRunning, @unchecked Sendable {
    private let pipeFactory: PipeCreating
    private let waiter: ChildProcessWaiting
    private let spawnSetup: SpawnSetupManaging
    public convenience init(pipeFactory: PipeCreating = SystemPipeFactory(), waiter: ChildProcessWaiting = SystemChildProcessWaiter()) {
        self.init(pipeFactory: pipeFactory, waiter: waiter, spawnSetup: SystemSpawnSetupManager())
    }
    init(pipeFactory: PipeCreating = SystemPipeFactory(), waiter: ChildProcessWaiting = SystemChildProcessWaiter(), spawnSetup: SpawnSetupManaging) {
        self.pipeFactory = pipeFactory
        self.waiter = waiter
        self.spawnSetup = spawnSetup
    }
    public static func fixedEnvironment() -> [String] { ["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"] }

    public func run(_ request: ProcessLaunchRequest, timeout: TimeInterval, maxOutputBytes: Int) throws -> ControlProcessOutcome {
        var stdoutPipe = [Int32](repeating: -1, count: 2)
        var stderrPipe = [Int32](repeating: -1, count: 2)
        guard pipeFactory.makePipe(&stdoutPipe) == 0 else { return .failure(.launchFailed) }
        guard setCloseOnExec(stdoutPipe) else { closeAll(&stdoutPipe); return .failure(.launchFailed) }
        guard pipeFactory.makePipe(&stderrPipe) == 0 else { closeAll(&stdoutPipe); return .failure(.launchFailed) }
        guard setCloseOnExec(stderrPipe) else { closeAll(&stdoutPipe); closeAll(&stderrPipe); return .failure(.launchFailed) }
        defer { closeAll(&stdoutPipe); closeAll(&stderrPipe) }

        var actions: posix_spawn_file_actions_t?
        var attrs: posix_spawnattr_t?
        var actionsInitialized = false
        var attrsInitialized = false
        guard posix_spawn_file_actions_init(&actions) == 0 else { return .failure(.launchFailed) }
        actionsInitialized = true
        defer { if actionsInitialized { posix_spawn_file_actions_destroy(&actions) } }
        guard posix_spawnattr_init(&attrs) == 0 else { return .failure(.launchFailed) }
        attrsInitialized = true
        defer { if attrsInitialized { posix_spawnattr_destroy(&attrs) } }
        guard spawnSetup.setup(actions: &actions, attrs: &attrs, stdoutPipe: stdoutPipe, stderrPipe: stderrPipe) == 0 else { return .failure(.launchFailed) }

        let argvStrings = [request.executablePath] + request.arguments
        var argv = argvStrings.map { strdup($0) }
        argv.append(nil)
        defer { for pointer in argv where pointer != nil { free(pointer) } }
        var env = Self.fixedEnvironment().map { strdup($0) }
        env.append(nil)
        defer { for pointer in env where pointer != nil { free(pointer) } }
        var pid = pid_t(0)
        let spawnResult = spawnSetup.spawn(pid: &pid, path: request.executablePath, actions: &actions, attrs: &attrs, argv: &argv, env: &env)
        closeDescriptor(&stdoutPipe[1])
        closeDescriptor(&stderrPipe[1])
        guard spawnResult == 0 else { return .failure(.launchFailed) }

        let outRead = stdoutPipe[0]; stdoutPipe[0] = -1
        let errRead = stderrPipe[0]; stderrPipe[0] = -1
        let outputGroup = DispatchGroup()
        let collectedStdout = CollectedPipeOutput()
        let drainPipeFactory = pipeFactory
        outputGroup.enter(); DispatchQueue.global(qos: .utility).async {
            collectedStdout.store(collectDrain(outRead, closer: drainPipeFactory, maxBytes: maxOutputBytes))
            outputGroup.leave()
        }
        outputGroup.enter(); DispatchQueue.global(qos: .utility).async { discardDrain(errRead, closer: drainPipeFactory); outputGroup.leave() }

        let deadline = Date().addingTimeInterval(timeout)
        var status: Int32 = 0
        while Date() < deadline {
            let waited = waiter.wait(pid: pid, status: &status, options: WNOHANG)
            if waited == pid {
                if outputGroup.wait(timeout: .now() + 0.25) == .success, !processGroupExists(pid) { return .success(exitCode: exitCode(from: status), stdout: collectedStdout.stringValue, stderr: "", stdoutOverflowed: collectedStdout.overflowed) }
                cleanupProcessGroup(pid, outputGroup: outputGroup)
                return .failure(.timeout)
            }
            if waited == -1 && errno == ECHILD {
                cleanupProcessGroup(pid, outputGroup: outputGroup)
                return .failure(.launchFailed)
            }
            Thread.sleep(forTimeInterval: 0.02)
        }

        cleanupProcessGroup(pid, outputGroup: outputGroup)
        return .failure(.timeout)
    }

    private func closeAll(_ fds: inout [Int32]) { for index in fds.indices { closeDescriptor(&fds[index]) } }
    private func closeDescriptor(_ fd: inout Int32) { if fd >= 0 { pipeFactory.close(fd); fd = -1 } }
    private func cleanupProcessGroup(_ pid: pid_t, outputGroup: DispatchGroup) {
        kill(-pid, SIGTERM)
        boundedReap(pid, until: Date().addingTimeInterval(0.5))
        let pipesClosedAfterTerm = outputGroup.wait(timeout: .now() + 0.25) == .success
        if !pipesClosedAfterTerm || processGroupExists(pid) { kill(-pid, SIGKILL) }
        boundedReap(pid, until: Date().addingTimeInterval(0.5))
        _ = outputGroup.wait(timeout: .now() + 1)
    }

    private func boundedReap(_ pid: pid_t, until deadline: Date) {
        var status: Int32 = 0
        while Date() < deadline {
            let waited = waiter.wait(pid: pid, status: &status, options: WNOHANG)
            if waited == pid || (waited == -1 && errno == ECHILD) { return }
            Thread.sleep(forTimeInterval: 0.02)
        }
    }
}

private func setCloseOnExec(_ fds: [Int32]) -> Bool {
    for fd in fds where fd >= 0 { guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { return false } }
    return true
}

private func processGroupExists(_ pid: pid_t) -> Bool {
    if kill(-pid, 0) == 0 { return true }
    return errno == EPERM
}

private func discardDrain(_ fd: Int32, closer: PipeCreating) {
    var buffer = [UInt8](repeating: 0, count: 8192)
    while true {
        let count = read(fd, &buffer, buffer.count)
        if count <= 0 { closer.close(fd); return }
    }
}

private func collectDrain(_ fd: Int32, closer: PipeCreating, maxBytes: Int) -> (data: Data, overflowed: Bool) {
    var collected = Data()
    let bound = max(0, maxBytes)
    var overflowed = false
    var buffer = [UInt8](repeating: 0, count: 8192)
    while true {
        let count = read(fd, &buffer, buffer.count)
        if count <= 0 {
            closer.close(fd)
            return (collected, overflowed)
        }
        let remaining = max(0, bound - collected.count)
        if remaining > 0 {
            collected.append(buffer, count: min(remaining, count))
        }
        if count > remaining {
            overflowed = true
        }
    }
}

private final class CollectedPipeOutput: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()
    private var didOverflow = false

    var stringValue: String {
        lock.lock()
        defer { lock.unlock() }
        return String(decoding: data, as: UTF8.self)
    }

    var overflowed: Bool {
        lock.lock()
        defer { lock.unlock() }
        return didOverflow
    }

    func store(_ value: (data: Data, overflowed: Bool)) {
        lock.lock()
        data = value.data
        didOverflow = value.overflowed
        lock.unlock()
    }
}

private func exitCode(from status: Int32) -> Int32 {
    let signal = status & 0x7f
    if signal == 0 { return (status >> 8) & 0xff }
    if signal != 0x7f { return 128 + signal }
    return status
}

private enum ControlCommandOutput {
    private static let allowedKeys: Set<String> = ["schema_version", "ok", "error_code"]
    private static let allowedFailureCodes: Set<String> = ["BAD_REQUEST", "INTERNAL_ERROR", "REPAIR_REQUIRED", "CONTROL_UNAVAILABLE"]

    static func normalizeFailure(exitCode: Int32, stdout: String) -> String? {
        guard exitCode != 0 else { return nil }
        guard let decoded = try? decode(stdout), decoded.ok == false else { return nil }
        return decoded.errorCode
    }

    private static func decode(_ raw: String) throws -> (ok: Bool, errorCode: String?) {
        let data = Data(raw.utf8)
        try StrictTopLevelJSON.rejectDuplicateTopLevelKeys(in: data, malformedMessage: "malformed control output", duplicateMessagePrefix: "duplicate control output field: ")
        let typedSchema = try StrictTopLevelJSON.decodeRequiredIntegerToken(in: data, key: "schema_version", invalidMessage: "control output schema_version must be an integer")
        let object = try JSONSerialization.jsonObject(with: data, options: [])
        guard let document = object as? [String: Any] else { throw StatusProtocolError.invalid("control output must be an object") }
        let keys = Set(document.keys)
        for key in keys.subtracting(allowedKeys).sorted() {
            throw StatusProtocolError.invalid("unknown control output field: \(key)")
        }
        for key in allowedKeys.subtracting(keys).sorted() {
            throw StatusProtocolError.invalid("missing control output field: \(key)")
        }
        guard typedSchema == 1 else { throw StatusProtocolError.invalid("unsupported control output schema_version") }
        guard let okValue = document["ok"] as? NSNumber, CFGetTypeID(okValue) == CFBooleanGetTypeID() else {
            throw StatusProtocolError.invalid("control output ok must be a bool")
        }
        let ok = okValue.boolValue
        let errorCode = try optionalString("error_code", document["error_code"])
        if ok {
            guard errorCode == nil else { throw StatusProtocolError.invalid("successful control output must not include an error_code") }
        } else {
            guard let errorCode, allowedFailureCodes.contains(errorCode) else {
                throw StatusProtocolError.invalid("control output error_code is not allowlisted")
            }
        }
        return (ok, errorCode)
    }

    private static func optionalString(_ name: String, _ value: Any?) throws -> String? {
        if value == nil || value is NSNull { return nil }
        guard let string = value as? String else { throw StatusProtocolError.invalid("\(name) must be a string") }
        return string
    }
}


public protocol StatusValueSink: AnyObject { func applyStatusValue(_ status: VPNStatus?) }
