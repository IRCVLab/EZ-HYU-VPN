import Darwin
import Foundation

public struct VPNServiceTimeouts: Equatable, Sendable {
    public let connect: TimeInterval
    public let write: TimeInterval
    public let read: TimeInterval
    public let total: TimeInterval

    public init(connect: TimeInterval = 0.5, write: TimeInterval = 0.5, read: TimeInterval = 0.5, total: TimeInterval = 1.5) {
        self.connect = connect
        self.write = write
        self.read = read
        self.total = total
    }
}

public struct SocketFileMetadata: Equatable, Sendable {
    public let ownerUID: uid_t
    public let mode: mode_t
    public let isSymlink: Bool
    public let isDirectory: Bool
    public let isSocket: Bool
    public let deviceID: UInt64
    public let inode: UInt64

    public init(
        ownerUID: uid_t,
        mode: mode_t,
        isSymlink: Bool,
        isDirectory: Bool,
        isSocket: Bool,
        deviceID: UInt64 = 0,
        inode: UInt64 = 0
    ) {
        self.ownerUID = ownerUID
        self.mode = mode
        self.isSymlink = isSymlink
        self.isDirectory = isDirectory
        self.isSocket = isSocket
        self.deviceID = deviceID
        self.inode = inode
    }

    var hasStableIdentity: Bool { deviceID != 0 || inode != 0 }
}

public protocol SocketMetadataProviding {
    func metadata(for path: String) throws -> SocketFileMetadata
}

public struct SystemSocketMetadataProvider: SocketMetadataProviding, Sendable {
    public init() {}

    public func metadata(for path: String) throws -> SocketFileMetadata {
        var linkInfo = stat()
        guard lstat(path, &linkInfo) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        return SocketFileMetadata(
            ownerUID: linkInfo.st_uid,
            mode: linkInfo.st_mode & 0o777,
            isSymlink: (linkInfo.st_mode & S_IFMT) == S_IFLNK,
            isDirectory: (linkInfo.st_mode & S_IFMT) == S_IFDIR,
            isSocket: (linkInfo.st_mode & S_IFMT) == S_IFSOCK,
            deviceID: UInt64(linkInfo.st_dev),
            inode: UInt64(linkInfo.st_ino)
        )
    }
}

package protocol RustIPCMonotonicClock: Sendable {
    func nowNanoseconds() -> UInt64
}

struct SystemRustIPCMonotonicClock: RustIPCMonotonicClock {
    func nowNanoseconds() -> UInt64 { DispatchTime.now().uptimeNanoseconds }
}

package protocol RustIPCSocketOperations: Sendable {
    func socket() -> Int32
    func setNoSigPipe(_ descriptor: Int32)
    func setNonBlocking(_ descriptor: Int32) throws
    func connect(_ descriptor: Int32, _ address: UnsafePointer<sockaddr>, _ length: socklen_t) -> Int32
    func poll(_ fds: UnsafeMutablePointer<pollfd>, _ count: nfds_t, _ timeout: Int32) -> Int32
    func read(_ descriptor: Int32, _ buffer: UnsafeMutableRawPointer, _ count: Int) -> Int
    func write(_ descriptor: Int32, _ buffer: UnsafeRawPointer, _ count: Int) -> Int
    func socketError(_ descriptor: Int32) throws -> Int32
    func peerEffectiveUID(_ descriptor: Int32) throws -> uid_t
    func close(_ descriptor: Int32)
}

struct SystemRustIPCSocketOperations: RustIPCSocketOperations {
    func socket() -> Int32 { Darwin.socket(AF_UNIX, SOCK_STREAM, 0) }

    func setNoSigPipe(_ descriptor: Int32) {
        var noSigPipe: Int32 = 1
        _ = withUnsafePointer(to: &noSigPipe) {
            Darwin.setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, $0, socklen_t(MemoryLayout<Int32>.size))
        }
    }

    func setNonBlocking(_ descriptor: Int32) throws {
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
            throw VPNServiceError.unavailable
        }
    }

    func connect(_ descriptor: Int32, _ address: UnsafePointer<sockaddr>, _ length: socklen_t) -> Int32 {
        Darwin.connect(descriptor, address, length)
    }

    func poll(_ fds: UnsafeMutablePointer<pollfd>, _ count: nfds_t, _ timeout: Int32) -> Int32 {
        Darwin.poll(fds, count, timeout)
    }

    func read(_ descriptor: Int32, _ buffer: UnsafeMutableRawPointer, _ count: Int) -> Int {
        Darwin.read(descriptor, buffer, count)
    }

    func write(_ descriptor: Int32, _ buffer: UnsafeRawPointer, _ count: Int) -> Int {
        Darwin.write(descriptor, buffer, count)
    }

    func socketError(_ descriptor: Int32) throws -> Int32 {
        var socketError: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &socketError, &length) == 0 else {
            throw VPNServiceError.unavailable
        }
        return socketError
    }

    func peerEffectiveUID(_ descriptor: Int32) throws -> uid_t {
        var credentials = xucred()
        var length = socklen_t(MemoryLayout<xucred>.size)
        let result = withUnsafeMutablePointer(to: &credentials) {
            getsockopt(descriptor, 0, LOCAL_PEERCRED, UnsafeMutableRawPointer($0), &length)
        }
        if result == 0 {
            return credentials.cr_uid
        }
        var effectiveUID: uid_t = 0
        var effectiveGID: gid_t = 0
        guard getpeereid(descriptor, &effectiveUID, &effectiveGID) == 0 else {
            throw VPNServiceError.unavailable
        }
        return effectiveUID
    }

    func close(_ descriptor: Int32) {
        _ = Darwin.close(descriptor)
    }
}

public final class RustIPCClient: VPNServiceRequesting, @unchecked Sendable {
    public static let defaultSocketPath = URL(fileURLWithPath: NSHomeDirectory())
        .appendingPathComponent("Library/Application Support/hyu-openconnect/daemon.sock")

    private let socketPath: URL
    private let metadata: SocketMetadataProviding
    private let requestIDGenerator: @Sendable () -> String
    private let timeouts: VPNServiceTimeouts
    private let responseMaxBytes: Int
    private let queue: DispatchQueue
    private let operations: RustIPCSocketOperations
    private let monotonicClock: RustIPCMonotonicClock

    public init(
        socketPath: URL = RustIPCClient.defaultSocketPath,
        metadata: SocketMetadataProviding = SystemSocketMetadataProvider(),
        requestIDGenerator: (@Sendable () -> String)? = nil,
        timeouts: VPNServiceTimeouts = VPNServiceTimeouts(),
        responseMaxBytes: Int = 64 * 1024,
        queue: DispatchQueue = DispatchQueue(label: "hyu.vpn.rust-ipc-client", qos: .utility)
    ) {
        self.socketPath = socketPath
        self.metadata = metadata
        self.requestIDGenerator = requestIDGenerator ?? defaultRustIPCRequestIDGenerator()
        self.timeouts = timeouts
        self.responseMaxBytes = responseMaxBytes
        self.queue = queue
        self.operations = SystemRustIPCSocketOperations()
        self.monotonicClock = SystemRustIPCMonotonicClock()
    }

    package init(
        socketPath: URL = RustIPCClient.defaultSocketPath,
        metadata: SocketMetadataProviding = SystemSocketMetadataProvider(),
        requestIDGenerator: (@Sendable () -> String)? = nil,
        timeouts: VPNServiceTimeouts = VPNServiceTimeouts(),
        responseMaxBytes: Int = 64 * 1024,
        queue: DispatchQueue = DispatchQueue(label: "hyu.vpn.rust-ipc-client", qos: .utility),
        operations: RustIPCSocketOperations,
        monotonicClock: RustIPCMonotonicClock
    ) {
        self.socketPath = socketPath
        self.metadata = metadata
        self.requestIDGenerator = requestIDGenerator ?? defaultRustIPCRequestIDGenerator()
        self.timeouts = timeouts
        self.responseMaxBytes = responseMaxBytes
        self.queue = queue
        self.operations = operations
        self.monotonicClock = monotonicClock
    }

    public func request(_ command: VPNCommand, completion: @escaping @Sendable (Result<VPNResponse, VPNServiceError>) -> Void) {
        queue.async {
            let result = self.performRequest(command: command)
            DispatchQueue.main.async { completion(result) }
        }
    }

    public func replaceCredentials(_ credentials: CredentialInput, completion: @escaping @Sendable (Result<Void, VPNServiceError>) -> Void) {
        queue.async {
            let result = self.performReplaceCredentials(credentials)
            DispatchQueue.main.async { completion(result) }
        }
    }

    public func requestSynchronously(_ command: VPNCommand) -> Result<VPNResponse, VPNServiceError> {
        performRequest(command: command)
    }

    package func requestSynchronouslyForTest(_ command: VPNCommand) -> Result<VPNResponse, VPNServiceError> {
        requestSynchronously(command)
    }

    public func replaceCredentialsSynchronously(_ credentials: CredentialInput) -> Result<Void, VPNServiceError> {
        performReplaceCredentials(credentials)
    }

    package func replaceCredentialsSynchronouslyForTest(_ credentials: CredentialInput) -> Result<Void, VPNServiceError> {
        replaceCredentialsSynchronously(credentials)
    }

    private func performRequest(command: VPNCommand) -> Result<VPNResponse, VPNServiceError> {
        let requestID = requestIDGenerator()
        do {
            var payload = try RustWireRequestEncoder.encode(command: command, requestID: requestID)
            defer { Self.zeroize(&payload) }
            let response = try send(payload: &payload, expectedRequestID: requestID)
            return .success(response)
        } catch let error as VPNServiceError {
            return .failure(error)
        } catch {
            return .failure(.unavailable)
        }
    }

    private func performReplaceCredentials(_ credentials: CredentialInput) -> Result<Void, VPNServiceError> {
        let requestID = requestIDGenerator()
        do {
            var payload = try RustWireRequestEncoder.encodeReplaceCredentials(credentials, requestID: requestID)
            defer { Self.zeroize(&payload) }
            let response = try send(payload: &payload, expectedRequestID: requestID)
            switch response {
            case .ack:
                return .success(())
            case .error(let code):
                return .failure(.backend(code))
            default:
                return .failure(.protocolViolation)
            }
        } catch let error as VPNServiceError {
            return .failure(error)
        } catch {
            return .failure(.unavailable)
        }
    }

    private func send(payload: inout Data, expectedRequestID: String) throws -> VPNResponse {
        let preConnectSocketIdentity = try validateSocketPath()
        let deadline = try monotonicDeadline(after: timeouts.total)
        let descriptor = operations.socket()
        guard descriptor >= 0 else { throw VPNServiceError.unavailable }
        defer { operations.close(descriptor) }
        operations.setNoSigPipe(descriptor)
        try operations.setNonBlocking(descriptor)
        try connect(descriptor: descriptor, deadline: deadline)
        try validatePeer(descriptor: descriptor, preConnectSocketIdentity: preConnectSocketIdentity)
        var frame = Self.frame(payload)
        defer { Self.zeroize(&frame) }
        try writeAll(frame, to: descriptor, stepTimeout: timeouts.write, deadline: deadline)
        let prefix = try readExact(count: 4, from: descriptor, stepTimeout: timeouts.read, deadline: deadline)
        let length = prefix.withUnsafeBytes { buffer in
            buffer.load(as: UInt32.self).bigEndian
        }
        guard length <= responseMaxBytes else { throw VPNServiceError.protocolViolation }
        var responsePayload = try readExact(count: Int(length), from: descriptor, stepTimeout: timeouts.read, deadline: deadline)
        defer { Self.zeroize(&responsePayload) }
        return try RustWireResponseDecoder.decode(payload: responsePayload, expectedRequestID: expectedRequestID)
    }

    private func validateSocketPath() throws -> SocketFileMetadata {
        let currentUID = getuid()
        let parentPath = socketPath.deletingLastPathComponent().path
        let parent: SocketFileMetadata
        do {
            parent = try metadata.metadata(for: parentPath)
        } catch {
            throw VPNServiceError.unavailable
        }
        guard parent.ownerUID == currentUID, parent.mode == 0o700, !parent.isSymlink, parent.isDirectory else {
            throw VPNServiceError.insecureSocket
        }
        return try validatedSocketMetadata(currentUID: currentUID)
    }

    private func validatedSocketMetadata(currentUID: uid_t) throws -> SocketFileMetadata {
        let socket: SocketFileMetadata
        do {
            socket = try metadata.metadata(for: socketPath.path)
        } catch {
            throw VPNServiceError.unavailable
        }
        guard socket.ownerUID == currentUID, socket.mode == 0o600, !socket.isSymlink, socket.isSocket else {
            throw VPNServiceError.insecureSocket
        }
        return socket
    }

    private func validatePeer(descriptor: Int32, preConnectSocketIdentity: SocketFileMetadata) throws {
        let currentUID = getuid()
        let postConnectSocketIdentity = try validatedSocketMetadata(currentUID: currentUID)
        if preConnectSocketIdentity.hasStableIdentity || postConnectSocketIdentity.hasStableIdentity {
            guard preConnectSocketIdentity.deviceID == postConnectSocketIdentity.deviceID,
                  preConnectSocketIdentity.inode == postConnectSocketIdentity.inode else {
                throw VPNServiceError.insecureSocket
            }
        }
        guard try operations.peerEffectiveUID(descriptor) == currentUID else {
            throw VPNServiceError.insecureSocket
        }
    }

    private func connect(descriptor: Int32, deadline: UInt64) throws {
        var address = sockaddr_un()
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketPath.path.utf8)
        guard pathBytes.count < MemoryLayout.size(ofValue: address.sun_path) else {
            throw VPNServiceError.unavailable
        }
        let sunPathCapacity = MemoryLayout.size(ofValue: address.sun_path)
        withUnsafeMutablePointer(to: &address.sun_path) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: sunPathCapacity) { chars in
                _ = memset(chars, 0, sunPathCapacity)
                for (index, byte) in pathBytes.enumerated() {
                    chars[index] = CChar(bitPattern: byte)
                }
            }
        }
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { ptr in
                operations.connect(descriptor, ptr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if result == 0 { return }
        if errno == EINTR {
            try connect(descriptor: descriptor, deadline: deadline)
            return
        }
        guard errno == EINPROGRESS else { throw VPNServiceError.unavailable }
        try wait(descriptor: descriptor, events: Int16(POLLOUT), stepTimeout: timeouts.connect, deadline: deadline)
        guard try operations.socketError(descriptor) == 0 else {
            throw VPNServiceError.unavailable
        }
    }

    private func writeAll(_ data: Data, to descriptor: Int32, stepTimeout: TimeInterval, deadline: UInt64) throws {
        try data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { return }
            var offset = 0
            while offset < rawBuffer.count {
                do {
                    try wait(descriptor: descriptor, events: Int16(POLLOUT), stepTimeout: stepTimeout, deadline: deadline)
                } catch VPNServiceError.timeout {
                    throw VPNServiceError.timeout
                } catch {
                    throw VPNServiceError.unavailable
                }
                let written = operations.write(descriptor, base.advanced(by: offset), rawBuffer.count - offset)
                if written > 0 {
                    offset += written
                } else if written == -1, errno == EINTR {
                    continue
                } else if written == -1, errno == EAGAIN || errno == EWOULDBLOCK {
                    continue
                } else if written == -1, errno == EPIPE {
                    throw VPNServiceError.unavailable
                } else {
                    throw VPNServiceError.unavailable
                }
            }
        }
    }

    private func readExact(count: Int, from descriptor: Int32, stepTimeout: TimeInterval, deadline: UInt64) throws -> Data {
        var data = Data(count: count)
        try data.withUnsafeMutableBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { return }
            var offset = 0
            while offset < count {
                do {
                    try wait(descriptor: descriptor, events: Int16(POLLIN), stepTimeout: stepTimeout, deadline: deadline)
                } catch VPNServiceError.timeout {
                    throw VPNServiceError.timeout
                } catch {
                    throw VPNServiceError.unavailable
                }
                let readCount = operations.read(descriptor, base.advanced(by: offset), count - offset)
                if readCount > 0 {
                    offset += readCount
                } else if readCount == 0 {
                    throw VPNServiceError.unavailable
                } else if errno == EINTR {
                    continue
                } else if errno == EAGAIN || errno == EWOULDBLOCK {
                    continue
                } else {
                    throw VPNServiceError.unavailable
                }
            }
        }
        return data
    }

    private func wait(descriptor: Int32, events: Int16, stepTimeout: TimeInterval, deadline: UInt64) throws {
        while true {
            let remainingTimeout = try remaining(step: stepTimeout, deadline: deadline)
            var pollDescriptor = pollfd(fd: descriptor, events: events, revents: 0)
            let milliseconds = max(1, Int32((remainingTimeout * 1000).rounded(.up)))
            let result = operations.poll(&pollDescriptor, 1, milliseconds)
            if result == 0 { throw VPNServiceError.timeout }
            if result < 0, errno == EINTR {
                continue
            }
            guard result > 0 else { throw VPNServiceError.unavailable }
            if (pollDescriptor.revents & events) != 0 {
                return
            }
            if (pollDescriptor.revents & Int16(POLLERR | POLLHUP | POLLNVAL)) != 0 {
                throw VPNServiceError.unavailable
            }
            throw VPNServiceError.unavailable
        }
    }

    private func monotonicDeadline(after timeout: TimeInterval) throws -> UInt64 {
        let now = monotonicClock.nowNanoseconds()
        let delta = UInt64((timeout * 1_000_000_000).rounded(.up))
        let deadline = now.addingReportingOverflow(delta)
        guard !deadline.overflow else { throw VPNServiceError.timeout }
        return deadline.partialValue
    }

    private func remaining(step: TimeInterval, deadline: UInt64) throws -> TimeInterval {
        let now = monotonicClock.nowNanoseconds()
        guard now < deadline else { throw VPNServiceError.timeout }
        let totalRemaining = Double(deadline - now) / 1_000_000_000
        return min(step, totalRemaining)
    }

    private static func frame(_ payload: Data) -> Data {
        var length = UInt32(payload.count).bigEndian
        var framed = Data(capacity: 4 + payload.count)
        withUnsafeBytes(of: &length) { framed.append(contentsOf: $0) }
        framed.append(payload)
        return framed
    }

    private static func zeroize(_ data: inout Data) {
        guard !data.isEmpty else { return }
        data.resetBytes(in: 0..<data.count)
    }
}

private final class RequestIDCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value: UInt64 = 1

    func next() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        let current = value
        value += 1
        return current
    }
}

func defaultRustIPCRequestIDGenerator() -> @Sendable () -> String {
    let counter = RequestIDCounter()
    let pid = getpid()
    return { "menu-\(pid)-\(counter.next())" }
}
