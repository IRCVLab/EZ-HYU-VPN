import Darwin
import Foundation
import Testing
@testable import HYUVPNMenuCore

@Suite struct RustIPCClientTests {
    @Test func framedRequestsMatchRustFixturesAndDecodeAckStatusOtpAndBackendErrors() throws {
        let cases: [(String, String, VPNCommand, Data, VPNResponse)] = [
            ("status-request-v1", "swift-status-1", .status, fixtureData("status-response-v1.frame"), .status(try fixtureStatus())),
            ("connect-request-v1", "swift-connect-1", .connect, fixtureData("connect-ack-response-v1.frame"), .ack),
            ("disconnect-request-v1", "swift-disconnect-1", .disconnect, fixtureData("disconnect-ack-response-v1.frame"), .ack),
            ("reconnect-request-v1", "swift-reconnect-1", .reconnect, fixtureData("reconnect-ack-response-v1.frame"), .ack),
            ("current-otp-request-v1", "swift-current-otp-1", .currentOTP, fixtureData("current-otp-response-v1.frame"), .currentOTP(TOTPDisplaySnapshot(code: "123456", secondsRemaining: 17))),
            ("automatic-on-request-v1", "swift-automatic-on-1", .automaticReconnect(true), fixtureData("automatic-on-ack-response-v1.frame"), .ack),
            ("automatic-off-request-v1", "swift-automatic-off-1", .automaticReconnect(false), fixtureData("automatic-off-ack-response-v1.frame"), .ack),
            ("status-request-v1", "swift-error-protocol-mismatch-1", .status, fixtureData("error-protocol-mismatch-v1.frame"), .error(.protocolMismatch)),
        ]

        for (requestFixture, requestID, command, responseFrame, expectedResponse) in cases {
            let server = try UnixFixtureServer(response: responseFrame)
            defer { server.stop() }
            let client = RustIPCClient(
                socketPath: server.socketURL,
                requestIDGenerator: { requestID },
                timeouts: .init(connect: 0.2, write: 0.2, read: 0.2, total: 0.5)
            )
            let outcome = waitForRequestResult { client.request(command, completion: $0) }
            #expect(outcome == .success(expectedResponse))
            #expect(try server.takeRequestFrame() == fixtureData("\(requestFixture).frame"))
        }
    }

    @Test func replaceCredentialsUsesExactRustFixtureAndReturnsVoid() throws {
        let server = try UnixFixtureServer(response: fixtureData("replace-credentials-ack-response-v1.frame"))
        defer { server.stop() }
        let client = RustIPCClient(
            socketPath: server.socketURL,
            requestIDGenerator: { "swift-replace-credentials-1" },
            timeouts: .init(connect: 0.2, write: 0.2, read: 0.2, total: 0.5)
        )
        let result = waitForVoidResult {
            client.replaceCredentials(CredentialInput(username: "swift-user", password: "swift-pass", totpSeed: "JBSWY3DPEHPK3PXP"), completion: $0)
        }
        if case .success = result { #expect(Bool(true)) } else { #expect(Bool(false)) }
        #expect(try server.takeRequestFrame() == fixtureData("replace-credentials-request-v1.frame"))
    }

    @Test func rejectsUnknownFieldsUnsupportedVersionRequestIDMismatchAndOversizedFrames() throws {
        let malformedResponses: [Data] = [
            framed(json: #"{"schema_version":1,"request_id":"swift-status-1","result":"ack","extra":true}"#),
            framed(json: #"{"schema_version":2,"request_id":"swift-status-1","result":"ack"}"#),
            framed(json: #"{"schema_version":1,"request_id":"other-id","result":"ack"}"#),
            oversizedFrame(length: 65_537),
        ]
        for response in malformedResponses {
            let server = try UnixFixtureServer(response: response)
            defer { server.stop() }
            let client = RustIPCClient(
                socketPath: server.socketURL,
                requestIDGenerator: { "swift-status-1" },
                timeouts: .init(connect: 0.2, write: 0.2, read: 0.2, total: 0.5)
            )
            let outcome = waitForRequestResult { client.request(.status, completion: $0) }
            #expect(outcome == Result<VPNResponse, VPNServiceError>.failure(.protocolViolation))
        }
    }

    @Test func reportsUnavailableTimeoutAndSocketSecurityFailures() throws {
        let missing = RustIPCClient(
            socketPath: temporaryRoot().appendingPathComponent("missing.sock"),
            requestIDGenerator: { "swift-status-1" },
            timeouts: .init(connect: 0.05, write: 0.05, read: 0.05, total: 0.1)
        )
        #expect(waitForRequestResult { missing.request(.status, completion: $0) } == Result<VPNResponse, VPNServiceError>.failure(.unavailable))

        let timeoutServer = try UnixFixtureServer(response: fixtureData("status-response-v1.frame"), responseDelay: 0.3)
        defer { timeoutServer.stop() }
        let timeoutClient = RustIPCClient(
            socketPath: timeoutServer.socketURL,
            requestIDGenerator: { "swift-status-1" },
            timeouts: .init(connect: 0.05, write: 0.05, read: 0.05, total: 0.1)
        )
        #expect(waitForRequestResult { timeoutClient.request(.status, completion: $0) } == Result<VPNResponse, VPNServiceError>.failure(.timeout))

        let unsafeRoot = temporaryRoot()
        let parent = unsafeRoot.appendingPathComponent("state", isDirectory: true)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: unsafeRoot) }
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: parent.path)
        let unsafeParentClient = RustIPCClient(socketPath: parent.appendingPathComponent("daemon.sock"), requestIDGenerator: { "swift-status-1" })
        #expect(waitForRequestResult { unsafeParentClient.request(.status, completion: $0) } == Result<VPNResponse, VPNServiceError>.failure(.insecureSocket))

        let symlinkServer = try UnixFixtureServer(response: fixtureData("ack-response-v1.frame"), at: parent.appendingPathComponent("real.sock"))
        defer { symlinkServer.stop() }
        let link = parent.appendingPathComponent("daemon.sock")
        try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: symlinkServer.socketURL.path)
        let symlinkClient = RustIPCClient(socketPath: link, requestIDGenerator: { "swift-connect-1" })
        #expect(waitForRequestResult { symlinkClient.request(.connect, completion: $0) } == Result<VPNResponse, VPNServiceError>.failure(.insecureSocket))
    }

    @Test func synchronousRequestsHonorMonotonicTotalTimeout() throws {
        let metadata = SequencedSocketMetadataProvider(sequence: [
            .parent(ownerUID: getuid(), mode: 0o700),
            .socket(ownerUID: getuid(), mode: 0o600, deviceID: 1, inode: 2),
            .socket(ownerUID: getuid(), mode: 0o600, deviceID: 1, inode: 2),
        ])
        let operations = FakeSocketOperations(
            connectResults: [(result: -1, err: EINPROGRESS)],
            pollResults: [(result: -1, err: EINTR), (result: -1, err: EINTR), (result: -1, err: EINTR)],
            writeResults: [],
            readChunks: [],
            socketError: 0,
            peerEffectiveUID: getuid()
        )
        let clock = DeterministicMonotonicClock(instants: [0, 0, 90_000_000, 100_000_000])
        let client = RustIPCClient(
            socketPath: URL(fileURLWithPath: "/tmp/fake.sock"),
            metadata: metadata,
            requestIDGenerator: { "swift-status-1" },
            timeouts: .init(connect: 1.0, write: 1.0, read: 1.0, total: 0.1),
            operations: operations,
            monotonicClock: clock
        )
        #expect(client.requestSynchronouslyForTest(.status) == .failure(.timeout))
        #expect(operations.pollTimeouts == [100, 10])
    }

    @Test func completionsReturnOnMainThread() throws {
        let server = try UnixFixtureServer(response: fixtureData("connect-ack-response-v1.frame"))
        defer { server.stop() }
        let client = RustIPCClient(
            socketPath: server.socketURL,
            requestIDGenerator: { "swift-connect-1" },
            timeouts: .init(connect: 0.2, write: 0.2, read: 0.2, total: 0.5)
        )
        let state = LockedMainThreadResult()
        DispatchQueue.global(qos: .userInitiated).async {
            client.request(.connect) { result in
                state.complete(isMainThread: Thread.isMainThread, result: result)
            }
        }
        let outcome = try state.wait(timeout: 1)
        #expect(outcome.isMainThread)
        #expect(outcome.result == Result<VPNResponse, VPNServiceError>.success(.ack))
    }

    @Test func retriesEINTRUntilDeadlineAndPeerTrustChecksBeforeWriting() throws {
        let metadata = SequencedSocketMetadataProvider(sequence: [
            .parent(ownerUID: getuid(), mode: 0o700),
            .socket(ownerUID: getuid(), mode: 0o600, deviceID: 1, inode: 2),
            .socket(ownerUID: getuid(), mode: 0o600, deviceID: 1, inode: 2),
        ])
        let operations = FakeSocketOperations(
            connectResults: [(result: -1, err: EINPROGRESS)],
            pollResults: [(result: -1, err: EINTR), (result: 1, err: 0), (result: -1, err: EINTR), (result: 1, err: 0), (result: -1, err: EINTR), (result: 1, err: 0)],
            writeResults: [(result: -1, err: EINTR), (result: 72, err: 0)],
            readChunks: [fixtureData("connect-ack-response-v1.frame")],
            socketError: 0,
            peerEffectiveUID: getuid()
        )
        let clock = DeterministicMonotonicClock(instants: [0, 0, 10_000_000, 20_000_000, 30_000_000, 40_000_000, 50_000_000, 60_000_000, 70_000_000])
        let client = RustIPCClient(
            socketPath: URL(fileURLWithPath: "/tmp/fake.sock"),
            metadata: metadata,
            requestIDGenerator: { "swift-connect-1" },
            timeouts: .init(connect: 0.2, write: 0.2, read: 0.2, total: 0.5),
            operations: operations,
            monotonicClock: clock
        )
        #expect(waitForRequestResult { client.request(.connect, completion: $0) } == .success(.ack))
        #expect(operations.writeCallCount > 0)
    }

    @Test func readsBufferedResponseWhenPeerClosesAfterWriting() throws {
        let metadata = SequencedSocketMetadataProvider(sequence: [
            .parent(ownerUID: getuid(), mode: 0o700),
            .socket(ownerUID: getuid(), mode: 0o600, deviceID: 1, inode: 2),
            .socket(ownerUID: getuid(), mode: 0o600, deviceID: 1, inode: 2),
        ])
        let operations = FakeSocketOperations(
            connectResults: [(result: 0, err: 0)],
            pollResults: [(result: 1, err: 0), (result: 1, err: 0), (result: 1, err: 0)],
            pollRevents: [Int16(POLLOUT), Int16(POLLIN | POLLHUP), Int16(POLLIN | POLLHUP)],
            writeResults: [],
            readChunks: [fixtureData("current-otp-response-v1.frame")],
            socketError: 0,
            peerEffectiveUID: getuid()
        )
        let client = RustIPCClient(
            socketPath: URL(fileURLWithPath: "/tmp/fake.sock"),
            metadata: metadata,
            requestIDGenerator: { "swift-current-otp-1" },
            timeouts: .init(connect: 0.2, write: 0.2, read: 0.2, total: 0.5),
            operations: operations,
            monotonicClock: DeterministicMonotonicClock(instants: Array(repeating: 0, count: 16))
        )

        #expect(client.requestSynchronouslyForTest(.currentOTP) == .success(.currentOTP(TOTPDisplaySnapshot(code: "123456", secondsRemaining: 17))))
    }

    @Test func rejectsMismatchedPeerIdentityBeforeSendingCredentials() throws {
        let metadata = SequencedSocketMetadataProvider(sequence: [
            .parent(ownerUID: getuid(), mode: 0o700),
            .socket(ownerUID: getuid(), mode: 0o600, deviceID: 1, inode: 2),
            .socket(ownerUID: getuid(), mode: 0o600, deviceID: 9, inode: 9),
        ])
        let operations = FakeSocketOperations(
            connectResults: [(result: 0, err: 0)],
            pollResults: [],
            writeResults: [],
            readChunks: [],
            socketError: 0,
            peerEffectiveUID: getuid() + 1
        )
        let client = RustIPCClient(
            socketPath: URL(fileURLWithPath: "/tmp/fake.sock"),
            metadata: metadata,
            requestIDGenerator: { "swift-replace-credentials-1" },
            timeouts: .init(connect: 0.2, write: 0.2, read: 0.2, total: 0.5),
            operations: operations,
            monotonicClock: DeterministicMonotonicClock(instants: [0, 0, 1_000_000])
        )
        let result = waitForVoidResult {
            client.replaceCredentials(
                CredentialInput(username: "swift-user", password: "swift-pass", totpSeed: "JBSWY3DPEHPK3PXP"),
                completion: $0
            )
        }
        if case .failure(.insecureSocket) = result {
            #expect(Bool(true))
        } else {
            #expect(Bool(false))
        }
        #expect(operations.writeCallCount == 0)
    }

    @Test func refreshCoordinatorDropsStaleForcedRefreshResultsAndStartsExactlyOneReplacementGeneration() {
        var coordinator = ServiceRefreshCoordinator()
        let first = coordinator.begin(force: true)
        #expect(first == 1)
        #expect(coordinator.begin(force: true) == nil)
        #expect(coordinator.shouldApply(generation: 1) == false)
        #expect(coordinator.finish(generation: 1) == 2)
        #expect(coordinator.shouldApply(generation: 2))
    }

    @Test func taskSixSourcesContainNoShellFallbackOrHyuVpnControl() throws {
        let root = repoRoot()
        let sourceFiles = [
            root.appendingPathComponent("macos/Sources/HYUVPNMenuCore/MenuCore.swift"),
            root.appendingPathComponent("macos/Sources/HYUVPNMenuCore/RustProtocol.swift"),
            root.appendingPathComponent("macos/Sources/HYUVPNMenuCore/RustIPCClient.swift"),
            root.appendingPathComponent("macos/Sources/HYUVPNMenuApp/AppDelegate.swift"),
        ]
        let combined = try sourceFiles.map { try String(contentsOf: $0, encoding: .utf8) }.joined(separator: "\n")
        for forbidden in ["hyu-vpn-control", "SecureVPNControlClient", "SystemControlProcessRunner", "ProcessLaunchRequest", "usesShell", "shell -c", "NSTask", "Process()"] {
            #expect(!combined.contains(forbidden))
        }
    }
}

private func repoRoot() -> URL {
    URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
}

private func fixtureDirectory() -> URL {
    repoRoot().deletingLastPathComponent().appendingPathComponent("tests/fixtures/protocol", isDirectory: true)
}

private func fixtureData(_ name: String) -> Data {
    try! Data(contentsOf: fixtureDirectory().appendingPathComponent(name))
}

private func fixtureStatus() throws -> VPNStatus {
    guard case .status(let status) = try RustWireResponseDecoder.decode(payload: fixtureData("status-response-v1.json"), expectedRequestID: "swift-status-1") else {
        fatalError("status fixture did not decode to status")
    }
    return status
}

private func temporaryRoot() -> URL {
    let root = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("hyu-vpn-rust-ipc-\(UUID().uuidString)", isDirectory: true)
    try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    return root
}

private func framed(json: String) -> Data {
    let payload = Data(json.utf8)
    var frame = Data()
    var length = UInt32(payload.count).bigEndian
    withUnsafeBytes(of: &length) { frame.append(contentsOf: $0) }
    frame.append(payload)
    return frame
}

private func oversizedFrame(length: UInt32) -> Data {
    var frame = Data()
    var value = length.bigEndian
    withUnsafeBytes(of: &value) { frame.append(contentsOf: $0) }
    return frame
}

private final class LockedBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: T?

    func store(_ newValue: T) {
        lock.lock()
        value = newValue
        lock.unlock()
    }

    func load() -> T? {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

private func waitForRequestResult(_ start: (@escaping @Sendable (Result<VPNResponse, VPNServiceError>) -> Void) -> Void) -> Result<VPNResponse, VPNServiceError> {
    let semaphore = DispatchSemaphore(value: 0)
    let box = LockedBox<Result<VPNResponse, VPNServiceError>>()
    start {
        box.store($0)
        semaphore.signal()
    }
    _ = semaphore.wait(timeout: .now() + 2)
    return box.load()!
}

private func waitForVoidResult(_ start: (@escaping @Sendable (Result<Void, VPNServiceError>) -> Void) -> Void) -> Result<Void, VPNServiceError> {
    let semaphore = DispatchSemaphore(value: 0)
    let box = LockedBox<Result<Void, VPNServiceError>>()
    start {
        box.store($0)
        semaphore.signal()
    }
    _ = semaphore.wait(timeout: .now() + 2)
    return box.load()!
}

private final class LockedMainThreadResult: @unchecked Sendable {
    struct Value {
        let isMainThread: Bool
        let result: Result<VPNResponse, VPNServiceError>
    }

    private let lock = NSLock()
    private let semaphore = DispatchSemaphore(value: 0)
    private var value: Value?

    func complete(isMainThread: Bool, result: Result<VPNResponse, VPNServiceError>) {
        lock.lock()
        value = Value(isMainThread: isMainThread, result: result)
        lock.unlock()
        semaphore.signal()
    }

    func wait(timeout: TimeInterval) throws -> Value {
        guard semaphore.wait(timeout: .now() + timeout) == .success else { throw TimeoutError() }
        lock.lock()
        defer { lock.unlock() }
        return value!
    }
}

private struct TimeoutError: Error {}

private final class DeterministicMonotonicClock: RustIPCMonotonicClock, @unchecked Sendable {
    private let lock = NSLock()
    private let instants: [UInt64]
    private var index = 0

    init(instants: [UInt64]) {
        self.instants = instants
    }

    func nowNanoseconds() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        guard !instants.isEmpty else { return 0 }
        let value = instants[min(index, instants.count - 1)]
        index = min(index + 1, instants.count - 1)
        return value
    }
}

private final class SequencedSocketMetadataProvider: SocketMetadataProviding, @unchecked Sendable {
    enum Entry {
        case parent(ownerUID: uid_t, mode: mode_t)
        case socket(ownerUID: uid_t, mode: mode_t, deviceID: UInt64, inode: UInt64)
    }

    private let lock = NSLock()
    private let sequence: [Entry]
    private var index = 0

    init(sequence: [Entry]) {
        self.sequence = sequence
    }

    func metadata(for path: String) throws -> SocketFileMetadata {
        lock.lock()
        defer { lock.unlock() }
        let entry = sequence[min(index, sequence.count - 1)]
        index = min(index + 1, sequence.count - 1)
        switch entry {
        case .parent(let ownerUID, let mode):
            return SocketFileMetadata(ownerUID: ownerUID, mode: mode, isSymlink: false, isDirectory: true, isSocket: false)
        case .socket(let ownerUID, let mode, let deviceID, let inode):
            return SocketFileMetadata(ownerUID: ownerUID, mode: mode, isSymlink: false, isDirectory: false, isSocket: true, deviceID: deviceID, inode: inode)
        }
    }
}

private final class FakeSocketOperations: RustIPCSocketOperations, @unchecked Sendable {
    private let lock = NSLock()
    private var connectResults: [(result: Int32, err: Int32)]
    private var pollResults: [(result: Int32, err: Int32)]
    private var pollRevents: [Int16]
    private var writeResults: [(result: Int, err: Int32)]
    private var unreadResponse: Data
    private let socketErrorValue: Int32
    private let peerEffectiveUIDValue: uid_t
    private(set) var writeCallCount = 0
    private var recordedPollTimeouts: [Int32] = []
    var pollTimeouts: [Int32] {
        lock.lock()
        defer { lock.unlock() }
        return recordedPollTimeouts
    }

    init(
        connectResults: [(result: Int32, err: Int32)],
        pollResults: [(result: Int32, err: Int32)],
        pollRevents: [Int16] = [],
        writeResults: [(result: Int, err: Int32)],
        readChunks: [Data],
        socketError: Int32,
        peerEffectiveUID: uid_t
    ) {
        self.connectResults = connectResults
        self.pollResults = pollResults
        self.pollRevents = pollRevents
        self.writeResults = writeResults
        self.unreadResponse = readChunks.reduce(into: Data(), +=)
        self.socketErrorValue = socketError
        self.peerEffectiveUIDValue = peerEffectiveUID
    }

    func socket() -> Int32 { 42 }

    func setNoSigPipe(_ descriptor: Int32) {}

    func setNonBlocking(_ descriptor: Int32) throws {}

    func connect(_ descriptor: Int32, _ address: UnsafePointer<sockaddr>, _ length: socklen_t) -> Int32 {
        lock.lock()
        defer { lock.unlock() }
        let next: (result: Int32, err: Int32) = connectResults.isEmpty ? (result: 0, err: 0) : connectResults.removeFirst()
        errno = next.err
        return next.result
    }

    func poll(_ fds: UnsafeMutablePointer<pollfd>, _ count: nfds_t, _ timeout: Int32) -> Int32 {
        lock.lock()
        defer { lock.unlock() }
        recordedPollTimeouts.append(timeout)
        let next: (result: Int32, err: Int32) = pollResults.isEmpty ? (result: 1, err: 0) : pollResults.removeFirst()
        errno = next.err
        if next.result > 0 {
            fds.pointee.revents = pollRevents.isEmpty ? fds.pointee.events : pollRevents.removeFirst()
        }
        return next.result
    }

    func read(_ descriptor: Int32, _ buffer: UnsafeMutableRawPointer, _ count: Int) -> Int {
        lock.lock()
        defer { lock.unlock() }
        if unreadResponse.isEmpty { return 0 }
        let amount = min(count, unreadResponse.count)
        unreadResponse.copyBytes(to: buffer.assumingMemoryBound(to: UInt8.self), count: amount)
        unreadResponse.removeFirst(amount)
        return amount
    }

    func write(_ descriptor: Int32, _ buffer: UnsafeRawPointer, _ count: Int) -> Int {
        lock.lock()
        defer { lock.unlock() }
        writeCallCount += 1
        let next: (result: Int, err: Int32) = writeResults.isEmpty ? (result: count, err: 0) : writeResults.removeFirst()
        errno = next.err
        return next.result
    }

    func socketError(_ descriptor: Int32) throws -> Int32 { socketErrorValue }

    func peerEffectiveUID(_ descriptor: Int32) throws -> uid_t { peerEffectiveUIDValue }

    func close(_ descriptor: Int32) {}
}

private final class UnixFixtureServer {
    let socketURL: URL
    private let listener: Int32
    private let requestLock = NSLock()
    private var requestFrame: Data?
    private var worker: DispatchWorkItem?

    init(response: Data, responseDelay: TimeInterval = 0, at customURL: URL? = nil) throws {
        let root = customURL?.deletingLastPathComponent() ?? temporaryRoot().appendingPathComponent("state", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: root.path)
        socketURL = customURL ?? root.appendingPathComponent("daemon.sock")
        unlink(socketURL.path)
        listener = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listener >= 0 else { throw POSIXError(.EIO) }
        var value: Int32 = 1
        setsockopt(listener, SOL_SOCKET, SO_NOSIGPIPE, &value, socklen_t(MemoryLayout<Int32>.size))
        var address = sockaddr_un()
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        address.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(socketURL.path.utf8)
        precondition(pathBytes.count < MemoryLayout.size(ofValue: address.sun_path))
        let sunPathCapacity = MemoryLayout.size(ofValue: address.sun_path)
        withUnsafeMutablePointer(to: &address.sun_path) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: sunPathCapacity) { chars in
                _ = memset(chars, 0, sunPathCapacity)
                for (index, byte) in pathBytes.enumerated() { chars[index] = CChar(bitPattern: byte) }
            }
        }
        let bindResult = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(listener, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bindResult == 0, listen(listener, 8) == 0 else { throw POSIXError(.EIO) }
        chmod(socketURL.path, 0o600)
        let workItem = DispatchWorkItem { [listener] in
            let connection = accept(listener, nil, nil)
            guard connection >= 0 else { return }
            defer { close(connection) }
            if responseDelay > 0 { Thread.sleep(forTimeInterval: responseDelay) }
            do {
                let frame = try readFrame(from: connection)
                self.requestLock.lock()
                self.requestFrame = frame
                self.requestLock.unlock()
                try writeAll(response, to: connection)
            } catch {
                return
            }
        }
        worker = workItem
        DispatchQueue.global(qos: .utility).async(execute: workItem)
    }

    func takeRequestFrame() throws -> Data {
        let deadline = Date().addingTimeInterval(1)
        while Date() < deadline {
            requestLock.lock()
            let value = requestFrame
            requestLock.unlock()
            if let value { return value }
            Thread.sleep(forTimeInterval: 0.01)
        }
        throw TimeoutError()
    }

    func stop() {
        close(listener)
        unlink(socketURL.path)
        try? FileManager.default.removeItem(at: socketURL.deletingLastPathComponent())
    }
}

private func readFrame(from descriptor: Int32) throws -> Data {
    let prefix = try readExact(count: 4, from: descriptor)
    let length = prefix.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
    let payload = try readExact(count: Int(length), from: descriptor)
    return prefix + payload
}

private func readExact(count: Int, from descriptor: Int32) throws -> Data {
    var data = Data(count: count)
    try data.withUnsafeMutableBytes { rawBuffer in
        guard let base = rawBuffer.baseAddress else { throw POSIXError(.EIO) }
        var offset = 0
        while offset < count {
            let readCount = Darwin.read(descriptor, base.advanced(by: offset), count - offset)
            guard readCount > 0 else { throw POSIXError(.EIO) }
            offset += readCount
        }
    }
    return data
}

private func writeAll(_ data: Data, to descriptor: Int32) throws {
    try data.withUnsafeBytes { rawBuffer in
        guard let base = rawBuffer.baseAddress else { return }
        var offset = 0
        while offset < rawBuffer.count {
            let written = Darwin.write(descriptor, base.advanced(by: offset), rawBuffer.count - offset)
            guard written > 0 else { throw POSIXError(.EIO) }
            offset += written
        }
    }
}
