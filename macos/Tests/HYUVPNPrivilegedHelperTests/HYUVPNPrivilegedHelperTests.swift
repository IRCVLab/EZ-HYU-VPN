import Foundation
import Darwin
import Testing
@testable import HYUVPNPrivilegedHelper

@Suite struct CommandSurfaceTests {
    @Test func parserAllowsOnlyExactCommandsWithoutExtraArguments() throws {
        #expect(try HelperCommand.parse(["helper", "start"]) == .start)
        #expect(try HelperCommand.parse(["helper", "stop"]) == .stop)
        #expect(try HelperCommand.parse(["helper", "status"]) == .status)
        #expect(try HelperCommand.parse(["helper", "repair"]) == .repair)
        for argv in [["helper"], ["helper", "Start"], ["helper", "start", "user"], ["helper", "stop", "--pid", "1"], ["helper", "/bin/sh"]] {
            #expect(throws: (any Error).self) { try HelperCommand.parse(argv) }
        }
    }

    @Test func startReadsExactlyBoundedValidatedPrivateUsernameHeaderOnly() throws {
        let input = CountingByteInput(Array("HYU-Username: student.name-1@hanyang.ac.kr\n\npassword-bytes".utf8))
        let request = try BoundedStartHeaderReader.read(from: input)
        #expect(request.username == "student.name-1@hanyang.ac.kr")
        #expect(input.readCount == Array("HYU-Username: student.name-1@hanyang.ac.kr\n\n".utf8).count)
        #expect(input.remaining == Array("password-bytes".utf8))
        for bad in ["student.name-1@hanyang.ac.kr\n", "HYU-Username: \n\n", "HYU-Username: bad user\n\n", "HYU-Username: ../bad\n\n", "HYU-Username: " + String(repeating: "a", count: 129) + "\n\n", "HYU-Username: valid\nX-Override: /bin/sh\n\n", String(repeating: "A", count: 513)] {
            #expect(throws: (any Error).self) { try BoundedStartHeaderReader.read(from: CountingByteInput(Array(bad.utf8))) }
        }
    }

    @Test func startRequiresSudoUserAndConsoleUIDMatch() throws {
        try InvocationIdentity(effectiveUID: 0, sudoUID: 501, sudoUser: "alice", consoleUID: 501, sudoAccountUID: 501).validateStartAuthorization()
        #expect(throws: (any Error).self) { try InvocationIdentity(effectiveUID: 0, sudoUID: nil, sudoUser: "alice", consoleUID: 501, sudoAccountUID: 501).validateStartAuthorization() }
        #expect(throws: (any Error).self) { try InvocationIdentity(effectiveUID: 0, sudoUID: 502, sudoUser: "alice", consoleUID: 501, sudoAccountUID: 502).validateStartAuthorization() }
        #expect(throws: (any Error).self) { try InvocationIdentity(effectiveUID: 0, sudoUID: 501, sudoUser: "", consoleUID: 501, sudoAccountUID: nil).validateStartAuthorization() }
        #expect(throws: (any Error).self) { try InvocationIdentity(effectiveUID: 501, sudoUID: 501, sudoUser: "alice", consoleUID: 501, sudoAccountUID: 501).validateStartAuthorization() }
    }

    @Test func configurationRejectsOverridesSymlinksAndWritableParents() throws {
        let config = HelperConfiguration.testFixture()
        var fs = FakeMetadata.secure(paths: config.requiredSecurePaths.map(\.path) + ["/", "/rooted"])
        try config.validate(using: fs)
        #expect(config.portal == "secure.hanyang.ac.kr")
        fs.symlinks.insert(config.openConnectExecutable.path)
        #expect(throws: (any Error).self) { try config.validate(using: fs) }
        fs.symlinks.remove(config.openConnectExecutable.path)
        fs.modes["/rooted"] = 0o777
        #expect(throws: (any Error).self) { try config.validate(using: fs) }
        let override = HelperConfiguration(openConnectExecutable: URL(fileURLWithPath: "/tmp/openconnect"), vpncScript: config.vpncScript, hipWrapper: config.hipWrapper, stateDirectory: config.stateDirectory, ledgerDirectory: config.ledgerDirectory)
        #expect(throws: (any Error).self) { try override.validate(using: FakeMetadata.secure(paths: override.requiredSecurePaths.map(\.path) + ["/", "/tmp"])) }
    }
}

@Suite struct LifecycleTests {
    @Test func startBuildsFixedOpenConnectArgvWithUsernameFromHeaderAndInheritedPipes() throws {
        var harness = HelperHarness()
        let result = try harness.run(command: .start, stdin: Data("HYU-Username: alice@hanyang.ac.kr\n\n".utf8))
        #expect(result.status == .started)
        let spawn = try #require(harness.process.spawned)
        #expect(spawn.executable == harness.config.openConnectExecutable.path)
        #expect(spawn.argv.contains("--protocol=gp"))
        #expect(!spawn.argv.contains("--server=secure.hanyang.ac.kr"))
        #expect(spawn.argv.last == "secure.hanyang.ac.kr")
        #expect(spawn.argv.contains("--authgroup=HYU-ExternalGW-General"))
        #expect(spawn.argv.contains("--user=alice@hanyang.ac.kr"))
        #expect(spawn.argv.contains("--script=\(harness.config.vpncScript.path)"))
        #expect(spawn.argv.contains("--csd-wrapper=\(harness.config.hipWrapper.path)"))
        #expect(spawn.argv.contains("--csd-user=alice"))
        #expect(spawn.inheritStdin)
        #expect(spawn.inheritStdout)
        #expect(!spawn.usesShell)
        let record = try #require(harness.store.savedRecords.last)
        #expect(record.pid == 1200)
        #expect(record.processGroupID == 1200)
        #expect(record.processBirthTime == 42)
        #expect(record.consoleUID == 501)
        #expect(record.portal == "secure.hanyang.ac.kr")
        #expect(record.executableIdentity.path == harness.config.openConnectExecutable.path)
        #expect(!record.sessionNonce.isEmpty)
        #expect(!record.ledger.path.path.isEmpty)
        #expect(harness.lock.acquiredUIDs == [501])
        #expect(harness.store.record == nil)
        #expect(harness.lock.releasedUIDs == [501])
    }

    @Test func channelLossTerminatesVerifiedOwnedProcessGroupOnlyAfterRevalidation() throws {
        var harness = HelperHarness()
        harness.process.channelLossAfterSpawn = true
        harness.process.waitResults = [false, true]
        _ = try harness.run(command: .start, stdin: Data("HYU-Username: alice\n\n".utf8))
        #expect(harness.process.signals == [.termGroup(pgid: 1200), .killGroup(pgid: 1200)])
        #expect(harness.process.validations.count == 2)
        #expect(harness.store.record == nil)
        #expect(harness.lock.releasedUIDs == [501])
    }

    @Test func startCommitFailureNeverReturnsStartedAndPreservesRecordWhenTeardownFails() throws {
        var harness = HelperHarness()
        harness.process.commitError = HelperError.processMismatch
        harness.process.killError = HelperError.processMismatch
        #expect(throws: (any Error).self) { try harness.run(command: .start, stdin: Data("HYU-Username: alice\n\n".utf8)) }
        #expect(harness.store.record != nil)
        #expect(harness.lock.releasedUIDs == [501])
    }

    @Test func startFailureAfterLockReleasesLockAndDoesNotLeaveRecord() throws {
        var harness = HelperHarness()
        harness.process.spawnError = HelperError.processMismatch
        #expect(throws: (any Error).self) { try harness.run(command: .start, stdin: Data("HYU-Username: alice\n\n".utf8)) }
        #expect(harness.lock.acquiredUIDs == [501])
        #expect(harness.lock.releasedUIDs == [501])
        #expect(harness.store.record == nil)
        #expect(harness.process.signals.isEmpty)
    }

    @Test func stopUsesBoundedTermThenKillForVerifiedRecord() throws {
        var harness = HelperHarness()
        try harness.installRecord(pid: 2222, pgid: 3333, birth: 77, nonce: "nonce12345", executable: harness.config.openConnectExecutable.path)
        harness.process.liveIdentity = .matching(pid: 2222, pgid: 3333, birth: 77, executable: harness.config.openConnectExecutable.path)
        harness.process.waitResults = [false, true]
        let result = try harness.run(command: .stop)
        #expect(result.status == .stopped)
        #expect(harness.process.signals == [.termGroup(pgid: 3333), .killGroup(pgid: 3333)])
        #expect(harness.store.record == nil)
        #expect(harness.lock.releasedUIDs == [501])
    }

    @Test func stopRejectsUnrelatedPidAndAllReuseMismatchesWithoutSignaling() throws {
        for mutation in ReuseMutation.allCases {
            var harness = HelperHarness()
            try harness.installRecord(pid: 2222, pgid: 3333, birth: 77, nonce: "nonce12345", executable: harness.config.openConnectExecutable.path)
            harness.apply(mutation: mutation)
            #expect(throws: (any Error).self) { try harness.run(command: .stop) }
            #expect(harness.process.signals.isEmpty)
        }
    }

    @Test func fileSessionStoreRejectsUnknownRecordKeys() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("hyu-record-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let path = directory.appendingPathComponent("session.json")
        let json = """
        {"pid":2222,"processGroupID":3333,"processBirthTime":77,"sessionNonce":"nonce12345","consoleUID":501,"portal":"secure.hanyang.ac.kr","executableIdentity":{"path":"/rooted/openconnect","fileID":"file-1"},"launchTime":0,"ledger":{"path":"/rooted/ledger/nonce12345.ledger","nonce":"nonce12345"},"tunnelInterface":null,"unexpected":true}
        """
        try Data(json.utf8).write(to: path)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
        defer { try? FileManager.default.removeItem(at: directory) }
        #expect(throws: (any Error).self) { _ = try FileSessionStore(path: path).load() }
    }

    @Test func statusReturnsBoundedSingleLineJsonAfterIdentityVerification() throws {
        var harness = HelperHarness()
        let stopped = try harness.run(command: .status).statusDocument!
        #expect(stopped.state == "stopped")
        #expect(stopped.pid == nil)
        try harness.installRecord(pid: 2222, pgid: 3333, birth: 77, nonce: "nonce12345", executable: harness.config.openConnectExecutable.path, tunnel: "utun7")
        harness.process.liveIdentity = .matching(pid: 2222, pgid: 3333, birth: 77, executable: harness.config.openConnectExecutable.path)
        let running = try harness.run(command: .status).statusDocument!
        #expect(running.schema_version == 1)
        #expect(running.state == "running")
        #expect(running.pid == 2222)
        #expect(running.session_nonce == "nonce12345")
        #expect(running.tunnel_interface == "utun7")
        let line = try running.singleLineJSON()
        #expect(!line.contains("\n"))
        #expect(line.utf8.count <= 512)
        let decoded = try JSONDecoder().decode(HelperStatusDocument.self, from: Data(line.utf8))
        #expect(decoded == running)
    }

    @Test func stoppedStatusJsonPreservesTheExactRustProtocolKeySet() throws {
        var harness = HelperHarness()
        let stopped = try #require(try harness.run(command: .status).statusDocument)
        let line = try stopped.singleLineJSON()
        let object = try #require(JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])

        #expect(Set(object.keys) == ["schema_version", "state", "pid", "session_nonce", "tunnel_interface"])
        #expect(object["pid"] is NSNull)
        #expect(object["session_nonce"] is NSNull)
        #expect(object["tunnel_interface"] is NSNull)
    }

    @Test func statusFailsClosedToRepairRequiredOnIdentityMismatchAndRepairIsOpaque() throws {
        var harness = HelperHarness()
        try harness.installRecord(pid: 2222, pgid: 3333, birth: 77, nonce: "nonce12345", executable: harness.config.openConnectExecutable.path)
        harness.process.liveIdentity = nil
        let status = try harness.run(command: .status)
        #expect(status.status == .repairRequired)
        #expect(status.statusDocument?.state == "repair-required")
        let repair = try harness.run(command: .repair)
        #expect(repair.status == .stopped)
        #expect(repair.ledger?.nonce == "nonce12345")
        #expect(harness.ledgerCoordinator.repairedNonces == ["nonce12345"])
        #expect(harness.process.signals.isEmpty)
    }

    @Test func repairBlocksOnlyExactLiveIdentityAndRepairsAfterPidReuseMismatches() throws {
        for mutation in [ReuseMutation.pgidMismatch, .birthMismatch, .executableMismatch, .pidMismatch] {
            var harness = HelperHarness()
            try harness.installRecord(pid: 2222, pgid: 3333, birth: 77, nonce: "nonce12345", executable: harness.config.openConnectExecutable.path)
            harness.apply(mutation: mutation)
            let repair = try harness.run(command: .repair)
            #expect(repair.status == .stopped)
            #expect(harness.ledgerCoordinator.repairedNonces == ["nonce12345"])
            #expect(harness.store.record == nil)
            #expect(harness.process.signals.isEmpty)
        }
        var exact = HelperHarness()
        try exact.installRecord(pid: 2222, pgid: 3333, birth: 77, nonce: "nonce12345", executable: exact.config.openConnectExecutable.path)
        exact.process.liveIdentity = .matching(pid: 2222, pgid: 3333, birth: 77, executable: exact.config.openConnectExecutable.path)
        #expect(throws: (any Error).self) { _ = try exact.run(command: .repair) }
        #expect(exact.ledgerCoordinator.repairedNonces.isEmpty)
    }
}

@Suite struct SystemProcessControllerTests {
    @Test func realHarmlessChildHasKernelBirthTimeAndCanBeReapedByForegroundMonitor() throws {
        let process = SystemProcessController()
        let child = try process.prepareSpawn(SpawnRequest(executable: URL(fileURLWithPath: "/bin/sleep"), arguments: ["1"], inheritStdin: true, inheritStdout: true, usesShell: false))
        #expect(child.pid > 0)
        #expect(child.processGroupID == child.pid)
        #expect(child.birthTime > 0)
        try process.commitSpawn(child)
        let live = try process.liveIdentity(for: child.pid)
        #expect(live?.birthTime == child.birthTime)
        let record = SessionRecord(pid: child.pid, processGroupID: child.processGroupID, processBirthTime: child.birthTime, sessionNonce: "nonce12345", consoleUID: UInt32(getuid()), portal: "secure.hanyang.ac.kr", executableIdentity: ExecutableIdentity(path: live?.executablePath ?? "/bin/sleep", fileID: "unused"), launchTime: Date(), ledger: OpaqueLedger(path: URL(fileURLWithPath: "/tmp/ledger"), nonce: "nonce12345"))
        let outcome = try process.monitorForeground(record: record) { _ in throw HelperError.processMismatch }
        #expect(outcome == .exited(status: 0))
    }
}

private final class CountingByteInput: ByteInput {
    private let bytes: [UInt8]
    private var index = 0
    var readCount = 0
    init(_ bytes: [UInt8]) { self.bytes = bytes }
    var remaining: [UInt8] { Array(bytes.dropFirst(index)) }
    func readOneByte() throws -> UInt8? {
        guard index < bytes.count else { return nil }
        defer { index += 1; readCount += 1 }
        return bytes[index]
    }
}

private struct HelperHarness {
    var config = HelperConfiguration.testFixture()
    var metadata: FakeMetadata
    var process = FakeProcessController()
    var store = InMemorySessionStore()
    var lock = FakeSessionLock()
    var clock = FixedClock()
    var nonce = FixedNonceGenerator()
    var identity = InvocationIdentity(effectiveUID: 0, sudoUID: 501, sudoUser: "alice", consoleUID: 501, sudoAccountUID: 501)
    var ledgerCoordinator = FakeLedgerCoordinator()
    init() { metadata = FakeMetadata.secure(paths: config.requiredSecurePaths.map(\.path) + ["/", "/rooted"]) }
    mutating func run(command: HelperCommand, stdin: Data = Data()) throws -> HelperResult {
        var helper = PrivilegedHelper(configuration: config, metadata: metadata, process: process, store: store, lock: lock, clock: clock, nonceGenerator: nonce, identity: identity, ledgerCoordinator: ledgerCoordinator)
        let startRequest = command == .start ? try StartHeaderParser.parse(stdin) : nil
        let result = try helper.run(command: command, startRequest: startRequest)
        process = helper.process as! FakeProcessController
        store = helper.store as! InMemorySessionStore
        lock = helper.lock as! FakeSessionLock
        ledgerCoordinator = helper.ledgerCoordinator as! FakeLedgerCoordinator
        return result
    }
    mutating func installRecord(pid: Int32, pgid: Int32, birth: UInt64, nonce: String, executable: String, tunnel: String? = nil, ledgerPath: URL? = nil) throws {
        try store.save(SessionRecord(pid: pid, processGroupID: pgid, processBirthTime: birth, sessionNonce: nonce, consoleUID: 501, portal: config.portal, executableIdentity: ExecutableIdentity(path: executable, fileID: "file-1"), launchTime: Date(timeIntervalSince1970: 123), ledger: OpaqueLedger(path: ledgerPath ?? config.ledgerDirectory.appendingPathComponent("\(nonce).ledger"), nonce: nonce), tunnelInterface: tunnel))
    }
    mutating func apply(mutation: ReuseMutation) {
        switch mutation {
        case .missingProcess: process.liveIdentity = nil
        case .pidMismatch: process.liveIdentity = .matching(pid: 9999, pgid: 3333, birth: 77, executable: config.openConnectExecutable.path)
        case .pgidMismatch: process.liveIdentity = .matching(pid: 2222, pgid: 9999, birth: 77, executable: config.openConnectExecutable.path)
        case .birthMismatch: process.liveIdentity = .matching(pid: 2222, pgid: 3333, birth: 78, executable: config.openConnectExecutable.path)
        case .nonceMismatch: store.record?.sessionNonce = ""; process.liveIdentity = .matching(pid: 2222, pgid: 3333, birth: 77, executable: config.openConnectExecutable.path)
        case .executableMismatch: process.liveIdentity = .matching(pid: 2222, pgid: 3333, birth: 77, executable: "/bin/sleep")
        case .portalMismatch: store.record?.portal = "evil.example"; process.liveIdentity = .matching(pid: 2222, pgid: 3333, birth: 77, executable: config.openConnectExecutable.path)
        case .uidMismatch: store.record?.consoleUID = 502; process.liveIdentity = .matching(pid: 2222, pgid: 3333, birth: 77, executable: config.openConnectExecutable.path)
        }
    }
}

private enum ReuseMutation: CaseIterable { case missingProcess, pidMismatch, pgidMismatch, birthMismatch, nonceMismatch, executableMismatch, portalMismatch, uidMismatch }

private struct FakeMetadata: FileMetadataProviding {
    var owners: [String: UInt32] = [:]
    var modes: [String: mode_t] = [:]
    var symlinks = Set<String>()
    var identities: [String: String] = [:]
    static func secure(paths: [String]) -> FakeMetadata {
        var fake = FakeMetadata()
        for path in paths { fake.owners[path] = 0; fake.modes[path] = 0o755; fake.identities[path] = "file-1" }
        return fake
    }
    func metadata(for path: String) throws -> SecureFileMetadata {
        guard let owner = owners[path], let mode = modes[path] else { throw HelperError.insecurePath(path) }
        return SecureFileMetadata(ownerUID: owner, mode: mode, isSymlink: symlinks.contains(path), fileID: identities[path] ?? path)
    }
}

private final class InMemorySessionStore: SessionStoring {
    var record: SessionRecord?
    var savedRecords: [SessionRecord] = []
    func load() throws -> SessionRecord? { record }
    func save(_ record: SessionRecord) throws { self.record = record; savedRecords.append(record) }
    func remove() throws { record = nil }
}
private final class FakeSessionLock: SessionLocking {
    var acquiredUIDs: [UInt32] = []
    var releasedUIDs: [UInt32] = []
    func acquire(consoleUID: UInt32) throws { acquiredUIDs.append(consoleUID) }
    func release(consoleUID: UInt32) throws { releasedUIDs.append(consoleUID) }
}
private struct FixedClock: ClockProviding { func now() -> Date { Date(timeIntervalSince1970: 123) } }
private struct FixedNonceGenerator: NonceGenerating { func makeNonce() throws -> String { "nonce12345" } }

private final class FakeProcessController: ProcessControlling {
    struct Spawned { let executable: String; let argv: [String]; let inheritStdin: Bool; let inheritStdout: Bool; let usesShell: Bool; let environment: [String: String] }
    enum Signal: Equatable { case termGroup(pgid: Int32), killGroup(pgid: Int32) }
    var spawned: Spawned?
    var channelLossAfterSpawn = false
    var spawnError: Error?
    var commitError: Error?
    var killError: Error?
    var liveIdentity: LiveProcessIdentity?
    var signals: [Signal] = []
    var validations: [SessionRecord] = []
    var waitResults: [Bool] = []
    var signalGuardBegun = false
    var signalGuardEnded = false
    var injectSignalAfterCommit = false
    var monitorExitStatus: Int32 = 0
    func beginLifecycleSignalGuard() throws { signalGuardBegun = true }
    func endLifecycleSignalGuard() { signalGuardEnded = true }
    func prepareSpawn(_ request: SpawnRequest) throws -> SpawnedProcess {
        if let spawnError { throw spawnError }
        spawned = Spawned(executable: request.executable.path, argv: request.arguments, inheritStdin: request.inheritStdin, inheritStdout: request.inheritStdout, usesShell: request.usesShell, environment: request.environment)
        liveIdentity = .matching(pid: 1200, pgid: 1200, birth: 42, executable: request.executable.path)
        return SpawnedProcess(pid: 1200, processGroupID: 1200, birthTime: 42)
    }
    func commitSpawn(_ process: SpawnedProcess) throws { if let commitError { throw commitError }; if injectSignalAfterCommit { channelLossAfterSpawn = true } }
    func abortSpawn(_ process: SpawnedProcess) throws { try killProcessGroup(process.processGroupID) }
    func liveIdentity(for pid: Int32) throws -> LiveProcessIdentity? { liveIdentity }
    func terminateProcessGroup(_ pgid: Int32) throws { signals.append(.termGroup(pgid: pgid)) }
    func killProcessGroup(_ pgid: Int32) throws { signals.append(.killGroup(pgid: pgid)); if let killError { throw killError }; liveIdentity = nil }
    func waitForExit(pid: Int32, timeout: TimeInterval) throws -> Bool { waitResults.isEmpty ? false : waitResults.removeFirst() }
    func monitorForeground(record: SessionRecord, onChannelLoss: (SessionRecord) throws -> Void) throws -> MonitorOutcome { if channelLossAfterSpawn { try onChannelLoss(record); return .channelLoss }; return .exited(status: monitorExitStatus) }
    func validateBeforeSignal(_ record: SessionRecord) throws { validations.append(record) }
}


private final class FakeLedgerCoordinator: SessionLedgerCoordinating {
    var verifyResult: Error?
    var repairResult: Error?
    var verifiedNonces: [String] = []
    var repairedNonces: [String] = []
    func verifyTeardownComplete(record: SessionRecord) throws {
        verifiedNonces.append(record.sessionNonce)
        if let verifyResult { throw verifyResult }
    }
    func repair(record: SessionRecord, configuration: HelperConfiguration) throws {
        repairedNonces.append(record.sessionNonce)
        if let repairResult { throw repairResult }
    }
}
