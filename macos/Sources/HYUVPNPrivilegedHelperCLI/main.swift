import Foundation
import HYUVPNPrivilegedHelper

func fail(_ message: String) -> Never {
    if let data = (message + "\n").data(using: .utf8) { FileHandle.standardError.write(data) }
    exit(64)
}

do {
    try InstalledExecutionGuard.validateCurrentExecutable(allowedCanonicalPath: InstalledExecutionGuard.privilegedHelperPath)
    let command = try HelperCommand.parse(CommandLine.arguments)
    let metadata = SystemFileMetadataProvider()
    let config = try HelperConfiguration.production(metadata: metadata, validateRuntime: command == .start)
    var helper = PrivilegedHelper(
        configuration: config,
        metadata: metadata,
        process: SystemProcessController(),
        store: FileSessionStore(path: config.stateDirectory.appendingPathComponent("session.json")),
        lock: FileSessionLock(directory: config.stateDirectory),
        clock: SystemClock(),
        nonceGenerator: SecureNonceGenerator(),
        identity: InvocationIdentity.current()
    )
    let startRequest = command == .start ? try BoundedStartHeaderReader.read(from: FileHandleByteInput(.standardInput)) : nil
    let result = try helper.run(command: command, startRequest: startRequest)
    if command == .status, let document = result.statusDocument {
        print(try document.singleLineJSON())
    } else {
        print("{\"status\":\"\(result.status)\"}")
    }
} catch {
    fail("hyu-vpn-privileged-helper: \(error)")
}
