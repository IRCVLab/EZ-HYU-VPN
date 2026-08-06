import Foundation
import Darwin
import HYUVPNPrivilegedHelper

private func writeBestEffort(_ message: String, to descriptor: Int32) {
    _ = fcntl(descriptor, F_SETNOSIGPIPE, 1)
    let bytes = Array(message.utf8)
    bytes.withUnsafeBytes { raw in
        guard let base = raw.baseAddress else { return }
        var offset = 0
        while offset < raw.count {
            let count = Darwin.write(descriptor, base.advanced(by: offset), raw.count - offset)
            if count > 0 {
                offset += count
            } else if count < 0, errno == EINTR {
                continue
            } else {
                return
            }
        }
    }
}

@main struct HYUVPNCWrapperD {
    static func main() {
        do {
            try InstalledExecutionGuard.validateCurrentExecutable(allowedCanonicalPath: InstalledExecutionGuard.wrapperDaemonPath, hashManifestPath: InstalledExecutionGuard.wrapperDaemonHashManifestPath)
            let env = ProcessInfo.processInfo.environment
            guard let reason = env["reason"], let nonce = env["HYU_NONCE"] else { throw HelperError.badConfiguration }
            try NetworkWrapperRunner().run(reason: reason, nonce: nonce, environment: env, suppliedLedgerPath: env["HYU_SESSION_LEDGER"].map { URL(fileURLWithPath: $0) })
            if reason == "connect" {
                guard let tunnel = env["TUNDEV"], tunnel.range(of: "^utun[0-9]{1,8}$", options: .regularExpression) != nil else { throw HelperError.badConfiguration }
                writeBestEffort("hyu-vpnc-wrapperd-event: network configuration verified tunnel=\(tunnel)\n", to: STDOUT_FILENO)
            }
        } catch {
            writeBestEffort("hyu-vpnc-wrapperd: \(error)\n", to: STDERR_FILENO)
            exit(70)
        }
    }
}
