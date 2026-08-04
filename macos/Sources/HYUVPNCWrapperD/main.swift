import Foundation
import HYUVPNPrivilegedHelper

@main struct HYUVPNCWrapperD {
    static func main() {
        do {
            try InstalledExecutionGuard.validateCurrentExecutable(allowedCanonicalPath: InstalledExecutionGuard.wrapperDaemonPath, hashManifestPath: InstalledExecutionGuard.wrapperDaemonHashManifestPath)
            let env = ProcessInfo.processInfo.environment
            guard let reason = env["reason"], let nonce = env["HYU_NONCE"] else { throw HelperError.badConfiguration }
            try NetworkWrapperRunner().run(reason: reason, nonce: nonce, environment: env, suppliedLedgerPath: env["HYU_SESSION_LEDGER"].map { URL(fileURLWithPath: $0) })
        } catch {
            FileHandle.standardError.write(Data("hyu-vpnc-wrapperd: \(error)\n".utf8))
            exit(70)
        }
    }
}
