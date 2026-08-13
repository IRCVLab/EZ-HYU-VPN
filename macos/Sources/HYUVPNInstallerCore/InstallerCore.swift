import Foundation
import CryptoKit
import HYUVPNMenuCore

package enum InstallerCoreError: Error, Equatable, CustomStringConvertible {
    case invalidInput(String)
    case commandFailed(code: String)
    case rootAuthorizationOrTransactionFailed

    package var description: String {
        switch self {
        case .invalidInput(let code): return code
        case .commandFailed(let code): return "HYU VPN installer command failed (\(code))."
        case .rootAuthorizationOrTransactionFailed: return "INSTALL_FAILED_ROOT_AUTHORIZATION_OR_TRANSACTION"
        }
    }
}

package protocol InstallerCredentialStoring: AnyObject {
    func contains(_ key: CredentialKey) throws -> Bool
    func read(_ key: CredentialKey) throws -> String?
    func write(_ value: String, for key: CredentialKey) throws
    func remove(_ key: CredentialKey) throws
}

package enum CredentialCleanupResult: Equatable, Sendable { case complete, incomplete }

package enum InstallerActivationDisposition: Equatable, Sendable {
    case installedWithMenuStartWarning(code: String)
    case fatalCleanupCredentials(code: String)
}

package enum InstallerActivationPolicy {
    package static func classify(serviceStarted: Bool, failedCode: String) -> InstallerActivationDisposition {
        if serviceStarted && ["OLD_MENU_TERM_FAILED", "OLD_MENU_KILL_FAILED", "OLD_MENU_STOP_TIMEOUT", "MENU_OPEN_FAILED", "MENU_SINGLE_PROCESS_FAILED"].contains(failedCode) {
            return .installedWithMenuStartWarning(code: failedCode)
        }
        return .fatalCleanupCredentials(code: failedCode)
    }
}

package enum InstallerAutomaticReconnectPolicy {
    package static func desiredAfterInstall(existingValue: Bool?) -> Bool {
        existingValue ?? true
    }
}

package enum InstallerCredentialBootstrapper {
    private static let validFallbackUsername = "hyu-user"
    private static let validFallbackPassword = "hyu-password"
    private static let validFallbackTOTP = "JBSWY3DPEHPK3PXP"

    package static func missingCredentialKeys(store: InstallerCredentialStoring) throws -> [CredentialKey] {
        try CredentialKey.allCases.filter { try !store.contains($0) }
    }

    package static func collectMissingFinalCredentials(store: InstallerCredentialStoring, prompt: (CredentialKey) throws -> String) throws -> [CredentialKey: String] {
        let missingKeys = try missingCredentialKeys(store: store)
        var values: [CredentialKey: String] = [:]
        for key in missingKeys {
            values[key] = try prompt(key)
        }
        return try validateCollectedCredentialValues(missingKeys: missingKeys, values: values)
    }

    package static func validateCollectedCredentialValues(missingKeys: [CredentialKey], values: [CredentialKey: String]) throws -> [CredentialKey: String] {
        guard Set(values.keys) == Set(missingKeys), Set(missingKeys).count == missingKeys.count else {
            throw InstallerCoreError.invalidInput("CREDENTIAL_FORM_VALUES_INVALID")
        }
        var collected: [CredentialKey: String] = [:]
        for key in missingKeys {
            guard let value = values[key] else { throw InstallerCoreError.invalidInput("CREDENTIAL_FORM_VALUES_INVALID") }
            switch key {
            case .username:
                collected[.username] = try validate(username: value, password: validFallbackPassword, totpSeed: validFallbackTOTP).username
            case .password:
                collected[.password] = try validate(username: validFallbackUsername, password: value, totpSeed: validFallbackTOTP).password
            case .totpSeed:
                guard let normalized = try validate(username: validFallbackUsername, password: validFallbackPassword, totpSeed: value).normalizedTOTPSeed else {
                    throw InstallerCoreError.invalidInput("TOTP_SEED_REQUIRED")
                }
                collected[.totpSeed] = normalized
            }
        }
        return collected
    }

    package static func writeCollectedCredentials(store: InstallerCredentialStoring, collected: [CredentialKey: String]) throws -> [CredentialKey] {
        var created: [CredentialKey] = []
        do {
            for key in CredentialKey.allCases where collected[key] != nil {
                try store.write(collected[key]!, for: key)
                created.append(key)
            }
            return created
        } catch {
            for key in created.reversed() { try? store.remove(key) }
            throw error
        }
    }

    package static func cleanupWrittenCredentialsAfterActivationFailure(store: InstallerCredentialStoring, writtenKeys: [CredentialKey]) -> CredentialCleanupResult {
        var complete = true
        for key in writtenKeys {
            do { try store.remove(key) } catch { complete = false }
        }
        return complete ? .complete : .incomplete
    }

    private static func validate(username: String, password: String, totpSeed: String) throws -> ValidatedCredentials {
        do {
            return try CredentialValidator.validate(CredentialResetInput(username: username, password: password, passwordConfirmation: password, totpSeed: totpSeed, totpSeedConfirmation: totpSeed))
        } catch let error as CredentialValidationError {
            throw InstallerCoreError.invalidInput(error.code)
        } catch {
            throw InstallerCoreError.invalidInput("CREDENTIAL_VALIDATION_FAILED")
        }
    }
}

package struct ConsoleIdentity: Equatable, Sendable {
    package let user: String
    package let uid: String
    package init(user: String, uid: String) { self.user = user; self.uid = uid }
}

package enum RootAdminInvocation {
    package static func makeInstallArgv(identity: ConsoleIdentity, installerDir: String, payload: String, manifest: String, stage: String, stageManifestSHA256: String, packageManifestSHA256: String, epoch: Int) throws -> [String] {
        guard isSafeIdentityToken(identity.user), identity.uid.range(of: #"^[0-9]+$"#, options: .regularExpression) != nil else {
            throw InstallerCoreError.commandFailed(code: "CONSOLE_IDENTITY_INVALID")
        }
        guard isSHA256(stageManifestSHA256), isSHA256(packageManifestSHA256) else {
            throw InstallerCoreError.commandFailed(code: "MANIFEST_DIGEST_INVALID")
        }
        return [
            "/usr/bin/env", "SUDO_USER=\(identity.user)", "SUDO_UID=\(identity.uid)",
            "/bin/zsh", "\(installerDir)/root-admin.sh", "--payload", payload, "--manifest", manifest,
            "--stage", stage, "--administrator-phase", "install", "--stage-manifest-sha256", stageManifestSHA256,
            "--package-manifest-sha256", packageManifestSHA256, "--live-install", "hyu-install-mutation-\(epoch)",
        ]
    }

    private static func isSafeIdentityToken(_ value: String) -> Bool {
        !value.isEmpty && value.count <= 64 && value.allSatisfy { $0.isLetter || $0.isNumber || $0 == "_" || $0 == "." || $0 == "-" }
    }

    private static func isSHA256(_ value: String) -> Bool {
        value.range(of: #"^[0-9a-f]{64}$"#, options: .regularExpression) != nil
    }
}

package enum RootAdminAuthorizationScript {
    private static let osascriptExecutable = "/usr/bin/osascript"
    private static let privilegedSource = [
        "on run argv",
        "do shell script (item 1 of argv) with administrator privileges",
        "end run",
    ]
    private static let parserTestSource = [
        "on run argv",
        "do shell script (item 1 of argv)",
        "end run",
    ]

    package static func makeOSAScriptArgv(_ commandArgv: [String]) -> [String] {
        makeOSAScriptArgv(source: privilegedSource, commandArgv: commandArgv)
    }

    package static func makeParserTestOSAScriptArgv(_ commandArgv: [String]) -> [String] {
        makeOSAScriptArgv(source: parserTestSource, commandArgv: commandArgv)
    }

    private static func makeOSAScriptArgv(source: [String], commandArgv: [String]) -> [String] {
        var argv = [osascriptExecutable]
        for line in source {
            argv.append("-e")
            argv.append(line)
        }
        argv.append("--")
        argv.append(commandArgv.map(posixShellQuoted).joined(separator: " "))
        return argv
    }

    private static func posixShellQuoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    }
}

package enum RootAdminFailureClassifier {
    private static let maxCapturedDiagnosticBytes = 8192

    package static func operationCode(exitStatus: Int32, capturedOutput: String) -> String {
        let bounded = String(capturedOutput.prefix(maxCapturedDiagnosticBytes))
        if bounded.localizedCaseInsensitiveContains("installed HYU VPN helper could not repair retained state") {
            return "RETAINED_STATE_REPAIR_FAILED"
        }
        if bounded.localizedCaseInsensitiveContains("recorded process did not match live process") {
            return "RETAINED_STATE_PROCESS_MISMATCH"
        }
        if bounded.localizedCaseInsensitiveContains("User canceled") || bounded.localizedCaseInsensitiveContains("user cancelled") {
            return "ADMIN_AUTHORIZATION_CANCELLED"
        }
        if bounded.localizedCaseInsensitiveContains("The user name or password was incorrect") {
            return "ADMIN_AUTHORIZATION_FAILED"
        }
        return "INSTALL_FAILED_ROOT_AUTHORIZATION_OR_TRANSACTION"
    }

    package static func sanitizedDiagnosticCode(exitStatus: Int32, capturedOutput: String) -> String {
        let code = operationCode(exitStatus: exitStatus, capturedOutput: capturedOutput)
        return "ROOT_TRANSACTION_EXIT_\(exitStatus)_\(code)"
    }
}

package enum RootAdminAuthorizer {
    package static func authorizeOnce(argv: [String], newlyCreatedKeys: [CredentialKey], store: InstallerCredentialStoring, authorize: ([String]) throws -> Void) throws {
        do {
            try authorize(argv)
        } catch let error as InstallerCoreError {
            for key in newlyCreatedKeys { try? store.remove(key) }
            switch error {
            case .commandFailed(let code):
                throw InstallerCoreError.commandFailed(code: code)
            case .invalidInput, .rootAuthorizationOrTransactionFailed:
                throw InstallerCoreError.rootAuthorizationOrTransactionFailed
            }
        } catch {
            for key in newlyCreatedKeys { try? store.remove(key) }
            throw InstallerCoreError.rootAuthorizationOrTransactionFailed
        }
    }
}

package enum NativePayloadManifest {
    private static let maxManifestBytes = 2 * 1024 * 1024

    package static func verify(payload: URL, manifest: URL) throws {
        let expected = try readManifest(manifest)
        let actual = try buildManifest(payload: payload)
        guard expected == actual else { throw InstallerCoreError.commandFailed(code: "VERIFY_MANIFEST_FAILED") }
    }

    package static func stage(payload: URL, manifest: URL, stage: URL) throws {
        try verify(payload: payload, manifest: manifest)
        let fm = FileManager.default
        if fm.fileExists(atPath: stage.path) { try fm.removeItem(at: stage) }
        try fm.createDirectory(at: stage, withIntermediateDirectories: true)
        try setMode(stage, 0o700)
        for rel in ["runtime/bin", "runtime/lib", "runtime/vpnc", "bin", "config/launchd"] {
            try fm.createDirectory(at: stage.appendingPathComponent(rel, isDirectory: true), withIntermediateDirectories: true)
        }
        let required: [(String, String, Int16)] = [
            ("runtime/openconnect/bin/openconnect", "runtime/bin/openconnect", 0o755),
            ("runtime/oathtool", "runtime/bin/oathtool", 0o755),
            ("runtime/gp-hip-report", "runtime/gp-hip-report", 0o755),
            ("runtime/vpnc/hyu-vpnc-wrapper", "runtime/vpnc/hyu-vpnc-wrapper", 0o755),
            ("runtime/vpnc/hyu-vpnc-wrapperd", "runtime/vpnc/hyu-vpnc-wrapperd", 0o755),
            ("runtime/vpnc/vpnc-script", "runtime/vpnc/vpnc-script", 0o755),
            ("com.hyu.vpn.helper", "com.hyu.vpn.helper", 0o755),
            ("hyu-vpn-macos-service", "bin/hyu-vpn-macos-service", 0o755),
            ("launchd/com.hyu.vpn.service.plist.in", "config/launchd/com.hyu.vpn.service.plist.in", 0o644),
        ]
        for (src, dst, mode) in required { try copyFile(payload.appendingPathComponent(src), stage.appendingPathComponent(dst), mode: mode) }
        let runtimeLib = payload.appendingPathComponent("runtime/openconnect/lib", isDirectory: true)
        if fm.fileExists(atPath: runtimeLib.path) { try copyTree(runtimeLib, stage.appendingPathComponent("runtime/lib", isDirectory: true), fileMode: 0o755) }
        try copyTree(payload.appendingPathComponent("HYU VPN.app", isDirectory: true), stage.appendingPathComponent("HYU VPN.app", isDirectory: true), fileMode: 0o644)
        try setMode(stage.appendingPathComponent("HYU VPN.app/Contents/MacOS/HYUVPNMenuApp"), 0o755)
        try setMode(stage.appendingPathComponent("HYU VPN.app/Contents/MacOS/HYUVPNCredentialReader"), 0o755)
        try "hyu-vpn-installer-stage\n".write(to: stage.appendingPathComponent(".hyu-vpn-dry-run-root"), atomically: true, encoding: .utf8)
        try writeManifest(for: stage)
    }

    private static func readManifest(_ url: URL) throws -> [String: ManifestEntry] {
        let values = try url.resourceValues(forKeys: [.isSymbolicLinkKey, .fileSizeKey])
        guard values.isSymbolicLink != true, let size = values.fileSize, size <= maxManifestBytes else { throw InstallerCoreError.commandFailed(code: "VERIFY_MANIFEST_FAILED") }
        let data = try Data(contentsOf: url)
        guard data.count <= maxManifestBytes else { throw InstallerCoreError.commandFailed(code: "VERIFY_MANIFEST_FAILED") }
        let top = try JSONSerialization.jsonObject(with: data)
        guard let object = top as? [String: Any], object["schema"] as? Int == 1, let files = object["files"] as? [String: Any] else { throw InstallerCoreError.commandFailed(code: "VERIFY_MANIFEST_FAILED") }
        var out: [String: ManifestEntry] = [:]
        for (rel, raw) in files {
            guard let info = raw as? [String: Any], let sha = info["sha256"] as? String, let mode = info["mode"] as? String, let size = info["size"] as? Int else { throw InstallerCoreError.commandFailed(code: "VERIFY_MANIFEST_FAILED") }
            out[rel] = ManifestEntry(sha256: sha, mode: mode, size: size)
        }
        return out
    }

    private static func buildManifest(payload: URL) throws -> [String: ManifestEntry] {
        var entries: [String: ManifestEntry] = [:]
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(at: payload, includingPropertiesForKeys: [.isRegularFileKey, .isDirectoryKey, .isSymbolicLinkKey, .fileSizeKey], options: []) else { throw InstallerCoreError.commandFailed(code: "VERIFY_MANIFEST_FAILED") }
        for case let url as URL in enumerator {
            let rel = try relativePath(root: payload, child: url)
            let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isDirectoryKey, .isSymbolicLinkKey, .fileSizeKey])
            if values.isSymbolicLink == true { throw InstallerCoreError.commandFailed(code: "VERIFY_MANIFEST_FAILED") }
            if values.isDirectory == true { continue }
            guard values.isRegularFile == true else { throw InstallerCoreError.commandFailed(code: "VERIFY_MANIFEST_FAILED") }
            if rel == "manifest.json" { continue }
            entries[rel] = ManifestEntry(sha256: try sha256(url), mode: try modeString(url), size: values.fileSize ?? 0)
        }
        return entries
    }

    private static func writeManifest(for root: URL) throws {
        let entries = try buildManifest(payload: root)
        var files: [String: Any] = [:]
        for key in entries.keys.sorted() { let e = entries[key]!; files[key] = ["mode": e.mode, "sha256": e.sha256, "size": e.size] }
        let data = try JSONSerialization.data(withJSONObject: ["schema": 1, "files": files], options: [.prettyPrinted, .sortedKeys])
        try data.write(to: root.appendingPathComponent("manifest.json"), options: .atomic)
    }

    private static func copyFile(_ src: URL, _ dst: URL, mode: Int16) throws {
        let fm = FileManager.default
        guard fm.fileExists(atPath: src.path) else { throw InstallerCoreError.commandFailed(code: "STAGE_PAYLOAD_FAILED") }
        try fm.createDirectory(at: dst.deletingLastPathComponent(), withIntermediateDirectories: true)
        if fm.fileExists(atPath: dst.path) { try fm.removeItem(at: dst) }
        try fm.copyItem(at: src, to: dst)
        try setMode(dst, mode)
    }

    private static func copyTree(_ src: URL, _ dst: URL, fileMode: Int16) throws {
        let fm = FileManager.default
        if fm.fileExists(atPath: dst.path) { try fm.removeItem(at: dst) }
        try fm.copyItem(at: src, to: dst)
        guard let enumerator = fm.enumerator(at: dst, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey]) else { return }
        for case let url as URL in enumerator {
            let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            if values.isSymbolicLink == true { throw InstallerCoreError.commandFailed(code: "STAGE_PAYLOAD_FAILED") }
            if values.isRegularFile == true { try setMode(url, fileMode) }
        }
    }

    private static func sha256(_ url: URL) throws -> String {
        let data = try Data(contentsOf: url)
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private static func setMode(_ url: URL, _ mode: Int16) throws { try FileManager.default.setAttributes([.posixPermissions: NSNumber(value: mode)], ofItemAtPath: url.path) }
    private static func modeString(_ url: URL) throws -> String { let attrs = try FileManager.default.attributesOfItem(atPath: url.path); let mode = (attrs[.posixPermissions] as? NSNumber)?.intValue ?? 0; return String(format: "%04o", mode & 0o7777) }
    private static func relativePath(root: URL, child: URL) throws -> String {
        let canonicalRoot = root.resolvingSymlinksInPath().standardizedFileURL.path
        let canonicalChild = child.resolvingSymlinksInPath().standardizedFileURL.path
        let prefix = canonicalRoot + "/"
        guard canonicalChild.hasPrefix(prefix) else { throw InstallerCoreError.commandFailed(code: "VERIFY_MANIFEST_FAILED") }
        return String(canonicalChild.dropFirst(prefix.count))
    }

    private struct ManifestEntry: Equatable { let sha256: String; let mode: String; let size: Int }
}
