import Foundation
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
