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

package enum InstallerCredentialBootstrapper {
    private static let validFallbackUsername = "hyu-user"
    private static let validFallbackPassword = "hyu-password"
    private static let validFallbackTOTP = "JBSWY3DPEHPK3PXP"

    package static func collectMissingFinalCredentials(store: InstallerCredentialStoring, prompt: (CredentialKey) throws -> String) throws -> [CredentialKey: String] {
        var collected: [CredentialKey: String] = [:]
        if try !store.contains(.username) {
            let username = try prompt(.username)
            try validate(username: username, password: validFallbackPassword, totpSeed: validFallbackTOTP)
            collected[.username] = username
        }
        if try !store.contains(.password) {
            let password = try prompt(.password)
            try validate(username: validFallbackUsername, password: password, totpSeed: validFallbackTOTP)
            collected[.password] = password
        }
        if try !store.contains(.totpSeed) {
            let totpSeed = try prompt(.totpSeed)
            try validate(username: validFallbackUsername, password: validFallbackPassword, totpSeed: totpSeed)
            collected[.totpSeed] = totpSeed
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

    private static func validate(username: String, password: String, totpSeed: String) throws {
        do {
            _ = try CredentialValidator.validate(CredentialResetInput(username: username, password: password, passwordConfirmation: password, totpSeed: totpSeed, totpSeedConfirmation: totpSeed))
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

package enum RootAdminAuthorizer {
    package static func authorizeOnce(argv: [String], newlyCreatedKeys: [CredentialKey], store: InstallerCredentialStoring, authorize: ([String]) throws -> Void) throws {
        do {
            try authorize(argv)
        } catch {
            for key in newlyCreatedKeys { try? store.remove(key) }
            throw InstallerCoreError.rootAuthorizationOrTransactionFailed
        }
    }
}
