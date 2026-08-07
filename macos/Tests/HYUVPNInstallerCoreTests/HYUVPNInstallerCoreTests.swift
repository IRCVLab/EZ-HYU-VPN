import Testing
import HYUVPNInstallerCore
import HYUVPNMenuCore

private class MemoryCredentialStore: InstallerCredentialStoring {
    var values: [CredentialKey: String]
    var removed: [CredentialKey] = []
    var writes: [(CredentialKey, String)] = []
    var reads: [CredentialKey] = []
    init(_ values: [CredentialKey: String] = [:]) { self.values = values }
    func contains(_ key: CredentialKey) throws -> Bool { values[key] != nil }
    func read(_ key: CredentialKey) throws -> String? { reads.append(key); return values[key] }
    func write(_ value: String, for key: CredentialKey) throws { values[key] = value; writes.append((key, value)) }
    func remove(_ key: CredentialKey) throws { values.removeValue(forKey: key); removed.append(key) }
}

@Suite struct HYUVPNInstallerCoreTests {
    @Test func credentialBootstrapCollectsOnlyMissingFinalCredentialsAndUsesValidator() throws {
        let store = MemoryCredentialStore([.username: "retained-user"])
        var prompts: [CredentialKey] = []
        let collected = try InstallerCredentialBootstrapper.collectMissingFinalCredentials(store: store) { key in
            prompts.append(key)
            switch key {
            case .username: return "new-user"
            case .password: return "vpn-password"
            case .totpSeed: return "JBSWY3DPEHPK3PXP"
            }
        }
        #expect(Set(collected.keys) == Set([.password, .totpSeed]))
        #expect(prompts == [.password, .totpSeed])
        #expect(store.reads.isEmpty)
        #expect(store.values[.username] == "retained-user")
        #expect(store.values[.password] == nil)
        #expect(collected[.password] == "vpn-password")
        #expect(collected[.totpSeed] == "JBSWY3DPEHPK3PXP")

        #expect(throws: InstallerCoreError.self) {
            _ = try InstallerCredentialBootstrapper.collectMissingFinalCredentials(store: MemoryCredentialStore([:])) { key in
                key == .totpSeed ? "123456" : "x"
            }
        }
    }


    @Test func collectedCredentialWriteRollsBackPartialNewKeysOnLaterFailure() throws {
        final class FailingWriteStore: MemoryCredentialStore {
            override func write(_ value: String, for key: CredentialKey) throws {
                if key == .password { throw InstallerCoreError.commandFailed(code: "WRITE_FAILED") }
                try super.write(value, for: key)
            }
        }
        let store = FailingWriteStore([.totpSeed: "retained-totp"])
        #expect(throws: InstallerCoreError.self) {
            _ = try InstallerCredentialBootstrapper.writeCollectedCredentials(store: store, collected: [.username: "new-user", .password: "new-password"])
        }
        #expect(store.removed == [.username])
        #expect(store.values[.username] == nil)
        #expect(store.values[.totpSeed] == "retained-totp")
    }


    @Test func credentialCollectionUsesValidatorNormalizedTOTPValue() throws {
        let store = MemoryCredentialStore([.username: "retained-user", .password: "retained-password"])
        let collected = try InstallerCredentialBootstrapper.collectMissingFinalCredentials(store: store) { key in
            #expect(key == .totpSeed)
            return "jbsw y3dp-ehpk 3pxp"
        }
        #expect(collected[.totpSeed] == "JBSWY3DPEHPK3PXP")
    }

    @Test func activationFailureCleanupRemovesOnlyNewlyWrittenCredentials() throws {
        let store = MemoryCredentialStore([.username: "existing-user", .password: "new-password", .totpSeed: "new-totp"])
        let cleanup = InstallerCredentialBootstrapper.cleanupWrittenCredentialsAfterActivationFailure(store: store, writtenKeys: [CredentialKey.password, CredentialKey.totpSeed])
        #expect(cleanup == .complete)
        #expect(store.values[.username] == "existing-user")
        #expect(store.values[.password] == nil)
        #expect(store.values[.totpSeed] == nil)
        #expect(store.removed == [.password, .totpSeed])
    }


    @Test func activationCleanupAttemptsEveryWrittenKeyAndReportsIncomplete() throws {
        final class FailingFirstRemoveStore: MemoryCredentialStore {
            override func remove(_ key: CredentialKey) throws {
                removed.append(key)
                if key == .password { throw InstallerCoreError.commandFailed(code: "REMOVE_FAILED") }
                values.removeValue(forKey: key)
            }
        }
        let store = FailingFirstRemoveStore([.username: "existing", .password: "new-password", .totpSeed: "new-totp"])
        let result = InstallerCredentialBootstrapper.cleanupWrittenCredentialsAfterActivationFailure(store: store, writtenKeys: [.password, .totpSeed])
        #expect(result == .incomplete)
        #expect(store.removed == [.password, .totpSeed])
        #expect(store.values[.username] == "existing")
        #expect(store.values[.totpSeed] == nil)
    }

    @Test func activationWarningKeepsCredentialsAfterServiceStartedButMenuStartFails() throws {
        #expect(InstallerActivationPolicy.classify(serviceStarted: true, failedCode: "MENU_OPEN_FAILED") == .installedWithMenuStartWarning(code: "MENU_OPEN_FAILED"))
        #expect(InstallerActivationPolicy.classify(serviceStarted: true, failedCode: "MENU_SINGLE_PROCESS_FAILED") == .installedWithMenuStartWarning(code: "MENU_SINGLE_PROCESS_FAILED"))
        #expect(InstallerActivationPolicy.classify(serviceStarted: false, failedCode: "SERVICE_KICKSTART_FAILED") == .fatalCleanupCredentials(code: "SERVICE_KICKSTART_FAILED"))
    }

    @Test func privilegedArgvInjectsConsoleSudoIdentityAndNoSecrets() throws {
        let argv = try RootAdminInvocation.makeInstallArgv(
            identity: ConsoleIdentity(user: "alice", uid: "501"),
            installerDir: "/Volumes/HYU VPN/installer",
            payload: "/Volumes/HYU VPN",
            manifest: "/Volumes/HYU VPN/manifest.json",
            stage: "/var/folders/stage",
            stageManifestSHA256: String(repeating: "a", count: 64),
            packageManifestSHA256: String(repeating: "b", count: 64),
            epoch: 1790000000
        )
        #expect(argv.prefix(4) == ["/usr/bin/env", "SUDO_USER=alice", "SUDO_UID=501", "/bin/zsh"])
        #expect(argv.contains("--administrator-phase"))
        #expect(argv.contains("install"))
        #expect(argv.contains("--live-install"))
        #expect(argv.contains("hyu-install-mutation-1790000000"))
        #expect(!argv.joined(separator: " ").contains("vpn-password"))
        #expect(!argv.joined(separator: " ").contains("JBSWY3DPEHPK3PXP"))
        #expect(throws: InstallerCoreError.self) {
            _ = try RootAdminInvocation.makeInstallArgv(identity: ConsoleIdentity(user: "bad user", uid: "501"), installerDir: "/i", payload: "/p", manifest: "/m", stage: "/s", stageManifestSHA256: String(repeating: "a", count: 64), packageManifestSHA256: String(repeating: "b", count: 64), epoch: 1)
        }
    }

    @Test func rootAuthorizationRunsOnceAndRollsBackOnlyNewKeysOnFailure() throws {
        let store = MemoryCredentialStore([.username: "created-user", .password: "created-pass", .totpSeed: "retained-totp"])
        var calls: [[String]] = []
        let argv = ["/usr/bin/env", "SUDO_USER=alice", "SUDO_UID=501", "/bin/zsh", "root-admin.sh"]
        #expect(throws: InstallerCoreError.self) {
            try RootAdminAuthorizer.authorizeOnce(argv: argv, newlyCreatedKeys: [.username, .password], store: store) { authorizedArgv in
                calls.append(authorizedArgv)
                throw InstallerCoreError.rootAuthorizationOrTransactionFailed
            }
        }
        #expect(calls == [argv])
        #expect(store.removed == [.username, .password])
        #expect(store.values[.totpSeed] == "retained-totp")
    }

    @Test func commandErrorsAreSanitizedCodesOnly() {
        #expect(InstallerCoreError.commandFailed(code: "VERIFY_MANIFEST_FAILED").description == "HYU VPN installer command failed (VERIFY_MANIFEST_FAILED).")
        #expect(!InstallerCoreError.commandFailed(code: "VERIFY_MANIFEST_FAILED").description.contains("raw stderr secret"))
        #expect(InstallerCoreError.rootAuthorizationOrTransactionFailed.description == "INSTALL_FAILED_ROOT_AUTHORIZATION_OR_TRANSACTION")
    }
}
