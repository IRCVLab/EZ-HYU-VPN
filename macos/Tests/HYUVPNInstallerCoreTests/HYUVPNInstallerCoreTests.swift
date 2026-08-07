import Foundation
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
    @Test func missingCredentialKeysPreserveFormOrderWithoutReadingSecrets() throws {
        let store = MemoryCredentialStore([.password: "retained-password"])
        #expect(try InstallerCredentialBootstrapper.missingCredentialKeys(store: store) == [.username, .totpSeed])
        #expect(store.reads.isEmpty)
    }

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


    @Test func rootAdminAppleScriptUsesFixedSourceAndPassesQuotedCommandAsArgv() throws {
        let rootArgv = try RootAdminInvocation.makeInstallArgv(
            identity: ConsoleIdentity(user: "alice", uid: "501"),
            installerDir: "/Volumes/HYU VPN/O'Brien \"Installer\"/back\\slash/installer",
            payload: "/Volumes/HYU VPN/O'Brien \"Payload\"/back\\slash",
            manifest: "/Volumes/HYU VPN/O'Brien \"Payload\"/back\\slash/manifest.json",
            stage: "/tmp/HYU stage/O'Brien \"Stage\"/back\\slash",
            stageManifestSHA256: String(repeating: "a", count: 64),
            packageManifestSHA256: String(repeating: "b", count: 64),
            epoch: 1790000000
        )
        let argv = RootAdminAuthorizationScript.makeOSAScriptArgv(rootArgv)
        #expect(argv.prefix(2) == ["/usr/bin/osascript", "-e"])
        #expect(argv.contains("on run argv"))
        #expect(argv.contains("do shell script (item 1 of argv) with administrator privileges"))
        #expect(argv.contains("end run"))
        #expect(argv.contains("--"))
        #expect(argv.last?.contains("O'\"'\"'Brien") == true)
        #expect(argv.last?.contains("\"Installer\"") == true)
        #expect(argv.last?.contains("back\\slash") == true)
        #expect(argv.dropLast().allSatisfy { !$0.contains("O'Brien") && !$0.contains("1790000000") })
        #expect(!argv.joined(separator: " ").contains("String(reflecting:"))
    }

    @Test func rootAdminHarmlessAppleScriptParserVariantExecutesQuotedCommandViaArgv() throws {
        let rootArgv = ["/bin/echo", "space value", "apostrophe'", "quote\"", "back\\slash"]
        let argv = RootAdminAuthorizationScript.makeParserTestOSAScriptArgv(rootArgv)
        let process = Process()
        process.executableURL = URL(fileURLWithPath: argv[0])
        process.arguments = Array(argv.dropFirst())
        let pipe = Pipe()
        process.standardOutput = pipe
        try process.run()
        process.waitUntilExit()
        let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        #expect(process.terminationStatus == 0)
        #expect(output == "space value apostrophe' quote\" back\\slash\n")
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


    @Test func rootAdminFailureOutputMapsKnownRetainedStateRepairFailureWithoutSecrets() throws {
        let rawOutput = """
        installed HYU VPN helper could not repair retained state
        username=shchoi00 password=super-secret totp=JBSWY3DPEHPK3PXP
        """
        #expect(RootAdminFailureClassifier.operationCode(exitStatus: 1, capturedOutput: rawOutput) == "RETAINED_STATE_REPAIR_FAILED")
        #expect(RootAdminFailureClassifier.sanitizedDiagnosticCode(exitStatus: 1, capturedOutput: rawOutput).contains("super-secret") == false)
        #expect(RootAdminFailureClassifier.sanitizedDiagnosticCode(exitStatus: 1, capturedOutput: rawOutput).contains("JBSWY3DPEHPK3PXP") == false)
    }

    @Test func rootAuthorizationPreservesMappedRootTransactionCodeAndStillRollsBackNewKeys() throws {
        let store = MemoryCredentialStore([.username: "created-user", .password: "created-pass", .totpSeed: "retained-totp"])
        let argv = ["/usr/bin/env", "SUDO_USER=alice", "SUDO_UID=501", "/bin/zsh", "root-admin.sh"]
        #expect(throws: InstallerCoreError.commandFailed(code: "RETAINED_STATE_REPAIR_FAILED")) {
            try RootAdminAuthorizer.authorizeOnce(argv: argv, newlyCreatedKeys: [.username, .password], store: store) { _ in
                throw InstallerCoreError.commandFailed(code: "RETAINED_STATE_REPAIR_FAILED")
            }
        }
        #expect(store.removed == [.username, .password])
        #expect(store.values[.totpSeed] == "retained-totp")
    }

    @Test func commandErrorsAreSanitizedCodesOnly() {
        #expect(InstallerCoreError.commandFailed(code: "VERIFY_MANIFEST_FAILED").description == "HYU VPN installer command failed (VERIFY_MANIFEST_FAILED).")
        #expect(!InstallerCoreError.commandFailed(code: "VERIFY_MANIFEST_FAILED").description.contains("raw stderr secret"))
        #expect(InstallerCoreError.rootAuthorizationOrTransactionFailed.description == "INSTALL_FAILED_ROOT_AUTHORIZATION_OR_TRANSACTION")
    }
}
