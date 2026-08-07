import Foundation
import HYUVPNInstallerCore
import HYUVPNMenuCore

private class MemoryCredentialStore: InstallerCredentialStoring {
    var values: [CredentialKey: String]
    var removed: [CredentialKey] = []
    var reads: [CredentialKey] = []
    init(_ values: [CredentialKey: String] = [:]) { self.values = values }
    func contains(_ key: CredentialKey) throws -> Bool { values[key] != nil }
    func read(_ key: CredentialKey) throws -> String? { reads.append(key); return values[key] }
    func write(_ value: String, for key: CredentialKey) throws { values[key] = value }
    func remove(_ key: CredentialKey) throws { values.removeValue(forKey: key); removed.append(key) }
}

private func expect(_ condition: @autoclosure () -> Bool, _ message: String) throws {
    if !condition() { throw HarnessError.failure(message) }
}

private enum HarnessError: Error, CustomStringConvertible { case failure(String); var description: String { switch self { case .failure(let message): return message } } }

private func credentialCollectionUsesContainsAndValidator() throws {
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
    try expect(prompts == [.password, .totpSeed], "only missing credentials prompted")
    try expect(store.reads.isEmpty, "existing credentials not decrypted for prompt decision")
    try expect(collected[.password] == "vpn-password", "password collected in memory")
    let normalized = try InstallerCredentialBootstrapper.collectMissingFinalCredentials(store: MemoryCredentialStore([.username: "retained", .password: "retained"])) { key in
        try expect(key == .totpSeed, "only missing totp prompted for normalization")
        return "jbsw y3dp-ehpk 3pxp"
    }
    try expect(normalized[.totpSeed] == "JBSWY3DPEHPK3PXP", "TOTP collected as validator-normalized value")
    do {
        _ = try InstallerCredentialBootstrapper.collectMissingFinalCredentials(store: MemoryCredentialStore([:])) { key in key == .totpSeed ? "123456" : "x" }
        throw HarnessError.failure("invalid TOTP accepted")
    } catch InstallerCoreError.invalidInput { }
}

private final class FailingWriteStore: MemoryCredentialStore {
    override func write(_ value: String, for key: CredentialKey) throws {
        if key == .password { throw InstallerCoreError.commandFailed(code: "WRITE_FAILED") }
        try super.write(value, for: key)
    }
}

private func writeRollbackOnlyNewKeys() throws {
    let store = FailingWriteStore([.totpSeed: "retained-totp"])
    do {
        _ = try InstallerCredentialBootstrapper.writeCollectedCredentials(store: store, collected: [.username: "new-user", .password: "new-password"])
        throw HarnessError.failure("write failure not thrown")
    } catch InstallerCoreError.commandFailed { }
    try expect(store.removed == [.username], "only newly-created key rolled back")
    try expect(store.values[.totpSeed] == "retained-totp", "pre-existing key retained")
}

private func activationFailureCleanupOnlyWrittenKeys() throws {
    let store = MemoryCredentialStore([.username: "existing-user", .password: "new-password", .totpSeed: "new-totp"])
    try InstallerCredentialBootstrapper.cleanupWrittenCredentialsAfterActivationFailure(store: store, writtenKeys: [.password, .totpSeed])
    try expect(store.values[.username] == "existing-user", "activation cleanup keeps existing username")
    try expect(store.values[.password] == nil && store.values[.totpSeed] == nil, "activation cleanup removes written keys")
    try expect(store.removed == [.password, .totpSeed], "activation cleanup removes only written keys")
}

private func privilegedArgvAndSingleAuthorization() throws {
    let argv = try RootAdminInvocation.makeInstallArgv(
        identity: ConsoleIdentity(user: "alice", uid: "501"), installerDir: "/installer", payload: "/payload", manifest: "/payload/manifest.json", stage: "/stage",
        stageManifestSHA256: String(repeating: "a", count: 64), packageManifestSHA256: String(repeating: "b", count: 64), epoch: 1790000000
    )
    try expect(argv.prefix(4) == ["/usr/bin/env", "SUDO_USER=alice", "SUDO_UID=501", "/bin/zsh"], "sudo identity injected")
    try expect(!argv.joined(separator: " ").contains("vpn-password"), "no secret in privileged argv")
    let store = MemoryCredentialStore([.username: "created-user", .totpSeed: "retained-totp"])
    var calls = 0
    do {
        try RootAdminAuthorizer.authorizeOnce(argv: argv, newlyCreatedKeys: [.username], store: store) { _ in calls += 1; throw InstallerCoreError.rootAuthorizationOrTransactionFailed }
        throw HarnessError.failure("authorization failure not thrown")
    } catch InstallerCoreError.rootAuthorizationOrTransactionFailed { }
    try expect(calls == 1, "graphical authorization called exactly once")
    try expect(store.removed == [.username], "root failure rolls back only newly-created keys")
}

do {
    try credentialCollectionUsesContainsAndValidator()
    try writeRollbackOnlyNewKeys()
    try activationFailureCleanupOnlyWrittenKeys()
    try privilegedArgvAndSingleAuthorization()
    print("HARNESS PASS hyu-vpn-installer-harness")
} catch {
    print("HARNESS FAIL \(error)")
    exit(1)
}
