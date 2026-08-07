import Foundation
import CryptoKit
import ServiceManagement
import Darwin
import HYUVPNMenuCore

package final class EncryptedCredentialStore: CredentialStore {
    enum AdapterError: Error { case storageFailure }

    private struct Document: Codable {
        let schemaVersion: Int
        var values: [String: String]

        enum CodingKeys: String, CodingKey {
            case schemaVersion = "schema_version"
            case values
        }
    }

    private static let maximumFileBytes = 64 * 1024
    private let root: URL
    private var keyURL: URL { root.appendingPathComponent("credentials.key") }
    private var encryptedURL: URL { root.appendingPathComponent("credentials.enc") }
    private var lockURL: URL { root.appendingPathComponent("credentials.lock") }

    package init(root: URL = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support/hyu-openconnect", isDirectory: true)) {
        self.root = root
    }

    package func contains(_ key: CredentialKey) throws -> Bool {
        try read(key) != nil
    }

    package func read(_ key: CredentialKey) throws -> String? {
        try withLock {
            guard let encrypted = try readSecureFile(encryptedURL) else { return nil }
            guard let keyData = try readSecureFile(keyURL), keyData.count == 32 else { throw AdapterError.storageFailure }
            return try decrypt(encrypted, using: SymmetricKey(data: keyData)).values[key.rawValue]
        }
    }

    package func write(_ value: String, for key: CredentialKey) throws {
        try withLock {
            let symmetricKey = try loadOrCreateKey()
            var document: Document
            if let encrypted = try readSecureFile(encryptedURL) {
                document = try decrypt(encrypted, using: symmetricKey)
            } else {
                document = Document(schemaVersion: 1, values: [:])
            }
            document.values[key.rawValue] = value
            try writeSecureFile(try encrypt(document, using: symmetricKey), to: encryptedURL)
        }
    }

    package func remove(_ key: CredentialKey) throws {
        try withLock {
            guard let encrypted = try readSecureFile(encryptedURL) else { return }
            guard let keyData = try readSecureFile(keyURL), keyData.count == 32 else { throw AdapterError.storageFailure }
            let symmetricKey = SymmetricKey(data: keyData)
            var document = try decrypt(encrypted, using: symmetricKey)
            document.values.removeValue(forKey: key.rawValue)
            try writeSecureFile(try encrypt(document, using: symmetricKey), to: encryptedURL)
        }
    }

    private func loadOrCreateKey() throws -> SymmetricKey {
        if let data = try readSecureFile(keyURL) {
            guard data.count == 32 else { throw AdapterError.storageFailure }
            return SymmetricKey(data: data)
        }
        let key = SymmetricKey(size: .bits256)
        let data = key.withUnsafeBytes { Data($0) }
        try writeSecureFile(data, to: keyURL)
        return key
    }

    private func encrypt(_ document: Document, using key: SymmetricKey) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let plaintext = try encoder.encode(document)
        guard let combined = try AES.GCM.seal(plaintext, using: key).combined else { throw AdapterError.storageFailure }
        return combined
    }

    private func decrypt(_ encrypted: Data, using key: SymmetricKey) throws -> Document {
        do {
            let plaintext = try AES.GCM.open(AES.GCM.SealedBox(combined: encrypted), using: key)
            let document = try JSONDecoder().decode(Document.self, from: plaintext)
            guard document.schemaVersion == 1,
                  Set(document.values.keys).isSubset(of: Set(CredentialKey.allCases.map(\.rawValue))) else {
                throw AdapterError.storageFailure
            }
            return document
        } catch {
            throw AdapterError.storageFailure
        }
    }

    private func withLock<T>(_ operation: () throws -> T) throws -> T {
        try ensureRootDirectory()
        let descriptor = open(lockURL.path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw AdapterError.storageFailure }
        defer { close(descriptor) }
        guard fchmod(descriptor, 0o600) == 0 else { throw AdapterError.storageFailure }
        try verifyDescriptor(descriptor, directory: false, mode: 0o600)
        guard flock(descriptor, LOCK_EX) == 0 else { throw AdapterError.storageFailure }
        defer { _ = flock(descriptor, LOCK_UN) }
        return try operation()
    }

    private func ensureRootDirectory() throws {
        let status = mkdir(root.path, 0o700)
        guard status == 0 || errno == EEXIST else { throw AdapterError.storageFailure }
        let descriptor = open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw AdapterError.storageFailure }
        defer { close(descriptor) }
        try verifyDescriptor(descriptor, directory: true, mode: 0o700)
    }

    private func readSecureFile(_ url: URL) throws -> Data? {
        let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if descriptor < 0 {
            if errno == ENOENT { return nil }
            throw AdapterError.storageFailure
        }
        defer { close(descriptor) }
        try verifyDescriptor(descriptor, directory: false, mode: 0o600)

        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = buffer.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
            if count == 0 { break }
            guard count > 0 else {
                if errno == EINTR { continue }
                throw AdapterError.storageFailure
            }
            guard result.count + count <= Self.maximumFileBytes else { throw AdapterError.storageFailure }
            result.append(contentsOf: buffer.prefix(count))
        }
        return result
    }

    private func writeSecureFile(_ data: Data, to url: URL) throws {
        guard data.count <= Self.maximumFileBytes else { throw AdapterError.storageFailure }
        try validateExistingFileIfPresent(url)
        let temporary = root.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp")
        let descriptor = open(temporary.path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw AdapterError.storageFailure }
        var committed = false
        defer {
            close(descriptor)
            if !committed { _ = unlink(temporary.path) }
        }
        guard fchmod(descriptor, 0o600) == 0 else { throw AdapterError.storageFailure }
        var offset = 0
        try data.withUnsafeBytes { bytes in
            while offset < bytes.count {
                let written = Darwin.write(descriptor, bytes.baseAddress?.advanced(by: offset), bytes.count - offset)
                guard written > 0 else {
                    if errno == EINTR { continue }
                    throw AdapterError.storageFailure
                }
                offset += written
            }
        }
        guard fsync(descriptor) == 0, rename(temporary.path, url.path) == 0 else { throw AdapterError.storageFailure }
        committed = true
        let directoryDescriptor = open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        if directoryDescriptor >= 0 {
            _ = fsync(directoryDescriptor)
            close(directoryDescriptor)
        }
    }

    private func validateExistingFileIfPresent(_ url: URL) throws {
        var info = stat()
        if lstat(url.path, &info) != 0 {
            if errno == ENOENT { return }
            throw AdapterError.storageFailure
        }
        guard FileTOTPMetadataPolicy.isSafe(ownerUID: info.st_uid, mode: info.st_mode, directory: false, expectedMode: 0o600) else {
            throw AdapterError.storageFailure
        }
    }

    private func verifyDescriptor(_ descriptor: Int32, directory: Bool, mode: mode_t) throws {
        var info = stat()
        guard fstat(descriptor, &info) == 0,
              FileTOTPMetadataPolicy.isSafe(ownerUID: info.st_uid, mode: info.st_mode, directory: directory, expectedMode: mode) else {
            throw AdapterError.storageFailure
        }
    }
}

package enum CredentialReaderCommand {
    private static let services: [String: CredentialKey] = [
        "gp-vpn-username": .username,
        "gp-vpn-password": .password,
        "gp-vpn-totp": .totpSeed,
    ]

    package static func run(arguments: [String], store: CredentialStore, output: (String) -> Void) -> Int32 {
        precondition(Set(Self.services.values) == Set(CredentialKey.allCases))
        guard arguments.count == 1, let key = services[arguments[0]] else { return 64 }
        do {
            guard let value = try store.read(key), !value.isEmpty else { return 1 }
            output(value)
            return 0
        } catch {
            return 1
        }
    }
}

package enum SystemCredentialBootstrap {
    package static func currentID() -> String? {
        try? EncryptedCredentialStore().read(.username)
    }
}

package final class MenuTOTPProvider {
    private let store: any CredentialStore

    package init(store: any CredentialStore = EncryptedCredentialStore()) {
        self.store = store
    }

    package func snapshot(at date: Date = Date()) -> TOTPDisplaySnapshot? {
        guard let seed = try? store.read(.totpSeed), !seed.isEmpty else { return nil }
        return try? TOTPDisplayGenerator.snapshot(seed: seed, at: date)
    }
}

package enum OTPClipboardPolicy {
    package static func copyableCode(_ value: String) -> String? {
        let bytes = Array(value.utf8)
        guard bytes.count == 6, bytes.allSatisfy({ (0x30...0x39).contains($0) }) else { return nil }
        return value
    }
}

package enum FileTOTPMetadataPolicy {
    package static func isSafe(ownerUID: uid_t, mode: mode_t, directory: Bool, expectedMode: mode_t, currentUID: uid_t = getuid()) -> Bool {
        guard ownerUID == currentUID else { return false }
        let expectedType = directory ? S_IFDIR : S_IFREG
        guard (mode & S_IFMT) == expectedType else { return false }
        return (mode & 0o777) == expectedMode
    }
}

package final class FileTOTPStateResetter: TOTPStateResetting {
    enum AdapterError: Error { case unsafePath }

    private let root: URL

    package init(home: URL = URL(fileURLWithPath: NSHomeDirectory())) {
        self.root = home.appendingPathComponent("Library/Application Support/hyu-openconnect", isDirectory: true)
    }

    package func resetTOTPState() throws {
        let mkdirStatus = mkdir(root.path, 0o700)
        guard mkdirStatus == 0 || errno == EEXIST else { throw AdapterError.unsafePath }

        let dirFD = open(root.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard dirFD >= 0 else { throw AdapterError.unsafePath }
        defer { close(dirFD) }
        try verifyDescriptor(dirFD, directory: true, mode: 0o700)

        let lockFD = openat(dirFD, "totp-counter.json.lock", O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard lockFD >= 0 else { throw AdapterError.unsafePath }
        defer { close(lockFD) }
        try verifyDescriptor(lockFD, directory: false, mode: 0o600)
        guard flock(lockFD, LOCK_EX) == 0 else { throw AdapterError.unsafePath }
        defer { _ = flock(lockFD, LOCK_UN) }

        var stateInfo = stat()
        let stateStatus = fstatat(dirFD, "totp-counter.json", &stateInfo, AT_SYMLINK_NOFOLLOW)
        if stateStatus != 0 {
            if errno == ENOENT { return }
            throw AdapterError.unsafePath
        }
        try verify(info: stateInfo, directory: false, mode: 0o600)
        guard unlinkat(dirFD, "totp-counter.json", 0) == 0 else { throw AdapterError.unsafePath }
    }

    private func verifyDescriptor(_ fd: Int32, directory: Bool, mode: mode_t) throws {
        var info = stat()
        guard fstat(fd, &info) == 0 else { throw AdapterError.unsafePath }
        try verify(info: info, directory: directory, mode: mode)
    }

    private func verify(info: stat, directory: Bool, mode: mode_t) throws {
        guard FileTOTPMetadataPolicy.isSafe(ownerUID: info.st_uid, mode: info.st_mode, directory: directory, expectedMode: mode) else {
            throw AdapterError.unsafePath
        }
    }
}

package enum SystemCredentialTransactionFactory {
    package static func make() -> CredentialTransaction {
        CredentialTransaction(store: EncryptedCredentialStore(), totpResetter: FileTOTPStateResetter())
    }
}


package enum LoginItemControllerError: Error, Equatable {
    case unavailable(code: String)
}

package enum LoginItemPlatformStatus: Equatable, Sendable {
    case enabled
    case notRegistered
    case requiresApproval
    case notFound
    case unknown(code: String)
}

package protocol LoginItemPlatforming {
    mutating func status() -> LoginItemPlatformStatus
    mutating func register() throws
    mutating func unregister() throws
    mutating func openSystemSettingsLoginItems()
}

package protocol LoginItemControlling {
    mutating func state() -> LoginItemState
    mutating func setEnabled(_ enabled: Bool) throws
    mutating func openSystemSettingsLoginItems()
}

package extension LoginItemControlling {
    mutating func handleMenuSelection() throws {
        switch state() {
        case .enabled:
            try setEnabled(false)
        case .disabled:
            try setEnabled(true)
        case .approvalRequired:
            openSystemSettingsLoginItems()
        case .unavailable(let code):
            throw LoginItemControllerError.unavailable(code: code)
        }
    }
}

package struct LoginItemController<Platform: LoginItemPlatforming>: LoginItemControlling {
    private var platform: Platform

    package init(platform: Platform) {
        self.platform = platform
    }

    package mutating func state() -> LoginItemState {
        Self.project(status: platform.status())
    }

    package mutating func setEnabled(_ enabled: Bool) throws {
        do {
            if enabled {
                try platform.register()
            } else {
                try platform.unregister()
            }
        } catch LoginItemControllerError.unavailable(let code) {
            if enabled && code == "LOGIN_ITEM_ALREADY_REGISTERED" { return }
            if !enabled && code == "LOGIN_ITEM_NOT_REGISTERED" { return }
            throw LoginItemControllerError.unavailable(code: code)
        } catch {
            let code = enabled ? "LOGIN_ITEM_REGISTER_FAILED" : "LOGIN_ITEM_UNREGISTER_FAILED"
            throw LoginItemControllerError.unavailable(code: code)
        }
    }

    package mutating func openSystemSettingsLoginItems() {
        platform.openSystemSettingsLoginItems()
    }

    package static func project(status: LoginItemPlatformStatus) -> LoginItemState {
        switch status {
        case .enabled:
            return .enabled
        case .notRegistered:
            return .disabled
        case .requiresApproval:
            return .approvalRequired
        case .notFound:
            return .disabled
        case .unknown(let code):
            return .unavailable(code: code)
        }
    }
}

package enum LoginItemStartupPolicy {
    package static func shouldRegisterOnLaunch(userChoice: Bool?, state: LoginItemState) -> Bool {
        if userChoice == false { return false }
        return state == .disabled
    }
}

package enum ServiceManagementErrorCode {
    package static let invalidSignature = 3
    package static let authorizationFailure = 4
    package static let toolNotValid = 5
    package static let jobNotFound = 6
    package static let launchDeniedByUser = 11
    package static let alreadyRegistered = 12
}

package struct SMAppServiceLoginItemPlatform: LoginItemPlatforming {
    package init() {}

    package mutating func status() -> LoginItemPlatformStatus {
        switch SMAppService.mainApp.status {
        case .enabled:
            return .enabled
        case .notRegistered:
            return .notRegistered
        case .requiresApproval:
            return .requiresApproval
        case .notFound:
            return .notFound
        @unknown default:
            return .unknown(code: "LOGIN_ITEM_STATUS_UNKNOWN")
        }
    }

    package mutating func register() throws {
        do {
            try SMAppService.mainApp.register()
        } catch {
            throw Self.normalize(error: error, registering: true)
        }
    }

    package mutating func unregister() throws {
        do {
            try SMAppService.mainApp.unregister()
        } catch {
            throw Self.normalize(error: error, registering: false)
        }
    }

    package mutating func openSystemSettingsLoginItems() {
        SMAppService.openSystemSettingsLoginItems()
    }

    package static func normalizeForTest(error: Error, registering: Bool) -> LoginItemControllerError {
        normalize(error: error, registering: registering)
    }

    private static func normalize(error: Error, registering: Bool) -> LoginItemControllerError {
        let nsError = error as NSError
        switch nsError.code {
        case ServiceManagementErrorCode.invalidSignature:
            return .unavailable(code: "LOGIN_ITEM_INVALID_SIGNATURE")
        case ServiceManagementErrorCode.authorizationFailure:
            return .unavailable(code: "LOGIN_ITEM_AUTHORIZATION_FAILED")
        case ServiceManagementErrorCode.toolNotValid:
            return .unavailable(code: "LOGIN_ITEM_TOOL_NOT_VALID")
        case ServiceManagementErrorCode.jobNotFound where !registering:
            return .unavailable(code: "LOGIN_ITEM_NOT_REGISTERED")
        case ServiceManagementErrorCode.launchDeniedByUser:
            return .unavailable(code: "LOGIN_ITEM_LAUNCH_DENIED_BY_USER")
        case ServiceManagementErrorCode.alreadyRegistered where registering:
            return .unavailable(code: "LOGIN_ITEM_ALREADY_REGISTERED")
        default:
            return .unavailable(code: registering ? "LOGIN_ITEM_REGISTER_FAILED" : "LOGIN_ITEM_UNREGISTER_FAILED")
        }
    }
}

package typealias SystemLoginItemController = LoginItemController<SMAppServiceLoginItemPlatform>

package extension SystemLoginItemController {
    init() {
        self.init(platform: SMAppServiceLoginItemPlatform())
    }
}
