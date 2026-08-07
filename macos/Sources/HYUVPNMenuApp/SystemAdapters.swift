import Foundation
import ServiceManagement
import Security
import Darwin
import HYUVPNMenuCore
import HYUVPNKeychainAccessShim

package final class KeychainCredentialStore: CredentialStore {
    enum AdapterError: Error { case keychainFailure }

    private static let account = "hyu-vpn"
    private static let services: [CredentialKey: String] = [
        .username: "gp-vpn-username",
        .password: "gp-vpn-password",
        .totpSeed: "gp-vpn-totp",
    ]

    init() {
        precondition(Set(Self.services.keys) == Set(CredentialKey.allCases))
    }

    package func read(_ key: CredentialKey) throws -> String? {
        var query = baseQuery(for: key)
        query[kSecReturnData as String] = kCFBooleanTrue
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw AdapterError.keychainFailure }
        guard let data = item as? Data, let value = String(data: data, encoding: .utf8) else {
            throw AdapterError.keychainFailure
        }
        return value
    }

    package func write(_ value: String, for key: CredentialKey) throws {
        guard let data = value.data(using: .utf8) else { throw AdapterError.keychainFailure }
        let query = baseQuery(for: key)
        let access = try KeychainCredentialAccessFactory.make()
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccess as String: access,
        ]
        let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else { throw AdapterError.keychainFailure }

        var addQuery = query
        addQuery[kSecValueData as String] = attributes[kSecValueData as String]
        addQuery[kSecAttrAccess as String] = attributes[kSecAttrAccess as String]
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus == errSecSuccess { return }
        if addStatus == errSecDuplicateItem {
            let retryStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
            if retryStatus == errSecSuccess { return }
        }
        throw AdapterError.keychainFailure
    }

    package func remove(_ key: CredentialKey) throws {
        let status = SecItemDelete(baseQuery(for: key) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw AdapterError.keychainFailure }
    }

    private func baseQuery(for key: CredentialKey) -> [String: Any] {
        guard let service = Self.services[key] else { preconditionFailure("closed credential key map") }
        return [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: Self.account,
        ]
    }
}

package enum KeychainCredentialAccessFactory {
    package static func make() throws -> SecAccess {
        var unmanagedAccess: Unmanaged<SecAccess>?
        let status = HYUVPNCreateCredentialAccess(&unmanagedAccess)
        guard status == errSecSuccess, let access = unmanagedAccess?.takeRetainedValue() else { throw KeychainCredentialStore.AdapterError.keychainFailure }
        return access
    }
}

package enum SystemCredentialBootstrap {
    package static func currentID() -> String? {
        try? KeychainCredentialStore().read(.username)
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
        CredentialTransaction(store: KeychainCredentialStore(), totpResetter: FileTOTPStateResetter())
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
            return .unavailable(code: "LOGIN_ITEM_NOT_FOUND")
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
