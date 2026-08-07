import Foundation
import Security
import Darwin
import HYUVPNMenuCore

final class KeychainCredentialStore: CredentialStore {
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

    func read(_ key: CredentialKey) throws -> String? {
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

    func write(_ value: String, for key: CredentialKey) throws {
        guard let data = value.data(using: .utf8) else { throw AdapterError.keychainFailure }
        let query = baseQuery(for: key)
        let attributes: [String: Any] = [kSecValueData as String: data]
        let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else { throw AdapterError.keychainFailure }

        var addQuery = query
        addQuery[kSecValueData as String] = data
        let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
        if addStatus == errSecSuccess { return }
        if addStatus == errSecDuplicateItem {
            let retryStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
            if retryStatus == errSecSuccess { return }
        }
        throw AdapterError.keychainFailure
    }

    func remove(_ key: CredentialKey) throws {
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

enum SystemCredentialBootstrap {
    static func currentID() -> String? {
        try? KeychainCredentialStore().read(.username)
    }
}

final class FileTOTPStateResetter: TOTPStateResetting {
    enum AdapterError: Error { case unsafePath }

    private let root: URL

    init(home: URL = URL(fileURLWithPath: NSHomeDirectory())) {
        self.root = home.appendingPathComponent("Library/Application Support/hyu-openconnect", isDirectory: true)
    }

    func resetTOTPState() throws {
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
        guard info.st_uid == getuid() else { throw AdapterError.unsafePath }
        if directory {
            guard (info.st_mode & S_IFMT) == S_IFDIR else { throw AdapterError.unsafePath }
        } else {
            guard (info.st_mode & S_IFMT) == S_IFREG else { throw AdapterError.unsafePath }
        }
        guard (info.st_mode & 0o777) == mode else { throw AdapterError.unsafePath }
    }
}

enum SystemCredentialTransactionFactory {
    static func make() -> CredentialTransaction {
        CredentialTransaction(store: KeychainCredentialStore(), totpResetter: FileTOTPStateResetter())
    }
}
