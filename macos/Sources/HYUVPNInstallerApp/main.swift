import AppKit
import CryptoKit
import Darwin
import Foundation
import HYUVPNInstallerCore
import HYUVPNMenuAppSupport
import HYUVPNMenuCore

@MainActor
enum InstallerApplicationMenu {
    static func make() -> NSMenu {
        let mainMenu = NSMenu()

        let applicationItem = NSMenuItem()
        let applicationMenu = NSMenu()
        applicationMenu.addItem(NSMenuItem(title: "Quit Install HYU VPN", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
        applicationItem.submenu = applicationMenu
        mainMenu.addItem(applicationItem)

        let editItem = NSMenuItem()
        let editMenu = NSMenu(title: "Edit")
        editMenu.addItem(NSMenuItem(title: "Cut", action: #selector(NSText.cut(_:)), keyEquivalent: "x"))
        editMenu.addItem(NSMenuItem(title: "Copy", action: #selector(NSText.copy(_:)), keyEquivalent: "c"))
        editMenu.addItem(NSMenuItem(title: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v"))
        editMenu.addItem(NSMenuItem.separator())
        editMenu.addItem(NSMenuItem(title: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a"))
        editItem.submenu = editMenu
        mainMenu.addItem(editItem)

        return mainMenu
    }
}

@MainActor
final class HYUVPNInstallerApp: NSObject, NSApplicationDelegate {
    private let app = NSApplication.shared
    private var statusWindow: NSWindow?
    private let statusLabel = NSTextField(labelWithString: "Preparing HYU VPN installer…")
    private let installerLogDisplayPath = "~/Library/Logs/HYU VPN/installer.log"

    func applicationDidFinishLaunching(_ notification: Notification) {
        app.setActivationPolicy(.regular)
        app.activate(ignoringOtherApps: true)
        let progress = showProgressWindow()
        do {
            let result = try InstallerController(bundleURL: Bundle.main.bundleURL, status: progress).runInstall()
            switch result {
            case .installed:
                showAlert(title: "HYU VPN Installed", message: "HYU VPN was installed successfully. You can connect from the menu bar app without another administrator password.", style: .informational)
            case .installedWithMenuStartWarning(let code):
                appendInstallerLog(operationCode: code)
                showAlert(title: "HYU VPN Installed", message: "Installed with menu-start warning. Open /Applications/HYU VPN.app manually. Operation code: \(code)\nDiagnostics: \(installerLogDisplayPath)", style: .warning)
            }
            app.terminate(nil)
        } catch {
            let code = sanitizedOperationCode(for: error)
            appendInstallerLog(operationCode: code)
            showAlert(title: "HYU VPN Install Failed", message: "Operation code: \(code)\nDiagnostics: \(installerLogDisplayPath)", style: .critical)
            app.terminate(nil)
        }
    }

    private func sanitizedOperationCode(for error: Error) -> String {
        if let installerError = error as? InstallerCoreError {
            switch installerError {
            case .invalidInput(let code), .commandFailed(let code): return sanitizeOperationCode(code)
            case .rootAuthorizationOrTransactionFailed: return "INSTALL_FAILED_ROOT_AUTHORIZATION_OR_TRANSACTION"
            }
        }
        if error is InstallerAppError { return "INSTALLER_APP_FAILED" }
        return "INSTALLER_UNKNOWN_FAILED"
    }

    private func sanitizeOperationCode(_ value: String) -> String {
        let filtered = value.filter { $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" }
        return String((filtered.isEmpty ? "UNKNOWN" : filtered).prefix(80))
    }

    private func appendInstallerLog(operationCode: String) {
        let code = sanitizeOperationCode(operationCode)
        let directory = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/HYU VPN", isDirectory: true)
        let logURL = directory.appendingPathComponent("installer.log")
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            if !FileManager.default.fileExists(atPath: logURL.path) {
                FileManager.default.createFile(atPath: logURL.path, contents: nil)
                try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: logURL.path) // 0600
            }
            let timestamp = ISO8601DateFormatter().string(from: Date())
            let line = "\(timestamp) Operation code: \(code)\n"
            let handle = try FileHandle(forWritingTo: logURL)
            defer { try? handle.close() }
            try handle.seekToEnd()
            try handle.write(contentsOf: Data(line.utf8))
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: logURL.path) // 0600
        } catch {
            return
        }
    }

    private func showProgressWindow() -> (String) -> Void {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 420, height: 130), styleMask: [.titled], backing: .buffered, defer: false)
        window.title = "Install HYU VPN"
        let content = NSView(frame: NSRect(x: 0, y: 0, width: 420, height: 130))
        statusLabel.frame = NSRect(x: 24, y: 52, width: 372, height: 24)
        statusLabel.alignment = .center
        content.addSubview(statusLabel)
        window.contentView = content
        window.center()
        window.makeKeyAndOrderFront(nil)
        statusWindow = window
        window.displayIfNeeded()
        RunLoop.current.run(until: Date().addingTimeInterval(0.05))
        return { [weak self] message in
            self?.statusLabel.stringValue = message
            self?.statusWindow?.displayIfNeeded()
            RunLoop.current.run(until: Date().addingTimeInterval(0.01))
        }
    }

    private func showAlert(title: String, message: String, style: NSAlert.Style) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.alertStyle = style
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
}

let application = NSApplication.shared
let delegate = HYUVPNInstallerApp()
application.mainMenu = InstallerApplicationMenu.make()
application.delegate = delegate
withExtendedLifetime(delegate) {
    application.run()
}

enum InstallerAppError: Error, CustomStringConvertible {
    case missingPayload(String)
    case cancelled

    var description: String {
        switch self {
        case .missingPayload(let value): return "The installer payload is missing: \(value)"
        case .cancelled: return "Installation was cancelled."
        }
    }
}

enum InstallerRunResult: Equatable {
    case installed
    case installedWithMenuStartWarning(code: String)
}

enum UserActivationResult: Equatable {
    case active
    case menuStartWarning(code: String)
}

@MainActor
struct InstallerController {
    let bundleURL: URL
    let status: (String) -> Void
    private var payloadURL: URL { bundleURL.deletingLastPathComponent() }
    private var automaticReconnectPreferencePath: String { NSHomeDirectory() + "/Library/Application Support/hyu-openconnect/automatic-reconnect" }
    private let credentialReader = InstallerEncryptedCredentialStore()

    func runInstall() throws -> InstallerRunResult {
        status("Preparing HYU VPN installer…")
        let payload = payloadURL.path
        let manifest = payloadURL.appendingPathComponent("manifest.json").path
        let installerDir = payloadURL.appendingPathComponent("installer").path
        try requireFile(manifest, label: "manifest.json")
        try requireFile("\(installerDir)/root-admin.sh", label: "installer/root-admin.sh")
        status("Verifying package manifest…")
        try NativePayloadManifest.verify(payload: URL(fileURLWithPath: payload), manifest: URL(fileURLWithPath: manifest))
        let stageDir = try makeTemporaryDirectory(prefix: "hyu-vpn-stage")
        defer { try? FileManager.default.removeItem(at: stageDir) }
        status("Preparing files for installation…")
        try NativePayloadManifest.stage(payload: URL(fileURLWithPath: payload), manifest: URL(fileURLWithPath: manifest), stage: stageDir)
        let packageDigest = try sha256(path: manifest)
        let stageManifest = stageDir.appendingPathComponent("manifest.json").path
        let stageDigest = try sha256(path: stageManifest)
        let existingAutomaticReconnect = try readAutoReconnectPreference(path: automaticReconnectPreferencePath)
        let desiredAutomaticReconnect = InstallerAutomaticReconnectPolicy.desiredAfterInstall(existingValue: existingAutomaticReconnect)
        try writeAutoReconnectPreference(enabled: false, path: automaticReconnectPreferencePath)

        status("Checking saved HYU VPN credentials…")
        let missingCredentialValues = try collectMissingCredentialsBeforeElevation()
        let identity = consoleIdentity()
        let rootArgv = try RootAdminInvocation.makeInstallArgv(
            identity: identity,
            installerDir: installerDir,
            payload: payload,
            manifest: manifest,
            stage: stageDir.path,
            stageManifestSHA256: stageDigest,
            packageManifestSHA256: packageDigest,
            epoch: Int(Date().timeIntervalSince1970)
        )
        status("Waiting for macOS administrator authorization…")
        do {
            try RootAdminAuthorizer.authorizeOnce(argv: rootArgv, newlyCreatedKeys: [], store: credentialReader) { argv in
                try runWithAdministratorPrivileges(argv)
            }
        } catch {
            try? restoreAutoReconnectPreference(existingValue: existingAutomaticReconnect, path: automaticReconnectPreferencePath)
            throw error
        }

        status("Saving HYU VPN credentials…")
        let credentialWriter = InstallerEncryptedCredentialStore()
        let writtenKeys = try InstallerCredentialBootstrapper.writeCollectedCredentials(store: credentialWriter, collected: missingCredentialValues)
        do {
            status("Starting HYU VPN menu app…")
            switch try activateUserSession(automaticReconnectEnabled: desiredAutomaticReconnect) {
            case .active:
                return .installed
            case .menuStartWarning(let code):
                return .installedWithMenuStartWarning(code: code)
            }
        } catch {
            let cleanup = InstallerCredentialBootstrapper.cleanupWrittenCredentialsAfterActivationFailure(store: credentialWriter, writtenKeys: writtenKeys)
            if cleanup == .incomplete { throw InstallerCoreError.commandFailed(code: "ACTIVATION_FAILED_CREDENTIAL_CLEANUP_INCOMPLETE") }
            throw error
        }
    }

    private func collectMissingCredentialsBeforeElevation() throws -> [CredentialKey: String] {
        let missingKeys = try InstallerCredentialBootstrapper.missingCredentialKeys(store: credentialReader)
        guard !missingKeys.isEmpty else { return [:] }
        var values = try promptCredentialForm(missingKeys: missingKeys)
        defer {
            for key in values.keys { values[key] = "" }
            values.removeAll(keepingCapacity: false)
        }
        return try InstallerCredentialBootstrapper.validateCollectedCredentialValues(missingKeys: missingKeys, values: values)
    }

    private func activateUserSession(automaticReconnectEnabled: Bool) throws -> UserActivationResult {
        let uid = String(getuid())
        let prefPath = automaticReconnectPreferencePath
        let servicePlist = NSHomeDirectory() + "/Library/LaunchAgents/com.hyu.vpn.service.plist"
        do {
            try writeAutoReconnectPreference(enabled: automaticReconnectEnabled, path: prefPath)
            try requireFile(servicePlist, label: "installed service LaunchAgent")
            try run(["/bin/launchctl", "bootstrap", "gui/\(uid)", servicePlist], code: "SERVICE_BOOTSTRAP_FAILED", allowFailure: true)
            try run(["/bin/launchctl", "kickstart", "-k", "gui/\(uid)/com.hyu.vpn.service"], code: "SERVICE_KICKSTART_FAILED")
        } catch {
            bestEffortDeactivateUserService(uid: uid, prefPath: prefPath, servicePlist: servicePlist)
            throw error
        }
        do {
            try stopExistingMenubar(uid: uid)
            try run(["/usr/bin/open", "-gj", "-a", "/Applications/HYU VPN.app"], code: "MENU_OPEN_FAILED")
            guard waitForSingleMenubar(uid: uid) else { throw InstallerCoreError.commandFailed(code: "MENU_SINGLE_PROCESS_FAILED") }
            return .active
        } catch let error as InstallerCoreError {
            let code = sanitizedCoreCode(error)
            switch InstallerActivationPolicy.classify(serviceStarted: true, failedCode: code) {
            case .installedWithMenuStartWarning(let warningCode): return .menuStartWarning(code: warningCode)
            case .fatalCleanupCredentials: throw error
            }
        }
    }

    private func sanitizedCoreCode(_ error: InstallerCoreError) -> String {
        switch error {
        case .invalidInput(let code), .commandFailed(let code): return code
        case .rootAuthorizationOrTransactionFailed: return "INSTALL_FAILED_ROOT_AUTHORIZATION_OR_TRANSACTION"
        }
    }

    private func bestEffortDeactivateUserService(uid: String, prefPath: String, servicePlist: String) {
        try? writeAutoReconnectPreference(enabled: false, path: prefPath)
        try? run(["/bin/launchctl", "bootout", "gui/\(uid)", servicePlist], code: "SERVICE_BOOTOUT_FAILED", allowFailure: true)
    }

    private func writeAutoReconnectPreference(enabled: Bool, path: String) throws {
        let preferenceDirectory = URL(fileURLWithPath: path).deletingLastPathComponent()
        try FileManager.default.createDirectory(at: preferenceDirectory, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: preferenceDirectory.path)
        let data = Data((enabled ? "true\n" : "false\n").utf8)
        try data.write(to: URL(fileURLWithPath: path), options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
    }

    private func readAutoReconnectPreference(path: String) throws -> Bool? {
        let url = URL(fileURLWithPath: path)
        guard FileManager.default.fileExists(atPath: path) else { return nil }
        let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey])
        guard values.isRegularFile == true, values.isSymbolicLink != true, let size = values.fileSize, size <= 8 else {
            throw InstallerCoreError.commandFailed(code: "AUTOMATIC_PREFERENCE_INVALID")
        }
        switch try String(contentsOf: url, encoding: .utf8) {
        case "true\n": return true
        case "false\n": return false
        default: throw InstallerCoreError.commandFailed(code: "AUTOMATIC_PREFERENCE_INVALID")
        }
    }

    private func restoreAutoReconnectPreference(existingValue: Bool?, path: String) throws {
        guard let existingValue else {
            try? FileManager.default.removeItem(atPath: path)
            return
        }
        try writeAutoReconnectPreference(enabled: existingValue, path: path)
    }

    private func stopExistingMenubar(uid: String) throws {
        try run(["/usr/bin/pkill", "-TERM", "-u", uid, "-x", "HYUVPNMenuApp"], code: "OLD_MENU_TERM_FAILED", allowFailure: true)
        if waitForMenubarExit(uid: uid) { return }
        try run(["/usr/bin/pkill", "-KILL", "-u", uid, "-x", "HYUVPNMenuApp"], code: "OLD_MENU_KILL_FAILED", allowFailure: true)
        guard waitForMenubarExit(uid: uid) else { throw InstallerCoreError.commandFailed(code: "OLD_MENU_STOP_TIMEOUT") }
    }

    private func waitForMenubarExit(uid: String) -> Bool {
        waitForMenubarCount(uid: uid, expected: 0)
    }

    private func waitForSingleMenubar(uid: String) -> Bool {
        waitForMenubarCount(uid: uid, expected: 1)
    }

    private func waitForMenubarCount(uid: String, expected: Int) -> Bool {
        for _ in 0..<50 {
            if menubarProcessCount(uid: uid) == expected { return true }
            Thread.sleep(forTimeInterval: 0.1)
        }
        return menubarProcessCount(uid: uid) == expected
    }

    private func menubarProcessCount(uid: String) -> Int {
        do {
            let output = try runCaptured(["/usr/bin/pgrep", "-u", uid, "-x", "HYUVPNMenuApp"], code: "MENU_PROCESS_COUNT_FAILED", allowFailure: true, maxBytes: 4096)
            return output.split(whereSeparator: \.isNewline).count
        } catch {
            return 0
        }
    }

    private func requireFile(_ path: String, label: String) throws {
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path, isDirectory: &isDir), !isDir.boolValue else { throw InstallerAppError.missingPayload(label) }
    }

    private func makeTemporaryDirectory(prefix: String) throws -> URL {
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("\(prefix).\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
        return url
    }

    private func promptCredentialForm(missingKeys: [CredentialKey]) throws -> [CredentialKey: String] {
        let alert = NSAlert()
        alert.messageText = "HYU VPN Credentials"
        alert.informativeText = "Enter the missing values below. For TOTP, paste the authenticator setup secret—not the current 6-digit code."
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        let rowHeight: CGFloat = 62
        let accessoryHeight = rowHeight * CGFloat(missingKeys.count)
        let accessory = NSView(frame: NSRect(x: 0, y: 0, width: 460, height: accessoryHeight))
        var fields: [NSTextField] = []
        for (index, key) in missingKeys.enumerated() {
            let labelText: String
            let placeholder: String
            switch key {
            case .username:
                labelText = "HYU ID"
                placeholder = "HYU ID"
            case .password:
                labelText = "VPN password"
                placeholder = "VPN password"
            case .totpSeed:
                labelText = "TOTP setup secret"
                placeholder = "Authenticator setup secret"
            }
            let top = accessoryHeight - CGFloat(index) * rowHeight
            let label = NSTextField(labelWithString: labelText)
            label.frame = NSRect(x: 0, y: top - 20, width: 460, height: 18)
            let field: NSTextField
            switch key {
            case .username:
                field = NSTextField(frame: NSRect(x: 0, y: top - 52, width: 460, height: 26))
            case .password, .totpSeed:
                field = NSSecureTextField(frame: NSRect(x: 0, y: top - 52, width: 460, height: 26))
            }
            field.placeholderString = placeholder
            accessory.addSubview(label)
            accessory.addSubview(field)
            fields.append(field)
        }
        alert.accessoryView = accessory
        for index in fields.indices.dropLast() {
            fields[index].nextKeyView = fields[index + 1]
        }
        fields.last?.nextKeyView = alert.buttons.first
        alert.window.recalculateKeyViewLoop()
        alert.window.initialFirstResponder = fields.first
        let response = alert.runModal()
        guard response == .alertFirstButtonReturn else {
            for field in fields { field.stringValue = "" }
            throw InstallerAppError.cancelled
        }
        var values: [CredentialKey: String] = [:]
        for (key, field) in zip(missingKeys, fields) {
            values[key] = key == .username ? field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines) : field.stringValue
            field.stringValue = ""
        }
        return values
    }

    private func run(_ argv: [String], code: String, allowFailure: Bool = false) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: argv[0])
        process.arguments = Array(argv.dropFirst())
        let nullOut = FileHandle(forWritingAtPath: "/dev/null")
        process.standardOutput = nullOut
        process.standardError = nullOut
        try process.run()
        process.waitUntilExit()
        try nullOut?.close()
        if process.terminationStatus != 0 && !allowFailure { throw InstallerCoreError.commandFailed(code: code) }
    }

    private func runCaptured(_ argv: [String], code: String, allowFailure: Bool = false, maxBytes: Int) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: argv[0])
        process.arguments = Array(argv.dropFirst())
        let stdout = Pipe()
        let stderrNull = FileHandle(forWritingAtPath: "/dev/null")
        process.standardOutput = stdout
        process.standardError = stderrNull
        try process.run()
        process.waitUntilExit()
        try stderrNull?.close()
        let data = stdout.fileHandleForReading.readDataToEndOfFile()
        if process.terminationStatus != 0 && !allowFailure { throw InstallerCoreError.commandFailed(code: code) }
        return String(decoding: data.prefix(maxBytes), as: UTF8.self)
    }

    private func sha256(path: String) throws -> String {
        let data = try Data(contentsOf: URL(fileURLWithPath: path), options: [.mappedIfSafe])
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private func consoleIdentity() -> ConsoleIdentity {
        ConsoleIdentity(user: NSUserName(), uid: String(getuid()))
    }

    private func runWithAdministratorPrivileges(_ argv: [String]) throws {
        try runRootAuthorizationCaptured(RootAdminAuthorizationScript.makeOSAScriptArgv(argv))
    }

    private func runRootAuthorizationCaptured(_ argv: [String]) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: argv[0])
        process.arguments = Array(argv.dropFirst())
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        process.waitUntilExit()
        let outputData = stdout.fileHandleForReading.readDataToEndOfFile() + stderr.fileHandleForReading.readDataToEndOfFile()
        guard process.terminationStatus == 0 else {
            let output = String(decoding: outputData.prefix(8192), as: UTF8.self)
            let code = RootAdminFailureClassifier.operationCode(exitStatus: process.terminationStatus, capturedOutput: output)
            throw InstallerCoreError.commandFailed(code: code)
        }
    }
}


final class InstallerEncryptedCredentialStore: InstallerCredentialStoring {
    private let store = EncryptedCredentialStore()

    func contains(_ key: CredentialKey) throws -> Bool { try store.contains(key) }
    func read(_ key: CredentialKey) throws -> String? { try store.read(key) }
    func write(_ value: String, for key: CredentialKey) throws { try store.write(value, for: key) }
    func remove(_ key: CredentialKey) throws { try store.remove(key) }
}
