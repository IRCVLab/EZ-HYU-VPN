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
    private let credentialReader = InstallerKeychainStore()

    func runInstall() throws -> InstallerRunResult {
        status("Preparing HYU VPN installer…")
        let payload = payloadURL.path
        let manifest = payloadURL.appendingPathComponent("manifest.json").path
        let installerDir = payloadURL.appendingPathComponent("installer").path
        try requireFile(manifest, label: "manifest.json")
        try requireFile("\(installerDir)/manifest.py", label: "installer/manifest.py")
        try requireFile("\(installerDir)/root-admin.sh", label: "installer/root-admin.sh")
        status("Verifying package manifest…")
        try run(["/usr/bin/python3", "\(installerDir)/manifest.py", "--payload", payload, "--manifest", manifest, "--verify-manifest"], code: "VERIFY_MANIFEST_FAILED")
        let stageDir = try makeTemporaryDirectory(prefix: "hyu-vpn-stage")
        defer { try? FileManager.default.removeItem(at: stageDir) }
        status("Preparing files for installation…")
        try run(["/usr/bin/python3", "\(installerDir)/manifest.py", "--payload", payload, "--manifest", manifest, "--stage-user-payload", "--stage-dir", stageDir.path], code: "STAGE_PAYLOAD_FAILED")
        let packageDigest = try sha256(path: manifest)
        let stageManifest = stageDir.appendingPathComponent("manifest.json").path
        let stageDigest = try sha256(path: stageManifest)

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
        try RootAdminAuthorizer.authorizeOnce(argv: rootArgv, newlyCreatedKeys: [], store: credentialReader) { argv in
            try runWithAdministratorPrivileges(argv)
        }

        status("Saving HYU VPN credentials…")
        let installedMenuExecutable = "/Applications/HYU VPN.app/Contents/MacOS/HYUVPNMenuApp"
        let credentialWriter = InstallerKeychainStore(additionalTrustedApplicationPath: installedMenuExecutable)
        let writtenKeys = try InstallerCredentialBootstrapper.writeCollectedCredentials(store: credentialWriter, collected: missingCredentialValues)
        do {
            status("Starting HYU VPN menu app…")
            switch try activateUserSession() {
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
        try InstallerCredentialBootstrapper.collectMissingFinalCredentials(store: credentialReader) { key in
            switch key {
            case .username:
                return try promptText(title: "HYU VPN ID", message: "Enter your HYU ID.", secure: false)
            case .password:
                return try promptConfirmedSecret(title: "HYU VPN Password", message: "Enter your HYU VPN password twice.", fieldLabel: "Password")
            case .totpSeed:
                return try promptConfirmedSecret(title: "TOTP Setup Secret", message: "Enter the authenticator setup secret twice, not the current 6-digit code.", fieldLabel: "Setup secret")
            }
        }
    }

    private func activateUserSession() throws -> UserActivationResult {
        let uid = String(getuid())
        let prefPath = NSHomeDirectory() + "/Library/Application Support/hyu-openconnect/auto-reconnect.json"
        let servicePlist = NSHomeDirectory() + "/Library/LaunchAgents/com.hyu.vpn.service.plist"
        do {
            try run(["/usr/bin/python3", "-I", "-c", "import sys; sys.path.insert(0,\"/Library/Application Support/HYU VPN/src\"); from hyu_vpn.control import AutoReconnectPreference; AutoReconnectPreference(sys.argv[1], owner_uid=int(sys.argv[2])).write(True)", prefPath, uid], code: "AUTO_RECONNECT_PREF_FAILED")
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
        try? run(["/usr/bin/python3", "-I", "-c", "import sys; sys.path.insert(0,\"/Library/Application Support/HYU VPN/src\"); from hyu_vpn.control import AutoReconnectPreference; AutoReconnectPreference(sys.argv[1], owner_uid=int(sys.argv[2])).write(False)", prefPath, uid], code: "AUTO_RECONNECT_RESTORE_FAILED", allowFailure: true)
        try? run(["/bin/launchctl", "bootout", "gui/\(uid)", servicePlist], code: "SERVICE_BOOTOUT_FAILED", allowFailure: true)
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

    private func promptText(title: String, message: String, secure: Bool) throws -> String {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")
        let field: NSTextField = secure ? NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24)) : NSTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
        alert.accessoryView = field
        guard alert.runModal() == .alertFirstButtonReturn else { throw InstallerAppError.cancelled }
        return secure ? field.stringValue : field.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func promptConfirmedSecret(title: String, message: String, fieldLabel: String) throws -> String {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = message
        alert.addButton(withTitle: "Continue")
        alert.addButton(withTitle: "Cancel")

        let firstField = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
        let confirmationField = NSSecureTextField(frame: NSRect(x: 0, y: 0, width: 320, height: 24))
        firstField.placeholderString = fieldLabel
        confirmationField.placeholderString = "Confirm \(fieldLabel.lowercased())"
        firstField.widthAnchor.constraint(equalToConstant: 320).isActive = true
        confirmationField.widthAnchor.constraint(equalToConstant: 320).isActive = true

        let fields = NSStackView(views: [
            NSTextField(labelWithString: fieldLabel),
            firstField,
            NSTextField(labelWithString: "Confirm \(fieldLabel.lowercased())"),
            confirmationField,
        ])
        fields.orientation = .vertical
        fields.alignment = .leading
        fields.spacing = 6
        alert.accessoryView = fields
        alert.window.initialFirstResponder = firstField
        guard alert.runModal() == .alertFirstButtonReturn else { throw InstallerAppError.cancelled }

        let first = firstField.stringValue
        let second = confirmationField.stringValue
        guard !first.isEmpty else { throw InstallerCoreError.invalidInput("SECRET_REQUIRED") }
        guard first == second else { throw InstallerCoreError.invalidInput("SECRET_MISMATCH") }
        return first
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


final class InstallerKeychainStore: InstallerCredentialStoring {
    private let store: KeychainCredentialStore

    init(additionalTrustedApplicationPath: String? = nil) {
        self.store = KeychainCredentialStore(additionalTrustedApplicationPath: additionalTrustedApplicationPath)
    }

    func contains(_ key: CredentialKey) throws -> Bool { try store.contains(key) }
    func read(_ key: CredentialKey) throws -> String? { try store.read(key) }
    func write(_ value: String, for key: CredentialKey) throws { try store.write(value, for: key) }
    func remove(_ key: CredentialKey) throws { try store.remove(key) }
}
