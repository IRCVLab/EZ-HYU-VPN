import AppKit
import Foundation
import HYUVPNMenuCore
import HYUVPNMenuAppSupport

final class ResetPayloadBox: @unchecked Sendable {
    var value: ValidatedCredentials?
    init(_ value: ValidatedCredentials) { self.value = value }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, StatusUpdateSink, StatusValueSink {
    private var statusItem: NSStatusItem?
    private var watcher: StatusWatcher?
    private var currentStatus: VPNStatus?
    private var currentPresentation = MenuPresentation(statusItemTitle: "", primaryText: "Status Unavailable", detailText: "", symbolName: "exclamationmark.shield.fill")
    private var lastControlResult: ControlResult?
    private let control = SecureVPNControlClient()
    private var lifecycle = AppLifecycleCoordinator()
    private var startupRetryWorkItem: DispatchWorkItem?
    private var resetController: CredentialResetController?
    private var pendingResetPayload: ValidatedCredentials?
    private var loginItemController = SystemLoginItemController()
    private var loginItemState: LoginItemState = .disabled
    private var lastLoginItemResult = "LOGIN_ITEM_UNAVAILABLE"
    private let launchAtLoginUserChoiceKey = "hyu.vpn.launchAtLogin.userChoice"

    func applicationDidFinishLaunching(_ notification: Notification) {
        installStatusItem()
        refreshLoginItemState()
        applyFirstLaunchLoginItemDefault()
        rebuildMenu()
        startWatcher()
        apply(lifecycle.handle(.appLaunched))
    }

    func applicationDidBecomeActive(_ notification: Notification) {
        refreshLoginItemState()
        rebuildMenu()
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        resetController?.dismissWithoutSaving()
        pendingResetPayload = nil
        let transition = lifecycle.handle(.terminateRequested)
        apply(transition)
        switch transition.terminationDirective {
        case .none, .terminateLater:
            return .terminateLater
        case .terminateNow:
            return .terminateNow
        }
    }

    nonisolated func applyStatusValue(_ status: VPNStatus?) {
        DispatchQueue.main.async { [weak self] in
            self?.currentStatus = status
            self?.refreshStatusButton()
            self?.rebuildMenu()
        }
    }

    nonisolated func apply(_ presentation: MenuPresentation) {
        DispatchQueue.main.async { [weak self] in
            self?.currentPresentation = presentation
            self?.refreshStatusButton()
            self?.rebuildMenu()
        }
    }

    private func installStatusItem() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        statusItem = item
        refreshStatusButton()
        item.menu = NSMenu(title: "HYU VPN")
    }

    private func startWatcher() {
        let configuration = StatusWatcherConfiguration.production()
        let statusReader = FileStatusReader(url: configuration.statusPath)
        let statusWatcher = StatusWatcher(configuration: configuration, reader: statusReader, sink: self)
        watcher = statusWatcher
        do {
            try statusWatcher.start()
        } catch {
            currentStatus = nil
            refreshStatusButton()
            rebuildMenu()
        }
    }

    private func refreshStatusButton() {
        guard let button = statusItem?.button else { return }
        let textualState = statusLineText()
        button.image = NSImage(systemSymbolName: currentPresentation.symbolName, accessibilityDescription: textualState)
        button.image?.isTemplate = true
        button.title = ""
        button.toolTip = textualState
        button.setAccessibilityLabel(textualState)
        button.setAccessibilityHelp(textualState)
    }

    private func rebuildMenu() {
        refreshLoginItemState()
        let menu = NSMenu(title: "HYU VPN")
        menu.addItem(disabledItem(title: statusLineText()))
        addPrimaryAction(to: menu)
        addDisconnectAction(to: menu)
        menu.addItem(NSMenuItem.separator())
        addResetAction(to: menu)
        addLaunchAtLoginAction(to: menu)
        addDiagnosticsAction(to: menu)
        menu.addItem(NSMenuItem.separator())
        addQuitAction(to: menu)
        statusItem?.menu = menu
    }

    private func addPrimaryAction(to menu: NSMenu) {
        let action = primaryAction()
        let item = NSMenuItem(title: action.title, action: #selector(primaryConnection(_:)), keyEquivalent: "")
        item.target = self
        item.isEnabled = action.isEnabled
        item.representedObject = action.command
        menu.addItem(item)
    }

    private func addDisconnectAction(to menu: NSMenu) {
        let item = NSMenuItem(title: "Disconnect", action: #selector(disconnect), keyEquivalent: "")
        item.target = self
        item.isEnabled = disconnectEnabled()
        menu.addItem(item)
    }

    private func addResetAction(to menu: NSMenu) {
        let item = NSMenuItem(title: "Reset Login Information…", action: #selector(resetLoginInformation), keyEquivalent: "")
        item.target = self
        item.isEnabled = !lifecycle.controlsDisabled
        menu.addItem(item)
    }

    private func addLaunchAtLoginAction(to menu: NSMenu) {
        let model = loginItemMenuItemModel()
        let item = NSMenuItem(title: model.title, action: #selector(toggleLaunchAtLogin), keyEquivalent: "")
        item.target = self
        item.isEnabled = model.isEnabled
        item.state = model.isChecked ? .on : .off
        menu.addItem(item)
    }

    private func addDiagnosticsAction(to menu: NSMenu) {
        let item = NSMenuItem(title: "Diagnostics…", action: #selector(showDiagnostics), keyEquivalent: "")
        item.target = self
        item.isEnabled = !lifecycle.controlsDisabled
        menu.addItem(item)
    }

    private func addQuitAction(to menu: NSMenu) {
        let item = NSMenuItem(title: "Quit HYU VPN", action: #selector(quit), keyEquivalent: "q")
        item.target = self
        item.isEnabled = !lifecycle.controlsDisabled
        menu.addItem(item)
    }

    private func disabledItem(title: String) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        item.isEnabled = false
        return item
    }

    private func primaryAction() -> (title: String, command: VPNControlCommand?, isEnabled: Bool) {
        guard let status = currentStatus else {
            return ("Connect", nil, false)
        }
        switch status.state {
        case .connected:
            return ("Reconnect", lifecycle.controlsDisabled ? nil : .reconnect, !lifecycle.controlsDisabled)
        case .connecting:
            return ("Connecting…", nil, false)
        case .disconnecting:
            return ("Disconnecting…", nil, false)
        case .disabled:
            return ("Connect", lifecycle.controlsDisabled ? nil : .connect, !lifecycle.controlsDisabled)
        case .waitingForNetwork:
            return ("Waiting for Network", nil, false)
        case .backoff:
            return ("Reconnect Now", lifecycle.controlsDisabled ? nil : .reconnect, !lifecycle.controlsDisabled)
        case .error:
            return ("Reconnect", lifecycle.controlsDisabled ? nil : .reconnect, !lifecycle.controlsDisabled)
        }
    }

    private func disconnectEnabled() -> Bool {
        guard let status = currentStatus else { return false }
        guard !lifecycle.controlsDisabled else { return false }
        switch status.state {
        case .connected, .connecting, .backoff, .error:
            return true
        case .disconnecting, .disabled, .waitingForNetwork:
            return false
        }
    }

    private func statusLineText() -> String {
        guard currentStatus != nil else { return "HYU VPN: Status Unavailable" }
        return "HYU VPN: \(currentPresentation.primaryText)"
    }

    @objc private func primaryConnection(_ sender: NSMenuItem) {
        guard let command = sender.representedObject as? VPNControlCommand else { return }
        let event: AppLifecycleEvent = command == .connect ? .primaryConnectRequested : .primaryReconnectRequested
        apply(lifecycle.handle(event))
    }

    @objc private func disconnect() {
        apply(lifecycle.handle(.disconnectRequested))
    }

    @objc private func resetLoginInformation() {
        guard resetController == nil, !lifecycle.controlsDisabled else { return }
        let controller = CredentialResetController(prefillUsername: SystemCredentialBootstrap.currentID()) { [weak self] controller, value in
            guard let self else { return }
            self.resetController = nil
            guard let value else { return }
            self.pendingResetPayload = value
            let transition = self.lifecycle.handle(.credentialResetRequested)
            if transition.effects.isEmpty {
                self.pendingResetPayload = nil
            }
            self.apply(transition)
            _ = controller
        }
        resetController = controller
        NSApp.activate(ignoringOtherApps: true)
        controller.present()
    }

    @objc private func toggleLaunchAtLogin() {
        do {
            switch loginItemState {
            case .enabled:
                try loginItemController.setEnabled(false)
                UserDefaults.standard.set(false, forKey: launchAtLoginUserChoiceKey)
            case .disabled:
                try loginItemController.setEnabled(true)
                UserDefaults.standard.set(true, forKey: launchAtLoginUserChoiceKey)
            case .approvalRequired:
                loginItemController.openSystemSettingsLoginItems()
            case .unavailable:
                return
            }
            lastLoginItemResult = "LOGIN_ITEM_OK"
            refreshLoginItemState()
        } catch LoginItemControllerError.unavailable(let code) {
            lastLoginItemResult = code
            refreshLoginItemState()
        } catch {
            lastLoginItemResult = "LOGIN_ITEM_TOGGLE_FAILED"
            refreshLoginItemState()
        }
        rebuildMenu()
    }

    @objc private func showDiagnostics() {
        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = "HYU VPN Diagnostics"
        alert.informativeText = diagnosticsText()
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    @objc private func quit() {
        NSApp.sendAction(#selector(NSApplication.terminate(_:)), to: nil, from: self)
    }

    private func apply(_ transition: AppLifecycleTransition) {
        for effect in transition.effects {
            switch effect {
            case .runControl(let command, let operation, let timeout):
                runControl(command: command, operation: operation, timeout: timeout)
            case .scheduleStartupRetry(let delay):
                scheduleStartupRetry(after: delay)
            case .cancelStartupRetry:
                cancelStartupRetry()
            case .replyToTermination(let allow):
                pendingResetPayload = nil
                NSApp.reply(toApplicationShouldTerminate: allow)
            case .showTerminationFailureAlert(let code):
                presentQuitFailure(code)
            case .runCredentialTransaction:
                runCredentialTransaction()
            case .showCredentialResetError(let code):
                pendingResetPayload = nil
                presentCredentialResetFailure(code)
            case .dismissCredentialReset:
                pendingResetPayload = nil
                resetController?.dismissWithoutSaving()
            }
        }
        refreshStatusButton()
        rebuildMenu()
    }

    private func runControl(command: VPNControlCommand, operation: ControlTowerOperation, timeout: TimeInterval) {
        let client = control
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let result: ControlResult
            do {
                result = try client.run(command, timeout: timeout)
            } catch {
                result = ControlResult(status: .failed, errorCode: "CONTROL_INSECURE")
            }
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                self.lastControlResult = result
                self.apply(self.lifecycle.handle(.controlCompleted(operation: operation, result: result)))
            }
        }
    }

    private func runCredentialTransaction() {
        guard let payload = pendingResetPayload else {
            apply(lifecycle.handle(.credentialTransactionCompleted(.failure(code: .readFailed))))
            return
        }
        pendingResetPayload = nil
        let box = ResetPayloadBox(payload)
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let transaction = SystemCredentialTransactionFactory.make()
            let result: CredentialTransactionResult
            if let value = box.value {
                result = transaction.apply(value)
            } else {
                result = .failure(code: .readFailed)
            }
            box.value = nil
            DispatchQueue.main.async { [weak self] in
                self?.apply(self?.lifecycle.handle(.credentialTransactionCompleted(result)) ?? AppLifecycleTransition(terminationDirective: .none, effects: []))
            }
        }
    }

    private func scheduleStartupRetry(after delay: TimeInterval) {
        cancelStartupRetry()
        let workItem = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.apply(self.lifecycle.handle(.startupRetryTimerFired))
        }
        startupRetryWorkItem = workItem
        DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: workItem)
    }

    private func cancelStartupRetry() {
        startupRetryWorkItem?.cancel()
        startupRetryWorkItem = nil
    }

    private func presentCredentialResetFailure(_ code: String) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Unable to reset HYU VPN login information"
        alert.informativeText = "Credential Reset Result: \(code)"
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    private func presentQuitFailure(_ code: String) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Unable to quit HYU VPN"
        alert.informativeText = "Last Control Result: \(code)"
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }

    private func applyFirstLaunchLoginItemDefault() {
        let choice = UserDefaults.standard.object(forKey: launchAtLoginUserChoiceKey) as? Bool
        guard LoginItemStartupPolicy.shouldRegisterOnLaunch(userChoice: choice, state: loginItemState) else { return }
        do {
            try loginItemController.setEnabled(true)
            UserDefaults.standard.set(true, forKey: launchAtLoginUserChoiceKey)
            lastLoginItemResult = "LOGIN_ITEM_OK"
            refreshLoginItemState()
        } catch LoginItemControllerError.unavailable(let code) {
            lastLoginItemResult = code
            refreshLoginItemState()
        } catch {
            lastLoginItemResult = "LOGIN_ITEM_REGISTER_FAILED"
            refreshLoginItemState()
        }
    }

    private func refreshLoginItemState() {
        loginItemState = loginItemController.state()
        if case .unavailable(let code) = loginItemState {
            lastLoginItemResult = code
        }
    }

    private func loginItemMenuItemModel() -> MenuItemModel {
        if let status = currentStatus {
            return MenuModel.make(status: status, diagnostics: "", launchAtLogin: loginItemState)[.launchAtLogin] ?? MenuItemModel(title: "Launch at Login Unavailable", isEnabled: false, isChecked: false, command: nil)
        }
        switch loginItemState {
        case .enabled:
            return MenuItemModel(title: "Launch at Login", isEnabled: true, isChecked: true, command: nil)
        case .disabled:
            return MenuItemModel(title: "Launch at Login", isEnabled: true, isChecked: false, command: nil)
        case .approvalRequired:
            return MenuItemModel(title: "Launch at Login (Open System Settings…)", isEnabled: true, isChecked: false, command: nil)
        case .unavailable:
            return MenuItemModel(title: "Launch at Login Unavailable", isEnabled: false, isChecked: false, command: nil)
        }
    }

    private func diagnosticsText() -> String {
        var lines = ["State: \(statusLineText())"]
        if let tunnelInterface = currentStatus?.tunnelInterface {
            lines.append("Tunnel Interface: \(tunnelInterface)")
        }
        if let backendError = currentStatus?.errorCode {
            lines.append("Backend Error: \(backendError)")
        }
        lines.append("Last Control Result: \(normalizedControlResult(lastControlResult))")
        lines.append("Login Item Result: \(lastLoginItemResult)")
        if let buildVersion = currentStatus?.backendBuildVersion {
            lines.append("Build Version: \(buildVersion)")
        }
        return lines.joined(separator: "\n")
    }

    private func normalizedControlResult(_ result: ControlResult?) -> String {
        guard let result else { return "UNAVAILABLE" }
        switch result.status {
        case .ok:
            return "CONTROL_OK"
        case .timeout:
            return result.errorCode ?? "CONTROL_TIMEOUT"
        case .failed:
            return result.errorCode ?? "CONTROL_FAILED"
        }
    }
}
