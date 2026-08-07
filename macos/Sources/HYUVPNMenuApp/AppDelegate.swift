import AppKit
import Foundation
import HYUVPNMenuCore

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, StatusUpdateSink, StatusValueSink {
    private enum ControlFollowUp {
        case none
        case startup
        case quit
    }

    private var statusItem: NSStatusItem?
    private var watcher: StatusWatcher?
    private var currentStatus: VPNStatus?
    private var currentPresentation = MenuPresentation(statusItemTitle: "", primaryText: "Status Unavailable", detailText: "", symbolName: "exclamationmark.shield.fill")
    private var lastControlResult: ControlResult?
    private let control = SecureVPNControlClient()
    private var operationGate = OperationGate()
    private var startupConnectPolicy = StartupConnectPolicy()
    private var startupRetryWorkItem: DispatchWorkItem?
    private var startupConnectPaused = false
    private var pendingDisconnectRequest = false
    private var terminationPending = false
    private var quitReplyPending = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        installStatusItem()
        rebuildMenu()
        startWatcher()
        runControl(command: .connect, operation: .connect, followUp: .startup)
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        terminationPending = true
        rebuildMenu()
        startTerminationIfPossible()
        return .terminateLater
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
        let menu = NSMenu(title: "HYU VPN")
        menu.addItem(disabledItem(title: statusLineText()))
        menu.addItem(NSMenuItem.separator())
        addPrimaryAction(to: menu)
        addDisconnectAction(to: menu)
        menu.addItem(NSMenuItem.separator())
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

    private func addDiagnosticsAction(to menu: NSMenu) {
        let item = NSMenuItem(title: "Diagnostics…", action: #selector(showDiagnostics), keyEquivalent: "")
        item.target = self
        item.isEnabled = !controlsDisabled
        menu.addItem(item)
    }

    private func addQuitAction(to menu: NSMenu) {
        let item = NSMenuItem(title: "Quit HYU VPN", action: #selector(quit), keyEquivalent: "q")
        item.target = self
        item.isEnabled = !controlsDisabled
        menu.addItem(item)
    }

    private func disabledItem(title: String) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        item.isEnabled = false
        return item
    }

    private var controlsDisabled: Bool {
        operationGate.isBusy || terminationPending || quitReplyPending
    }

    private func primaryAction() -> (title: String, command: VPNControlCommand?, isEnabled: Bool) {
        guard let status = currentStatus else {
            return ("Connect", nil, false)
        }
        switch status.state {
        case .connected:
            return ("Reconnect", controlsDisabled ? nil : .reconnect, !controlsDisabled)
        case .connecting:
            return ("Connecting…", nil, false)
        case .disconnecting:
            return ("Disconnecting…", nil, false)
        case .disabled:
            return ("Connect", controlsDisabled ? nil : .connect, !controlsDisabled)
        case .waitingForNetwork:
            return ("Waiting for Network", nil, false)
        case .backoff:
            return ("Reconnect Now", controlsDisabled ? nil : .reconnect, !controlsDisabled)
        case .error:
            return ("Reconnect", controlsDisabled ? nil : .reconnect, !controlsDisabled)
        }
    }

    private func disconnectEnabled() -> Bool {
        guard let status = currentStatus else { return false }
        guard !controlsDisabled else { return false }
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
        startupRetryWorkItem?.cancel()
        startupRetryWorkItem = nil
        startupConnectPaused = false
        pendingDisconnectRequest = false
        let operation: ControlTowerOperation = command == .connect ? .connect : .reconnect
        runControl(command: command, operation: operation)
    }

    @objc private func disconnect() {
        startupRetryWorkItem?.cancel()
        startupRetryWorkItem = nil
        startupConnectPaused = true
        pendingDisconnectRequest = true
        startPendingDisconnectIfNeeded()
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

    private func runControl(
        command: VPNControlCommand,
        operation: ControlTowerOperation,
        timeout: TimeInterval = 3,
        followUp: ControlFollowUp = .none
    ) {
        guard operationGate.begin(operation) else { return }
        rebuildMenu()
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
                self.operationGate.finish(operation)
                self.rebuildMenu()
                switch followUp {
                case .none:
                    break
                case .startup:
                    self.handleStartupConnectResult(result)
                case .quit:
                    self.handleQuitDisconnectResult(result)
                }
                if self.terminationPending, followUp != .quit {
                    self.startTerminationIfPossible()
                }
                self.startPendingDisconnectIfNeeded()
            }
        }
    }

    private func handleStartupConnectResult(_ result: ControlResult) {
        guard !startupConnectPaused else { return }
        switch startupConnectPolicy.next(after: startupOutcome(for: result)) {
        case .retry(let delay):
            scheduleStartupRetry(after: delay)
        case .stop:
            startupRetryWorkItem?.cancel()
            startupRetryWorkItem = nil
        }
    }

    private func startPendingDisconnectIfNeeded() {
        guard pendingDisconnectRequest else { return }
        guard !operationGate.isBusy else { return }
        pendingDisconnectRequest = false
        runControl(command: .disconnect, operation: .disconnect)
    }

    private func scheduleStartupRetry(after delay: TimeInterval) {
        guard !startupConnectPaused else { return }
        startupRetryWorkItem?.cancel()
        let workItem = DispatchWorkItem { [weak self] in
            guard let self else { return }
            guard !startupConnectPaused else { return }
            runControl(command: .connect, operation: .connect, followUp: .startup)
        }
        startupRetryWorkItem = workItem
        DispatchQueue.main.asyncAfter(deadline: .now() + delay, execute: workItem)
    }

    private func startupOutcome(for result: ControlResult) -> StartupConnectOutcome {
        switch result.status {
        case .ok:
            return .success
        case .timeout:
            return .failure(code: result.errorCode ?? "CONTROL_TIMEOUT")
        case .failed:
            switch result.errorCode {
            case "CONTROL_LAUNCH_FAILED":
                return .launchFailure
            case "CONTROL_UNAVAILABLE":
                return .controlUnavailable
            default:
                return .failure(code: result.errorCode ?? "CONTROL_FAILED")
            }
        }
    }

    private func startTerminationIfPossible() {
        guard terminationPending else { return }
        guard !quitReplyPending else { return }
        guard !operationGate.isBusy else { return }
        quitReplyPending = true
        runControl(command: .disconnect, operation: .quit, timeout: 15, followUp: .quit)
    }

    private func handleQuitDisconnectResult(_ result: ControlResult) {
        quitReplyPending = false
        switch result.status {
        case .ok:
            terminationPending = false
            NSApp.reply(toApplicationShouldTerminate: true)
        case .failed, .timeout:
            terminationPending = false
            rebuildMenu()
            presentQuitFailure(result)
            NSApp.reply(toApplicationShouldTerminate: false)
        }
    }

    private func presentQuitFailure(_ result: ControlResult) {
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Unable to quit HYU VPN"
        alert.informativeText = "Last Control Result: \(normalizedControlResult(result))"
        alert.addButton(withTitle: "OK")
        alert.runModal()
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
