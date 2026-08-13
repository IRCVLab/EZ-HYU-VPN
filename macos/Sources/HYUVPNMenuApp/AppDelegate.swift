import AppKit
import Foundation
import HYUVPNMenuCore
import HYUVPNMenuAppSupport

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem?
    private var currentStatus: VPNStatus?
    private var currentPresentation = MenuPresentation(statusItemTitle: "", primaryText: "Status Unavailable", detailText: "", symbolName: "exclamationmark.shield.fill")
    private let service: any VPNServiceRequesting
    private var lifecycle = AppLifecycleCoordinator()
    private var startupRetryWorkItem: DispatchWorkItem?
    private var resetController: CredentialResetController?
    private var pendingResetPayload: ValidatedCredentials?
    private var currentOTPSnapshot: TOTPDisplaySnapshot?
    private var otpMenuItem: NSMenuItem?
    private var serviceRefreshTimer: Timer?
    private var serviceRefreshInFlight = false
    private var serviceRefreshCoordinator = ServiceRefreshCoordinator()
    private var loginItemController = SystemLoginItemController()
    private var loginItemState: LoginItemState = .disabled
    private var lastLoginItemResult = "LOGIN_ITEM_UNAVAILABLE"
    private let launchAtLoginUserChoiceKey = "hyu.vpn.launchAtLogin.userChoice"
    private let lastAnnouncedUpdateKey = "hyu.vpn.update.lastAnnouncedVersion"
    private let lastUpdateCheckKey = "hyu.vpn.update.lastCheckTime"
    private let updateCheckInterval: TimeInterval = 6 * 60 * 60
    private var updateChecker: UpdateChecking?
    private var updateOffer: UpdateOffer?
    private var updateCheckTimer: Timer?

    init(service: any VPNServiceRequesting = RustIPCClient()) {
        self.service = service
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        installStatusItem()
        refreshLoginItemState()
        applyFirstLaunchLoginItemDefault()
        rebuildMenu()
        apply(lifecycle.handle(.appLaunched))
        startServiceRefreshTimer()
        configureUpdateChecker()
        startUpdateChecks()
    }

    func applicationWillTerminate(_ notification: Notification) {
        serviceRefreshTimer?.invalidate()
        serviceRefreshTimer = nil
        updateCheckTimer?.invalidate()
        updateCheckTimer = nil
    }

    func applicationDidBecomeActive(_ notification: Notification) {
        refreshLoginItemState()
        refreshServiceSnapshot(force: true)
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

    private func installStatusItem() {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)
        statusItem = item
        refreshStatusButton()
        item.menu = NSMenu(title: "HYU VPN")
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
        addOTPAction(to: menu)
        addPrimaryAction(to: menu)
        addDisconnectAction(to: menu)
        menu.addItem(NSMenuItem.separator())
        addResetAction(to: menu)
        addLaunchAtLoginAction(to: menu)
        addUpdateAction(to: menu)
        menu.addItem(NSMenuItem.separator())
        addQuitAction(to: menu)
        statusItem?.menu = menu
    }

    private func addOTPAction(to menu: NSMenu) {
        let item = NSMenuItem(title: "OTP unavailable", action: #selector(copyOTP(_:)), keyEquivalent: "")
        item.target = self
        otpMenuItem = item
        refreshOTPItem()
        menu.addItem(item)
    }

    private func startServiceRefreshTimer() {
        serviceRefreshTimer?.invalidate()
        let timer = Timer(timeInterval: 1, target: self, selector: #selector(refreshServiceFromTimer), userInfo: nil, repeats: true)
        RunLoop.main.add(timer, forMode: .common)
        serviceRefreshTimer = timer
        refreshServiceSnapshot(force: true)
    }

    @objc private func refreshServiceFromTimer() {
        refreshServiceSnapshot()
    }

    private func refreshOTPItem() {
        guard let item = otpMenuItem else { return }
        let model = OTPMenuPresenter.model(snapshot: currentOTPSnapshot)
        item.title = model.title
        item.representedObject = model.code
        item.isEnabled = model.isEnabled
    }

    private func refreshServiceSnapshot(force: Bool = false) {
        guard let generation = serviceRefreshCoordinator.begin(force: force) else { return }
        serviceRefreshInFlight = true
        performRefresh(generation: generation)
    }

    private func performRefresh(generation: Int) {
        service.request(.status) { [weak self] result in
            Task { @MainActor [weak self] in
                guard let self else { return }
                if self.serviceRefreshCoordinator.shouldApply(generation: generation) {
                    self.applyStatusSnapshot(result)
                }
                guard self.serviceRefreshCoordinator.shouldContinue(generation: generation) else {
                    self.completeRefresh(generation: generation)
                    return
                }
                self.service.request(.currentOTP) { [weak self] otpResult in
                    Task { @MainActor [weak self] in
                        guard let self else { return }
                        if self.serviceRefreshCoordinator.shouldApply(generation: generation) {
                            self.applyOTPSnapshot(otpResult)
                        }
                        self.completeRefresh(generation: generation)
                    }
                }
            }
        }
    }

    private func completeRefresh(generation: Int) {
        if let nextGeneration = serviceRefreshCoordinator.finish(generation: generation) {
            performRefresh(generation: nextGeneration)
            return
        }
        serviceRefreshInFlight = false
    }

    private func applyStatusSnapshot(_ result: Result<VPNResponse, VPNServiceError>) {
        switch result {
        case .success(.status(let status)):
            currentStatus = status
            currentPresentation = MenuPresenter.present(status)
        default:
            currentStatus = nil
            currentPresentation = MenuPresentation(statusItemTitle: "", primaryText: "Status unavailable", detailText: "CONTROL_STATUS_UNAVAILABLE", symbolName: "exclamationmark.shield.fill")
        }
        refreshStatusButton()
        rebuildMenu()
    }

    private func applyOTPSnapshot(_ result: Result<VPNResponse, VPNServiceError>) {
        switch result {
        case .success(.currentOTP(let snapshot)):
            currentOTPSnapshot = snapshot
        default:
            currentOTPSnapshot = nil
        }
        refreshOTPItem()
    }

    @objc private func copyOTP(_ sender: NSMenuItem) {
        guard let candidate = sender.representedObject as? String,
              let code = OTPClipboardPolicy.copyableCode(candidate) else { return }
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(code, forType: .string)
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

    private func addQuitAction(to menu: NSMenu) {
        let item = NSMenuItem(title: "Quit HYU VPN", action: #selector(quit), keyEquivalent: "q")
        item.target = self
        item.isEnabled = !lifecycle.controlsDisabled
        menu.addItem(item)
    }

    private func addUpdateAction(to menu: NSMenu) {
        guard let offer = updateOffer else { return }
        let item = NSMenuItem(title: "Update Available: v\(offer.version)…", action: #selector(openUpdate(_:)), keyEquivalent: "")
        item.target = self
        item.representedObject = offer.releaseURL
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
        let controller = CredentialResetController(prefillUsername: nil) { [weak self] controller, value in
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

    @objc private func quit() {
        NSApp.sendAction(#selector(NSApplication.terminate(_:)), to: nil, from: self)
    }

    @objc private func openUpdate(_ sender: NSMenuItem) {
        guard let offer = updateOffer,
              let representedURL = sender.representedObject as? URL,
              representedURL == offer.releaseURL
        else { return }
        NSWorkspace.shared.open(offer.releaseURL)
    }

    private func configureUpdateChecker() {
        guard let versionString = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String,
              let currentVersion = SemanticVersion(versionString),
              let feedString = Bundle.main.object(forInfoDictionaryKey: "HYUUpdateFeedURL") as? String,
              let feedURL = URL(string: feedString),
              let allowedHost = Bundle.main.object(forInfoDictionaryKey: "HYUUpdateAllowedReleaseHost") as? String,
              let allowedPath = Bundle.main.object(forInfoDictionaryKey: "HYUUpdateAllowedReleasePathPrefix") as? String
        else { return }
        updateChecker = HTTPSUpdateChecker(policy: UpdatePolicy(
            currentVersion: currentVersion,
            feedURL: feedURL,
            allowedReleaseHost: allowedHost,
            allowedReleasePathPrefix: allowedPath
        ))
    }

    private func startUpdateChecks() {
        guard updateChecker != nil else { return }
        DispatchQueue.main.asyncAfter(deadline: .now() + 5) { [weak self] in self?.performUpdateCheck() }
        let timer = Timer(timeInterval: updateCheckInterval, target: self, selector: #selector(performScheduledUpdateCheck), userInfo: nil, repeats: true)
        RunLoop.main.add(timer, forMode: .common)
        updateCheckTimer = timer
    }

    @objc private func performScheduledUpdateCheck() {
        performUpdateCheck()
    }

    private func performUpdateCheck() {
        let now = Date().timeIntervalSince1970
        let lastCheck = UserDefaults.standard.double(forKey: lastUpdateCheckKey)
        guard lastCheck == 0 || now - lastCheck >= updateCheckInterval else { return }
        UserDefaults.standard.set(now, forKey: lastUpdateCheckKey)
        updateChecker?.check { [weak self] offer in
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                self.updateOffer = offer
                self.rebuildMenu()
                if let offer { self.presentUpdateAlertIfNeeded(offer) }
            }
        }
    }

    private func presentUpdateAlertIfNeeded(_ offer: UpdateOffer) {
        let version = offer.version.description
        guard UserDefaults.standard.string(forKey: lastAnnouncedUpdateKey) != version else { return }
        UserDefaults.standard.set(version, forKey: lastAnnouncedUpdateKey)
        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = "HYU VPN v\(version) is available"
        alert.informativeText = "A newer version is available to download. Your VPN connection will not be changed."
        alert.addButton(withTitle: "Download")
        alert.addButton(withTitle: "Later")
        NSApp.activate(ignoringOtherApps: true)
        if alert.runModal() == .alertFirstButtonReturn {
            NSWorkspace.shared.open(offer.releaseURL)
        }
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
        let serviceCommand: VPNCommand
        switch command {
        case .connect: serviceCommand = .connect
        case .disconnect: serviceCommand = .disconnect
        case .reconnect: serviceCommand = .reconnect
        case .setAutomaticReconnect(let enabled): serviceCommand = .automaticReconnect(enabled)
        }
        service.request(serviceCommand) { [weak self] result in
            Task { @MainActor [weak self] in
                guard let self else { return }
                let controlResult: ControlResult
                switch result {
            case .success(.ack):
                controlResult = ControlResult(status: .ok, errorCode: nil)
            case .success(.error(let code)):
                controlResult = ControlResult(status: .failed, errorCode: code.rawValue)
            case .success:
                controlResult = ControlResult(status: .failed, errorCode: "CONTROL_PROTOCOL")
            case .failure(.timeout):
                controlResult = ControlResult(status: .timeout, errorCode: "CONTROL_TIMEOUT")
            case .failure(.unavailable):
                controlResult = ControlResult(status: .failed, errorCode: "CONTROL_UNAVAILABLE")
            case .failure(.backend(let code)):
                controlResult = ControlResult(status: .failed, errorCode: code.rawValue)
            case .failure:
                controlResult = ControlResult(status: .failed, errorCode: "CONTROL_INSECURE")
            }
                self.apply(self.lifecycle.handle(.controlCompleted(operation: operation, result: controlResult)))
                self.refreshServiceSnapshot(force: true)
                _ = timeout
            }
        }
    }

    private func runCredentialTransaction() {
        guard let payload = pendingResetPayload,
              let seed = payload.normalizedTOTPSeed else {
            apply(lifecycle.handle(.credentialTransactionCompleted(.failure(code: .writeFailed))))
            return
        }
        pendingResetPayload = nil
        service.replaceCredentials(CredentialInput(username: payload.username, password: payload.password, totpSeed: seed)) { [weak self] result in
            Task { @MainActor [weak self] in
                guard let self else { return }
                let transactionResult: CredentialTransactionResult
                switch result {
            case .success:
                transactionResult = .success
            case .failure:
                transactionResult = .failure(code: .writeFailed)
            }
                self.apply(self.lifecycle.handle(.credentialTransactionCompleted(transactionResult)))
                self.refreshServiceSnapshot(force: true)
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
            return MenuModel.make(status: status, launchAtLogin: loginItemState)[.launchAtLogin] ?? MenuItemModel(title: "Launch at Login Unavailable", isEnabled: false, isChecked: false, command: nil)
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
}
