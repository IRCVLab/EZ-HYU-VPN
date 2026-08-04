import AppKit
import Foundation
import UserNotifications
import HYUVPNMenuCore

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, StatusUpdateSink, StatusValueSink {
    private var statusItem: NSStatusItem?
    private var watcher: StatusWatcher?
    private var currentStatus: VPNStatus?
    private var lastPresentation = MenuPresentation(statusItemTitle: "", primaryText: "Status unavailable", detailText: "", symbolName: "exclamationmark.shield", countdownText: "", connectedDurationText: "")
    private var lastControlStatus = ""
    private lazy var notifications = AsyncNotificationCoordinator(store: UserDefaultsNotificationPreferenceStore(), client: UserNotificationClient())
    private let control = SecureVPNControlClient()

    func applicationDidFinishLaunching(_ notification: Notification) {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem = item
        if let button = item.button {
            button.image = NSImage(systemSymbolName: "exclamationmark.shield", accessibilityDescription: "HYU VPN")
            button.image?.isTemplate = true
            button.title = ""
        }
        item.menu = NSMenu(title: "HYU VPN")
        let configuration = StatusWatcherConfiguration.production()
        let statusReader = FileStatusReader(url: configuration.statusPath)
        let statusWatcher = StatusWatcher(configuration: configuration, reader: statusReader, sink: self)
        watcher = statusWatcher
        do { try statusWatcher.start() } catch { apply(lastPresentation) }
    }

    nonisolated func applyStatusValue(_ status: VPNStatus?) {
        DispatchQueue.main.async { [weak self] in
            self?.currentStatus = status
            if let status {
                self?.notifications.statusDidChange(status) { [weak self] result in
                    DispatchQueue.main.async {
                        if case .failure(let error) = result { self?.lastControlStatus = NotificationFailureDiagnostic.normalizedCode(for: error) }
                        self?.rebuildMenu()
                    }
                }
            } else { self?.notifications.statusUnavailable() }
        }
    }

    nonisolated func apply(_ presentation: MenuPresentation) {
        DispatchQueue.main.async { [weak self] in self?.applyPresentation(presentation) }
    }

    private func applyPresentation(_ presentation: MenuPresentation) {
        lastPresentation = presentation
        if let button = statusItem?.button {
            button.title = presentation.statusItemTitle
            button.image = NSImage(systemSymbolName: presentation.symbolName, accessibilityDescription: presentation.primaryText)
            button.image?.isTemplate = true
        }
        rebuildMenu()
    }

    private func rebuildMenu() {
        let menu = NSMenu(title: "HYU VPN")
        if let status = currentStatus {
            appendModeledItems(MenuModel.make(status: status, notificationsEnabled: notifications.isEnabled, diagnostics: lastControlStatus, now: Date()), to: menu)
        } else {
            menu.addItem(NSMenuItem(title: lastPresentation.primaryText, action: nil, keyEquivalent: ""))
            menu.addItem(NSMenuItem(title: lastPresentation.detailText, action: nil, keyEquivalent: ""))
        }
        statusItem?.menu = menu
    }

    private func appendModeledItems(_ model: [MenuAction: MenuItemModel], to menu: NSMenu) {
        add(.currentState, nil, model, menu); add(.expiry, nil, model, menu); add(.connectedDuration, nil, model, menu)
        menu.addItem(NSMenuItem.separator())
        add(.connect, #selector(connect), model, menu); add(.disconnect, #selector(disconnect), model, menu); add(.reconnect, #selector(reconnect), model, menu)
        menu.addItem(NSMenuItem.separator())
        add(.automaticReconnect, #selector(toggleAutomatic), model, menu); add(.expiryNotifications, #selector(toggleNotifications), model, menu)
        menu.addItem(NSMenuItem.separator())
        add(.diagnostics, #selector(showDiagnostics), model, menu)
        menu.addItem(NSMenuItem.separator())
        add(.quit, #selector(quit), model, menu)
    }

    private func add(_ action: MenuAction, _ selector: Selector?, _ model: [MenuAction: MenuItemModel], _ menu: NSMenu) {
        guard let itemModel = model[action], !itemModel.title.isEmpty else { return }
        let item = NSMenuItem(title: itemModel.title, action: selector, keyEquivalent: action == .quit ? "q" : "")
        item.target = self; item.isEnabled = itemModel.isEnabled; item.state = itemModel.isChecked ? .on : .off
        menu.addItem(item)
    }

    @objc private func connect() { launch(.connect) }
    @objc private func disconnect() { launch(.disconnect) }
    @objc private func reconnect() { launch(.reconnect) }
    @objc private func toggleAutomatic() { if let status = currentStatus { launch(.setAutomaticReconnect(!status.automaticReconnectEnabled)) } }
    @objc private func toggleNotifications() {
        guard let status = currentStatus else { return }
        notifications.setEnabled(!notifications.isEnabled, status: status) { [weak self] result in
            DispatchQueue.main.async {
                if case .failure(let error) = result { self?.lastControlStatus = NotificationFailureDiagnostic.normalizedCode(for: error) }
                self?.rebuildMenu()
            }
        }
    }
    @objc private func showDiagnostics() { rebuildMenu() }
    @objc private func quit() { NSApp.terminate(nil) }

    private func launch(_ command: VPNControlCommand) {
        let client = control
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let result: ControlResult
            do { result = try client.run(command) } catch { result = ControlResult(status: .failed, errorCode: "CONTROL_INSECURE") }
            DispatchQueue.main.async {
                self?.lastControlStatus = result.errorCode ?? "CONTROL_OK"
                self?.rebuildMenu()
            }
        }
    }
}


final class NotificationScheduleBox: @unchecked Sendable { private let lock = NSLock(); private var stored: Error?; func record(_ error: Error) { lock.lock(); if stored == nil { stored = error }; lock.unlock() }; var error: Error? { lock.lock(); defer { lock.unlock() }; return stored } }

final class UserNotificationClient: AsyncNotificationClient, @unchecked Sendable {
    func requestAuthorization(completion: @escaping @Sendable (Result<Bool, Error>) -> Void) {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { granted, error in
            if let error { completion(.failure(error)) } else { completion(.success(granted)) }
        }
    }
    func cancel(_ identifiers: [String]) { UNUserNotificationCenter.current().removePendingNotificationRequests(withIdentifiers: identifiers) }
    func schedule(_ requests: [PlannedNotification], completion: @escaping @Sendable (Result<Void, Error>) -> Void) {
        guard !requests.isEmpty else { completion(.success(())); return }
        let group = DispatchGroup()
        let box = NotificationScheduleBox()
        for request in requests {
            group.enter()
            let content = UNMutableNotificationContent(); content.title = request.title; content.body = request.body
            let trigger = UNTimeIntervalNotificationTrigger(timeInterval: TimeInterval(request.timeInterval), repeats: false)
            UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: request.identifier, content: content, trigger: trigger)) { error in
                if let error { box.record(error) }
                group.leave()
            }
        }
        group.notify(queue: .global(qos: .utility)) {
            if let error = box.error { completion(.failure(error)) } else { completion(.success(())) }
        }
    }
}


let application = NSApplication.shared
let delegate = AppDelegate()
application.delegate = delegate
application.setActivationPolicy(.accessory)
application.run()
