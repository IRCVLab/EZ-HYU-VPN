import AppKit
import Foundation
import HYUVPNMenuCore

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, StatusUpdateSink, StatusValueSink {
    private var statusItem: NSStatusItem?
    private var watcher: StatusWatcher?
    private var currentStatus: VPNStatus?
    private var lastPresentation = MenuPresentation(statusItemTitle: "", primaryText: "Status unavailable", detailText: "", symbolName: "exclamationmark.shield.fill")
    private var lastControlStatus = ""
    private let control = SecureVPNControlClient()

    func applicationDidFinishLaunching(_ notification: Notification) {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem = item
        if let button = item.button {
            button.image = NSImage(systemSymbolName: "exclamationmark.shield.fill", accessibilityDescription: "HYU VPN")
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
            self?.rebuildMenu()
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
            appendModeledItems(MenuModel.make(status: status, diagnostics: lastControlStatus, launchAtLogin: .disabled), to: menu)
        } else {
            menu.addItem(NSMenuItem(title: lastPresentation.primaryText, action: nil, keyEquivalent: ""))
            menu.addItem(NSMenuItem(title: lastPresentation.detailText, action: nil, keyEquivalent: ""))
        }
        statusItem?.menu = menu
    }

    private func appendModeledItems(_ model: [MenuAction: MenuItemModel], to menu: NSMenu) {
        add(.currentState, nil, model, menu)
        menu.addItem(NSMenuItem.separator())
        add(.primaryConnection, #selector(primaryConnection), model, menu)
        add(.disconnect, #selector(disconnect), model, menu)
        menu.addItem(NSMenuItem.separator())
        add(.diagnostics, #selector(showDiagnostics), model, menu)
        menu.addItem(NSMenuItem.separator())
        add(.quit, #selector(quit), model, menu)
    }

    private func add(_ action: MenuAction, _ selector: Selector?, _ model: [MenuAction: MenuItemModel], _ menu: NSMenu) {
        guard let itemModel = model[action], !itemModel.title.isEmpty else { return }
        let item = NSMenuItem(title: itemModel.title, action: selector, keyEquivalent: action == .quit ? "q" : "")
        item.target = self; item.isEnabled = itemModel.isEnabled; item.state = itemModel.isChecked ? .on : .off
        item.representedObject = itemModel.command
        menu.addItem(item)
    }

    @objc private func primaryConnection(_ sender: NSMenuItem) {
        guard let command = sender.representedObject as? VPNControlCommand else { return }
        launch(command)
    }
    @objc private func disconnect() { launch(.disconnect) }
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

let application = NSApplication.shared
let delegate = AppDelegate()
application.delegate = delegate
application.setActivationPolicy(.accessory)
application.run()
