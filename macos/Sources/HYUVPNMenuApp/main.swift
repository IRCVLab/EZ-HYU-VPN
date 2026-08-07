import AppKit
import Darwin
import Foundation
import HYUVPNMenuCore
import HYUVPNMenuAppSupport

enum BootstrapMode: Equatable {
    case app
    case registerLoginItem
    case unregisterLoginItem

    static func parse(_ arguments: [String]) -> BootstrapMode? {
        switch Array(arguments.dropFirst()) {
        case []:
            return .app
        case ["--register-login-item"]:
            return .registerLoginItem
        case ["--unregister-login-item"]:
            return .unregisterLoginItem
        default:
            return nil
        }
    }
}

private func printOutcome(_ code: String) {
    FileHandle.standardOutput.write(Data((code + "\n").utf8))
}

private func runLoginItemMode(_ mode: BootstrapMode) -> Never {
    var controller = SystemLoginItemController()
    switch mode {
    case .registerLoginItem:
        do {
            try controller.setEnabled(true)
            printOutcome("LOGIN_ITEM_REGISTERED")
            exit(EX_OK)
        } catch LoginItemControllerError.unavailable(let code) {
            printOutcome(code)
            exit(1)
        } catch {
            printOutcome("LOGIN_ITEM_REGISTER_FAILED")
            exit(1)
        }
    case .unregisterLoginItem:
        switch controller.state() {
        case .disabled:
            printOutcome("LOGIN_ITEM_NOT_REGISTERED")
            exit(EX_OK)
        case .unavailable(let code) where code == "LOGIN_ITEM_NOT_FOUND":
            printOutcome("LOGIN_ITEM_NOT_FOUND")
            exit(EX_OK)
        case .unavailable(let code):
            printOutcome(code)
            exit(1)
        case .enabled, .approvalRequired:
            do {
                try controller.setEnabled(false)
                printOutcome("LOGIN_ITEM_UNREGISTERED")
                exit(EX_OK)
            } catch LoginItemControllerError.unavailable(let code) {
                printOutcome(code)
                exit(1)
            } catch {
                printOutcome("LOGIN_ITEM_UNREGISTER_FAILED")
                exit(1)
            }
        }
    case .app:
        fatalError("app mode is not a login item CLI mode")
    }
}

guard let mode = BootstrapMode.parse(ProcessInfo.processInfo.arguments) else {
    exit(EX_USAGE)
}

switch mode {
case .app:
    let application = NSApplication.shared
    let delegate = AppDelegate()
    application.delegate = delegate
    application.setActivationPolicy(.accessory)
    withExtendedLifetime(delegate) {
        application.run()
    }
case .registerLoginItem, .unregisterLoginItem:
    runLoginItemMode(mode)
}
