import AppKit
import Darwin
import Foundation

enum AppInvocation {
    case launch
    case registerLoginItem
    case unregisterLoginItem
}

private func parseInvocation(arguments: [String]) -> AppInvocation? {
    switch Array(arguments.dropFirst()) {
    case []:
        return .launch
    case ["--register-login-item"]:
        return .registerLoginItem
    case ["--unregister-login-item"]:
        return .unregisterLoginItem
    default:
        return nil
    }
}

private func exitUsage() -> Never {
    Foundation.exit(Int32(EX_USAGE))
}

private func exitLoginItemUnavailable() -> Never {
    FileHandle.standardError.write(Data("LOGIN_ITEM_UNAVAILABLE\n".utf8))
    Foundation.exit(Int32(EX_UNAVAILABLE))
}

let arguments = ProcessInfo.processInfo.arguments

guard let invocation = parseInvocation(arguments: arguments) else {
    exitUsage()
}

switch invocation {
case .launch:
    let application = NSApplication.shared
    let delegate = AppDelegate()
    application.delegate = delegate
    application.setActivationPolicy(.accessory)
    withExtendedLifetime(delegate) {
        application.run()
    }
case .registerLoginItem, .unregisterLoginItem:
    exitLoginItemUnavailable()
}
