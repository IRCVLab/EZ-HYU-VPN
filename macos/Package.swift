// swift-tools-version: 6.0
import PackageDescription

let frameworkPath = "/Library/Developer/CommandLineTools/Library/Developer/Frameworks"
let interopPath = "/Library/Developer/CommandLineTools/Library/Developer/usr/lib"
let package = Package(
    name: "HYUVPNPrivilegedHelperPackage",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "HYUVPNPrivilegedHelper", targets: ["HYUVPNPrivilegedHelper"]),
        .executable(name: "hyu-vpn-privileged-helper", targets: ["HYUVPNPrivilegedHelperCLI"]),
        .executable(name: "hyu-vpn-helper-test-harness", targets: ["HYUVPNPrivilegedHelperTestHarness"]),
        .executable(name: "hyu-vpnc-wrapperd", targets: ["HYUVPNCWrapperD"]),
        .library(name: "HYUVPNMenuCore", targets: ["HYUVPNMenuCore"]),
        .executable(name: "HYUVPNMenuApp", targets: ["HYUVPNMenuApp"]),
        .executable(name: "hyu-vpn-menu-harness", targets: ["HYUVPNMenuAppTestHarness"]),
    ],
    targets: [
        .target(
            name: "HYUVPNPrivilegedHelper",
            swiftSettings: [.unsafeFlags(["-warnings-as-errors"])]
        ),
        .executableTarget(
            name: "HYUVPNPrivilegedHelperCLI",
            dependencies: ["HYUVPNPrivilegedHelper"],
            swiftSettings: [.unsafeFlags(["-warnings-as-errors"])]
        ),
        .executableTarget(
            name: "HYUVPNPrivilegedHelperTestHarness",
            dependencies: ["HYUVPNPrivilegedHelper"],
            path: "Tests/HYUVPNPrivilegedHelperTestHarness",
            swiftSettings: [.unsafeFlags(["-warnings-as-errors"])]
        ),
        .executableTarget(
            name: "HYUVPNCWrapperD",
            dependencies: ["HYUVPNPrivilegedHelper"],
            swiftSettings: [.unsafeFlags(["-warnings-as-errors"])]
        ),
        .target(
            name: "HYUVPNMenuCore",
            swiftSettings: [.unsafeFlags(["-warnings-as-errors"])]
        ),
        .target(
            name: "HYUVPNKeychainAccessShim",
            publicHeadersPath: "include",
            cSettings: [.unsafeFlags(["-Wall", "-Wextra", "-Werror"])]
        ),
        .target(
            name: "HYUVPNMenuAppSupport",
            dependencies: ["HYUVPNMenuCore", "HYUVPNKeychainAccessShim"],
            path: "Sources/HYUVPNMenuApp",
            exclude: ["main.swift", "AppDelegate.swift"],
            sources: ["CredentialResetController.swift", "SystemAdapters.swift"],
            swiftSettings: [.unsafeFlags(["-warnings-as-errors"])]
        ),
        .executableTarget(
            name: "HYUVPNMenuApp",
            dependencies: ["HYUVPNMenuCore", "HYUVPNMenuAppSupport"],
            path: "Sources/HYUVPNMenuApp",
            exclude: ["CredentialResetController.swift", "SystemAdapters.swift"],
            sources: ["main.swift", "AppDelegate.swift"],
            swiftSettings: [.unsafeFlags(["-warnings-as-errors"])]
        ),
        .executableTarget(
            name: "HYUVPNMenuAppTestHarness",
            dependencies: ["HYUVPNMenuCore", "HYUVPNMenuAppSupport"],
            path: "Tests/HYUVPNMenuAppTestHarness",
            swiftSettings: [.unsafeFlags(["-warnings-as-errors"])]
        ),
        .testTarget(
            name: "HYUVPNMenuAppTests",
            dependencies: ["HYUVPNMenuCore"],
            swiftSettings: [.unsafeFlags(["-F", frameworkPath, "-warnings-as-errors"])],
            linkerSettings: [.unsafeFlags(["-F", frameworkPath, "-Xlinker", "-rpath", "-Xlinker", frameworkPath, "-Xlinker", "-rpath", "-Xlinker", interopPath])]
        ),
        .testTarget(
            name: "HYUVPNPrivilegedHelperTests",
            dependencies: ["HYUVPNPrivilegedHelper"],
            swiftSettings: [.unsafeFlags(["-F", frameworkPath, "-warnings-as-errors"])],
            linkerSettings: [.unsafeFlags(["-F", frameworkPath, "-Xlinker", "-rpath", "-Xlinker", frameworkPath, "-Xlinker", "-rpath", "-Xlinker", interopPath])]
        ),
    ]
)
