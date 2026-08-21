import Foundation

public enum LoginItemState: Equatable, Sendable {
    case enabled
    case disabled
    case approvalRequired
    case unavailable(code: String)
}

public enum StartupConnectOutcome: Equatable, Sendable {
    case success
    case controlUnavailable
    case launchFailure
    case failure(code: String)
}

public enum StartupConnectDecision: Equatable, Sendable {
    case retry(after: TimeInterval)
    case stop
}

public struct StartupConnectPolicy: Equatable, Sendable {
    public static let maximumAttempts = 30
    private var transientAttempts: Int

    public init(transientAttempts: Int = 0) {
        self.transientAttempts = transientAttempts
    }

    public mutating func next(after outcome: StartupConnectOutcome) -> StartupConnectDecision {
        guard outcome.isTransient else { return .stop }
        transientAttempts += 1
        guard transientAttempts < Self.maximumAttempts else { return .stop }
        return .retry(after: 1)
    }
}

private extension StartupConnectOutcome {
    var isTransient: Bool {
        switch self {
        case .controlUnavailable, .launchFailure:
            return true
        case .failure(let code):
            return code == "CONTROL_UNAVAILABLE"
        case .success:
            return false
        }
    }
}

public enum ControlTowerOperation: Equatable, Hashable, Sendable {
    case connect
    case reconnect
    case disconnect
    case credentialSave
    case quit
}

public struct OperationGate: Equatable, Sendable {
    private var active: ControlTowerOperation?

    public init(active: ControlTowerOperation? = nil) {
        self.active = active
    }

    public var activeOperation: ControlTowerOperation? { active }
    public var isBusy: Bool { active != nil }

    public mutating func begin(_ operation: ControlTowerOperation) -> Bool {
        guard active == nil else { return false }
        active = operation
        return true
    }

    public mutating func finish(_ operation: ControlTowerOperation) {
        guard active == operation else { return }
        active = nil
    }
}

public enum AppLifecycleTerminationDirective: Equatable, Sendable {
    case none
    case terminateLater
    case terminateNow
}

public enum AppLifecycleEvent: Equatable, Sendable {
    case appLaunched
    case primaryConnectRequested
    case primaryReconnectRequested
    case disconnectRequested
    case terminateRequested
    case credentialResetRequested
    case credentialTransactionCompleted(CredentialTransactionResult)
    case startupRetryTimerFired
    case controlCompleted(operation: ControlTowerOperation, result: ControlResult)
}

public enum AppLifecycleEffect: Equatable, Sendable {
    case runControl(command: VPNControlCommand, operation: ControlTowerOperation, timeout: TimeInterval)
    case scheduleStartupRetry(after: TimeInterval)
    case cancelStartupRetry
    case replyToTermination(Bool)
    case showTerminationFailureAlert(String)
    case runCredentialTransaction
    case showCredentialResetError(String)
    case dismissCredentialReset
}

public struct AppLifecycleTransition: Equatable, Sendable {
    public let terminationDirective: AppLifecycleTerminationDirective
    public let effects: [AppLifecycleEffect]

    public init(terminationDirective: AppLifecycleTerminationDirective, effects: [AppLifecycleEffect]) {
        self.terminationDirective = terminationDirective
        self.effects = effects
    }
}

public struct AppLifecycleCoordinator: Equatable, Sendable {
    private enum ActiveSource: Equatable, Sendable {
        case startup
        case primaryConnect
        case primaryReconnect
        case disconnect
        case credentialDisconnect
        case credentialConnect
        case quit
    }

    private var startupPolicy: StartupConnectPolicy
    private var operationGate: OperationGate
    private var activeSource: ActiveSource?
    private var startupRetryScheduled: Bool
    private var startupConnectPaused: Bool
    private var pendingDisconnectRequest: Bool
    private var terminationPending: Bool
    private var terminationAttachedToDisconnect: Bool
    private var terminationResolved: Bool
    private var credentialTransactionRunning: Bool
    private var credentialCancelledBeforeTransaction: Bool

    public init(
        startupPolicy: StartupConnectPolicy = StartupConnectPolicy(),
        operationGate: OperationGate = OperationGate(),
        activeSource: ControlTowerOperation? = nil,
        startupRetryScheduled: Bool = false,
        startupConnectPaused: Bool = false,
        pendingDisconnectRequest: Bool = false,
        terminationPending: Bool = false,
        terminationAttachedToDisconnect: Bool = false,
        terminationResolved: Bool = false,
        credentialTransactionRunning: Bool = false,
        credentialCancelledBeforeTransaction: Bool = false
    ) {
        self.startupPolicy = startupPolicy
        self.operationGate = operationGate
        self.activeSource = activeSource.map {
            switch $0 {
            case .connect: return .primaryConnect
            case .reconnect: return .primaryReconnect
            case .disconnect: return .disconnect
            case .credentialSave: return .credentialDisconnect
            case .quit: return .quit
            }
        }
        self.startupRetryScheduled = startupRetryScheduled
        self.startupConnectPaused = startupConnectPaused
        self.pendingDisconnectRequest = pendingDisconnectRequest
        self.terminationPending = terminationPending
        self.terminationAttachedToDisconnect = terminationAttachedToDisconnect
        self.terminationResolved = terminationResolved
        self.credentialTransactionRunning = credentialTransactionRunning
        self.credentialCancelledBeforeTransaction = credentialCancelledBeforeTransaction
    }

    public var activeOperation: ControlTowerOperation? { operationGate.activeOperation }
    public var controlsDisabled: Bool { operationGate.isBusy || terminationPending }

    public mutating func handle(_ event: AppLifecycleEvent) -> AppLifecycleTransition {
        if terminationResolved {
            if case .terminateRequested = event {
                return AppLifecycleTransition(terminationDirective: .terminateNow, effects: [])
            }
            return AppLifecycleTransition(terminationDirective: .none, effects: [])
        }

        switch event {
        case .appLaunched:
            return startControlIfPossible(command: .connect, operation: .connect, timeout: 3, source: .startup)

        case .primaryConnectRequested:
            return startPrimary(command: .connect, operation: .connect, source: .primaryConnect)

        case .primaryReconnectRequested:
            return startPrimary(command: .reconnect, operation: .reconnect, source: .primaryReconnect)

        case .disconnectRequested:
            var effects = cancelRetryEffects()
            startupConnectPaused = true
            guard !terminationPending else {
                pendingDisconnectRequest = false
                return AppLifecycleTransition(terminationDirective: .none, effects: effects)
            }
            if activeOperation == nil {
                pendingDisconnectRequest = false
                let transition = startControlIfPossible(command: .disconnect, operation: .disconnect, timeout: 3, source: .disconnect)
                effects.append(contentsOf: transition.effects)
            } else if activeOperation != .disconnect && activeOperation != .quit && activeOperation != .credentialSave {
                pendingDisconnectRequest = true
            }
            return AppLifecycleTransition(terminationDirective: .none, effects: effects)

        case .credentialResetRequested:
            var effects = cancelRetryEffects()
            startupConnectPaused = true
            pendingDisconnectRequest = false
            guard !terminationPending else {
                return AppLifecycleTransition(terminationDirective: .none, effects: effects)
            }
            guard !terminationResolved, operationGate.begin(.credentialSave) else {
                return AppLifecycleTransition(terminationDirective: .none, effects: effects)
            }
            activeSource = .credentialConnect
            credentialTransactionRunning = true
            effects.append(.runCredentialTransaction)
            return AppLifecycleTransition(terminationDirective: .none, effects: effects)

        case .credentialTransactionCompleted(let result):
            return handleCredentialTransactionCompleted(result)

        case .terminateRequested:
            var effects = cancelRetryEffects()
            startupConnectPaused = true
            pendingDisconnectRequest = false
            if terminationPending {
                return AppLifecycleTransition(terminationDirective: .terminateLater, effects: effects)
            }
            terminationPending = true
            if let activeOperation {
                if activeOperation == .disconnect {
                    terminationAttachedToDisconnect = true
                }
                if activeOperation == .credentialSave {
                    if credentialTransactionRunning {
                        effects.append(.dismissCredentialReset)
                    } else if activeSource == .credentialDisconnect {
                        credentialCancelledBeforeTransaction = true
                        effects.append(.dismissCredentialReset)
                    }
                }
                return AppLifecycleTransition(terminationDirective: .terminateLater, effects: effects)
            }
            let transition = startControlIfPossible(command: .disconnect, operation: .quit, timeout: 15, source: .quit)
            effects.append(contentsOf: transition.effects)
            return AppLifecycleTransition(terminationDirective: .terminateLater, effects: effects)

        case .startupRetryTimerFired:
            guard startupRetryScheduled else {
                return AppLifecycleTransition(terminationDirective: .none, effects: [])
            }
            startupRetryScheduled = false
            guard !startupConnectPaused, !terminationPending else {
                return AppLifecycleTransition(terminationDirective: .none, effects: [])
            }
            return startControlIfPossible(command: .connect, operation: .connect, timeout: 3, source: .startup)

        case .controlCompleted(let operation, let result):
            return handleControlCompleted(operation: operation, result: result)
        }
    }

    private mutating func startPrimary(command: VPNControlCommand, operation: ControlTowerOperation, source: ActiveSource) -> AppLifecycleTransition {
        var effects = cancelRetryEffects()
        startupConnectPaused = false
        pendingDisconnectRequest = false
        if terminationPending {
            return AppLifecycleTransition(terminationDirective: .none, effects: effects)
        }
        let transition = startControlIfPossible(command: command, operation: operation, timeout: 3, source: source)
        effects.append(contentsOf: transition.effects)
        return AppLifecycleTransition(terminationDirective: .none, effects: effects)
    }

    private mutating func handleControlCompleted(operation: ControlTowerOperation, result: ControlResult) -> AppLifecycleTransition {
        guard activeOperation == operation else {
            return AppLifecycleTransition(terminationDirective: .none, effects: [])
        }
        let completedSource = activeSource

        if operation == .credentialSave {
            return handleCredentialControlCompleted(source: completedSource, result: result)
        }

        operationGate.finish(operation)
        activeSource = nil

        if operation == .quit || (operation == .disconnect && terminationAttachedToDisconnect) {
            terminationAttachedToDisconnect = false
            terminationPending = false
            pendingDisconnectRequest = false
            startupRetryScheduled = false
            switch result.status {
            case .ok:
                terminationResolved = true
                return AppLifecycleTransition(terminationDirective: .none, effects: [.replyToTermination(true)])
            case .failed, .timeout:
                return AppLifecycleTransition(terminationDirective: .none, effects: [.replyToTermination(false), .showTerminationFailureAlert(normalizedControlResult(result))])
            }
        }

        if terminationPending {
            return startControlIfPossible(command: .disconnect, operation: .quit, timeout: 15, source: .quit)
        }

        var effects: [AppLifecycleEffect] = []
        if completedSource == .startup, !startupConnectPaused {
            switch startupPolicy.next(after: startupOutcome(for: result)) {
            case .retry(let delay):
                startupRetryScheduled = true
                effects.append(.scheduleStartupRetry(after: delay))
            case .stop:
                startupRetryScheduled = false
            }
        }

        if pendingDisconnectRequest, self.activeOperation == nil {
            pendingDisconnectRequest = false
            let transition = startControlIfPossible(command: .disconnect, operation: .disconnect, timeout: 3, source: .disconnect)
            effects.append(contentsOf: transition.effects)
        }

        return AppLifecycleTransition(terminationDirective: .none, effects: effects)
    }

    private mutating func handleCredentialControlCompleted(source: ActiveSource?, result: ControlResult) -> AppLifecycleTransition {
        finishCredentialReset()
        if terminationPending {
            terminationResolved = true
            terminationPending = false
            return AppLifecycleTransition(terminationDirective: .none, effects: [.replyToTermination(result.status == .ok)])
        }
        if result.status == .ok {
            return AppLifecycleTransition(terminationDirective: .none, effects: [])
        }
        return AppLifecycleTransition(terminationDirective: .none, effects: [.showCredentialResetError(normalizedControlResult(result))])
    }

    private mutating func handleCredentialTransactionCompleted(_ result: CredentialTransactionResult) -> AppLifecycleTransition {
        guard activeOperation == .credentialSave, credentialTransactionRunning else {
            return AppLifecycleTransition(terminationDirective: .none, effects: [])
        }
        finishCredentialReset()
        switch result {
        case .success:
            if terminationPending {
                terminationResolved = true
                terminationPending = false
                return AppLifecycleTransition(terminationDirective: .none, effects: [.replyToTermination(true)])
            }
            return AppLifecycleTransition(terminationDirective: .none, effects: [])
        case .failure(let code):
            if terminationPending {
                terminationResolved = true
                terminationPending = false
                return AppLifecycleTransition(terminationDirective: .none, effects: [.replyToTermination(true)])
            }
            return AppLifecycleTransition(terminationDirective: .none, effects: [.showCredentialResetError(code.rawValue)])
        }
    }

    private mutating func finishCredentialReset() {
        operationGate.finish(.credentialSave)
        activeSource = nil
        credentialTransactionRunning = false
        credentialCancelledBeforeTransaction = false
        pendingDisconnectRequest = false
    }

    private mutating func startControlIfPossible(command: VPNControlCommand, operation: ControlTowerOperation, timeout: TimeInterval, source: ActiveSource) -> AppLifecycleTransition {
        guard !terminationResolved, operationGate.begin(operation) else {
            return AppLifecycleTransition(terminationDirective: .none, effects: [])
        }
        activeSource = source
        return AppLifecycleTransition(terminationDirective: .none, effects: [.runControl(command: command, operation: operation, timeout: timeout)])
    }

    private mutating func cancelRetryEffects() -> [AppLifecycleEffect] {
        guard startupRetryScheduled else { return [] }
        startupRetryScheduled = false
        return [.cancelStartupRetry]
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

    private func normalizedControlResult(_ result: ControlResult) -> String {
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

public struct CredentialResetInput: Equatable, Sendable, CustomDebugStringConvertible {
    public let username: String
    public let password: String
    public let passwordConfirmation: String
    public let totpSeed: String
    public let totpSeedConfirmation: String

    public init(username: String, password: String, passwordConfirmation: String, totpSeed: String, totpSeedConfirmation: String) {
        self.username = username
        self.password = password
        self.passwordConfirmation = passwordConfirmation
        self.totpSeed = totpSeed
        self.totpSeedConfirmation = totpSeedConfirmation
    }

    public var debugDescription: String { "CredentialResetInput([REDACTED])" }
}

public struct ValidatedCredentials: Equatable, Sendable, CustomDebugStringConvertible {
    public static let cleared = ValidatedCredentials(username: "", password: "", normalizedTOTPSeed: nil)

    public let username: String
    public let password: String
    public let normalizedTOTPSeed: String?

    public init(username: String, password: String, normalizedTOTPSeed: String?) {
        self.username = username
        self.password = password
        self.normalizedTOTPSeed = normalizedTOTPSeed
    }

    public var debugDescription: String { "ValidatedCredentials([REDACTED])" }
}

public enum CredentialValidationError: String, Error, Equatable, CustomStringConvertible, Sendable {
    case usernameRequired = "USERNAME_REQUIRED"
    case usernameTooLong = "USERNAME_TOO_LONG"
    case usernameContainsControlCharacter = "USERNAME_CONTAINS_CONTROL_CHARACTER"
    case passwordRequired = "PASSWORD_REQUIRED"
    case passwordTooLong = "PASSWORD_TOO_LONG"
    case passwordContainsDisallowedCharacter = "PASSWORD_CONTAINS_DISALLOWED_CHARACTER"
    case passwordMismatch = "PASSWORD_MISMATCH"
    case totpSeedRequired = "TOTP_SEED_REQUIRED"
    case totpSeedMismatch = "TOTP_SEED_MISMATCH"
    case totpSeedInvalidAlphabetOrPadding = "TOTP_SEED_INVALID_ALPHABET_OR_PADDING"
    case totpSeedTooShort = "TOTP_SEED_TOO_SHORT"
    case totpSeedTooLong = "TOTP_SEED_TOO_LONG"
    case totpSeedLooksLikeOneTimeCode = "TOTP_SEED_LOOKS_LIKE_ONE_TIME_CODE"

    public var code: String { rawValue }
    public var description: String { rawValue }
}

public enum CredentialValidator {
    public static func validate(_ input: CredentialResetInput) throws -> ValidatedCredentials {
        try validateUsername(input.username)
        try validatePassword(input.password, confirmation: input.passwordConfirmation)
        let seed = try validateTOTPSeed(input.totpSeed, confirmation: input.totpSeedConfirmation)
        return ValidatedCredentials(username: input.username, password: input.password, normalizedTOTPSeed: seed)
    }

    private static func validateUsername(_ username: String) throws {
        guard !username.isEmpty else { throw CredentialValidationError.usernameRequired }
        guard username.count <= 128 else { throw CredentialValidationError.usernameTooLong }
        guard !username.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw CredentialValidationError.usernameContainsControlCharacter
        }
    }

    private static func validatePassword(_ password: String, confirmation: String) throws {
        guard !password.isEmpty else { throw CredentialValidationError.passwordRequired }
        guard password.utf8.count <= 1024 else { throw CredentialValidationError.passwordTooLong }
        guard !password.unicodeScalars.contains(where: { $0.value == 0 || $0.value == 10 || $0.value == 13 }) else {
            throw CredentialValidationError.passwordContainsDisallowedCharacter
        }
        guard password == confirmation else { throw CredentialValidationError.passwordMismatch }
    }

    private static func validateTOTPSeed(_ seed: String, confirmation: String) throws -> String? {
        guard !seed.isEmpty, !confirmation.isEmpty else { throw CredentialValidationError.totpSeedRequired }
        let normalizedSeed = normalizeTOTP(seed)
        let normalizedConfirmation = normalizeTOTP(confirmation)
        guard !normalizedSeed.isEmpty, !normalizedConfirmation.isEmpty else { throw CredentialValidationError.totpSeedRequired }
        guard normalizedSeed == normalizedConfirmation else { throw CredentialValidationError.totpSeedMismatch }
        if normalizedSeed.range(of: #"^[0-9]{6}$"#, options: .regularExpression) != nil {
            throw CredentialValidationError.totpSeedLooksLikeOneTimeCode
        }
        guard normalizedSeed.count >= 16 else { throw CredentialValidationError.totpSeedTooShort }
        guard normalizedSeed.count <= 256 else { throw CredentialValidationError.totpSeedTooLong }
        guard isStrictRFC4648Base32Shape(normalizedSeed) else {
            throw CredentialValidationError.totpSeedInvalidAlphabetOrPadding
        }
        return normalizedSeed
    }

    private static func isStrictRFC4648Base32Shape(_ value: String) -> Bool {
        guard value.allSatisfy({ ($0 >= "A" && $0 <= "Z") || ($0 >= "2" && $0 <= "7") || $0 == "=" }) else {
            return false
        }
        guard let firstPadding = value.firstIndex(of: "=") else {
            return [0, 2, 4, 5, 7].contains(value.count % 8)
        }
        guard value[firstPadding...].allSatisfy({ $0 == "=" }) else { return false }
        guard value.count % 8 == 0 else { return false }
        let dataCount = value[..<firstPadding].count
        let paddingCount = value[firstPadding...].count
        switch paddingCount {
        case 6: return dataCount % 8 == 2
        case 4: return dataCount % 8 == 4
        case 3: return dataCount % 8 == 5
        case 1: return dataCount % 8 == 7
        default: return false
        }
    }

    private static func normalizeTOTP(_ value: String) -> String {
        value.unicodeScalars.reduce(into: "") { result, scalar in
            switch scalar.value {
            case 0x20, 0x09, 0x0A, 0x0D, 0x2D:
                return
            default:
                result.unicodeScalars.append(contentsOf: String(scalar).uppercased().unicodeScalars)
            }
        }
    }
}

public enum CredentialKey: String, CaseIterable, Equatable, Hashable, Sendable {
    case username
    case password
    case totpSeed
}

public protocol CredentialStore: AnyObject {
    func read(_ key: CredentialKey) throws -> String?
    func write(_ value: String, for key: CredentialKey) throws
    func remove(_ key: CredentialKey) throws
}

public protocol TOTPStateResetting: AnyObject {
    func resetTOTPState() throws
}

public enum CredentialTransactionErrorCode: String, Equatable, Sendable {
    case readFailed = "READ_FAILED"
    case writeFailed = "WRITE_FAILED"
    case rollbackFailed = "ROLLBACK_FAILED"
    case totpResetFailed = "TOTP_RESET_FAILED"
}

public enum CredentialTransactionResult: Equatable, CustomStringConvertible, Sendable {
    case success
    case failure(code: CredentialTransactionErrorCode)

    public var description: String {
        switch self {
        case .success:
            return "SUCCESS"
        case .failure(let code):
            return code.rawValue
        }
    }
}

public final class CredentialTransaction {
    private let store: CredentialStore
    private let totpResetter: TOTPStateResetting
    private let reconnect: () -> Void

    public init(store: CredentialStore, totpResetter: TOTPStateResetting, reconnect: @escaping () -> Void = {}) {
        self.store = store
        self.totpResetter = totpResetter
        self.reconnect = reconnect
    }

    public func apply(_ credentials: ValidatedCredentials) -> CredentialTransactionResult {
        let originals: [CredentialKey: String?]
        do {
            originals = [
                .username: try store.read(.username),
                .password: try store.read(.password),
                .totpSeed: try store.read(.totpSeed),
            ]
        } catch {
            return .failure(code: .readFailed)
        }

        var changed: [CredentialKey] = []
        do {
            try write(credentials.username, for: .username, changed: &changed)
            try write(credentials.password, for: .password, changed: &changed)
            if let seed = credentials.normalizedTOTPSeed {
                try write(seed, for: .totpSeed, changed: &changed)
                do {
                    try totpResetter.resetTOTPState()
                } catch {
                    return rollback(changed: changed, originals: originals, fallback: .totpResetFailed)
                }
            }
        } catch {
            return rollback(changed: changed, originals: originals, fallback: .writeFailed)
        }

        reconnect()
        return .success
    }

    private func write(_ value: String, for key: CredentialKey, changed: inout [CredentialKey]) throws {
        try store.write(value, for: key)
        changed.append(key)
    }

    private func rollback(changed: [CredentialKey], originals: [CredentialKey: String?], fallback: CredentialTransactionErrorCode) -> CredentialTransactionResult {
        var rollbackFailed = false
        for key in changed.reversed() {
            do {
                if let original = originals[key] ?? nil {
                    try store.write(original, for: key)
                } else {
                    try store.remove(key)
                }
            } catch {
                rollbackFailed = true
            }
        }
        return .failure(code: rollbackFailed ? .rollbackFailed : fallback)
    }
}
