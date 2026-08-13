import Foundation

public enum VPNCommand: Equatable, Sendable {
    case status
    case connect
    case disconnect
    case reconnect
    case automaticReconnect(Bool)
    case credentialsPresent
    case currentOTP
}

public struct CredentialInput: Equatable, Sendable, CustomDebugStringConvertible {
    public let username: String
    public let password: String
    public let totpSeed: String

    public init(username: String, password: String, totpSeed: String) {
        self.username = username
        self.password = password
        self.totpSeed = totpSeed
    }

    public var debugDescription: String { "CredentialInput([REDACTED])" }
}

public enum VPNBackendErrorCode: String, CaseIterable, Equatable, Sendable {
    case authenticationFailed = "AUTHENTICATION_FAILED"
    case portalUnreachable = "PORTAL_UNREACHABLE"
    case connectTimeoutNoTunnel = "CONNECT_TIMEOUT_NO_TUNNEL"
    case networkScriptFailed = "NETWORK_SCRIPT_FAILED"
    case repairRequired = "REPAIR_REQUIRED"
    case serviceUnavailable = "SERVICE_UNAVAILABLE"
    case protocolMismatch = "PROTOCOL_MISMATCH"
    case credentialStoreFailure = "CREDENTIAL_STORE_FAILURE"
}

public enum VPNResponse: Equatable, Sendable {
    case ack
    case status(VPNStatus)
    case credentialsPresent(Bool)
    case currentOTP(TOTPDisplaySnapshot)
    case error(VPNBackendErrorCode)
}

public enum VPNServiceError: Error, Equatable, Sendable {
    case unavailable
    case timeout
    case protocolViolation
    case insecureSocket
    case backend(VPNBackendErrorCode)
}

public protocol VPNServiceRequesting: AnyObject, Sendable {
    func request(_ command: VPNCommand, completion: @escaping @Sendable (Result<VPNResponse, VPNServiceError>) -> Void)
    func replaceCredentials(_ credentials: CredentialInput, completion: @escaping @Sendable (Result<Void, VPNServiceError>) -> Void)
}

enum RustWireRequestEncoder {
    private static let schemaVersion = 1

    static func encode(command: VPNCommand, requestID: String) throws -> Data {
        try validate(requestID: requestID)
        let wireCommand = commandName(for: command)
        let json = "{\"schema_version\":\(schemaVersion),\"request_id\":\"\(requestID)\",\"command\":\"\(wireCommand)\"}"
        return Data(json.utf8)
    }

    static func encodeReplaceCredentials(_ credentials: CredentialInput, requestID: String) throws -> Data {
        try validate(requestID: requestID)
        let json = "{\"schema_version\":\(schemaVersion),\"request_id\":\"\(requestID)\",\"command\":\"replace_credentials\",\"credentials\":{\"username\":\"\(escape(credentials.username))\",\"password\":\"\(escape(credentials.password))\",\"totp_seed\":\"\(escape(credentials.totpSeed))\"}}"
        return Data(json.utf8)
    }

    private static func commandName(for command: VPNCommand) -> String {
        switch command {
        case .status: return "status"
        case .connect: return "connect"
        case .disconnect: return "disconnect"
        case .reconnect: return "reconnect"
        case .automaticReconnect(true): return "automatic_on"
        case .automaticReconnect(false): return "automatic_off"
        case .credentialsPresent: return "credentials_present"
        case .currentOTP: return "current_otp"
        }
    }

    private static func validate(requestID: String) throws {
        guard !requestID.isEmpty,
              requestID.utf8.count <= 128,
              requestID.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5a) || ($0 >= 0x61 && $0 <= 0x7a) || $0 == 0x2d || $0 == 0x5f || $0 == 0x2e })
        else { throw VPNServiceError.protocolViolation }
    }

    private static func escape(_ string: String) -> String {
        var escaped = ""
        escaped.reserveCapacity(string.utf8.count)
        for scalar in string.unicodeScalars {
            switch scalar.value {
            case 0x22: escaped.append("\\\"")
            case 0x5c: escaped.append("\\\\")
            case 0x08: escaped.append("\\b")
            case 0x0c: escaped.append("\\f")
            case 0x0a: escaped.append("\\n")
            case 0x0d: escaped.append("\\r")
            case 0x09: escaped.append("\\t")
            case 0x00...0x1f:
                escaped.append(String(format: "\\u%04x", scalar.value))
            default:
                escaped.unicodeScalars.append(scalar)
            }
        }
        return escaped
    }
}

enum RustWireResponseDecoder {
    private static let allowedRequestIDs = CharacterSet(charactersIn: "-_.").union(.alphanumerics)

    static func decode(payload: Data, expectedRequestID: String) throws -> VPNResponse {
        try StrictTopLevelJSON.rejectDuplicateTopLevelKeys(
            in: payload,
            malformedMessage: "malformed response",
            duplicateMessagePrefix: "duplicate response field: "
        )
        let schemaVersion = try StrictTopLevelJSON.decodeRequiredIntegerToken(
            in: payload,
            key: "schema_version",
            invalidMessage: "schema_version must be an integer"
        )
        guard schemaVersion == 1 else { throw VPNServiceError.protocolViolation }
        let object = try JSONSerialization.jsonObject(with: payload, options: [])
        guard let document = object as? [String: Any] else { throw VPNServiceError.protocolViolation }
        let result = try requiredString("result", document["result"])
        let requestID = try requiredString("request_id", document["request_id"])
        guard requestID == expectedRequestID,
              !requestID.isEmpty,
              requestID.utf8.count <= 128,
              requestID.rangeOfCharacter(from: allowedRequestIDs.inverted) == nil
        else { throw VPNServiceError.protocolViolation }
        switch result {
        case "ack":
            try requireKeys(document, ["schema_version", "request_id", "result"])
            return .ack
        case "status":
            try requireKeys(document, ["schema_version", "request_id", "result", "status"])
            guard let statusObject = document["status"] else { throw VPNServiceError.protocolViolation }
            let statusData = try JSONSerialization.data(withJSONObject: statusObject, options: [.sortedKeys])
            return .status(try VPNStatusDecoder.decode(statusData))
        case "credentials_present":
            try requireKeys(document, ["schema_version", "request_id", "result", "present"])
            return .credentialsPresent(try exactBool("present", document["present"]))
        case "current_otp":
            try requireKeys(document, ["schema_version", "request_id", "result", "code", "remaining_seconds"])
            let code = try requiredString("code", document["code"])
            guard code.utf8.count == 6, code.utf8.allSatisfy({ 0x30...0x39 ~= $0 }) else {
                throw VPNServiceError.protocolViolation
            }
            let remaining = try exactInt("remaining_seconds", document["remaining_seconds"])
            guard (1...30).contains(remaining) else { throw VPNServiceError.protocolViolation }
            return .currentOTP(TOTPDisplaySnapshot(code: code, secondsRemaining: remaining))
        case "error":
            try requireKeys(document, ["schema_version", "request_id", "result", "error_code"])
            let code = try requiredString("error_code", document["error_code"])
            guard let backend = VPNBackendErrorCode(rawValue: code) else { throw VPNServiceError.protocolViolation }
            return .error(backend)
        default:
            throw VPNServiceError.protocolViolation
        }
    }

    private static func requireKeys(_ document: [String: Any], _ allowed: Set<String>) throws {
        let keys = Set(document.keys)
        guard keys == allowed else { throw VPNServiceError.protocolViolation }
    }

    private static func exactBool(_ name: String, _ value: Any?) throws -> Bool {
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else {
            throw VPNServiceError.protocolViolation
        }
        return number.boolValue
    }

    private static func exactInt(_ name: String, _ value: Any?) throws -> Int {
        guard let number = value as? NSNumber, CFGetTypeID(number) != CFBooleanGetTypeID() else {
            throw VPNServiceError.protocolViolation
        }
        let double = number.doubleValue
        guard double.rounded() == double else { throw VPNServiceError.protocolViolation }
        return number.intValue
    }

    private static func requiredString(_ name: String, _ value: Any?) throws -> String {
        guard let string = value as? String, !string.isEmpty else { throw VPNServiceError.protocolViolation }
        return string
    }
}
