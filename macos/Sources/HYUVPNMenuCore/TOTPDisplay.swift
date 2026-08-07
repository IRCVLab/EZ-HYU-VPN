import CryptoKit
import Foundation

public struct TOTPDisplaySnapshot: Equatable, Sendable {
    public let code: String
    public let secondsRemaining: Int

    public init(code: String, secondsRemaining: Int) {
        self.code = code
        self.secondsRemaining = secondsRemaining
    }
}

public enum TOTPDisplayError: Error, Equatable, Sendable {
    case invalidSeed
    case invalidTime
}

public enum TOTPDisplayGenerator {
    private static let period: UInt64 = 30

    public static func snapshot(seed: String, at date: Date = Date()) throws -> TOTPDisplaySnapshot {
        let timestamp = date.timeIntervalSince1970
        guard timestamp.isFinite, timestamp >= 0 else { throw TOTPDisplayError.invalidTime }
        let keyData = try decodeBase32(seed)
        let wholeSeconds = UInt64(timestamp.rounded(.down))
        var bigEndianCounter = (wholeSeconds / period).bigEndian
        let message = withUnsafeBytes(of: &bigEndianCounter) { Data($0) }
        let authenticationCode = HMAC<Insecure.SHA1>.authenticationCode(
            for: message,
            using: SymmetricKey(data: keyData)
        )
        let bytes = Array(authenticationCode)
        let offset = Int(bytes[bytes.count - 1] & 0x0f)
        guard offset + 3 < bytes.count else { throw TOTPDisplayError.invalidSeed }
        let truncated = (UInt32(bytes[offset] & 0x7f) << 24)
            | (UInt32(bytes[offset + 1]) << 16)
            | (UInt32(bytes[offset + 2]) << 8)
            | UInt32(bytes[offset + 3])
        let code = String(format: "%06u", truncated % 1_000_000)
        let secondsRemaining = Int(period - (wholeSeconds % period))
        return TOTPDisplaySnapshot(code: code, secondsRemaining: secondsRemaining)
    }

    private static func decodeBase32(_ value: String) throws -> Data {
        guard !value.isEmpty else { throw TOTPDisplayError.invalidSeed }
        let scalars = Array(value.unicodeScalars)
        let firstPadding = scalars.firstIndex(where: { $0.value == 0x3d })
        let dataCount = firstPadding ?? scalars.count
        let paddingCount = scalars.count - dataCount

        if paddingCount == 0 {
            guard [0, 2, 4, 5, 7].contains(dataCount % 8) else { throw TOTPDisplayError.invalidSeed }
        } else {
            guard scalars[dataCount...].allSatisfy({ $0.value == 0x3d }), scalars.count % 8 == 0 else {
                throw TOTPDisplayError.invalidSeed
            }
            let validPadding: Bool
            switch paddingCount {
            case 6: validPadding = dataCount % 8 == 2
            case 4: validPadding = dataCount % 8 == 4
            case 3: validPadding = dataCount % 8 == 5
            case 1: validPadding = dataCount % 8 == 7
            default: validPadding = false
            }
            guard validPadding else { throw TOTPDisplayError.invalidSeed }
        }

        var decoded = Data()
        var buffer = 0
        var bufferedBits = 0
        for scalar in scalars.prefix(dataCount) {
            let digit: Int
            switch scalar.value {
            case 0x41...0x5a: digit = Int(scalar.value - 0x41)
            case 0x32...0x37: digit = Int(scalar.value - 0x32 + 26)
            default: throw TOTPDisplayError.invalidSeed
            }
            buffer = (buffer << 5) | digit
            bufferedBits += 5
            if bufferedBits >= 8 {
                bufferedBits -= 8
                decoded.append(UInt8((buffer >> bufferedBits) & 0xff))
                buffer &= bufferedBits == 0 ? 0 : (1 << bufferedBits) - 1
            }
        }
        guard !decoded.isEmpty, buffer == 0 else { throw TOTPDisplayError.invalidSeed }
        return decoded
    }
}
