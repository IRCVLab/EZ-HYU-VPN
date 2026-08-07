import Foundation

public struct SemanticVersion: Comparable, CustomStringConvertible, Sendable {
    public let major: UInt
    public let minor: UInt
    public let patch: UInt

    public init?(_ value: String) {
        guard value.range(of: #"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"#, options: .regularExpression) != nil else { return nil }
        let fields = value.split(separator: ".", omittingEmptySubsequences: false)
        guard fields.count == 3,
              let major = UInt(fields[0]),
              let minor = UInt(fields[1]),
              let patch = UInt(fields[2])
        else { return nil }
        self.major = major
        self.minor = minor
        self.patch = patch
    }

    public var description: String { "\(major).\(minor).\(patch)" }

    public static func < (lhs: SemanticVersion, rhs: SemanticVersion) -> Bool {
        (lhs.major, lhs.minor, lhs.patch) < (rhs.major, rhs.minor, rhs.patch)
    }
}

public struct UpdatePolicy: Sendable {
    public let currentVersion: SemanticVersion
    public let feedURL: URL
    public let allowedReleaseHost: String
    public let allowedReleasePathPrefix: String

    public init(currentVersion: SemanticVersion, feedURL: URL, allowedReleaseHost: String, allowedReleasePathPrefix: String) {
        self.currentVersion = currentVersion
        self.feedURL = feedURL
        self.allowedReleaseHost = allowedReleaseHost
        self.allowedReleasePathPrefix = allowedReleasePathPrefix
    }
}

public struct UpdateOffer: Equatable, Sendable {
    public let version: SemanticVersion
    public let releaseURL: URL

    public init(version: SemanticVersion, releaseURL: URL) {
        self.version = version
        self.releaseURL = releaseURL
    }
}

public enum UpdateCheckError: Error {
    case invalidFeed
}

public enum UpdateFeedDecoder {
    public static let maxBytes = 16 * 1024

    public static func offer(from data: Data, policy: UpdatePolicy) throws -> UpdateOffer? {
        guard !data.isEmpty, data.count <= maxBytes else { throw UpdateCheckError.invalidFeed }
        let fields = try StrictFeedObject(data: data).fields
        guard Set(fields.keys) == Set(["schema_version", "version", "release_url"]),
              fields["schema_version"] == .integer(1),
              case let .string(versionString)? = fields["version"],
              case let .string(releaseURLString)? = fields["release_url"],
              let version = SemanticVersion(versionString),
              let releaseURL = URL(string: releaseURLString),
              releaseURL.scheme?.lowercased() == "https",
              releaseURL.user == nil,
              releaseURL.password == nil,
              releaseURL.port == nil,
              releaseURL.host?.lowercased() == policy.allowedReleaseHost.lowercased(),
              releaseURL.path.hasPrefix(policy.allowedReleasePathPrefix)
        else { throw UpdateCheckError.invalidFeed }
        guard version > policy.currentVersion else { return nil }
        return UpdateOffer(version: version, releaseURL: releaseURL)
    }
}

public protocol UpdateChecking: AnyObject {
    func check(completion: @escaping (UpdateOffer?) -> Void)
}

public typealias UpdateDataLoader = (URLRequest, @escaping (Result<Data, Error>) -> Void) -> Void

public final class HTTPSUpdateChecker: UpdateChecking, @unchecked Sendable {
    private let policy: UpdatePolicy
    private let loader: UpdateDataLoader
    private let lock = NSLock()
    private var inFlight = false
    private var completions: [(UpdateOffer?) -> Void] = []

    public init(policy: UpdatePolicy, loader: @escaping UpdateDataLoader = HTTPSUpdateChecker.ephemeralLoad) {
        self.policy = policy
        self.loader = loader
    }

    public func check(completion: @escaping (UpdateOffer?) -> Void) {
        let shouldStart = lock.withLock { () -> Bool in
            completions.append(completion)
            guard !inFlight else { return false }
            inFlight = true
            return true
        }
        guard shouldStart else { return }
        guard let request = Self.makeRequest(policy.feedURL) else {
            finish(nil)
            return
        }
        loader(request) { [weak self] result in
            guard let self else { return }
            let offer: UpdateOffer?
            switch result {
            case let .success(data): offer = try? UpdateFeedDecoder.offer(from: data, policy: self.policy)
            case .failure: offer = nil
            }
            self.finish(offer)
        }
    }

    private func finish(_ offer: UpdateOffer?) {
        let callbacks = lock.withLock { () -> [(UpdateOffer?) -> Void] in
            let callbacks = completions
            completions.removeAll(keepingCapacity: true)
            inFlight = false
            return callbacks
        }
        callbacks.forEach { $0(offer) }
    }

    private static func makeRequest(_ url: URL) -> URLRequest? {
        guard url.scheme?.lowercased() == "https", url.host != nil, url.user == nil, url.password == nil, url.port == nil else { return nil }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalAndRemoteCacheData, timeoutInterval: 10)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        return request
    }

    public static func ephemeralLoad(request: URLRequest, completion: @escaping (Result<Data, Error>) -> Void) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 10
        configuration.timeoutIntervalForResource = 10
        configuration.httpCookieAcceptPolicy = .never
        configuration.httpShouldSetCookies = false
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.urlCache = nil
        let session = URLSession(configuration: configuration)
        let completionBox = UpdateLoadCompletionBox(completion)
        session.dataTask(with: request) { data, response, error in
            defer { session.finishTasksAndInvalidate() }
            guard error == nil,
                  let response = response as? HTTPURLResponse,
                  (200..<300).contains(response.statusCode),
                  let data
            else {
                completionBox.call(.failure(error ?? UpdateCheckError.invalidFeed))
                return
            }
            completionBox.call(.success(data))
        }.resume()
    }
}

private final class UpdateLoadCompletionBox: @unchecked Sendable {
    private let completion: (Result<Data, Error>) -> Void
    init(_ completion: @escaping (Result<Data, Error>) -> Void) { self.completion = completion }
    func call(_ result: Result<Data, Error>) { completion(result) }
}

private enum FeedScalar: Equatable {
    case integer(UInt)
    case string(String)
    case unsupported
}

private struct StrictFeedObject {
    let fields: [String: FeedScalar]

    init(data: Data) throws {
        var parser = FeedParser(bytes: Array(data))
        fields = try parser.parseObject()
    }
}

private struct FeedParser {
    private let bytes: [UInt8]
    private var index = 0

    init(bytes: [UInt8]) { self.bytes = bytes }

    mutating func parseObject() throws -> [String: FeedScalar] {
        skipWhitespace()
        try consume(0x7B)
        skipWhitespace()
        var result: [String: FeedScalar] = [:]
        if consumeIfPresent(0x7D) {
            skipWhitespace()
            guard index == bytes.count else { throw UpdateCheckError.invalidFeed }
            return result
        }
        while true {
            let key = try parseString()
            guard result[key] == nil else { throw UpdateCheckError.invalidFeed }
            skipWhitespace()
            try consume(0x3A)
            skipWhitespace()
            result[key] = try parseScalar()
            skipWhitespace()
            if consumeIfPresent(0x7D) { break }
            try consume(0x2C)
            skipWhitespace()
        }
        skipWhitespace()
        guard index == bytes.count else { throw UpdateCheckError.invalidFeed }
        return result
    }

    private mutating func parseScalar() throws -> FeedScalar {
        guard index < bytes.count else { throw UpdateCheckError.invalidFeed }
        if bytes[index] == 0x22 { return .string(try parseString()) }
        if bytes[index] >= 0x30, bytes[index] <= 0x39 { return .integer(try parseInteger()) }
        for token in ["true", "false", "null"] {
            let tokenBytes = Array(token.utf8)
            if bytes[index...].starts(with: tokenBytes) {
                index += tokenBytes.count
                return .unsupported
            }
        }
        throw UpdateCheckError.invalidFeed
    }

    private mutating func parseInteger() throws -> UInt {
        let start = index
        if bytes[index] == 0x30 {
            index += 1
            if index < bytes.count, bytes[index] >= 0x30, bytes[index] <= 0x39 { throw UpdateCheckError.invalidFeed }
        } else {
            while index < bytes.count, bytes[index] >= 0x30, bytes[index] <= 0x39 { index += 1 }
        }
        guard let text = String(bytes: bytes[start..<index], encoding: .utf8), let value = UInt(text) else { throw UpdateCheckError.invalidFeed }
        return value
    }

    private mutating func parseString() throws -> String {
        guard index < bytes.count, bytes[index] == 0x22 else { throw UpdateCheckError.invalidFeed }
        let start = index
        index += 1
        var escaped = false
        while index < bytes.count {
            let byte = bytes[index]
            if escaped {
                escaped = false
            } else if byte == 0x5C {
                escaped = true
            } else if byte == 0x22 {
                index += 1
                let data = Data(bytes[start..<index])
                guard let string = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]) as? String else { throw UpdateCheckError.invalidFeed }
                return string
            } else if byte < 0x20 {
                throw UpdateCheckError.invalidFeed
            }
            index += 1
        }
        throw UpdateCheckError.invalidFeed
    }

    private mutating func skipWhitespace() {
        while index < bytes.count, [0x20, 0x09, 0x0A, 0x0D].contains(bytes[index]) { index += 1 }
    }

    private mutating func consume(_ byte: UInt8) throws {
        guard consumeIfPresent(byte) else { throw UpdateCheckError.invalidFeed }
    }

    private mutating func consumeIfPresent(_ byte: UInt8) -> Bool {
        guard index < bytes.count, bytes[index] == byte else { return false }
        index += 1
        return true
    }
}
