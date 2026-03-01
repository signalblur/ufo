import Foundation

public enum ExitCode: Int32 {
    case success = 0
    case usage = 2
    case policyDenied = 3
    case notFound = 4
    case subprocessFailure = 5
    case ioFailure = 6
    case internalError = 70
}

public enum UFOError: Error, Equatable {
    case usage(String)
    case validation(String)
    case policyDenied(String)
    case notFound(String)
    case conflict(String)
    case io(String)
    case subprocess(String)
    case internalError(String)

    public var message: String {
        switch self {
        case .usage(let message):
            return "Usage error: \(message)"
        case .validation(let message):
            return "Validation error: \(message)"
        case .policyDenied(let message):
            return "Policy denied: \(message)"
        case .notFound(let message):
            return "Not found: \(message)"
        case .conflict(let message):
            return "Conflict: \(message)"
        case .io(let message):
            return "I/O error: \(message)"
        case .subprocess(let message):
            return "Subprocess error: \(message)"
        case .internalError(let message):
            return "Internal error: \(message)"
        }
    }

    public var exitCode: ExitCode {
        switch self {
        case .usage:
            return .usage
        case .validation, .policyDenied, .conflict:
            return .policyDenied
        case .notFound:
            return .notFound
        case .subprocess:
            return .subprocessFailure
        case .io:
            return .ioFailure
        case .internalError:
            return .internalError
        }
    }
}

public enum SecretInput: Equatable {
    case stdin
}

public enum Command: Equatable {
    case keychainCreate(name: String, path: String?)
    case keychainHarden(name: String)
    case keychainList
    case keychainDelete(name: String, yes: Bool, confirm: String?)
    case secretSet(keychain: String, service: String, account: String, input: SecretInput)
    case secretRun(
        keychain: String,
        service: String,
        account: String,
        environmentVariable: String,
        executable: String,
        arguments: [String],
        timeout: TimeInterval?
    )
    case secretGet(keychain: String, service: String, account: String, reveal: Bool)
    case secretRemove(keychain: String, service: String, account: String, yes: Bool)
    case secretSearch(keychain: String, query: String)
    case doctor
    case help(topic: String?)
}

public struct CommandResult: Equatable {
    public let exitCode: Int32
    public let standardOutput: String
    public let standardError: String

    public init(exitCode: Int32, standardOutput: String, standardError: String) {
        self.exitCode = exitCode
        self.standardOutput = standardOutput
        self.standardError = standardError
    }
}

public struct ProcessResult: Equatable {
    public let exitCode: Int32
    public let standardOutput: Data
    public let standardError: Data

    public init(exitCode: Int32, standardOutput: Data, standardError: Data) {
        self.exitCode = exitCode
        self.standardOutput = standardOutput
        self.standardError = standardError
    }
}

public struct SecretMetadata: Codable, Equatable {
    public let service: String
    public let account: String
    public var updatedAt: Date

    public init(service: String, account: String, updatedAt: Date) {
        self.service = service
        self.account = account
        self.updatedAt = updatedAt
    }
}

public struct ManagedKeychain: Codable, Equatable {
    public let name: String
    public let path: String
    public let createdAt: Date
    public var hardenedAt: Date?
    public var secrets: [SecretMetadata]

    public init(
        name: String,
        path: String,
        createdAt: Date,
        hardenedAt: Date? = nil,
        secrets: [SecretMetadata] = []
    ) {
        self.name = name
        self.path = path
        self.createdAt = createdAt
        self.hardenedAt = hardenedAt
        self.secrets = secrets
    }
}

public struct ManagedRegistry: Codable, Equatable {
    public let version: Int
    public var keychains: [ManagedKeychain]

    public init(version: Int = 1, keychains: [ManagedKeychain] = []) {
        self.version = version
        self.keychains = keychains
    }
}

public struct AuditHealth: Equatable {
    public let activeLogPath: String
    public let usingFallbackDirectory: Bool
    public let writable: Bool
    public let lastError: String?

    public init(
        activeLogPath: String,
        usingFallbackDirectory: Bool,
        writable: Bool,
        lastError: String?
    ) {
        self.activeLogPath = activeLogPath
        self.usingFallbackDirectory = usingFallbackDirectory
        self.writable = writable
        self.lastError = lastError
    }
}
