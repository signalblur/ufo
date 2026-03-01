import Foundation

public enum InputValidation {
    private static let controlCharacters = CharacterSet.controlCharacters
    private static let environmentVariablePattern = "^[A-Za-z_][A-Za-z0-9_]*$"
    private static let blockedEnvironmentVariables: Set<String> = [
        "PATH",
        "HOME",
        "SHELL",
        "TMPDIR",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_INSERT_LIBRARIES"
    ]
    public static let maximumSecretCharacters = 4_096
    public static let maximumSecretInputBytes = maximumSecretCharacters * 4

    public static func validateKeychainName(_ name: String) throws {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw UFOError.validation("Keychain name cannot be empty.")
        }
        guard trimmed == name else {
            throw UFOError.validation("Keychain name cannot contain leading or trailing whitespace.")
        }
        guard trimmed.count <= 128 else {
            throw UFOError.validation("Keychain name must be 128 characters or fewer.")
        }

        let pattern = "^[A-Za-z0-9][A-Za-z0-9._-]*$"
        let range = NSRange(location: 0, length: trimmed.utf16.count)
        let regex = try NSRegularExpression(pattern: pattern)
        guard regex.firstMatch(in: trimmed, options: [], range: range) != nil else {
            throw UFOError.validation(
                "Keychain name must start with an alphanumeric character and contain only letters, numbers, '.', '_', or '-'."
            )
        }
    }

    public static func validateService(_ service: String) throws {
        try validateLabel(service, fieldName: "Service")
    }

    public static func validateAccount(_ account: String) throws {
        try validateLabel(account, fieldName: "Account")
    }

    public static func validateQuery(_ query: String) throws {
        try validateLabel(query, fieldName: "Query")
    }

    public static func validateEnvironmentVariableName(_ value: String) throws {
        guard !value.isEmpty else {
            throw UFOError.validation("Environment variable name cannot be empty.")
        }

        guard value.count <= 128 else {
            throw UFOError.validation("Environment variable name must be 128 characters or fewer.")
        }

        let range = NSRange(location: 0, length: value.utf16.count)
        let regex = try NSRegularExpression(pattern: environmentVariablePattern)
        guard regex.firstMatch(in: value, options: [], range: range) != nil else {
            throw UFOError.validation(
                "Environment variable name must start with a letter or underscore and contain only letters, numbers, or underscores."
            )
        }

        if blockedEnvironmentVariables.contains(value) || value.hasPrefix("DYLD_") || value.hasPrefix("LD_") {
            throw UFOError.validation(
                "Environment variable '\(value)' is blocked for safety. Use an app-specific variable name."
            )
        }
    }

    public static func validateSecret(_ value: String) throws {
        guard !value.isEmpty else {
            throw UFOError.validation("Secret value cannot be empty.")
        }

        guard value.count <= maximumSecretCharacters else {
            throw UFOError.validation("Secret value must be \(maximumSecretCharacters) characters or fewer.")
        }

        guard value.unicodeScalars.first(where: { $0.value == 0 }) == nil else {
            throw UFOError.validation("Secret value cannot contain NUL bytes.")
        }
    }

    private static func validateLabel(_ value: String, fieldName: String) throws {
        guard !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw UFOError.validation("\(fieldName) cannot be empty.")
        }

        guard value.count <= 256 else {
            throw UFOError.validation("\(fieldName) must be 256 characters or fewer.")
        }

        guard value.unicodeScalars.first(where: { controlCharacters.contains($0) }) == nil else {
            throw UFOError.validation("\(fieldName) cannot contain control characters.")
        }
    }
}

public enum KeychainPath {
    public static func filename(for name: String) -> String {
        if name.hasSuffix(".keychain") || name.hasSuffix(".keychain-db") {
            return name
        }
        return "\(name).keychain-db"
    }
}
