import Foundation

public struct KeychainProtectionPolicy {
    private let fileSystem: FileSysteming

    private static let protectedExactNames: Set<String> = [
        "login",
        "login.keychain",
        "login.keychain-db",
        "system",
        "system.keychain",
        "icloud",
        "icloud.keychain",
        "local items",
        "local items.keychain",
        "local items.keychain-db",
        "appleid",
        "appleid.keychain"
    ]

    private static let protectedNameTokens: [String] = [
        "login",
        "icloud",
        "system",
        "local items",
        "appleid"
    ]

    private static let protectedPathTokens: [String] = [
        "/library/keychains",
        "/system/library/keychains",
        "/network/library/keychains",
        "/private/var/keychains",
        "/private/var/db",
        "/system/"
    ]

    public init(fileSystem: FileSysteming) {
        self.fileSystem = fileSystem
    }

    public func assertNameAllowed(_ name: String) throws {
        let normalized = name.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !normalized.isEmpty else {
            throw UFOError.policyDenied("Keychain name cannot be empty.")
        }

        let wildcardCharacters = CharacterSet(charactersIn: "*?[]")
        if normalized.rangeOfCharacter(from: wildcardCharacters) != nil {
            throw UFOError.policyDenied("Wildcard keychain names are not allowed.")
        }

        if Self.protectedExactNames.contains(normalized) {
            throw UFOError.policyDenied("'\(name)' is a protected keychain name.")
        }

        if Self.protectedNameTokens.contains(where: { normalized.contains($0) }) {
            throw UFOError.policyDenied("'\(name)' matches a protected keychain token.")
        }
    }

    public func assertPathAllowed(_ path: String) throws {
        let canonical = normalize(path)
        let parentPath = normalize((path as NSString).deletingLastPathComponent)

        if isProtectedPath(canonical) || isProtectedPath(parentPath) {
            throw UFOError.policyDenied("Path '\(path)' is in a protected system keychain location.")
        }

        let basename = (canonical as NSString).lastPathComponent
        if Self.protectedExactNames.contains(basename) {
            throw UFOError.policyDenied("Path '\(path)' resolves to a protected keychain.")
        }

        if Self.protectedNameTokens.contains(where: { basename.contains($0) }) {
            throw UFOError.policyDenied("Path '\(path)' contains a protected keychain token.")
        }
    }

    private func normalize(_ path: String) -> String {
        fileSystem.canonicalPath(path)
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
    }

    private func isProtectedPath(_ path: String) -> Bool {
        Self.protectedPathTokens.contains { token in
            path.hasPrefix(token) || path.contains(token)
        }
    }
}
