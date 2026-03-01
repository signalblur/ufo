import Foundation
import Testing
@testable import UFOLib

@Suite("Keychain Protection Policy")
struct KeychainProtectionPolicyTests {
    @Test("Allows safe names and paths")
    func allowsSafeInputs() {
        let policy = KeychainProtectionPolicy(fileSystem: FakeFileSystem())

        do {
            try policy.assertNameAllowed("team-api")
            try policy.assertPathAllowed("~/.ufo/keychains/team.keychain-db")
        } catch {
            Issue.record("Unexpected error: \(error)")
        }
    }

    @Test("Rejects wildcard and protected names")
    func rejectsProtectedNames() {
        let policy = KeychainProtectionPolicy(fileSystem: FakeFileSystem())

        expectPolicyError("Keychain name cannot be empty.") {
            try policy.assertNameAllowed("  ")
        }

        expectPolicyError("Wildcard keychain names are not allowed.") {
            try policy.assertNameAllowed("prod*")
        }

        expectPolicyError("'login' is a protected keychain name.") {
            try policy.assertNameAllowed("login")
        }

        expectPolicyError("'corp-icloud' matches a protected keychain token.") {
            try policy.assertNameAllowed("corp-icloud")
        }
    }

    @Test("Rejects protected path patterns")
    func rejectsProtectedPaths() {
        let policy = KeychainProtectionPolicy(fileSystem: FakeFileSystem())

        expectPolicyError("Path '/Library/Keychains/login.keychain-db' is in a protected system keychain location.") {
            try policy.assertPathAllowed("/Library/Keychains/login.keychain-db")
        }

        expectPolicyError("Path '/tmp/System.keychain' resolves to a protected keychain.") {
            try policy.assertPathAllowed("/tmp/System.keychain")
        }

        expectPolicyError("Path '/tmp/icloud-work.keychain-db' contains a protected keychain token.") {
            try policy.assertPathAllowed("/tmp/icloud-work.keychain-db")
        }
    }

    @Test("Rejects paths when canonical parent resolves to protected location")
    func rejectsCanonicalParentPath() {
        let policy = KeychainProtectionPolicy(fileSystem: ParentRedirectFileSystem())

        expectPolicyError("Path '/tmp/link/safe.keychain-db' is in a protected system keychain location.") {
            try policy.assertPathAllowed("/tmp/link/safe.keychain-db")
        }
    }
}

private func expectPolicyError(_ message: String, _ operation: () throws -> Void) {
    do {
        try operation()
        Issue.record("Expected policy error")
    } catch {
        #expect(error as? UFOError == .policyDenied(message))
    }
}

private struct ParentRedirectFileSystem: FileSysteming {
    let homeDirectoryPath: String = "/Users/tester"

    func expandTilde(in path: String) -> String {
        path
    }

    func canonicalPath(_ path: String) -> String {
        if path == "/tmp/link" {
            return "/Library/Keychains"
        }

        if path == "/tmp/link/safe.keychain-db" {
            return "/tmp/link/safe.keychain-db"
        }

        return path
    }

    func createDirectory(at path: String) throws {}

    func fileExists(at path: String) -> Bool {
        false
    }

    func isWritableDirectory(_ path: String) -> Bool {
        false
    }

    func readFile(at path: String) throws -> Data {
        Data()
    }

    func writeFile(_ data: Data, to path: String) throws {}

    func appendFile(_ data: Data, to path: String) throws {}

    func modificationDate(at path: String) throws -> Date {
        Date(timeIntervalSince1970: 0)
    }

    func moveItem(at source: String, to destination: String) throws {}

    func removeItem(at path: String) throws {}
}
