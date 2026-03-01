import Foundation
import UFOLib

private struct HarnessFileSystem: FileSysteming {
    var homeDirectoryPath: String {
        "/Users/fuzz"
    }

    func expandTilde(in path: String) -> String {
        if path == "~" {
            return homeDirectoryPath
        }

        if path.hasPrefix("~/") {
            return homeDirectoryPath + String(path.dropFirst())
        }

        return path
    }

    func canonicalPath(_ path: String) -> String {
        let expanded = expandTilde(in: path)
        let standardized = (expanded as NSString).standardizingPath
        return standardized.isEmpty ? "/" : standardized
    }

    func createDirectory(at path: String) throws {}

    func fileExists(at path: String) -> Bool {
        false
    }

    func isWritableDirectory(_ path: String) -> Bool {
        true
    }

    func readFile(at path: String) throws -> Data {
        throw UFOError.io("Unsupported in fuzz harness.")
    }

    func writeFile(_ data: Data, to path: String) throws {}

    func appendFile(_ data: Data, to path: String) throws {}

    func modificationDate(at path: String) throws -> Date {
        Date(timeIntervalSince1970: 0)
    }

    func moveItem(at source: String, to destination: String) throws {}

    func removeItem(at path: String) throws {}
}

private func runParserAndValidationFuzz(payload: Data) {
    let bounded = Data(payload.prefix(8192))
    let input = String(decoding: bounded, as: UTF8.self)
    let parts = input.components(separatedBy: "|")

    func field(_ index: Int, fallback: String) -> String {
        if index < parts.count {
            return parts[index]
        }
        return fallback
    }

    let keychain = field(0, fallback: "team")
    let path = field(1, fallback: "~/.ufo/keychains")
    let service = field(2, fallback: "github")
    let account = field(3, fallback: "ci")
    let query = field(4, fallback: "git")
    let confirm = field(5, fallback: "team")
    let value = field(6, fallback: "token")
    let topic = field(7, fallback: "secret set")

    let parser = CommandParser()
    let candidates: [[String]] = [
        [],
        ["help", topic],
        ["doctor"],
        ["keychain", "create", keychain, "--path", path],
        ["keychain", "harden", keychain],
        ["keychain", "delete", keychain, "--yes", "--confirm", confirm],
        ["secret", "set", "--keychain", keychain, "--service", service, "--account", account, "--value", value],
        ["secret", "set", "--keychain", keychain, "--service", service, "--account", account, "--stdin"],
        ["secret", "set", "--keychain", keychain, "--service", service, "--account", account, "--stdin", "--value", value],
        ["secret", "get", "--keychain", keychain, "--service", service, "--account", account, "--reveal"],
        ["secret", "remove", "--keychain", keychain, "--service", service, "--account", account, "--yes"],
        ["secret", "search", "--keychain", keychain, "--query", query]
    ]

    for command in candidates {
        _ = try? parser.parse(command)
    }

    _ = try? InputValidation.validateKeychainName(keychain)
    _ = try? InputValidation.validateService(service)
    _ = try? InputValidation.validateAccount(account)
    _ = try? InputValidation.validateQuery(query)
    _ = try? InputValidation.validateSecret(value)
    _ = KeychainPath.filename(for: keychain)

    let policy = KeychainProtectionPolicy(fileSystem: HarnessFileSystem())
    _ = try? policy.assertNameAllowed(keychain)
    _ = try? policy.assertPathAllowed(path)
}

let payload = FileHandle.standardInput.readDataToEndOfFile()
runParserAndValidationFuzz(payload: payload)
