import Foundation

public final class SecurityCLI {
    public static let executablePath = "/usr/bin/security"

    private let processRunner: ProcessRunning

    public init(processRunner: ProcessRunning) {
        self.processRunner = processRunner
    }

    public func createKeychain(at path: String) throws {
        _ = try run(["create-keychain", "-p", "", path])
    }

    public func hardenKeychain(at path: String) throws {
        _ = try run(["set-keychain-settings", "-lut", "300", path])
    }

    public func deleteKeychain(at path: String) throws {
        _ = try run(["delete-keychain", path])
    }

    public func setSecret(keychainPath: String, service: String, account: String, value: String) throws {
        _ = try run([
            "add-generic-password",
            "-U",
            "-s",
            service,
            "-a",
            account,
            "-w",
            value,
            keychainPath
        ])
    }

    public func getSecret(keychainPath: String, service: String, account: String) throws -> String {
        let result = try run([
            "find-generic-password",
            "-s",
            service,
            "-a",
            account,
            "-w",
            keychainPath
        ])

        return String(decoding: result.standardOutput, as: UTF8.self)
            .trimmingCharacters(in: .newlines)
    }

    public func removeSecret(keychainPath: String, service: String, account: String) throws {
        _ = try run([
            "delete-generic-password",
            "-s",
            service,
            "-a",
            account,
            keychainPath
        ])
    }

    private func run(_ arguments: [String]) throws -> ProcessResult {
        let result: ProcessResult
        let redactedArguments = sanitize(arguments)
        do {
            result = try processRunner.run(
                executable: Self.executablePath,
                arguments: arguments,
                standardInput: nil
            )
        } catch let error as UFOError {
            throw error
        } catch {
            throw UFOError.subprocess(
                "Failed running '\(Self.executablePath) \(redactedArguments.joined(separator: " "))': \(error.localizedDescription)"
            )
        }

        guard result.exitCode == 0 else {
            let stderr = String(decoding: result.standardError, as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            let detail = stderr.isEmpty ? "exit code \(result.exitCode)" : stderr
            throw UFOError.subprocess(
                "security command failed for args [\(redactedArguments.joined(separator: ", "))]: \(detail)"
            )
        }

        return result
    }

    private func sanitize(_ arguments: [String]) -> [String] {
        let sensitiveFlags: Set<String> = ["-w", "-p"]

        var redacted: [String] = []
        var shouldRedactValue = false

        for argument in arguments {
            if shouldRedactValue {
                redacted.append("<redacted>")
                shouldRedactValue = false
                continue
            }

            redacted.append(argument)
            if sensitiveFlags.contains(argument) {
                shouldRedactValue = true
            }
        }

        return redacted
    }
}
