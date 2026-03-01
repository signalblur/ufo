import Foundation

public final class SecurityCLI {
    public static let executablePath = "/usr/bin/security"
    public static let defaultSubprocessTimeout: TimeInterval = 10

    private let processRunner: ProcessRunning
    private let subprocessTimeout: TimeInterval

    public init(
        processRunner: ProcessRunning,
        subprocessTimeout: TimeInterval = SecurityCLI.defaultSubprocessTimeout
    ) {
        self.processRunner = processRunner
        self.subprocessTimeout = subprocessTimeout
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
        let valueHex = Data(value.utf8).map { String(format: "%02x", $0) }.joined()
        let command = interactiveCommand([
            "add-generic-password",
            "-U",
            "-s",
            service,
            "-a",
            account,
            "-X",
            valueHex,
            keychainPath
        ])

        _ = try run(
            ["-i"],
            standardInput: Data("\(command)\n".utf8),
            sensitiveValues: [valueHex]
        )
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

        return decodeSecretOutput(result.standardOutput)
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

    private func run(
        _ arguments: [String],
        standardInput: Data? = nil,
        sensitiveValues: [String] = []
    ) throws -> ProcessResult {
        let result: ProcessResult
        let redactedArguments = sanitize(arguments)
        do {
            result = try processRunner.run(
                executable: Self.executablePath,
                arguments: arguments,
                standardInput: standardInput,
                timeout: subprocessTimeout,
                environment: nil
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
            let sanitizedDetail = redactSensitive(detail, sensitiveValues: sensitiveValues)
            throw UFOError.subprocess(
                "security command failed for args [\(redactedArguments.joined(separator: ", "))]: \(sanitizedDetail)"
            )
        }

        return result
    }

    private func sanitize(_ arguments: [String]) -> [String] {
        let sensitiveFlags: Set<String> = ["-w", "-p", "-X"]

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

    private func redactSensitive(_ detail: String, sensitiveValues: [String]) -> String {
        guard !sensitiveValues.isEmpty else {
            return detail
        }

        var sanitized = detail
        for value in sensitiveValues where !value.isEmpty {
            sanitized = sanitized.replacingOccurrences(of: value, with: "<redacted>")
        }
        return sanitized
    }

    private func interactiveCommand(_ arguments: [String]) -> String {
        arguments.map(quoteInteractiveToken).joined(separator: " ")
    }

    private func quoteInteractiveToken(_ token: String) -> String {
        let escaped = token
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")
            .replacingOccurrences(of: "\r", with: "\\r")
        return "\"\(escaped)\""
    }

    private func decodeSecretOutput(_ output: Data) -> String {
        var payload = output
        if payload.last == 0x0A {
            payload.removeLast()
            if payload.last == 0x0D {
                payload.removeLast()
            }
        }

        return String(decoding: payload, as: UTF8.self)
    }
}
