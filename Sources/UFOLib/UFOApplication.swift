import Foundation

public final class UFOApplication {
    private static let defaultSecretRunTimeout: TimeInterval = 300

    private struct GlobalExecutionOptions {
        let arguments: [String]
        let traceEnabled: Bool
    }

    private final class TraceCollector {
        private let enabled: Bool
        private var lines: [String]
        private let formatter: ISO8601DateFormatter

        init(enabled: Bool) {
            self.enabled = enabled
            self.lines = []
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            self.formatter = formatter
        }

        func log(_ message: String) {
            guard enabled else {
                return
            }

            let timestamp = formatter.string(from: Date())
            lines.append("[trace \(timestamp)] \(message)")
        }

        func prepend(to output: String) -> String {
            guard enabled, !lines.isEmpty else {
                return output
            }

            let traceOutput = lines.joined(separator: "\n")
            guard !output.isEmpty else {
                return traceOutput
            }

            return "\(traceOutput)\n\(output)"
        }
    }

    private let parser: CommandParser
    private let fileSystem: FileSysteming
    private let inputReader: InputReading
    private let policy: KeychainProtectionPolicy
    private let registryStore: ManagedRegistryStore
    private let securityCLI: SecurityCLI
    private let processRunner: ProcessRunning
    private let auditLogger: AuditLogger

    public init(
        parser: CommandParser,
        fileSystem: FileSysteming,
        inputReader: InputReading,
        policy: KeychainProtectionPolicy,
        registryStore: ManagedRegistryStore,
        securityCLI: SecurityCLI,
        processRunner: ProcessRunning,
        auditLogger: AuditLogger
    ) {
        self.parser = parser
        self.fileSystem = fileSystem
        self.inputReader = inputReader
        self.policy = policy
        self.registryStore = registryStore
        self.securityCLI = securityCLI
        self.processRunner = processRunner
        self.auditLogger = auditLogger
    }

    public func run(arguments: [String]) -> CommandResult {
        var effectiveArguments = arguments
        var trace = TraceCollector(enabled: false)

        do {
            let globalOptions = try parseGlobalExecutionOptions(arguments)
            effectiveArguments = globalOptions.arguments
            trace = TraceCollector(enabled: globalOptions.traceEnabled)

            trace.log("raw args=\(effectiveArguments)")
            let command = try parser.parse(effectiveArguments)
            trace.log("command=\(eventName(for: command)) args=\(effectiveArguments)")

            let result = try execute(command, trace: trace)
            let outcome = result.exitCode == ExitCode.success.rawValue ? "success" : "failure"
            auditLogger.log(event: eventName(for: command), outcome: outcome, metadata: metadata(for: command))

            return CommandResult(
                exitCode: result.exitCode,
                standardOutput: trace.prepend(to: result.standardOutput),
                standardError: result.standardError
            )
        } catch let error as UFOError {
            let eventArguments = effectiveArguments.isEmpty ? ["help"] : effectiveArguments
            auditLogger.log(
                event: eventName(for: eventArguments),
                outcome: "failure",
                metadata: ["error": error.message]
            )
            return CommandResult(
                exitCode: error.exitCode.rawValue,
                standardOutput: trace.prepend(to: ""),
                standardError: error.message
            )
        } catch {
            let wrapped = UFOError.internalError(error.localizedDescription)
            let eventArguments = effectiveArguments.isEmpty ? ["help"] : effectiveArguments
            auditLogger.log(
                event: eventName(for: eventArguments),
                outcome: "failure",
                metadata: ["error": wrapped.message]
            )
            return CommandResult(
                exitCode: wrapped.exitCode.rawValue,
                standardOutput: trace.prepend(to: ""),
                standardError: wrapped.message
            )
        }
    }

    private func execute(_ command: Command, trace: TraceCollector) throws -> CommandResult {
        switch command {
        case .help(let topic):
            return successResult(HelpText.render(topic: topic))
        case .doctor:
            return successResult(try runDoctor())
        case .keychainCreate(let name, let path):
            return successResult(try createKeychain(name: name, directory: path))
        case .keychainHarden(let name):
            return successResult(try hardenKeychain(name: name))
        case .keychainList:
            return successResult(try listKeychains())
        case .keychainInventory(let user):
            return successResult(try listUserKeychainInventory(user: user, trace: trace))
        case .keychainDelete(let name, let yes, let confirm):
            return successResult(try deleteKeychain(name: name, yes: yes, confirm: confirm))
        case .secretSet(let keychain, let service, let account, let input):
            return successResult(try setSecret(keychain: keychain, service: service, account: account, input: input))
        case .secretRun(
            let keychain,
            let service,
            let account,
            let environmentVariable,
            let executable,
            let arguments,
            let timeout
        ):
            return try runSecretCommand(
                keychain: keychain,
                service: service,
                account: account,
                environmentVariable: environmentVariable,
                executable: executable,
                arguments: arguments,
                timeout: timeout,
                trace: trace
            )
        case .secretRunShortcut(
            let keychain,
            let service,
            let account,
            let environmentVariable,
            let executable,
            let arguments,
            let timeout
        ):
            return try runSecretCommandShortcut(
                keychain: keychain,
                service: service,
                account: account,
                environmentVariable: environmentVariable,
                executable: executable,
                arguments: arguments,
                timeout: timeout,
                trace: trace
            )
        case .secretGet(let keychain, let service, let account, let reveal):
            return successResult(try getSecret(keychain: keychain, service: service, account: account, reveal: reveal))
        case .secretRemove(let keychain, let service, let account, let yes):
            return successResult(try removeSecret(keychain: keychain, service: service, account: account, yes: yes))
        case .secretSearch(let keychain, let query):
            return successResult(try searchSecrets(keychain: keychain, query: query))
        }
    }

    private func successResult(_ output: String) -> CommandResult {
        CommandResult(
            exitCode: ExitCode.success.rawValue,
            standardOutput: output,
            standardError: ""
        )
    }

    private func parseGlobalExecutionOptions(_ arguments: [String]) throws -> GlobalExecutionOptions {
        var remaining = arguments
        var traceEnabled = false

        while let first = remaining.first, first == "--trace" {
            guard !traceEnabled else {
                throw UFOError.usage("Option '--trace' was provided multiple times.")
            }
            traceEnabled = true
            remaining.removeFirst()
        }

        return GlobalExecutionOptions(arguments: remaining, traceEnabled: traceEnabled)
    }

    private func listUserKeychainInventory(user: String?, trace: TraceCollector) throws -> String {
        let currentUser = NSUserName()
        let requestedUser = user?.trimmingCharacters(in: .whitespacesAndNewlines)
        if let requestedUser {
            try validateUserName(requestedUser)
        }

        let targetUser = requestedUser ?? currentUser
        let useSudo = requestedUser != nil && requestedUser != currentUser

        let executable: String
        let arguments: [String]
        if useSudo {
            executable = "/usr/bin/sudo"
            arguments = ["-n", "-u", targetUser, SecurityCLI.executablePath, "list-keychains", "-d", "user"]
        } else {
            executable = SecurityCLI.executablePath
            arguments = ["list-keychains", "-d", "user"]
        }

        trace.log("keychain inventory query_user=\(targetUser) mode=\(useSudo ? "sudo -n" : "current-user")")

        let result = try processRunner.run(
            executable: executable,
            arguments: arguments,
            standardInput: nil,
            timeout: SecurityCLI.defaultSubprocessTimeout,
            environment: nil
        )

        guard result.exitCode == 0 else {
            let stderr = String(decoding: result.standardError, as: UTF8.self)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            let detail = stderr.isEmpty ? "exit code \(result.exitCode)" : stderr
            throw UFOError.subprocess("Failed listing keychains for user '\(targetUser)': \(detail)")
        }

        let visibleKeychains = parseKeychainPaths(from: result.standardOutput)
        let managedKeychains = try registryStore.listKeychains()
        let managedByPath = Dictionary(uniqueKeysWithValues: managedKeychains.map {
            (fileSystem.canonicalPath($0.path), $0)
        })

        let dateFormatter = ISO8601DateFormatter()
        dateFormatter.formatOptions = [.withInternetDateTime]

        var lines: [String] = []
        lines.append("Keychain inventory")
        lines.append(
            "Defaults: --user is optional. Without it, UFO uses the current macOS user and 'security list-keychains -d user'."
        )
        lines.append("Defaults: 'managed/status/secrets' metadata comes from \(registryStore.registryPath).")
        lines.append(
            "Context: user=\(targetUser) mode=\(useSudo ? "sudo -n (non-interactive)" : "current-user")"
        )

        guard !visibleKeychains.isEmpty else {
            lines.append("No keychains were returned for this user search list.")
            return lines.joined(separator: "\n")
        }

        lines.append("path\tmanaged\tmanaged_name\tstatus\tsecrets\texists\tmodified_at")
        for path in visibleKeychains {
            let canonicalPath = fileSystem.canonicalPath(path)
            let managed = managedByPath[canonicalPath]

            let managedFlag = managed == nil ? "no" : "yes"
            let managedName = managed?.name ?? "-"
            let status = managed == nil ? "-" : (managed?.hardenedAt == nil ? "pending" : "hardened")
            let secrets = managed.map { String($0.secrets.count) } ?? "-"
            let exists = fileSystem.fileExists(at: canonicalPath)
            let modifiedAt: String
            if exists, let date = try? fileSystem.modificationDate(at: canonicalPath) {
                modifiedAt = dateFormatter.string(from: date)
            } else {
                modifiedAt = "-"
            }

            lines.append(
                "\(canonicalPath)\t\(managedFlag)\t\(managedName)\t\(status)\t\(secrets)\t\(exists ? "yes" : "no")\t\(modifiedAt)"
            )
        }

        return lines.joined(separator: "\n")
    }

    private func parseKeychainPaths(from output: Data) -> [String] {
        String(decoding: output, as: UTF8.self)
            .split(whereSeparator: \.isNewline)
            .map { line in
                var value = String(line).trimmingCharacters(in: .whitespacesAndNewlines)
                if value.hasPrefix("\"") && value.hasSuffix("\"") && value.count >= 2 {
                    value.removeFirst()
                    value.removeLast()
                }
                return value
            }
            .filter { !$0.isEmpty }
    }

    private func validateUserName(_ value: String) throws {
        guard !value.isEmpty else {
            throw UFOError.validation("User name cannot be empty.")
        }

        let regex = try NSRegularExpression(pattern: "^[A-Za-z_][A-Za-z0-9._-]{0,127}$")
        let range = NSRange(location: 0, length: value.utf16.count)
        guard regex.firstMatch(in: value, options: [], range: range) != nil else {
            throw UFOError.validation(
                "User name must start with a letter or underscore and contain only letters, numbers, '.', '_', or '-'."
            )
        }
    }

    private func createKeychain(name: String, directory: String?) throws -> String {
        try InputValidation.validateKeychainName(name)
        try policy.assertNameAllowed(name)

        if try registryStore.managedKeychain(named: name) != nil {
            throw UFOError.conflict("Managed keychain '\(name)' already exists.")
        }

        let targetDirectory = fileSystem.canonicalPath(directory ?? "~/.ufo/keychains")
        try policy.assertPathAllowed(targetDirectory)

        let keychainPath = fileSystem.canonicalPath("\(targetDirectory)/\(KeychainPath.filename(for: name))")
        try policy.assertPathAllowed(keychainPath)

        try securityCLI.createKeychain(at: keychainPath)
        do {
            _ = try registryStore.addKeychain(name: name, path: keychainPath)
        } catch {
            try? securityCLI.deleteKeychain(at: keychainPath)
            throw error
        }

        return "Created managed keychain '\(name)' at \(keychainPath)."
    }

    private func hardenKeychain(name: String) throws -> String {
        let managed = try requireManagedKeychain(named: name)
        try policy.assertNameAllowed(managed.name)
        try policy.assertPathAllowed(managed.path)

        try securityCLI.hardenKeychain(at: managed.path)
        _ = try registryStore.markHardened(name: name)

        return "Hardened managed keychain '\(name)'."
    }

    private func listKeychains() throws -> String {
        let keychains = try registryStore.listKeychains()
        guard !keychains.isEmpty else {
            return "No managed keychains found."
        }

        var lines = ["name\tstatus\tpath"]
        for keychain in keychains {
            let status = keychain.hardenedAt == nil ? "pending" : "hardened"
            lines.append("\(keychain.name)\t\(status)\t\(keychain.path)")
        }
        return lines.joined(separator: "\n")
    }

    private func deleteKeychain(name: String, yes: Bool, confirm: String?) throws -> String {
        guard yes else {
            throw UFOError.validation("'keychain delete' requires --yes.")
        }
        guard confirm == name else {
            throw UFOError.validation("'keychain delete' requires --confirm <name> matching the keychain name.")
        }

        let managed = try requireManagedKeychain(named: name)
        try policy.assertNameAllowed(managed.name)
        try policy.assertPathAllowed(managed.path)

        try securityCLI.deleteKeychain(at: managed.path)
        _ = try registryStore.removeKeychain(name: name)

        return "Deleted managed keychain '\(name)'."
    }

    private func setSecret(
        keychain: String,
        service: String,
        account: String,
        input _: SecretInput
    ) throws -> String {
        try InputValidation.validateService(service)
        try InputValidation.validateAccount(account)

        let managed = try requireManagedKeychain(named: keychain)
        try policy.assertNameAllowed(managed.name)
        try policy.assertPathAllowed(managed.path)

        let rawValue = try inputReader.readStandardInput(maxBytes: InputValidation.maximumSecretInputBytes)

        try InputValidation.validateSecret(rawValue)

        try securityCLI.setSecret(
            keychainPath: managed.path,
            service: service,
            account: account,
            value: rawValue
        )
        try registryStore.upsertSecretMetadata(keychainName: keychain, service: service, account: account)

        return "Stored secret metadata for service '\(service)' account '\(account)' in keychain '\(keychain)'."
    }

    private func getSecret(
        keychain: String,
        service: String,
        account: String,
        reveal: Bool
    ) throws -> String {
        guard reveal else {
            throw UFOError.validation("'secret get' requires --reveal.")
        }

        try InputValidation.validateService(service)
        try InputValidation.validateAccount(account)

        let managed = try requireManagedKeychain(named: keychain)
        try policy.assertNameAllowed(managed.name)
        try policy.assertPathAllowed(managed.path)

        return try securityCLI.getSecret(
            keychainPath: managed.path,
            service: service,
            account: account
        )
    }

    private func runSecretCommand(
        keychain: String,
        service: String,
        account: String,
        environmentVariable: String,
        executable: String,
        arguments: [String],
        timeout: TimeInterval?,
        trace: TraceCollector
    ) throws -> CommandResult {
        try InputValidation.validateService(service)
        try InputValidation.validateAccount(account)
        try InputValidation.validateEnvironmentVariableName(environmentVariable)

        let managed = try requireManagedKeychain(named: keychain)
        try policy.assertNameAllowed(managed.name)
        try policy.assertPathAllowed(managed.path)

        trace.log(
            "secret run keychain=\(managed.name) service=\(service) account=\(account) env=\(environmentVariable) command=\(executable)"
        )

        let secret = try securityCLI.getSecret(
            keychainPath: managed.path,
            service: service,
            account: account
        )

        trace.log("secret source keychain_path=\(managed.path) value=<redacted>")

        var environment = ProcessInfo.processInfo.environment
        environment[environmentVariable] = secret

        let effectiveTimeout = timeout ?? Self.defaultSecretRunTimeout
        let result = try processRunner.run(
            executable: "/usr/bin/env",
            arguments: ["--", executable] + arguments,
            standardInput: nil,
            timeout: effectiveTimeout,
            environment: environment
        )

        trace.log("child process exit_code=\(result.exitCode) timeout=\(effectiveTimeout)s")

        return CommandResult(
            exitCode: result.exitCode,
            standardOutput: String(decoding: result.standardOutput, as: UTF8.self),
            standardError: String(decoding: result.standardError, as: UTF8.self)
        )
    }

    private func runSecretCommandShortcut(
        keychain: String?,
        service: String?,
        account: String?,
        environmentVariable: String,
        executable: String,
        arguments: [String],
        timeout: TimeInterval?,
        trace: TraceCollector
    ) throws -> CommandResult {
        try InputValidation.validateEnvironmentVariableName(environmentVariable)
        if let service {
            try InputValidation.validateService(service)
        }
        if let account {
            try InputValidation.validateAccount(account)
        }

        let managed = try resolveManagedKeychainForShortcut(named: keychain, trace: trace)
        let resolved = try resolveSecretMetadataForShortcut(
            in: managed,
            environmentVariable: environmentVariable,
            service: service,
            account: account,
            trace: trace
        )

        trace.log(
            "shortcut resolved keychain=\(managed.name) service=\(resolved.service) account=\(resolved.account) env=\(environmentVariable)"
        )

        return try runSecretCommand(
            keychain: managed.name,
            service: resolved.service,
            account: resolved.account,
            environmentVariable: environmentVariable,
            executable: executable,
            arguments: arguments,
            timeout: timeout,
            trace: trace
        )
    }

    private func resolveManagedKeychainForShortcut(named name: String?, trace: TraceCollector) throws -> ManagedKeychain {
        if let name {
            let managed = try requireManagedKeychain(named: name)
            try policy.assertNameAllowed(managed.name)
            try policy.assertPathAllowed(managed.path)
            trace.log("shortcut keychain selector provided keychain=\(managed.name)")
            return managed
        }

        let keychains = try registryStore.listKeychains()
        guard !keychains.isEmpty else {
            throw UFOError.notFound("No managed keychains found. Create one with 'ufo keychain create <name>'.")
        }

        guard keychains.count == 1 else {
            throw UFOError.usage(
                "Multiple managed keychains found. Provide --keychain or use 'ufo secret run ...' with explicit selectors."
            )
        }

        let managed = keychains[0]
        try policy.assertNameAllowed(managed.name)
        try policy.assertPathAllowed(managed.path)
        trace.log("shortcut default keychain inferred keychain=\(managed.name)")
        return managed
    }

    private func resolveSecretMetadataForShortcut(
        in managed: ManagedKeychain,
        environmentVariable: String,
        service: String?,
        account: String?,
        trace: TraceCollector
    ) throws -> SecretMetadata {
        guard !managed.secrets.isEmpty else {
            throw UFOError.notFound(
                "No secret metadata found in keychain '\(managed.name)'. Store a secret first with 'ufo secret set'."
            )
        }

        var candidates = managed.secrets
        if let service {
            candidates = candidates.filter { $0.service == service }
        }
        if let account {
            candidates = candidates.filter { $0.account == account }
        }

        if service != nil || account != nil {
            guard !candidates.isEmpty else {
                var selectors: [String] = []
                if let service {
                    selectors.append("service '\(service)'")
                }
                if let account {
                    selectors.append("account '\(account)'")
                }
                throw UFOError.notFound(
                    "No secret metadata matches \(selectors.joined(separator: " and ")) in keychain '\(managed.name)'."
                )
            }

            guard candidates.count == 1 else {
                throw UFOError.usage(
                    "Multiple secret metadata entries match in keychain '\(managed.name)'. Provide both --service and --account."
                )
            }
            trace.log("shortcut secret selector used explicit service/account")
            return candidates[0]
        }

        let envLookupTokens = defaultLookupTokens(for: environmentVariable)
        let envMatches = candidates.filter { metadata in
            let serviceToken = normalizeLookupToken(metadata.service)
            let accountToken = normalizeLookupToken(metadata.account)
            return envLookupTokens.contains(serviceToken) || envLookupTokens.contains(accountToken)
        }

        if envMatches.count == 1 {
            trace.log("shortcut secret inferred from env token env=\(environmentVariable)")
            return envMatches[0]
        }

        if envMatches.count > 1 {
            throw UFOError.usage(
                "Multiple secrets match --env \(environmentVariable) in keychain '\(managed.name)'. Provide --service and --account."
            )
        }

        if candidates.count == 1 {
            trace.log("shortcut secret defaulted to only metadata entry")
            return candidates[0]
        }

        throw UFOError.usage(
            "Multiple secrets are stored in keychain '\(managed.name)'. Provide --service and --account."
        )
    }

    private func defaultLookupTokens(for environmentVariable: String) -> Set<String> {
        let normalized = normalizeLookupToken(environmentVariable)
        guard !normalized.isEmpty else {
            return []
        }

        var tokens: Set<String> = [normalized]
        let suffixes = ["_API_KEY", "_TOKEN", "_KEY", "_SECRET"]
        for suffix in suffixes where normalized.hasSuffix(suffix) {
            let trimmed = String(normalized.dropLast(suffix.count))
            if !trimmed.isEmpty {
                tokens.insert(trimmed)
            }
        }

        return tokens
    }

    private func normalizeLookupToken(_ value: String) -> String {
        let uppercased = value.uppercased()
        let replaced = uppercased.replacingOccurrences(of: "[^A-Z0-9]+", with: "_", options: .regularExpression)
        let collapsed = replaced.replacingOccurrences(of: "_{2,}", with: "_", options: .regularExpression)
        return collapsed.trimmingCharacters(in: CharacterSet(charactersIn: "_"))
    }

    private func removeSecret(
        keychain: String,
        service: String,
        account: String,
        yes: Bool
    ) throws -> String {
        guard yes else {
            throw UFOError.validation("'secret remove' requires --yes.")
        }

        try InputValidation.validateService(service)
        try InputValidation.validateAccount(account)

        let managed = try requireManagedKeychain(named: keychain)
        try policy.assertNameAllowed(managed.name)
        try policy.assertPathAllowed(managed.path)

        try securityCLI.removeSecret(
            keychainPath: managed.path,
            service: service,
            account: account
        )
        try registryStore.removeSecretMetadata(keychainName: keychain, service: service, account: account)

        return "Removed secret metadata for service '\(service)' account '\(account)' from keychain '\(keychain)'."
    }

    private func searchSecrets(keychain: String, query: String) throws -> String {
        try InputValidation.validateQuery(query)

        let managed = try requireManagedKeychain(named: keychain)
        try policy.assertNameAllowed(managed.name)
        try policy.assertPathAllowed(managed.path)

        let results = try registryStore.searchSecrets(keychainName: keychain, query: query)
            .sorted { ($0.service, $0.account) < ($1.service, $1.account) }

        guard !results.isEmpty else {
            return "No metadata matches '\(query)' in keychain '\(keychain)'."
        }

        var lines = ["service\taccount"]
        for secret in results {
            lines.append("\(secret.service)\t\(secret.account)")
        }
        return lines.joined(separator: "\n")
    }

    private func runDoctor() throws -> String {
        var reportLines: [String] = []
        var failures: [String] = []

        if fileSystem.fileExists(at: SecurityCLI.executablePath) {
            reportLines.append("security_binary: ok (\(SecurityCLI.executablePath))")
        } else {
            let message = "security_binary: fail (missing \(SecurityCLI.executablePath))"
            reportLines.append(message)
            failures.append(message)
        }

        do {
            _ = try registryStore.load()
            reportLines.append("registry: ok (\(registryStore.registryPath))")
        } catch {
            let detail = (error as? UFOError)?.message ?? error.localizedDescription
            let message = "registry: fail (\(detail))"
            reportLines.append(message)
            failures.append(message)
        }

        let logHealth = auditLogger.health()
        if logHealth.writable {
            let mode = logHealth.usingFallbackDirectory ? "fallback" : "primary"
            reportLines.append("audit_log: ok (\(mode) \(logHealth.activeLogPath))")
        } else {
            let detail = logHealth.lastError ?? "directory not writable"
            let message = "audit_log: fail (\(detail))"
            reportLines.append(message)
            failures.append(message)
        }

        if failures.isEmpty {
            return reportLines.joined(separator: "\n")
        }

        throw UFOError.io(reportLines.joined(separator: "\n"))
    }

    private func requireManagedKeychain(named name: String) throws -> ManagedKeychain {
        guard let managed = try registryStore.managedKeychain(named: name) else {
            throw UFOError.notFound("Managed keychain '\(name)' was not found.")
        }
        return managed
    }

    private func eventName(for command: Command) -> String {
        switch command {
        case .keychainCreate:
            return "keychain.create"
        case .keychainHarden:
            return "keychain.harden"
        case .keychainList:
            return "keychain.list"
        case .keychainInventory:
            return "keychain.inventory"
        case .keychainDelete:
            return "keychain.delete"
        case .secretSet:
            return "secret.set"
        case .secretRun:
            return "secret.run"
        case .secretRunShortcut:
            return "secret.run.shortcut"
        case .secretGet:
            return "secret.get"
        case .secretRemove:
            return "secret.remove"
        case .secretSearch:
            return "secret.search"
        case .doctor:
            return "doctor"
        case .help:
            return "help"
        }
    }

    private func eventName(for arguments: [String]) -> String {
        let first = arguments[0]

        if first.hasPrefix("--") {
            return "secret.run.shortcut"
        }

        if arguments.count >= 2 {
            return "\(arguments[0]).\(arguments[1])"
        }

        return first
    }

    private func metadata(for command: Command) -> [String: String] {
        switch command {
        case .keychainCreate(let name, _):
            return ["keychain": name]
        case .keychainHarden(let name):
            return ["keychain": name]
        case .keychainList:
            return [:]
        case .keychainInventory(let user):
            return ["user": user ?? "<current>"]
        case .keychainDelete(let name, _, _):
            return ["keychain": name]
        case .secretSet(let keychain, let service, let account, _):
            return [
                "keychain": keychain,
                "service": service,
                "account": account,
                "source": "stdin"
            ]
        case .secretRun(
            let keychain,
            let service,
            let account,
            let environmentVariable,
            let executable,
            _,
            let timeout
        ):
            let timeoutSeconds = timeout ?? Self.defaultSecretRunTimeout
            return [
                "keychain": keychain,
                "service": service,
                "account": account,
                "env": environmentVariable,
                "command": executable,
                "timeout": String(timeoutSeconds)
            ]
        case .secretRunShortcut(
            let keychain,
            let service,
            let account,
            let environmentVariable,
            let executable,
            _,
            let timeout
        ):
            let timeoutSeconds = timeout ?? Self.defaultSecretRunTimeout
            return [
                "keychain": keychain ?? "<auto>",
                "service": service ?? "<auto>",
                "account": account ?? "<auto>",
                "env": environmentVariable,
                "command": executable,
                "timeout": String(timeoutSeconds)
            ]
        case .secretGet(let keychain, let service, let account, _):
            return [
                "keychain": keychain,
                "service": service,
                "account": account
            ]
        case .secretRemove(let keychain, let service, let account, _):
            return [
                "keychain": keychain,
                "service": service,
                "account": account
            ]
        case .secretSearch(let keychain, _):
            return ["keychain": keychain]
        case .doctor, .help:
            return [:]
        }
    }
}
