import Foundation

public final class UFOApplication {
    private let parser: CommandParser
    private let fileSystem: FileSysteming
    private let inputReader: InputReading
    private let policy: KeychainProtectionPolicy
    private let registryStore: ManagedRegistryStore
    private let securityCLI: SecurityCLI
    private let auditLogger: AuditLogger

    public init(
        parser: CommandParser,
        fileSystem: FileSysteming,
        inputReader: InputReading,
        policy: KeychainProtectionPolicy,
        registryStore: ManagedRegistryStore,
        securityCLI: SecurityCLI,
        auditLogger: AuditLogger
    ) {
        self.parser = parser
        self.fileSystem = fileSystem
        self.inputReader = inputReader
        self.policy = policy
        self.registryStore = registryStore
        self.securityCLI = securityCLI
        self.auditLogger = auditLogger
    }

    public func run(arguments: [String]) -> CommandResult {
        do {
            let command = try parser.parse(arguments)
            let output = try execute(command)
            auditLogger.log(event: eventName(for: command), outcome: "success", metadata: metadata(for: command))
            return CommandResult(exitCode: ExitCode.success.rawValue, standardOutput: output, standardError: "")
        } catch let error as UFOError {
            auditLogger.log(
                event: eventName(for: arguments),
                outcome: "failure",
                metadata: ["error": error.message]
            )
            return CommandResult(
                exitCode: error.exitCode.rawValue,
                standardOutput: "",
                standardError: error.message
            )
        } catch {
            let wrapped = UFOError.internalError(error.localizedDescription)
            auditLogger.log(
                event: eventName(for: arguments),
                outcome: "failure",
                metadata: ["error": wrapped.message]
            )
            return CommandResult(
                exitCode: wrapped.exitCode.rawValue,
                standardOutput: "",
                standardError: wrapped.message
            )
        }
    }

    private func execute(_ command: Command) throws -> String {
        switch command {
        case .help(let topic):
            return HelpText.render(topic: topic)
        case .doctor:
            return try runDoctor()
        case .keychainCreate(let name, let path):
            return try createKeychain(name: name, directory: path)
        case .keychainHarden(let name):
            return try hardenKeychain(name: name)
        case .keychainList:
            return try listKeychains()
        case .keychainDelete(let name, let yes, let confirm):
            return try deleteKeychain(name: name, yes: yes, confirm: confirm)
        case .secretSet(let keychain, let service, let account, let input):
            return try setSecret(keychain: keychain, service: service, account: account, input: input)
        case .secretGet(let keychain, let service, let account, let reveal):
            return try getSecret(keychain: keychain, service: service, account: account, reveal: reveal)
        case .secretRemove(let keychain, let service, let account, let yes):
            return try removeSecret(keychain: keychain, service: service, account: account, yes: yes)
        case .secretSearch(let keychain, let query):
            return try searchSecrets(keychain: keychain, query: query)
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
        input: SecretInput
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
        case .keychainDelete:
            return "keychain.delete"
        case .secretSet:
            return "secret.set"
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
        if arguments.count >= 2 {
            return "\(arguments[0]).\(arguments[1])"
        }

        return arguments[0]
    }

    private func metadata(for command: Command) -> [String: String] {
        switch command {
        case .keychainCreate(let name, _):
            return ["keychain": name]
        case .keychainHarden(let name):
            return ["keychain": name]
        case .keychainList:
            return [:]
        case .keychainDelete(let name, _, _):
            return ["keychain": name]
        case .secretSet(let keychain, let service, let account, _):
            return [
                "keychain": keychain,
                "service": service,
                "account": account,
                "source": "stdin"
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
