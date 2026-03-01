import Foundation

public final class ManagedRegistryStore {
    private let fileSystem: FileSysteming
    private let clock: Clock
    public let registryPath: String
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    public init(
        fileSystem: FileSysteming,
        clock: Clock,
        registryPath: String = "~/.ufo/registry.json"
    ) {
        self.fileSystem = fileSystem
        self.clock = clock
        self.registryPath = fileSystem.canonicalPath(registryPath)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        self.encoder = encoder

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        self.decoder = decoder
    }

    public func load() throws -> ManagedRegistry {
        guard fileSystem.fileExists(at: registryPath) else {
            return ManagedRegistry()
        }

        let data = try fileSystem.readFile(at: registryPath)
        let decoded: ManagedRegistry
        do {
            decoded = try decoder.decode(ManagedRegistry.self, from: data)
        } catch {
            throw UFOError.io("Registry at \(registryPath) is not valid JSON: \(error.localizedDescription)")
        }

        try validate(decoded)
        return decoded
    }

    public func listKeychains() throws -> [ManagedKeychain] {
        try load().keychains.sorted { lhs, rhs in
            lhs.name.localizedCaseInsensitiveCompare(rhs.name) == .orderedAscending
        }
    }

    public func managedKeychain(named name: String) throws -> ManagedKeychain? {
        let registry = try load()
        return registry.keychains.first(where: { $0.name == name })
    }

    @discardableResult
    public func addKeychain(name: String, path: String) throws -> ManagedKeychain {
        var registry = try load()
        if registry.keychains.contains(where: { $0.name == name }) {
            throw UFOError.conflict("Managed keychain '\(name)' already exists.")
        }

        let managed = ManagedKeychain(name: name, path: path, createdAt: clock.now())
        registry.keychains.append(managed)
        try save(registry)
        return managed
    }

    @discardableResult
    public func markHardened(name: String) throws -> ManagedKeychain {
        var registry = try load()
        guard let index = registry.keychains.firstIndex(where: { $0.name == name }) else {
            throw UFOError.notFound("Managed keychain '\(name)' was not found.")
        }

        registry.keychains[index].hardenedAt = clock.now()
        try save(registry)
        return registry.keychains[index]
    }

    @discardableResult
    public func removeKeychain(name: String) throws -> ManagedKeychain {
        var registry = try load()
        guard let index = registry.keychains.firstIndex(where: { $0.name == name }) else {
            throw UFOError.notFound("Managed keychain '\(name)' was not found.")
        }

        let removed = registry.keychains.remove(at: index)
        try save(registry)
        return removed
    }

    public func upsertSecretMetadata(
        keychainName: String,
        service: String,
        account: String
    ) throws {
        var registry = try load()
        guard let index = registry.keychains.firstIndex(where: { $0.name == keychainName }) else {
            throw UFOError.notFound("Managed keychain '\(keychainName)' was not found.")
        }

        let now = clock.now()
        if let secretIndex = registry.keychains[index].secrets.firstIndex(where: {
            $0.service == service && $0.account == account
        }) {
            registry.keychains[index].secrets[secretIndex].updatedAt = now
        } else {
            registry.keychains[index].secrets.append(
                SecretMetadata(service: service, account: account, updatedAt: now)
            )
        }

        registry.keychains[index].secrets.sort { lhs, rhs in
            if lhs.service == rhs.service {
                return lhs.account < rhs.account
            }
            return lhs.service < rhs.service
        }

        try save(registry)
    }

    public func removeSecretMetadata(
        keychainName: String,
        service: String,
        account: String
    ) throws {
        var registry = try load()
        guard let index = registry.keychains.firstIndex(where: { $0.name == keychainName }) else {
            throw UFOError.notFound("Managed keychain '\(keychainName)' was not found.")
        }

        registry.keychains[index].secrets.removeAll { secret in
            secret.service == service && secret.account == account
        }
        try save(registry)
    }

    public func searchSecrets(keychainName: String, query: String) throws -> [SecretMetadata] {
        guard !query.isEmpty else {
            return []
        }

        guard let keychain = try managedKeychain(named: keychainName) else {
            throw UFOError.notFound("Managed keychain '\(keychainName)' was not found.")
        }

        let normalized = query.lowercased()
        return keychain.secrets.filter { secret in
            secret.service.lowercased().contains(normalized) ||
                secret.account.lowercased().contains(normalized)
        }
    }

    public func save(_ registry: ManagedRegistry) throws {
        try validate(registry)
        let data = try encoder.encode(registry)
        try fileSystem.writeFile(data, to: registryPath)
    }

    private func validate(_ registry: ManagedRegistry) throws {
        var seenNames = Set<String>()
        for keychain in registry.keychains {
            let inserted = seenNames.insert(keychain.name).inserted
            if !inserted {
                throw UFOError.io("Registry contains duplicate keychain name '\(keychain.name)'.")
            }
        }
    }
}
