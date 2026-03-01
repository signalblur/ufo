import Foundation
import Testing
@testable import UFOLib

@Suite("Managed Registry Store")
struct ManagedRegistryStoreTests {
    @Test("Uses default registry path when omitted")
    func usesDefaultRegistryPath() {
        let fileSystem = FakeFileSystem()
        let store = ManagedRegistryStore(fileSystem: fileSystem, clock: FakeClock(currentDate: .init()))
        #expect(store.registryPath == "/Users/tester/.ufo/registry.json")
    }

    @Test("Loads empty registry when file missing")
    func loadMissingRegistry() throws {
        let fixture = makeFixture()
        let registry = try fixture.store.load()
        #expect(registry == ManagedRegistry())
    }

    @Test("Adds, lists, and resolves managed keychains")
    func addListAndLookup() throws {
        let fixture = makeFixture()
        _ = try fixture.store.addKeychain(name: "b", path: "/tmp/b.keychain-db")
        _ = try fixture.store.addKeychain(name: "a", path: "/tmp/a.keychain-db")

        let listed = try fixture.store.listKeychains()
        #expect(listed.map(\.name) == ["a", "b"])
        #expect(try fixture.store.managedKeychain(named: "b")?.path == "/tmp/b.keychain-db")
        #expect(try fixture.store.managedKeychain(named: "missing") == nil)
    }

    @Test("Rejects duplicate keychain add")
    func addDuplicate() throws {
        let fixture = makeFixture()
        _ = try fixture.store.addKeychain(name: "alpha", path: "/tmp/a")
        expectStoreError(.conflict("Managed keychain 'alpha' already exists.")) {
            _ = try fixture.store.addKeychain(name: "alpha", path: "/tmp/b")
        }
    }

    @Test("Marks hardened and removes keychains")
    func markHardenedAndRemove() throws {
        let fixture = makeFixture()
        _ = try fixture.store.addKeychain(name: "alpha", path: "/tmp/a")

        fixture.clock.currentDate = Date(timeIntervalSince1970: 1_700_000_050)
        let hardened = try fixture.store.markHardened(name: "alpha")
        #expect(hardened.hardenedAt == fixture.clock.currentDate)

        let removed = try fixture.store.removeKeychain(name: "alpha")
        #expect(removed.name == "alpha")

        expectStoreError(.notFound("Managed keychain 'alpha' was not found.")) {
            _ = try fixture.store.markHardened(name: "alpha")
        }
        expectStoreError(.notFound("Managed keychain 'alpha' was not found.")) {
            _ = try fixture.store.removeKeychain(name: "alpha")
        }
    }

    @Test("Upserts, removes, and searches secret metadata")
    func upsertRemoveSearchMetadata() throws {
        let fixture = makeFixture()
        _ = try fixture.store.addKeychain(name: "alpha", path: "/tmp/a")

        try fixture.store.upsertSecretMetadata(keychainName: "alpha", service: "github", account: "ci")
        try fixture.store.upsertSecretMetadata(keychainName: "alpha", service: "github", account: "bot")
        try fixture.store.upsertSecretMetadata(keychainName: "alpha", service: "apple", account: "ops")

        fixture.clock.currentDate = Date(timeIntervalSince1970: 1_700_001_000)
        try fixture.store.upsertSecretMetadata(keychainName: "alpha", service: "github", account: "ci")

        #expect(try fixture.store.searchSecrets(keychainName: "alpha", query: "") == [])

        let matches = try fixture.store.searchSecrets(keychainName: "alpha", query: "git")
        #expect(matches.count == 2)
        #expect(matches.contains(where: { $0.account == "ci" && $0.updatedAt == fixture.clock.currentDate }))

        try fixture.store.removeSecretMetadata(keychainName: "alpha", service: "github", account: "ci")
        #expect(try fixture.store.searchSecrets(keychainName: "alpha", query: "git").count == 1)

        expectStoreError(.notFound("Managed keychain 'missing' was not found.")) {
            try fixture.store.removeSecretMetadata(keychainName: "missing", service: "s", account: "a")
        }
        expectStoreError(.notFound("Managed keychain 'missing' was not found.")) {
            try fixture.store.upsertSecretMetadata(keychainName: "missing", service: "s", account: "a")
        }
        expectStoreError(.notFound("Managed keychain 'missing' was not found.")) {
            _ = try fixture.store.searchSecrets(keychainName: "missing", query: "x")
        }
    }

    @Test("Rejects corrupt JSON registry")
    func loadCorruptJSON() {
        let fixture = makeFixture()
        fixture.fileSystem.writeString("not-json", to: fixture.store.registryPath)

        do {
            _ = try fixture.store.load()
            Issue.record("Expected invalid JSON error")
        } catch {
            guard case .io(let message) = error as? UFOError else {
                Issue.record("Unexpected error: \(error)")
                return
            }
            #expect(message.contains("is not valid JSON"))
        }
    }

    @Test("Rejects duplicate names in registry file")
    func loadDuplicateNames() {
        let fixture = makeFixture()
        let payload = """
        {
          "version" : 1,
          "keychains" : [
            {
              "createdAt" : "2026-01-01T00:00:00Z",
              "hardenedAt" : null,
              "name" : "dup",
              "path" : "/tmp/one",
              "secrets" : []
            },
            {
              "createdAt" : "2026-01-02T00:00:00Z",
              "hardenedAt" : null,
              "name" : "dup",
              "path" : "/tmp/two",
              "secrets" : []
            }
          ]
        }
        """
        fixture.fileSystem.writeString(payload, to: fixture.store.registryPath)

        expectStoreError(.io("Registry contains duplicate keychain name 'dup'.")) {
            _ = try fixture.store.load()
        }
    }

    @Test("Propagates write failure on save")
    func saveWriteFailure() {
        let fixture = makeFixture()
        fixture.fileSystem.writeFailures.insert(fixture.fileSystem.canonicalPath(fixture.store.registryPath))

        expectStoreError(.io("write failed")) {
            try fixture.store.save(ManagedRegistry())
        }
    }
}

private func makeFixture() -> (
    fileSystem: FakeFileSystem,
    clock: FakeClock,
    store: ManagedRegistryStore
) {
    let fileSystem = FakeFileSystem()
    let clock = FakeClock(currentDate: Date(timeIntervalSince1970: 1_700_000_000))
    let store = ManagedRegistryStore(fileSystem: fileSystem, clock: clock, registryPath: "~/.ufo/registry.json")
    return (fileSystem, clock, store)
}

private func expectStoreError(_ expected: UFOError, _ operation: () throws -> Void) {
    do {
        try operation()
        Issue.record("Expected error \(expected)")
    } catch {
        #expect(error as? UFOError == expected)
    }
}
