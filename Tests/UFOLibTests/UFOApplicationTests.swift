import Foundation
import Testing
@testable import UFOLib

@Suite("UFO Application")
struct UFOApplicationTests {
    @Test("Help output and unknown command errors")
    func helpAndUnknownCommands() {
        let fixture = makeFixture()

        let help = fixture.app.run(arguments: [])
        #expect(help.exitCode == 0)
        #expect(help.standardOutput.contains("Usage:"))

        let unknown = fixture.app.run(arguments: ["bad"])
        #expect(unknown.exitCode == ExitCode.usage.rawValue)
        #expect(unknown.standardError.contains("Unknown command 'bad'"))
    }

    @Test("Creates keychain and rejects duplicates")
    func createAndConflict() {
        let fixture = makeFixture()

        let created = fixture.app.run(arguments: ["keychain", "create", "team"])
        #expect(created.exitCode == 0)
        #expect(created.standardOutput.contains("Created managed keychain 'team'"))
        #expect(
            fixture.processRunner.invocations.first?.arguments == [
                "create-keychain", "-p", "", "/Users/tester/.ufo/keychains/team.keychain-db"
            ]
        )

        let conflict = fixture.app.run(arguments: ["keychain", "create", "team"])
        #expect(conflict.exitCode == ExitCode.policyDenied.rawValue)
        #expect(conflict.standardError.contains("already exists"))
    }

    @Test("Rejects protected keychain names and paths")
    func createRejectsProtectedInputs() {
        let fixture = makeFixture()

        let protectedName = fixture.app.run(arguments: ["keychain", "create", "login"])
        #expect(protectedName.exitCode == ExitCode.policyDenied.rawValue)
        #expect(protectedName.standardError.contains("protected keychain name"))

        let invalidName = fixture.app.run(arguments: ["keychain", "create", " bad"])
        #expect(invalidName.exitCode == ExitCode.policyDenied.rawValue)
        #expect(invalidName.standardError.contains("leading or trailing whitespace"))

        let protectedPath = fixture.app.run(arguments: [
            "keychain", "create", "safe", "--path", "/Library/Keychains"
        ])
        #expect(protectedPath.exitCode == ExitCode.policyDenied.rawValue)
        #expect(protectedPath.standardError.contains("protected system keychain location"))
    }

    @Test("Recovers by deleting keychain when registry write fails")
    func createFailureRecoveryDelete() {
        let fixture = makeFixture()
        fixture.fileSystem.writeFailures.insert(
            fixture.fileSystem.canonicalPath(fixture.registryStore.registryPath)
        )

        let result = fixture.app.run(arguments: ["keychain", "create", "recoverable"])
        #expect(result.exitCode == ExitCode.ioFailure.rawValue)
        #expect(result.standardError.contains("write failed"))
        #expect(fixture.processRunner.invocations.count == 2)
        #expect(fixture.processRunner.invocations[0].arguments[0] == "create-keychain")
        #expect(fixture.processRunner.invocations[1].arguments[0] == "delete-keychain")
    }

    @Test("Lists hardens and deletes with safety checks")
    func keychainLifecycleAndDeleteSafety() {
        let fixture = makeFixture()

        #expect(fixture.app.run(arguments: ["keychain", "list"]).standardOutput == "No managed keychains found.")

        _ = fixture.app.run(arguments: ["keychain", "create", "alpha"])
        let listed = fixture.app.run(arguments: ["keychain", "list"])
        #expect(listed.standardOutput.contains("alpha\tpending"))

        let harden = fixture.app.run(arguments: ["keychain", "harden", "alpha"])
        #expect(harden.exitCode == 0)
        #expect(harden.standardOutput.contains("Hardened managed keychain 'alpha'"))

        let listedAfter = fixture.app.run(arguments: ["keychain", "list"])
        #expect(listedAfter.standardOutput.contains("alpha\thardened"))

        let missing = fixture.app.run(arguments: ["keychain", "harden", "missing"])
        #expect(missing.exitCode == ExitCode.notFound.rawValue)

        let noYes = fixture.app.run(arguments: ["keychain", "delete", "alpha", "--confirm", "alpha"])
        #expect(noYes.exitCode == ExitCode.policyDenied.rawValue)
        #expect(noYes.standardError.contains("requires --yes"))

        let badConfirm = fixture.app.run(arguments: ["keychain", "delete", "alpha", "--yes", "--confirm", "wrong"])
        #expect(badConfirm.exitCode == ExitCode.policyDenied.rawValue)
        #expect(badConfirm.standardError.contains("matching the keychain name"))

        let deleted = fixture.app.run(arguments: ["keychain", "delete", "alpha", "--yes", "--confirm", "alpha"])
        #expect(deleted.exitCode == 0)
        #expect(deleted.standardOutput.contains("Deleted managed keychain 'alpha'"))
    }

    @Test("Secret set/get/remove/search workflow")
    func secretWorkflow() {
        let fixture = makeFixture()
        _ = fixture.app.run(arguments: ["keychain", "create", "alpha"])

        let setValue = fixture.app.run(arguments: [
            "secret", "set", "--keychain", "alpha", "--service", "github", "--account", "ci", "--value", "123"
        ])
        #expect(setValue.exitCode == 0)

        let setStdin = fixture.app.run(arguments: [
            "secret", "set", "--keychain", "alpha", "--service", "apple", "--account", "ops", "--stdin"
        ])
        #expect(setStdin.exitCode == 0)

        let setSecondGithub = fixture.app.run(arguments: [
            "secret", "set", "--keychain", "alpha", "--service", "github", "--account", "bot", "--value", "abc"
        ])
        #expect(setSecondGithub.exitCode == 0)

        let search = fixture.app.run(arguments: [
            "secret", "search", "--keychain", "alpha", "--query", "ap"
        ])
        #expect(search.exitCode == 0)
        #expect(search.standardOutput.contains("service\taccount"))
        #expect(search.standardOutput.contains("apple\tops"))

        let githubSearch = fixture.app.run(arguments: [
            "secret", "search", "--keychain", "alpha", "--query", "github"
        ])
        let githubLines = githubSearch.standardOutput.split(separator: "\n").map(String.init)
        #expect(githubLines == ["service\taccount", "github\tbot", "github\tci"])
        #expect(githubSearch.standardOutput.contains("github\tbot"))
        #expect(githubSearch.standardOutput.contains("github\tci"))

        let searchMiss = fixture.app.run(arguments: [
            "secret", "search", "--keychain", "alpha", "--query", "zzz"
        ])
        #expect(searchMiss.standardOutput.contains("No metadata matches"))

        let getNoReveal = fixture.app.run(arguments: [
            "secret", "get", "--keychain", "alpha", "--service", "github", "--account", "ci"
        ])
        #expect(getNoReveal.exitCode == ExitCode.policyDenied.rawValue)

        fixture.processRunner.enqueueSuccess(standardOutput: Data("revealed\n".utf8))
        let revealed = fixture.app.run(arguments: [
            "secret", "get", "--keychain", "alpha", "--service", "github", "--account", "ci", "--reveal"
        ])
        #expect(revealed.exitCode == 0)
        #expect(revealed.standardOutput == "revealed")

        let removeNoYes = fixture.app.run(arguments: [
            "secret", "remove", "--keychain", "alpha", "--service", "github", "--account", "ci"
        ])
        #expect(removeNoYes.exitCode == ExitCode.policyDenied.rawValue)

        let removed = fixture.app.run(arguments: [
            "secret", "remove", "--keychain", "alpha", "--service", "github", "--account", "ci", "--yes"
        ])
        #expect(removed.exitCode == 0)

        let afterRemove = fixture.app.run(arguments: [
            "secret", "search", "--keychain", "alpha", "--query", "ci"
        ])
        #expect(afterRemove.standardOutput.contains("No metadata matches"))
    }

    @Test("Secret command validation and missing managed keychain checks")
    func secretValidationAndMissingManaged() {
        let fixture = makeFixture()

        let missingManaged = fixture.app.run(arguments: [
            "secret", "set", "--keychain", "missing", "--service", "svc", "--account", "acct", "--value", "v"
        ])
        #expect(missingManaged.exitCode == ExitCode.notFound.rawValue)

        _ = fixture.app.run(arguments: ["keychain", "create", "alpha"])
        let emptyQuery = fixture.app.run(arguments: [
            "secret", "search", "--keychain", "alpha", "--query", ""
        ])
        #expect(emptyQuery.exitCode == ExitCode.usage.rawValue)

        fixture.inputReader.value = "\n"
        let emptyStdinSecret = fixture.app.run(arguments: [
            "secret", "set", "--keychain", "alpha", "--service", "svc", "--account", "acct", "--stdin"
        ])
        #expect(emptyStdinSecret.exitCode == ExitCode.policyDenied.rawValue)
        #expect(emptyStdinSecret.standardError.contains("Secret value cannot be empty"))
    }

    @Test("Doctor reports success and failure details")
    func doctorOutput() {
        let fixture = makeFixture()
        let success = fixture.app.run(arguments: ["doctor"])
        #expect(success.exitCode == 0)
        #expect(success.standardOutput.contains("security_binary: ok"))

        let badFileSystem = FakeFileSystem()
        badFileSystem.createDirectoryFailures.insert("/var/log/ufo")
        badFileSystem.createDirectoryFailures.insert("/Users/tester/Library/Logs/ufo")
        let badStore = ManagedRegistryStore(fileSystem: badFileSystem, clock: fixture.clock, registryPath: "~/.ufo/registry.json")
        badFileSystem.writeString("not-json", to: badStore.registryPath)

        let badApp = UFOApplication(
            parser: CommandParser(),
            fileSystem: badFileSystem,
            inputReader: fixture.inputReader,
            policy: KeychainProtectionPolicy(fileSystem: badFileSystem),
            registryStore: badStore,
            securityCLI: SecurityCLI(processRunner: fixture.processRunner),
            auditLogger: AuditLogger(fileSystem: badFileSystem, clock: fixture.clock)
        )

        let failed = badApp.run(arguments: ["doctor"])
        #expect(failed.exitCode == ExitCode.ioFailure.rawValue)
        #expect(failed.standardError.contains("security_binary: fail"))
        #expect(failed.standardError.contains("registry: fail"))
        #expect(failed.standardError.contains("audit_log: fail"))

        let fallbackFileSystem = FakeFileSystem()
        fallbackFileSystem.writeString("binary", to: "/usr/bin/security")
        fallbackFileSystem.createDirectoryFailures.insert("/var/log/ufo")
        let fallbackStore = ManagedRegistryStore(
            fileSystem: fallbackFileSystem,
            clock: fixture.clock,
            registryPath: "~/.ufo/registry.json"
        )
        let fallbackApp = UFOApplication(
            parser: CommandParser(),
            fileSystem: fallbackFileSystem,
            inputReader: fixture.inputReader,
            policy: KeychainProtectionPolicy(fileSystem: fallbackFileSystem),
            registryStore: fallbackStore,
            securityCLI: SecurityCLI(processRunner: fixture.processRunner),
            auditLogger: AuditLogger(fileSystem: fallbackFileSystem, clock: fixture.clock)
        )
        let fallback = fallbackApp.run(arguments: ["doctor"])
        #expect(fallback.exitCode == 0)
        #expect(fallback.standardOutput.contains("audit_log: ok (fallback"))

        let genericRegistryFileSystem = FakeFileSystem()
        genericRegistryFileSystem.writeString("binary", to: "/usr/bin/security")
        let genericStore = ManagedRegistryStore(
            fileSystem: genericRegistryFileSystem,
            clock: fixture.clock,
            registryPath: "~/.ufo/registry.json"
        )
        genericRegistryFileSystem.writeString("{}", to: genericStore.registryPath)
        genericRegistryFileSystem.readGenericFailures.insert(genericStore.registryPath)
        let genericRegistryApp = UFOApplication(
            parser: CommandParser(),
            fileSystem: genericRegistryFileSystem,
            inputReader: fixture.inputReader,
            policy: KeychainProtectionPolicy(fileSystem: genericRegistryFileSystem),
            registryStore: genericStore,
            securityCLI: SecurityCLI(processRunner: fixture.processRunner),
            auditLogger: AuditLogger(fileSystem: genericRegistryFileSystem, clock: fixture.clock)
        )
        let genericRegistryFailure = genericRegistryApp.run(arguments: ["doctor"])
        #expect(genericRegistryFailure.exitCode == ExitCode.ioFailure.rawValue)
        #expect(genericRegistryFailure.standardError.contains("registry: fail (generic read failure)"))
    }

    @Test("Maps generic errors to internal error exit code")
    func wrapsGenericError() {
        struct Boom: Error {}

        let fixture = makeFixture()
        _ = fixture.app.run(arguments: ["keychain", "create", "alpha"])

        let badApp = UFOApplication(
            parser: CommandParser(),
            fileSystem: fixture.fileSystem,
            inputReader: FakeInputReader(value: "", error: Boom()),
            policy: KeychainProtectionPolicy(fileSystem: fixture.fileSystem),
            registryStore: fixture.registryStore,
            securityCLI: SecurityCLI(processRunner: fixture.processRunner),
            auditLogger: fixture.logger
        )

        let result = badApp.run(arguments: [
            "secret", "set", "--keychain", "alpha", "--service", "svc", "--account", "acct", "--stdin"
        ])
        #expect(result.exitCode == ExitCode.internalError.rawValue)
        #expect(result.standardError.contains("Internal error"))
    }

    @Test("Subprocess errors map to subprocess exit code")
    func subprocessFailureMapping() {
        let fixture = makeFixture()
        _ = fixture.app.run(arguments: ["keychain", "create", "alpha"])

        fixture.processRunner.enqueueSuccess(exitCode: 1, standardError: Data("denied".utf8))
        let result = fixture.app.run(arguments: ["keychain", "harden", "alpha"])
        #expect(result.exitCode == ExitCode.subprocessFailure.rawValue)
        #expect(result.standardError.contains("Subprocess error"))
    }
}

private struct AppFixture {
    let fileSystem: FakeFileSystem
    let clock: FakeClock
    let inputReader: FakeInputReader
    let processRunner: FakeProcessRunner
    let registryStore: ManagedRegistryStore
    let logger: AuditLogger
    let app: UFOApplication
}

private func makeFixture() -> AppFixture {
    let fileSystem = FakeFileSystem()
    let clock = FakeClock(currentDate: Date(timeIntervalSince1970: 1_700_000_000))
    let inputReader = FakeInputReader(value: "stdin-secret\n")
    let processRunner = FakeProcessRunner()

    fileSystem.writeString("binary", to: "/usr/bin/security")

    let registryStore = ManagedRegistryStore(fileSystem: fileSystem, clock: clock, registryPath: "~/.ufo/registry.json")
    let logger = AuditLogger(fileSystem: fileSystem, clock: clock)

    let app = UFOApplication(
        parser: CommandParser(),
        fileSystem: fileSystem,
        inputReader: inputReader,
        policy: KeychainProtectionPolicy(fileSystem: fileSystem),
        registryStore: registryStore,
        securityCLI: SecurityCLI(processRunner: processRunner),
        auditLogger: logger
    )

    return AppFixture(
        fileSystem: fileSystem,
        clock: clock,
        inputReader: inputReader,
        processRunner: processRunner,
        registryStore: registryStore,
        logger: logger,
        app: app
    )
}
