import Foundation
import Testing
@testable import UFOLib

@Suite("Models")
struct ModelsTests {
    @Test("UFOError maps to deterministic messages and exit codes")
    func ufoErrorMappings() {
        #expect(UFOError.usage("x").message == "Usage error: x")
        #expect(UFOError.usage("x").exitCode == .usage)

        #expect(UFOError.validation("x").message == "Validation error: x")
        #expect(UFOError.validation("x").exitCode == .policyDenied)

        #expect(UFOError.policyDenied("x").message == "Policy denied: x")
        #expect(UFOError.policyDenied("x").exitCode == .policyDenied)

        #expect(UFOError.notFound("x").message == "Not found: x")
        #expect(UFOError.notFound("x").exitCode == .notFound)

        #expect(UFOError.conflict("x").message == "Conflict: x")
        #expect(UFOError.conflict("x").exitCode == .policyDenied)

        #expect(UFOError.io("x").message == "I/O error: x")
        #expect(UFOError.io("x").exitCode == .ioFailure)

        #expect(UFOError.subprocess("x").message == "Subprocess error: x")
        #expect(UFOError.subprocess("x").exitCode == .subprocessFailure)

        #expect(UFOError.internalError("x").message == "Internal error: x")
        #expect(UFOError.internalError("x").exitCode == .internalError)
    }

    @Test("Initializers assign expected values")
    func modelInitializers() {
        let commandResult = CommandResult(exitCode: 1, standardOutput: "o", standardError: "e")
        #expect(commandResult.exitCode == 1)
        #expect(commandResult.standardOutput == "o")
        #expect(commandResult.standardError == "e")

        let processResult = ProcessResult(exitCode: 2, standardOutput: Data("a".utf8), standardError: Data("b".utf8))
        #expect(processResult.exitCode == 2)
        #expect(String(decoding: processResult.standardOutput, as: UTF8.self) == "a")
        #expect(String(decoding: processResult.standardError, as: UTF8.self) == "b")

        let date = Date(timeIntervalSince1970: 1_000)
        let secret = SecretMetadata(service: "svc", account: "acct", updatedAt: date)
        let keychain = ManagedKeychain(name: "k", path: "/tmp/k", createdAt: date, hardenedAt: nil, secrets: [secret])
        let registry = ManagedRegistry(version: 2, keychains: [keychain])
        let audit = AuditHealth(activeLogPath: "/tmp/log", usingFallbackDirectory: true, writable: false, lastError: "x")

        #expect(secret.service == "svc")
        #expect(keychain.name == "k")
        #expect(registry.version == 2)
        #expect(audit.activeLogPath == "/tmp/log")
    }
}
