import Foundation
import Testing
@testable import UFOLib

@Suite("Security CLI")
struct SecurityCLITests {
    @Test("Uses fixed security executable and strict argument arrays")
    func strictSecurityCommandConstruction() throws {
        let runner = FakeProcessRunner()
        let cli = SecurityCLI(processRunner: runner)

        try cli.createKeychain(at: "/tmp/a.keychain-db")
        try cli.hardenKeychain(at: "/tmp/a.keychain-db")
        try cli.deleteKeychain(at: "/tmp/a.keychain-db")
        try cli.setSecret(keychainPath: "/tmp/a.keychain-db", service: "svc", account: "acct", value: "value")
        _ = try cli.getSecret(keychainPath: "/tmp/a.keychain-db", service: "svc", account: "acct")
        try cli.removeSecret(keychainPath: "/tmp/a.keychain-db", service: "svc", account: "acct")

        #expect(runner.invocations.count == 6)
        for invocation in runner.invocations {
            #expect(invocation.executable == "/usr/bin/security")
            #expect(invocation.standardInput == nil)
        }

        #expect(runner.invocations[0].arguments == ["create-keychain", "-p", "", "/tmp/a.keychain-db"])
        #expect(runner.invocations[1].arguments == ["set-keychain-settings", "-lut", "300", "/tmp/a.keychain-db"])
        #expect(runner.invocations[2].arguments == ["delete-keychain", "/tmp/a.keychain-db"])
        #expect(
            runner.invocations[3].arguments == [
                "add-generic-password", "-U", "-s", "svc", "-a", "acct", "-w", "value", "/tmp/a.keychain-db"
            ]
        )
        #expect(
            runner.invocations[4].arguments == [
                "find-generic-password", "-s", "svc", "-a", "acct", "-w", "/tmp/a.keychain-db"
            ]
        )
        #expect(
            runner.invocations[5].arguments == [
                "delete-generic-password", "-s", "svc", "-a", "acct", "/tmp/a.keychain-db"
            ]
        )
    }

    @Test("Trims secret output newlines")
    func getSecretTrimsNewline() throws {
        let runner = FakeProcessRunner()
        runner.enqueueSuccess(standardOutput: Data("top-secret\n".utf8))
        let cli = SecurityCLI(processRunner: runner)

        let secret = try cli.getSecret(keychainPath: "/tmp/a", service: "svc", account: "acct")
        #expect(secret == "top-secret")
    }

    @Test("Reports subprocess failure details")
    func nonZeroExitReporting() {
        let runner = FakeProcessRunner()
        runner.enqueueSuccess(exitCode: 7, standardError: Data("boom".utf8))
        let cli = SecurityCLI(processRunner: runner)

        expectSubprocessError(
            "security command failed for args [create-keychain, -p, <redacted>, /tmp/a]: boom"
        ) {
            try cli.createKeychain(at: "/tmp/a")
        }
    }

    @Test("Redacts secret argument values in subprocess failures")
    func setSecretFailureRedactsValue() {
        let runner = FakeProcessRunner()
        runner.enqueueSuccess(exitCode: 1, standardError: Data("denied".utf8))
        let cli = SecurityCLI(processRunner: runner)

        do {
            try cli.setSecret(keychainPath: "/tmp/a", service: "svc", account: "acct", value: "top-secret")
            Issue.record("Expected subprocess error")
        } catch {
            guard case .subprocess(let message) = error as? UFOError else {
                Issue.record("Unexpected error: \(error)")
                return
            }
            #expect(message.contains("top-secret") == false)
            #expect(message.contains("<redacted>"))
        }
    }

    @Test("Uses exit code detail when stderr empty")
    func emptyStderrIncludesExitCode() {
        let runner = FakeProcessRunner()
        runner.enqueueSuccess(exitCode: 42)
        let cli = SecurityCLI(processRunner: runner)

        expectSubprocessError(
            "security command failed for args [set-keychain-settings, -lut, 300, /tmp/a]: exit code 42"
        ) {
            try cli.hardenKeychain(at: "/tmp/a")
        }
    }

    @Test("Propagates typed errors and wraps untyped runner errors")
    func runErrorHandling() {
        struct RunnerError: Error {}

        let runner = FakeProcessRunner()
        runner.enqueueFailure(UFOError.io("already typed"))
        let cli = SecurityCLI(processRunner: runner)
        do {
            try cli.deleteKeychain(at: "/tmp/a")
            Issue.record("Expected error")
        } catch {
            #expect(error as? UFOError == .io("already typed"))
        }

        let runner2 = FakeProcessRunner()
        runner2.enqueueFailure(RunnerError())
        let cli2 = SecurityCLI(processRunner: runner2)
        do {
            try cli2.deleteKeychain(at: "/tmp/a")
            Issue.record("Expected wrapped error")
        } catch {
            guard case .subprocess(let message) = error as? UFOError else {
                Issue.record("Unexpected error: \(error)")
                return
            }
            #expect(message.contains("Failed running '/usr/bin/security delete-keychain /tmp/a'"))
        }
    }
}

private func expectSubprocessError(_ message: String, _ operation: () throws -> Void) {
    do {
        try operation()
        Issue.record("Expected subprocess error")
    } catch {
        #expect(error as? UFOError == .subprocess(message))
    }
}
