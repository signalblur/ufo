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
        for (index, invocation) in runner.invocations.enumerated() {
            #expect(invocation.executable == "/usr/bin/security")
            #expect(invocation.timeout == SecurityCLI.defaultSubprocessTimeout)
            #expect(invocation.environment == nil)
            if index == 3 {
                #expect(invocation.standardInput != nil)
            } else {
                #expect(invocation.standardInput == nil)
            }
        }

        #expect(runner.invocations[0].arguments == ["create-keychain", "-p", "", "/tmp/a.keychain-db"])
        #expect(runner.invocations[1].arguments == ["set-keychain-settings", "-lut", "300", "/tmp/a.keychain-db"])
        #expect(runner.invocations[2].arguments == ["delete-keychain", "/tmp/a.keychain-db"])
        #expect(runner.invocations[3].arguments == ["-i"])
        let setSecretInput = String(decoding: runner.invocations[3].standardInput ?? Data(), as: UTF8.self)
        #expect(
            setSecretInput ==
                "\"add-generic-password\" \"-U\" \"-s\" \"svc\" \"-a\" \"acct\" \"-X\" \"76616c7565\" \"/tmp/a.keychain-db\"\n"
        )
        #expect(setSecretInput.contains("value") == false)
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

    @Test("Removes only transport newline from secret output")
    func getSecretRemovesTransportNewline() throws {
        let runner = FakeProcessRunner()
        runner.enqueueSuccess(standardOutput: Data("top-secret\n".utf8))
        let cli = SecurityCLI(processRunner: runner)

        let secret = try cli.getSecret(keychainPath: "/tmp/a", service: "svc", account: "acct")
        #expect(secret == "top-secret")
    }

    @Test("Preserves leading and trailing newline bytes in secret payload")
    func getSecretPreservesPayloadNewlines() throws {
        let runner = FakeProcessRunner()
        runner.enqueueSuccess(standardOutput: Data("\nedge\n\n".utf8))
        let cli = SecurityCLI(processRunner: runner)

        let secret = try cli.getSecret(keychainPath: "/tmp/a", service: "svc", account: "acct")
        #expect(secret == "\nedge\n")
    }

    @Test("Handles CRLF-terminated transport output")
    func getSecretHandlesCRLFTransportTerminator() throws {
        let runner = FakeProcessRunner()
        runner.enqueueSuccess(standardOutput: Data("secret\r\n".utf8))
        let cli = SecurityCLI(processRunner: runner)

        let secret = try cli.getSecret(keychainPath: "/tmp/a", service: "svc", account: "acct")
        #expect(secret == "secret")
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
            #expect(message.contains("746f702d736563726574") == false)
            #expect(message.contains("[-i]"))
        }
    }

    @Test("Passes default and custom subprocess timeout values")
    func subprocessTimeoutConfiguration() throws {
        let defaultRunner = FakeProcessRunner()
        let defaultCLI = SecurityCLI(processRunner: defaultRunner)
        try defaultCLI.deleteKeychain(at: "/tmp/default")
        #expect(defaultRunner.invocations[0].timeout == SecurityCLI.defaultSubprocessTimeout)

        let customRunner = FakeProcessRunner()
        let customCLI = SecurityCLI(processRunner: customRunner, subprocessTimeout: 2.5)
        try customCLI.deleteKeychain(at: "/tmp/custom")
        #expect(customRunner.invocations[0].timeout == 2.5)
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
