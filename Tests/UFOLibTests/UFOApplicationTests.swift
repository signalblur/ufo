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

    @Test("Keychain inventory lists visible keychains with metadata and defaults")
    func keychainInventoryOutput() {
        let fixture = makeFixture()
        _ = fixture.app.run(arguments: ["keychain", "create", "alpha"])
        fixture.fileSystem.writeString("managed", to: "/Users/tester/.ufo/keychains/alpha.keychain-db")
        fixture.fileSystem.writeString("login", to: "/Users/tester/Library/Keychains/login.keychain-db")

        fixture.processRunner.enqueueSuccess(standardOutput: Data(
            "\"/Users/tester/Library/Keychains/login.keychain-db\"\n\"/Users/tester/.ufo/keychains/alpha.keychain-db\"\n".utf8
        ))

        let result = fixture.app.run(arguments: ["keychain", "inventory"])

        #expect(result.exitCode == 0)
        #expect(result.standardOutput.contains("Keychain inventory"))
        #expect(result.standardOutput.contains("Defaults:"))
        #expect(result.standardOutput.contains("mode=current-user"))
        #expect(result.standardOutput.contains("/Users/tester/.ufo/keychains/alpha.keychain-db\tyes\talpha\tpending\t0\tyes"))
        #expect(result.standardOutput.contains("/Users/tester/Library/Keychains/login.keychain-db\tno\t-\t-\t-\tyes"))

        #expect(fixture.processRunner.invocations.count == 2)
        let inventoryInvocation = fixture.processRunner.invocations[1]
        #expect(inventoryInvocation.executable == "/usr/bin/security")
        #expect(inventoryInvocation.arguments == ["list-keychains", "-d", "user"])
    }

    @Test("Keychain inventory can target a specific user via sudo")
    func keychainInventorySpecificUser() {
        let fixture = makeFixture()
        fixture.processRunner.enqueueSuccess(standardOutput: Data("\"/Users/alice/login.keychain-db\"\n".utf8))

        let result = fixture.app.run(arguments: ["keychain", "inventory", "--user", "alice"])
        #expect(result.exitCode == 0)
        #expect(result.standardOutput.contains("Context: user=alice mode=sudo -n"))

        #expect(fixture.processRunner.invocations.count == 1)
        let invocation = fixture.processRunner.invocations[0]
        #expect(invocation.executable == "/usr/bin/sudo")
        #expect(invocation.arguments == [
            "-n", "-u", "alice", "/usr/bin/security", "list-keychains", "-d", "user"
        ])
    }

    @Test("Keychain inventory handles empty and failing subprocess output")
    func keychainInventoryEmptyAndFailurePaths() {
        let emptyFixture = makeFixture()
        emptyFixture.processRunner.enqueueSuccess(standardOutput: Data())
        let empty = emptyFixture.app.run(arguments: ["keychain", "inventory"])
        #expect(empty.exitCode == 0)
        #expect(empty.standardOutput.contains("No keychains were returned"))

        let stderrFixture = makeFixture()
        stderrFixture.processRunner.enqueueSuccess(exitCode: 42, standardError: Data("permission denied".utf8))
        let stderrFailure = stderrFixture.app.run(arguments: ["keychain", "inventory"])
        #expect(stderrFailure.exitCode == ExitCode.subprocessFailure.rawValue)
        #expect(stderrFailure.standardError.contains("permission denied"))

        let noStderrFixture = makeFixture()
        noStderrFixture.processRunner.enqueueSuccess(exitCode: 7, standardError: Data())
        let noStderrFailure = noStderrFixture.app.run(arguments: ["keychain", "inventory"])
        #expect(noStderrFailure.exitCode == ExitCode.subprocessFailure.rawValue)
        #expect(noStderrFailure.standardError.contains("exit code 7"))
    }

    @Test("Keychain inventory includes hardened status and validates user names")
    func keychainInventoryHardenedAndUserValidation() {
        let fixture = makeFixture()
        _ = fixture.app.run(arguments: ["keychain", "create", "alpha"])
        _ = fixture.app.run(arguments: ["keychain", "harden", "alpha"])
        fixture.fileSystem.writeString("managed", to: "/Users/tester/.ufo/keychains/alpha.keychain-db")
        fixture.processRunner.enqueueSuccess(standardOutput: Data("\"/Users/tester/.ufo/keychains/alpha.keychain-db\"\n".utf8))

        let hardened = fixture.app.run(arguments: ["keychain", "inventory"])
        #expect(hardened.exitCode == 0)
        #expect(hardened.standardOutput.contains("/Users/tester/.ufo/keychains/alpha.keychain-db\tyes\talpha\thardened"))

        let emptyUser = fixture.app.run(arguments: ["keychain", "inventory", "--user", ""])
        #expect(emptyUser.exitCode == ExitCode.policyDenied.rawValue)
        #expect(emptyUser.standardError.contains("User name cannot be empty"))

        let invalidUser = fixture.app.run(arguments: ["keychain", "inventory", "--user", "bad user"])
        #expect(invalidUser.exitCode == ExitCode.policyDenied.rawValue)
        #expect(invalidUser.standardError.contains("User name must start with a letter or underscore"))
    }

    @Test("Trace flag prints troubleshooting details to stdout")
    func traceFlagOutput() {
        let fixture = makeFixture()

        let listResult = fixture.app.run(arguments: ["--trace", "keychain", "list"])
        #expect(listResult.exitCode == 0)
        #expect(listResult.standardOutput.contains("[trace"))
        #expect(listResult.standardOutput.contains("command=keychain.list"))

        let errorResult = fixture.app.run(arguments: ["--trace", "bad"])
        #expect(errorResult.exitCode == ExitCode.usage.rawValue)
        #expect(errorResult.standardOutput.contains("raw args=[\"bad\"]"))

        let duplicateTrace = fixture.app.run(arguments: ["--trace", "--trace", "keychain", "list"])
        #expect(duplicateTrace.exitCode == ExitCode.usage.rawValue)
        #expect(duplicateTrace.standardError.contains("Option '--trace' was provided multiple times."))
    }

    @Test("Secret set/get/remove/search workflow")
    func secretWorkflow() {
        let fixture = makeFixture()
        _ = fixture.app.run(arguments: ["keychain", "create", "alpha"])

        fixture.inputReader.value = "123\n"
        let setValue = fixture.app.run(arguments: [
            "secret", "set", "--keychain", "alpha", "--service", "github", "--account", "ci", "--stdin"
        ])
        #expect(setValue.exitCode == 0)

        fixture.inputReader.value = "stdin-secret\n"
        let setStdin = fixture.app.run(arguments: [
            "secret", "set", "--keychain", "alpha", "--service", "apple", "--account", "ops", "--stdin"
        ])
        #expect(setStdin.exitCode == 0)

        fixture.inputReader.value = "abc\n"
        let setSecondGithub = fixture.app.run(arguments: [
            "secret", "set", "--keychain", "alpha", "--service", "github", "--account", "bot", "--stdin"
        ])
        #expect(setSecondGithub.exitCode == 0)
        #expect(fixture.inputReader.requestedMaxBytes == [
            InputValidation.maximumSecretInputBytes,
            InputValidation.maximumSecretInputBytes,
            InputValidation.maximumSecretInputBytes
        ])

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
            "secret", "set", "--keychain", "missing", "--service", "svc", "--account", "acct", "--stdin"
        ])
        #expect(missingManaged.exitCode == ExitCode.notFound.rawValue)
        #expect(fixture.inputReader.requestedMaxBytes.isEmpty)

        _ = fixture.app.run(arguments: ["keychain", "create", "alpha"])
        let emptyQuery = fixture.app.run(arguments: [
            "secret", "search", "--keychain", "alpha", "--query", ""
        ])
        #expect(emptyQuery.exitCode == ExitCode.usage.rawValue)

        fixture.inputReader.value = ""
        let emptyStdinSecret = fixture.app.run(arguments: [
            "secret", "set", "--keychain", "alpha", "--service", "svc", "--account", "acct", "--stdin"
        ])
        #expect(emptyStdinSecret.exitCode == ExitCode.policyDenied.rawValue)
        #expect(emptyStdinSecret.standardError.contains("Secret value cannot be empty"))

        fixture.inputReader.value = String(repeating: "a", count: InputValidation.maximumSecretInputBytes + 1)
        let oversizedStdinSecret = fixture.app.run(arguments: [
            "secret", "set", "--keychain", "alpha", "--service", "svc", "--account", "acct", "--stdin"
        ])
        #expect(oversizedStdinSecret.exitCode == ExitCode.policyDenied.rawValue)
        #expect(
            oversizedStdinSecret.standardError
                .contains("Secret stdin input exceeds \(InputValidation.maximumSecretInputBytes) bytes")
        )
        #expect(fixture.inputReader.requestedMaxBytes == [
            InputValidation.maximumSecretInputBytes,
            InputValidation.maximumSecretInputBytes
        ])
    }

    @Test("Secret run injects secret into child process environment")
    func secretRunWorkflow() {
        let fixture = makeFixture()
        _ = fixture.app.run(arguments: ["keychain", "create", "alpha"])

        fixture.processRunner.enqueueSuccess(standardOutput: Data("runtime-secret\n".utf8))
        fixture.processRunner.enqueueSuccess(standardOutput: Data("script-ok".utf8))
        let run = fixture.app.run(arguments: [
            "secret", "run",
            "--keychain", "alpha",
            "--service", "openai",
            "--account", "ci",
            "--env", "OPENAI_API_KEY",
            "--",
            "python3",
            "script.py",
            "--mode",
            "prod"
        ])

        #expect(run.exitCode == 0)
        #expect(run.standardOutput == "script-ok")
        #expect(run.standardError.isEmpty)

        #expect(fixture.processRunner.invocations.count == 3)
        let firstRunInvocation = fixture.processRunner.invocations[2]
        #expect(firstRunInvocation.executable == "/usr/bin/env")
        #expect(firstRunInvocation.arguments == ["--", "python3", "script.py", "--mode", "prod"])
        #expect(firstRunInvocation.timeout == 300)
        #expect(firstRunInvocation.standardInput == nil)
        #expect(firstRunInvocation.environment?["OPENAI_API_KEY"] == "runtime-secret")
    }

    @Test("Shortcut run resolves defaults for single keychain and service token")
    func secretRunShortcutDefaults() {
        let fixture = makeFixture()
        _ = fixture.app.run(arguments: ["keychain", "create", "alpha"])

        fixture.inputReader.value = "stored-secret"
        _ = fixture.app.run(arguments: [
            "secret", "set",
            "--keychain", "alpha",
            "--service", "openai",
            "--account", "ci",
            "--stdin"
        ])

        fixture.processRunner.enqueueSuccess(standardOutput: Data("runtime-secret\n".utf8))
        fixture.processRunner.enqueueSuccess(standardOutput: Data("shortcut-ok".utf8))
        let shortcut = fixture.app.run(arguments: [
            "--env", "OPENAI_API_KEY",
            "python3",
            "script.py"
        ])

        #expect(shortcut.exitCode == 0)
        #expect(shortcut.standardOutput == "shortcut-ok")
        #expect(shortcut.standardError.isEmpty)

        #expect(fixture.processRunner.invocations.count == 4)
        let getInvocation = fixture.processRunner.invocations[2]
        #expect(getInvocation.arguments == [
            "find-generic-password", "-s", "openai", "-a", "ci", "-w", "/Users/tester/.ufo/keychains/alpha.keychain-db"
        ])

        let childInvocation = fixture.processRunner.invocations[3]
        #expect(childInvocation.executable == "/usr/bin/env")
        #expect(childInvocation.arguments == ["--", "python3", "script.py"])
        #expect(childInvocation.environment?["OPENAI_API_KEY"] == "runtime-secret")
    }

    @Test("Shortcut run supports explicit keychain service and account selectors")
    func secretRunShortcutExplicitSelectors() {
        let fixture = makeFixture()
        _ = fixture.app.run(arguments: ["keychain", "create", "alpha"])
        do {
            try fixture.registryStore.upsertSecretMetadata(keychainName: "alpha", service: "openai", account: "ci")
        } catch {
            Issue.record("Unexpected setup error: \(error)")
            return
        }

        fixture.processRunner.enqueueSuccess(standardOutput: Data("explicit-secret\n".utf8))
        fixture.processRunner.enqueueSuccess(standardOutput: Data("explicit-ok".utf8))
        let result = fixture.app.run(arguments: [
            "--env", "OPENAI_API_KEY",
            "--keychain", "alpha",
            "--service", "openai",
            "--account", "ci",
            "python3",
            "script.py"
        ])

        #expect(result.exitCode == 0)
        #expect(result.standardOutput == "explicit-ok")
        #expect(fixture.processRunner.invocations.count == 3)
        #expect(fixture.processRunner.invocations[1].arguments == [
            "find-generic-password", "-s", "openai", "-a", "ci", "-w", "/Users/tester/.ufo/keychains/alpha.keychain-db"
        ])
    }

    @Test("Shortcut run handles missing keychains and missing metadata")
    func secretRunShortcutMissingState() {
        let noKeychainFixture = makeFixture()
        let noKeychain = noKeychainFixture.app.run(arguments: [
            "--env", "OPENAI_API_KEY",
            "python3",
            "script.py"
        ])
        #expect(noKeychain.exitCode == ExitCode.notFound.rawValue)
        #expect(noKeychain.standardError.contains("No managed keychains found"))

        let noMetadataFixture = makeFixture()
        _ = noMetadataFixture.app.run(arguments: ["keychain", "create", "alpha"])
        let noMetadata = noMetadataFixture.app.run(arguments: [
            "--env", "OPENAI_API_KEY",
            "python3",
            "script.py"
        ])
        #expect(noMetadata.exitCode == ExitCode.notFound.rawValue)
        #expect(noMetadata.standardError.contains("No secret metadata found"))
    }

    @Test("Shortcut run surfaces explicit selector not-found and ambiguous states")
    func secretRunShortcutSelectorFailures() {
        let fixture = makeFixture()
        _ = fixture.app.run(arguments: ["keychain", "create", "alpha"])
        do {
            try fixture.registryStore.upsertSecretMetadata(keychainName: "alpha", service: "openai", account: "ci")
            try fixture.registryStore.upsertSecretMetadata(keychainName: "alpha", service: "openai", account: "ops")
        } catch {
            Issue.record("Unexpected setup error: \(error)")
            return
        }

        let noMatch = fixture.app.run(arguments: [
            "--env", "OPENAI_API_KEY",
            "--service", "github",
            "--account", "bot",
            "python3",
            "script.py"
        ])
        #expect(noMatch.exitCode == ExitCode.notFound.rawValue)
        #expect(noMatch.standardError.contains("No secret metadata matches service 'github' and account 'bot'"))

        let multiple = fixture.app.run(arguments: [
            "--env", "OPENAI_API_KEY",
            "--service", "openai",
            "python3",
            "script.py"
        ])
        #expect(multiple.exitCode == ExitCode.usage.rawValue)
        #expect(multiple.standardError.contains("Multiple secret metadata entries match"))

        let multipleWithoutEnvMatch = fixture.app.run(arguments: [
            "--env", "NOMATCH",
            "python3",
            "script.py"
        ])
        #expect(multipleWithoutEnvMatch.exitCode == ExitCode.usage.rawValue)
        #expect(multipleWithoutEnvMatch.standardError.contains("Multiple secrets are stored in keychain"))
    }

    @Test("Shortcut run can infer from account tokens and fallback when env token is empty")
    func secretRunShortcutAccountInferenceAndSingleFallback() {
        let accountFixture = makeFixture()
        _ = accountFixture.app.run(arguments: ["keychain", "create", "alpha"])
        do {
            try accountFixture.registryStore.upsertSecretMetadata(
                keychainName: "alpha",
                service: "custom-service",
                account: "openai"
            )
        } catch {
            Issue.record("Unexpected setup error: \(error)")
            return
        }

        accountFixture.processRunner.enqueueSuccess(standardOutput: Data("inferred-secret\n".utf8))
        accountFixture.processRunner.enqueueSuccess(standardOutput: Data("inferred-ok".utf8))
        let inferred = accountFixture.app.run(arguments: [
            "--env", "OPENAI_API_KEY",
            "python3",
            "script.py"
        ])
        #expect(inferred.exitCode == 0)
        #expect(inferred.standardOutput == "inferred-ok")
        #expect(accountFixture.processRunner.invocations[1].arguments == [
            "find-generic-password", "-s", "custom-service", "-a", "openai", "-w", "/Users/tester/.ufo/keychains/alpha.keychain-db"
        ])

        let fallbackFixture = makeFixture()
        _ = fallbackFixture.app.run(arguments: ["keychain", "create", "alpha"])
        do {
            try fallbackFixture.registryStore.upsertSecretMetadata(keychainName: "alpha", service: "github", account: "ci")
        } catch {
            Issue.record("Unexpected setup error: \(error)")
            return
        }

        fallbackFixture.processRunner.enqueueSuccess(standardOutput: Data("fallback-secret\n".utf8))
        fallbackFixture.processRunner.enqueueSuccess(standardOutput: Data("fallback-ok".utf8))
        let fallback = fallbackFixture.app.run(arguments: [
            "--env", "___",
            "python3",
            "script.py"
        ])
        #expect(fallback.exitCode == 0)
        #expect(fallback.standardOutput == "fallback-ok")
    }

    @Test("Shortcut run requires explicit selectors for ambiguous defaults")
    func secretRunShortcutAmbiguityHandling() {
        let fixture = makeFixture()
        _ = fixture.app.run(arguments: ["keychain", "create", "alpha"])

        fixture.inputReader.value = "secret-one"
        _ = fixture.app.run(arguments: [
            "secret", "set",
            "--keychain", "alpha",
            "--service", "openai",
            "--account", "ci",
            "--stdin"
        ])

        fixture.inputReader.value = "secret-two"
        _ = fixture.app.run(arguments: [
            "secret", "set",
            "--keychain", "alpha",
            "--service", "openai",
            "--account", "ops",
            "--stdin"
        ])

        let ambiguousSecret = fixture.app.run(arguments: [
            "--env", "OPENAI_API_KEY",
            "python3",
            "script.py"
        ])
        #expect(ambiguousSecret.exitCode == ExitCode.usage.rawValue)
        #expect(ambiguousSecret.standardError.contains("Multiple secrets match --env OPENAI_API_KEY"))

        _ = fixture.app.run(arguments: ["keychain", "create", "beta"])
        let ambiguousKeychain = fixture.app.run(arguments: [
            "--env", "OPENAI_API_KEY",
            "python3",
            "script.py"
        ])
        #expect(ambiguousKeychain.exitCode == ExitCode.usage.rawValue)
        #expect(ambiguousKeychain.standardError.contains("Multiple managed keychains found"))
    }

    @Test("Secret run validates env name and reports child failures")
    func secretRunValidationAndFailure() {
        let fixture = makeFixture()
        _ = fixture.app.run(arguments: ["keychain", "create", "alpha"])

        let invalidEnv = fixture.app.run(arguments: [
            "secret", "run",
            "--keychain", "alpha",
            "--service", "openai",
            "--account", "ci",
            "--env", "BAD-NAME",
            "--",
            "python3",
            "script.py"
        ])
        #expect(invalidEnv.exitCode == ExitCode.policyDenied.rawValue)
        #expect(invalidEnv.standardError.contains("Environment variable name"))

        let blockedEnv = fixture.app.run(arguments: [
            "secret", "run",
            "--keychain", "alpha",
            "--service", "openai",
            "--account", "ci",
            "--env", "PATH",
            "--",
            "python3",
            "script.py"
        ])
        #expect(blockedEnv.exitCode == ExitCode.policyDenied.rawValue)
        #expect(blockedEnv.standardError.contains("is blocked for safety"))

        fixture.processRunner.enqueueSuccess(standardOutput: Data("super-secret\n".utf8))
        fixture.processRunner.enqueueSuccess(exitCode: 7, standardError: Data("child stderr".utf8))
        let failedChild = fixture.app.run(arguments: [
            "secret", "run",
            "--keychain", "alpha",
            "--service", "openai",
            "--account", "ci",
            "--env", "OPENAI_API_KEY",
            "--",
            "python3",
            "script.py"
        ])
        #expect(failedChild.exitCode == 7)
        #expect(failedChild.standardOutput.isEmpty)
        #expect(failedChild.standardError == "child stderr")
        #expect(failedChild.standardError.contains("super-secret") == false)
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
            processRunner: fixture.processRunner,
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
            processRunner: fixture.processRunner,
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
            processRunner: fixture.processRunner,
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
            processRunner: fixture.processRunner,
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
        processRunner: processRunner,
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
