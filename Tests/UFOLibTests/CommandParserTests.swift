import Testing
@testable import UFOLib

@Suite("Command Parser")
struct CommandParserTests {
    private let parser = CommandParser()

    @Test("Parses root help for empty args")
    func parseEmptyArgs() throws {
        let command = try parser.parse([])
        #expect(command == .help(topic: nil))
    }

    @Test("Parses help topic")
    func parseHelpTopic() throws {
        let command = try parser.parse(["help", "secret", "set"])
        #expect(command == .help(topic: "secret set"))
    }

    @Test("Parses bare help command")
    func parseBareHelp() throws {
        let command = try parser.parse(["help"])
        #expect(command == .help(topic: nil))
    }

    @Test("Parses keychain create")
    func parseKeychainCreate() throws {
        let command = try parser.parse(["keychain", "create", "team", "--path", "/tmp/k"])
        #expect(command == .keychainCreate(name: "team", path: "/tmp/k"))
    }

    @Test("Rejects malformed keychain create/harden")
    func parseMalformedKeychainCommands() {
        expectError(.usage("'keychain create' requires <name>.")) {
            _ = try parser.parse(["keychain", "create"])
        }
        expectError(.usage("'keychain harden' requires exactly one <name>.")) {
            _ = try parser.parse(["keychain", "harden", "a", "b"])
        }

        expectError(.usage("Missing keychain subcommand. Use 'ufo help keychain'.")) {
            _ = try parser.parse(["keychain"])
        }

        expectError(.usage("Unknown keychain subcommand 'oops'.")) {
            _ = try parser.parse(["keychain", "oops"])
        }

        expectError(.usage("'keychain delete' requires <name>.")) {
            _ = try parser.parse(["keychain", "delete"])
        }
    }

    @Test("Parses keychain delete with safety flags")
    func parseKeychainDelete() throws {
        let command = try parser.parse([
            "keychain", "delete", "alpha", "--yes", "--confirm", "alpha"
        ])
        #expect(command == .keychainDelete(name: "alpha", yes: true, confirm: "alpha"))
    }

    @Test("Parses secret set via stdin")
    func parseSecretSetViaStdin() throws {
        let byStdin = try parser.parse([
            "secret", "set", "--keychain", "k", "--service", "svc", "--account", "acct", "--stdin"
        ])
        #expect(byStdin == .secretSet(keychain: "k", service: "svc", account: "acct", input: .stdin))
    }

    @Test("Rejects insecure secret set forms")
    func parseSecretSetRejectsInsecureForms() {
        expectError(.usage("'secret set' requires --stdin.")) {
            _ = try parser.parse([
                "secret", "set", "--keychain", "k", "--service", "svc", "--account", "acct"
            ])
        }

        expectError(.usage("'secret set --value' is disabled to avoid argv secret exposure. Use --stdin.")) {
            _ = try parser.parse([
                "secret", "set", "--keychain", "k", "--service", "svc", "--account", "acct", "--value", "v"
            ])
        }

        expectError(.usage("'secret set --value' is disabled to avoid argv secret exposure. Use --stdin.")) {
            _ = try parser.parse([
                "secret", "set", "--keychain", "k", "--service", "svc", "--account", "acct", "--stdin", "--value", "v"
            ])
        }
    }

    @Test("Parses secret get/remove/search")
    func parseSecretCommands() throws {
        let get = try parser.parse([
            "secret", "get", "--keychain", "k", "--service", "svc", "--account", "acct", "--reveal"
        ])
        #expect(get == .secretGet(keychain: "k", service: "svc", account: "acct", reveal: true))

        let remove = try parser.parse([
            "secret", "remove", "--keychain", "k", "--service", "svc", "--account", "acct", "--yes"
        ])
        #expect(remove == .secretRemove(keychain: "k", service: "svc", account: "acct", yes: true))

        let search = try parser.parse([
            "secret", "search", "--keychain", "k", "--query", "gh"
        ])
        #expect(search == .secretSearch(keychain: "k", query: "gh"))

        expectError(.usage("Missing secret subcommand. Use 'ufo help secret'.")) {
            _ = try parser.parse(["secret"])
        }

        expectError(.usage("Unknown secret subcommand 'oops'.")) {
            _ = try parser.parse(["secret", "oops"])
        }
    }

    @Test("Rejects unknown command forms and option syntax")
    func parseInvalidForms() {
        expectError(.usage("Unknown command 'unknown'. Use 'ufo help'.")) {
            _ = try parser.parse(["unknown"])
        }

        expectError(.usage("'doctor' does not accept arguments.")) {
            _ = try parser.parse(["doctor", "oops"])
        }

        expectError(.usage("'keychain list' does not accept arguments.")) {
            _ = try parser.parse(["keychain", "list", "--bad"])
        }

        expectError(.usage("Option '--query' requires a value.")) {
            _ = try parser.parse([
                "secret", "search", "--keychain", "k", "--query"
            ])
        }

        expectError(.usage("Option '--query' requires a value.")) {
            _ = try parser.parse([
                "secret", "search", "--keychain", "k", "--query", "--next"
            ])
        }

        expectError(.usage("Unknown option '--bogus'.")) {
            _ = try parser.parse([
                "secret", "search", "--keychain", "k", "--query", "x", "--bogus", "z"
            ])
        }

        expectError(.usage("Unexpected positional argument 'extra'.")) {
            _ = try parser.parse([
                "secret", "search", "--keychain", "k", "--query", "x", "extra"
            ])
        }

        expectError(.usage("Option '--keychain' was provided multiple times.")) {
            _ = try parser.parse([
                "secret", "search", "--keychain", "a", "--keychain", "b", "--query", "x"
            ])
        }

        expectError(.usage("Option '--yes' was provided multiple times.")) {
            _ = try parser.parse([
                "keychain", "delete", "name", "--yes", "--yes", "--confirm", "name"
            ])
        }
    }
}

private func expectError(_ expected: UFOError, _ operation: () throws -> Void) {
    do {
        try operation()
        Issue.record("Expected error \(expected)")
    } catch {
        #expect(error as? UFOError == expected)
    }
}
